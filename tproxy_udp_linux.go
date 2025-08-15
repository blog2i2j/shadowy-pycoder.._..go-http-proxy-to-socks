//go:build linux || (android && arm)
// +build linux android,arm

package gohpts

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"

	"github.com/shadowy-pycoder/mshark/layers"
	"github.com/shadowy-pycoder/mshark/network"
	"github.com/wzshiming/socks5"
	"golang.org/x/sys/unix"
)

const (
	readTimeoutUDP  time.Duration = 5 * time.Second
	writeTimeoutUDP time.Duration = 5 * time.Second
	idleTimeoutUDP  time.Duration = 30 * time.Second
	udpBufferSize   int           = 4096
)

type udpConn struct {
	*socks5.UDPConn
	srcAddr  *net.UDPAddr
	dstAddr  *net.UDPAddr
	lastSeen time.Time
	written  atomic.Uint64
	reqChan  chan layers.Layer
	respChan chan layers.Layer
}

func (uc *udpConn) SrcPort() *uint16 {
	srcPort := uint16(uc.dstAddr.Port)
	return &srcPort
}

func (uc *udpConn) DstPort() *uint16 {
	dstPort := uint16(uc.dstAddr.Port)
	return &dstPort
}

func newUDPConn(srcAddr *net.UDPAddr, dstAddr *net.UDPAddr, sockDialer *socks5.Dialer) (*udpConn, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	conn, err := sockDialer.DialContext(ctx, "udp4", dstAddr.String())
	if err != nil {
		return nil, err
	}
	relayConn, ok := conn.(*socks5.UDPConn)
	if !ok {
		return nil, fmt.Errorf("failed obtaining relay connection")
	}
	return &udpConn{
		UDPConn:  relayConn,
		srcAddr:  srcAddr,
		dstAddr:  dstAddr,
		lastSeen: time.Now(),
		reqChan:  make(chan layers.Layer),
		respChan: make(chan layers.Layer),
	}, nil
}

type udpConnections struct {
	wg   sync.WaitGroup
	quit chan struct{}
	sync.RWMutex
	clients map[string]*udpConn
}

func (ucs *udpConnections) Add(conn *udpConn) {
	ucs.Lock()
	ucs.clients[fmt.Sprintf("%s,%s", conn.srcAddr, conn.dstAddr)] = conn
	ucs.Unlock()
}

func (ucs *udpConnections) Get(srcAddr, dstAddr *net.UDPAddr) (*udpConn, bool) {
	ucs.RLock()
	defer ucs.RUnlock()
	conn, ok := ucs.clients[fmt.Sprintf("%s,%s", srcAddr, dstAddr)]
	return conn, ok
}

func (ucs *udpConnections) Remove(conn *udpConn) {
	ucs.Lock()
	delete(ucs.clients, fmt.Sprintf("%s,%s", conn.srcAddr, conn.dstAddr))
	ucs.Unlock()
}

func (ucs *udpConnections) UpdateLastSeen(conn *udpConn) {
	ucs.Lock()
	conn.lastSeen = time.Now()
	ucs.Unlock()
}

func (ucs *udpConnections) RemoveByAddr(addr string) {
	ucs.Lock()
	delete(ucs.clients, addr)
	ucs.Unlock()
}

func (ucs *udpConnections) Cleanup() {
	ucs.wg.Add(1)
	t := time.NewTicker(idleTimeoutUDP)
	for {
		select {
		case <-ucs.quit:
			ucs.Lock()
			for _, conn := range ucs.clients {
				conn.Close()
			}
			ucs.Unlock()
			ucs.wg.Done()
			return
		case <-t.C:
			ucs.Lock()
			for k, conn := range ucs.clients {
				if time.Since(conn.lastSeen) > idleTimeoutUDP {
					conn.Close()
					ucs.RemoveByAddr(k)
				}
			}
			ucs.Unlock()
		}
	}
}

type tproxyServerUDP struct {
	conn         *net.UDPConn
	quit         chan struct{}
	wg           sync.WaitGroup
	p            *proxyapp
	clients      *udpConnections
	iface        *net.Interface
	gwConn       *net.UDPConn
	gwDNS        *net.UDPAddr
	startingFlag atomic.Bool
}

func newTproxyServerUDP(p *proxyapp) *tproxyServerUDP {
	tsu := &tproxyServerUDP{
		quit: make(chan struct{}),
		p:    p,
	}
	lc := net.ListenConfig{
		Control: func(network, address string, conn syscall.RawConn) error {
			var operr error
			if err := conn.Control(func(fd uintptr) {
				operr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEADDR, 1)
				operr = unix.SetsockoptInt(int(fd), unix.SOL_IP, unix.IP_TRANSPARENT, 1)
				operr = unix.SetsockoptInt(int(fd), unix.SOL_IP, unix.IP_RECVORIGDSTADDR, 1)
			}); err != nil {
				return err
			}
			return operr
		},
	}
	pconn, err := lc.ListenPacket(context.Background(), "udp4", tsu.p.tproxyAddrUDP)
	if err != nil {
		var msg string
		if errors.Is(err, unix.EPERM) {
			msg = "try `sudo setcap 'cap_net_admin+ep` for the binary or run with sudo:"
		}
		tsu.p.logger.Fatal().Err(err).Msg(msg)
	}
	tsu.conn = pconn.(*net.UDPConn)
	tsu.clients = &udpConnections{quit: tsu.quit, clients: make(map[string]*udpConn)}
	if tsu.p.iface != nil {
		tsu.iface = tsu.p.iface
	} else {
		tsu.iface, err = network.GetDefaultInterface()
		if err != nil {
			tsu.iface, err = network.GetDefaultInterfaceFromRoute()
			if err != nil {
				tsu.p.logger.Fatal().Err(err).Msgf("[udp %s] Failed getting default interface", tsu.p.tproxyMode)
			}
		}
	}
	if tsu.p.arpspoofer != nil {
		gw := tsu.p.arpspoofer.GatewayIP()
		tsu.gwDNS = &net.UDPAddr{IP: net.ParseIP(gw.String()), Port: 53}
		lc = net.ListenConfig{
			Control: func(network, address string, conn syscall.RawConn) error {
				var operr error
				if err := conn.Control(func(fd uintptr) {
					operr = unix.SetsockoptInt(int(fd), unix.SOL_IP, unix.IP_TRANSPARENT, 1)
					operr = unix.SetsockoptInt(int(fd), unix.SOL_IP, unix.IP_FREEBIND, 1)
					operr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEADDR, 1)
				}); err != nil {
					return err
				}
				return operr
			},
		}
		pconn, err = lc.ListenPacket(context.Background(), "udp4", tsu.gwDNS.String())
		if err != nil {
			tsu.p.logger.Fatal().Err(err).Msgf("[udp %s] failed listening on gateway DNS", tsu.p.tproxyMode)
		}
		tsu.gwConn = pconn.(*net.UDPConn)
	}
	return tsu
}

func (tsu *tproxyServerUDP) ListenAndServe() {
	tsu.startingFlag.Store(true)
	tsu.wg.Add(1)
	go tsu.clients.Cleanup()
	if tsu.p.arpspoofer != nil {
		go func() {
			tsu.listenAndServeDNS()
			tsu.wg.Done()
		}()
	}
	buf := make([]byte, udpBufferSize)
	oob := make([]byte, 1500)
	tsu.startingFlag.Store(false)
	for {
		select {
		case <-tsu.quit:
			tsu.wg.Done()
			return
		default:
			err := tsu.conn.SetReadDeadline(time.Now().Add(readTimeoutUDP))
			if err != nil {
				if errors.Is(err, net.ErrClosed) {
					continue
				}
				tsu.p.logger.Error().Err(err).Msgf("[udp %s] Failed setting read deadline", tsu.p.tproxyMode)
				continue
			}
			n, oobn, _, srcAddr, er := tsu.conn.ReadMsgUDP(buf, oob)
			if n > 0 {
				dstAddr, err := tsu.getOriginalDst(oob[:oobn])
				if err != nil {
					tsu.p.logger.Error().Err(err).Msgf("[udp %s] Failed getting original destination", tsu.p.tproxyMode)
					continue
				}
				conn, found := tsu.clients.Get(srcAddr, dstAddr)
				if !found {
					sockDialer, _, err := tsu.p.getSocks()
					if err != nil {
						tsu.p.logger.Error().Err(err).Msgf("[udp %s] Failed getting SOCKS5 client for %s→ %s", tsu.p.tproxyMode, srcAddr, dstAddr)
						continue
					}
					conn, err = newUDPConn(srcAddr, dstAddr, sockDialer)
					if err != nil {
						tsu.p.logger.Error().Err(err).Msgf("[udp %s] Failed creating UDP connection for %s→ %s", tsu.p.tproxyMode, srcAddr, dstAddr)
						continue
					}
					tsu.clients.Add(conn)
					go func() {
						tsu.handleConnection(conn)
					}()
				}
				srcConnStr := fmt.Sprintf("%s→ %s", srcAddr, dstAddr)
				dstConnStr := fmt.Sprintf("%s→ %s→ %s", tsu.conn.LocalAddr(), conn.LocalAddr(), dstAddr)
				tsu.p.logger.Debug().Msgf("[udp %s] src: %s - dst: %s", tsu.p.tproxyMode, srcConnStr, dstConnStr)
				err = conn.SetWriteDeadline(time.Now().Add(writeTimeoutUDP))
				if err != nil {
					if errors.Is(err, net.ErrClosed) {
						continue
					}
					tsu.p.logger.Error().Err(err).Msgf("[udp %s] Failed setting write deadline", tsu.p.tproxyMode)
					continue
				}
				if tsu.p.sniff {
					if next := layers.ParseNextLayer(buf[:n], conn.SrcPort(), conn.DstPort()); next != nil {
						tsu.wg.Add(1)
						sniffheader := make([]string, 0, 3)
						id := getID(tsu.p.nocolor)
						if tsu.p.json {
							sniffheader = append(
								sniffheader,
								fmt.Sprintf(
									"{\"connection\":{\"tproxy_mode\":%q,\"src_remote\":%q,\"src_local\":%q,\"dst_local\":%q,\"dst_remote\":%q,\"original_dst\":%s}}",
									tsu.p.tproxyMode,
									srcAddr,
									conn.dstAddr,
									tsu.conn.LocalAddr(),
									conn.LocalAddr(),
									conn.dstAddr,
								),
							)
						} else {
							connections := colorizeConnectionsTransparent(
								srcAddr,
								conn.dstAddr,
								tsu.conn.LocalAddr(),
								conn.LocalAddr(),
								conn.dstAddr.String(),
								id, tsu.p.nocolor)
							sniffheader = append(sniffheader, connections)
						}
						go tsu.p.sniffreporter(&tsu.wg, &sniffheader, conn.reqChan, conn.respChan, id)
						conn.reqChan <- next
					}
				}
				nw, err := conn.WriteToUDP(buf[:n], dstAddr)
				if err != nil {
					if ne, ok := err.(net.Error); ok && ne.Timeout() {
						continue
					}
					if errors.Is(err, net.ErrClosed) {
						continue
					}
					tsu.p.logger.Error().Err(err).Msgf("[udp %s] Failed sending message %s→ %s", tsu.p.tproxyMode, srcAddr, dstAddr)
					continue
				}
				conn.written.Add(uint64(nw))
				tsu.clients.UpdateLastSeen(conn)
			}
			if er != nil {
				if ne, ok := er.(net.Error); ok && ne.Timeout() {
					continue
				}
				if errors.Is(err, net.ErrClosed) {
					continue
				}
				if errors.Is(er, io.EOF) {
					continue
				}
				tsu.p.logger.Error().Err(er).Msgf("[udp %s] Failed reading UDP message", tsu.p.tproxyMode)
				continue
			}
		}
	}
}

func (tsu *tproxyServerUDP) handleConnection(conn *udpConn) {
	tsu.wg.Add(1)
	buf := make([]byte, udpBufferSize)
	defer func() {
		srcConnStr := fmt.Sprintf("%s→ %s", conn.srcAddr, conn.dstAddr)
		dstConnStr := fmt.Sprintf("%s→ %s→ %s", tsu.conn.LocalAddr(), conn.LocalAddr(), conn.dstAddr)
		tsu.p.logger.Debug().Msgf("Copied %s for udp src: %s - dst: %s", prettifyBytes(int64(conn.written.Load())), srcConnStr, dstConnStr)
		tsu.wg.Done()
	}()
readLoop:
	for {
		select {
		case <-tsu.quit:
			return
		default:
			er := conn.SetReadDeadline(time.Now().Add(readTimeoutUDP))
			if er != nil {
				if errors.Is(er, net.ErrClosed) {
					return
				}
				tsu.p.logger.Debug().Err(er).Msgf("[udp %s] Failed setting read deadline %s→ %s", tsu.p.tproxyMode, conn.LocalAddr(), tsu.conn.LocalAddr())
				break readLoop
			}
			nr, er := conn.Read(buf)
			if nr > 0 {
				er := tsu.conn.SetWriteDeadline(time.Now().Add(writeTimeoutUDP))
				if er != nil {
					tsu.p.logger.Debug().Err(er).Msgf("[udp %s] Failed setting write deadline %s→ %s", tsu.p.tproxyMode, tsu.conn.LocalAddr(), conn.srcAddr)
					break readLoop
				}
				if tsu.p.sniff {
					if next := layers.ParseNextLayer(buf[:nr], conn.SrcPort(), conn.DstPort()); next != nil {
						conn.respChan <- next
					}
				}
				nw, ew := tsu.conn.WriteToUDP(buf[0:nr], conn.srcAddr)
				if nw < 0 || nr < nw {
					nw = 0
					if ew == nil {
						ew = errInvalidWrite
					}
				}
				conn.written.Add(uint64(nw))
				if ew != nil {
					if errors.Is(ew, net.ErrClosed) {
						return
					}
					if ne, ok := ew.(net.Error); ok && ne.Timeout() {
						break readLoop
					}
				}
				if nr != nw {
					tsu.p.logger.Debug().Err(io.ErrShortWrite).Msgf("[udp %s] Failed sending message %s→ %s", tsu.p.tproxyMode, tsu.conn.LocalAddr(), conn.srcAddr)
					break readLoop
				}
			}
			if er != nil {
				if ne, ok := er.(net.Error); ok && ne.Timeout() {
					break readLoop
				}
				if errors.Is(er, net.ErrClosed) {
					return
				}
				if errors.Is(er, io.EOF) {
					break readLoop
				}
				break readLoop
			}
		}
	}
	conn.Close()
	tsu.clients.Remove(conn)
}

type dnsConn struct {
	*net.UDPConn
	srcAddr  *net.UDPAddr
	dstAddr  *net.UDPAddr
	written  atomic.Uint64
	reqChan  chan layers.Layer
	respChan chan layers.Layer
}

func (dc *dnsConn) close() error {
	close(dc.reqChan)
	close(dc.respChan)
	return dc.Close()
}

func newDNSConn(srcAddr, dstAddr *net.UDPAddr, mark uint) (*dnsConn, error) {
	dialer := getBaseDialer(timeout, mark)
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	conn, err := dialer.DialContext(ctx, "udp4", dstAddr.String())
	if err != nil {
		return nil, err
	}
	udpConn, ok := conn.(*net.UDPConn)
	if !ok {
		return nil, fmt.Errorf("failed obtaining dns connection")
	}
	return &dnsConn{
		UDPConn:  udpConn,
		srcAddr:  srcAddr,
		dstAddr:  dstAddr,
		reqChan:  make(chan layers.Layer),
		respChan: make(chan layers.Layer),
	}, nil
}

func (tsu *tproxyServerUDP) listenAndServeDNS() {
	tsu.wg.Add(1)
	buf := make([]byte, udpBufferSize)
	for {
		select {
		case <-tsu.quit:
			return
		default:
			err := tsu.gwConn.SetReadDeadline(time.Now().Add(readTimeoutUDP))
			if err != nil {
				if errors.Is(err, net.ErrClosed) {
					continue
				}
				tsu.p.logger.Error().Err(err).Msgf("[udp %s] Failed setting read deadline", tsu.p.tproxyMode)
				continue
			}
			n, srcAddr, er := tsu.gwConn.ReadFromUDP(buf)
			if n > 0 {
				conn, err := newDNSConn(srcAddr, tsu.gwDNS, tsu.p.mark)
				if err != nil {
					tsu.p.logger.Error().Err(err).Msgf("[udp %s] Failed creating UDP connection %s→ %s", tsu.p.tproxyMode, srcAddr, tsu.gwDNS)
					continue
				}
				srcConnStr := fmt.Sprintf("%s→ %s", srcAddr, tsu.gwConn.LocalAddr())
				dstConnStr := fmt.Sprintf("%s→ %s", conn.LocalAddr(), conn.dstAddr)
				tsu.p.logger.Debug().Msgf("[udp %s] src: %s - dst: %s", tsu.p.tproxyMode, srcConnStr, dstConnStr)
				err = conn.SetWriteDeadline(time.Now().Add(writeTimeoutUDP))
				if err != nil {
					if errors.Is(err, net.ErrClosed) {
						continue
					}
					tsu.p.logger.Error().Err(err).Msgf("[udp %s] Failed setting write deadline", tsu.p.tproxyMode)
					continue
				}
				if tsu.p.sniff {
					dns := &layers.DNSMessage{}
					if err := dns.Parse(buf[:n]); err == nil {
						tsu.wg.Add(1)
						sniffheader := make([]string, 0, 3)
						id := getID(tsu.p.nocolor)
						if tsu.p.json {
							sniffheader = append(
								sniffheader,
								fmt.Sprintf(
									"{\"connection\":{\"tproxy_mode\":%q,\"src_remote\":%q,\"src_local\":%q,\"dst_local\":%q,\"dst_remote\":%q,\"original_dst\":%q}}",
									tsu.p.tproxyMode,
									srcAddr,
									tsu.gwConn.LocalAddr(),
									conn.LocalAddr(),
									conn.dstAddr,
									tsu.gwConn.LocalAddr(),
								),
							)
						} else {
							connections := colorizeConnectionsTransparent(
								srcAddr,
								tsu.gwConn.LocalAddr(),
								conn.LocalAddr(),
								conn.dstAddr,
								tsu.gwConn.LocalAddr().String(),
								id, tsu.p.nocolor)
							sniffheader = append(sniffheader, connections)
						}
						go tsu.p.sniffreporter(&tsu.wg, &sniffheader, conn.reqChan, conn.respChan, id)
						conn.reqChan <- dns
					} else {
						tsu.p.logger.Error().Err(err).Msgf("%v", buf[:n])
					}
				}
				nw, err := conn.Write(buf[:n])
				if err != nil {
					if ne, ok := err.(net.Error); ok && ne.Timeout() {
						continue
					}
					if errors.Is(err, net.ErrClosed) {
						continue
					}
					tsu.p.logger.Error().Err(err).Msgf("[udp %s] Failed sending message %s→ %s", tsu.p.tproxyMode, conn.LocalAddr(), conn.dstAddr)
					continue
				}
				conn.written.Add(uint64(nw))
				go tsu.handleDNSConnection(conn)
			}
			if er != nil {
				if ne, ok := er.(net.Error); ok && ne.Timeout() {
					continue
				}
				if errors.Is(err, net.ErrClosed) {
					continue
				}
				if errors.Is(er, io.EOF) {
					continue
				}
				tsu.p.logger.Error().Err(er).Msgf("[udp %s] Failed reading UDP message", tsu.p.tproxyMode)
				continue
			}
		}
	}
}

func (tsu *tproxyServerUDP) handleDNSConnection(conn *dnsConn) {
	tsu.wg.Add(1)
	defer func() {
		srcConnStr := fmt.Sprintf("%s→ %s", conn.srcAddr, tsu.gwConn.LocalAddr())
		dstConnStr := fmt.Sprintf("%s→ %s", conn.LocalAddr(), conn.dstAddr)
		tsu.p.logger.Debug().Msgf("Copied %s for udp src: %s - dst: %s", prettifyBytes(int64(conn.written.Load())), srcConnStr, dstConnStr)
		conn.close()
		tsu.wg.Done()
	}()
	buf := make([]byte, udpBufferSize)
	er := conn.SetReadDeadline(time.Now().Add(readTimeoutUDP))
	if er != nil {
		if errors.Is(er, net.ErrClosed) {
			return
		}
		tsu.p.logger.Debug().Err(er).Msgf("[udp %s] Failed setting read deadline %s→ %s", tsu.p.tproxyMode, conn.dstAddr, conn.LocalAddr())
		return
	}
	nr, er := conn.Read(buf)
	if nr > 0 {
		er := tsu.gwConn.SetWriteDeadline(time.Now().Add(writeTimeoutUDP))
		if er != nil {
			if errors.Is(er, net.ErrClosed) {
				return
			}
			tsu.p.logger.Debug().Err(er).Msgf("[udp %s] Failed setting write deadline %s→ %s", tsu.p.tproxyMode, conn.LocalAddr(), conn.srcAddr)
			return
		}
		if tsu.p.sniff {
			dns := &layers.DNSMessage{}
			if err := dns.Parse(buf[:nr]); err == nil {
				conn.respChan <- dns
			} else {
				tsu.p.logger.Error().Err(err).Msgf("%v", buf[:nr])
			}
		}
		nw, ew := tsu.gwConn.WriteToUDP(buf[0:nr], conn.srcAddr)
		if nw < 0 || nr < nw {
			nw = 0
			if ew == nil {
				ew = errInvalidWrite
			}
		}
		conn.written.Add(uint64(nw))
		if ew != nil {
			if errors.Is(ew, net.ErrClosed) {
				return
			}
			if ne, ok := ew.(net.Error); ok && ne.Timeout() {
				return
			}
		}
		if nr != nw {
			tsu.p.logger.Debug().
				Err(io.ErrShortWrite).
				Msgf("[udp %s] Failed sending message %s→ %s", tsu.p.tproxyMode, conn.LocalAddr(), conn.srcAddr)
			return
		}
	}
	if er != nil {
		return
	}
}

func (tsu *tproxyServerUDP) Shutdown() {
	for tsu.startingFlag.Load() {
		time.Sleep(50 * time.Millisecond)
	}
	close(tsu.quit)
	done := make(chan struct{})
	go func() {
		tsu.wg.Wait()
		close(done)
	}()
	select {
	case <-done:
		tsu.p.logger.Info().Msgf("[udp %s] Server gracefully shutdown", tsu.p.tproxyMode)
		return
	case <-time.After(shutdownTimeout):
		tsu.p.logger.Error().Msgf("[udp %s] Server timed out waiting for connections to finish", tsu.p.tproxyMode)
		return
	}
}

func (tsu *tproxyServerUDP) getOriginalDst(oob []byte) (*net.UDPAddr, error) {
	cmsgs, err := unix.ParseSocketControlMessage(oob)
	if err != nil {
		return nil, err
	}
	for _, cmsg := range cmsgs {
		if cmsg.Header.Level == unix.SOL_IP && cmsg.Header.Type == unix.IP_RECVORIGDSTADDR {
			originalDst := &syscall.RawSockaddrInet4{}
			copy((*[unsafe.Sizeof(*originalDst)]byte)(unsafe.Pointer(originalDst))[:], cmsg.Data)
			dstHost := netip.AddrFrom4(originalDst.Addr)
			dstPort := uint16(originalDst.Port<<8) | originalDst.Port>>8
			dstAddr, err := net.ResolveUDPAddr("udp4", fmt.Sprintf("%s:%d", dstHost, dstPort))
			if err != nil {
				return nil, err
			}
			return dstAddr, nil
		}
	}
	return nil, fmt.Errorf("original destination not found")
}

func (tsu *tproxyServerUDP) ApplyRedirectRules(opts map[string]string) {
	_, tproxyPortUDP, _ := net.SplitHostPort(tsu.p.tproxyAddrUDP)
	var setex string
	if tsu.p.debug {
		setex = "set -ex"
	}
	switch tsu.p.tproxyMode {
	case "redirect":
		tsu.p.logger.Fatal().Msgf("Unsupported mode: %s", tsu.p.tproxyMode)
	case "tproxy":
		cmdClear := exec.Command("bash", "-c", fmt.Sprintf(`
        %s
        iptables -t mangle -D PREROUTING -p udp -m socket -j DIVERT 2>/dev/null || true
        iptables -t mangle -D PREROUTING -p udp -j GOHPTS_UDP 2>/dev/null || true
        iptables -t mangle -F GOHPTS_UDP 2>/dev/null || true
        iptables -t mangle -X GOHPTS_UDP 2>/dev/null || true
        `, setex))
		cmdClear.Stdout = os.Stdout
		cmdClear.Stderr = os.Stderr
		if err := cmdClear.Run(); err != nil {
			tsu.p.logger.Fatal().Err(err).Msgf("[udp %s] Failed while configuring iptables. Are you root?", tsu.p.tproxyMode)
		}
		prefix, err := network.GetIPv4PrefixFromInterface(tsu.iface)
		if err != nil {
			tsu.p.logger.Fatal().Err(err).Msgf("[udp %s] Failed getting host from %s", tsu.p.tproxyMode, tsu.iface.Name)
		}
		cmdInit0 := exec.Command("bash", "-c", fmt.Sprintf(`
        %s
        iptables -t mangle -N GOHPTS_UDP 2>/dev/null || true
        iptables -t mangle -F GOHPTS_UDP

        iptables -t mangle -A GOHPTS_UDP -p udp -d 127.0.0.0/8 -j RETURN
        iptables -t mangle -A GOHPTS_UDP -p udp -d 224.0.0.0/4 -j RETURN
        iptables -t mangle -A GOHPTS_UDP -p udp -d 255.255.255.255/32 -j RETURN
		iptables -t mangle -A GOHPTS_UDP -p udp -d %s -j RETURN
        `, setex, prefix.Masked()))
		cmdInit0.Stdout = os.Stdout
		cmdInit0.Stderr = os.Stderr
		if err := cmdInit0.Run(); err != nil {
			tsu.p.logger.Fatal().Err(err).Msgf("[udp %s] Failed while configuring iptables. Are you root?", tsu.p.tproxyMode)
		}
		cmdDocker := exec.Command("bash", "-c", fmt.Sprintf(`
        %s
        if command -v docker >/dev/null 2>&1
        then
            for subnet in $(docker network inspect $(docker network ls -q) --format '{{range .IPAM.Config}}{{.Subnet}}{{end}}'); do
              iptables -t mangle -A GOHPTS_UDP -p udp -d "$subnet" -j RETURN
            done
        fi`, setex))
		cmdDocker.Stdout = os.Stdout
		cmdDocker.Stderr = os.Stderr
		if err := cmdDocker.Run(); err != nil {
			tsu.p.logger.Fatal().Err(err).Msgf("[udp %s] Failed while configuring iptables. Are you root?", tsu.p.tproxyMode)
		}

		cmdInit := exec.Command("bash", "-c", fmt.Sprintf(`
        %s
        iptables -t mangle -A GOHPTS_UDP -p udp -m mark --mark %d -j RETURN
        iptables -t mangle -A GOHPTS_UDP -s %s -p udp -j TPROXY --on-port %s --tproxy-mark 1

        iptables -t mangle -A PREROUTING -p udp -m socket -j DIVERT
        iptables -t mangle -A PREROUTING -p udp -j GOHPTS_UDP
        `, setex, tsu.p.mark, prefix.Masked(), tproxyPortUDP))
		cmdInit.Stdout = os.Stdout
		cmdInit.Stderr = os.Stderr
		if err := cmdInit.Run(); err != nil {
			tsu.p.logger.Fatal().Err(err).Msgf("[udp %s] Failed while configuring iptables. Are you root?", tsu.p.tproxyMode)
		}
		_ = createSysctlOptCmd("net.ipv4.ip_nonlocal_bind", "1", setex, opts, tsu.p.debug).Run()
	default:
		tsu.p.logger.Fatal().Msgf("Unreachable, unknown mode: %s", tsu.p.tproxyMode)
	}
}

func (tsu *tproxyServerUDP) ClearRedirectRules() error {
	var setex string
	if tsu.p.debug {
		setex = "set -ex"
	}
	if tsu.p.tproxyMode == "tproxy" {
		cmd := exec.Command("bash", "-c", fmt.Sprintf(`
        %s
        iptables -t mangle -D PREROUTING -p udp -m socket -j DIVERT 2>/dev/null || true
        iptables -t mangle -D PREROUTING -p udp -j GOHPTS_UDP 2>/dev/null || true
        iptables -t mangle -F GOHPTS_UDP 2>/dev/null || true
        iptables -t mangle -X GOHPTS_UDP 2>/dev/null || true
        `, setex))
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		if !tsu.p.debug {
			cmd.Stdout = nil
		}
		if err := cmd.Run(); err != nil {
			return err
		}
	}
	return nil
}
