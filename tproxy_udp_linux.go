//go:build linux
// +build linux

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
	"syscall"
	"time"
	"unsafe"

	"github.com/shadowy-pycoder/mshark/network"
	"github.com/wzshiming/socks5"
	"golang.org/x/sys/unix"
)

var (
	googleDNSAddr             *net.UDPAddr  = &net.UDPAddr{IP: net.ParseIP("8.8.8.8"), Port: 53}
	idleUDPConnectionsTimeout time.Duration = 60 * time.Second
)

type udpConn struct {
	*socks5.UDPConn
	clientAddr *net.UDPAddr
	dstAddr    *net.UDPAddr
	lastSeen   time.Time
}

func (uc *udpConn) ClientAddr() *net.UDPAddr {
	return uc.clientAddr
}

func (uc *udpConn) DstAddr() *net.UDPAddr {
	return uc.dstAddr
}

func newUDPConn(clientAddr *net.UDPAddr, dstAddr *net.UDPAddr, sockDialer *socks5.Dialer) (*udpConn, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	conn, err := sockDialer.DialContext(ctx, "udp", dstAddr.String())
	if err != nil {
		return nil, err
	}
	relayConn, ok := conn.(*socks5.UDPConn)
	if !ok {
		return nil, fmt.Errorf("failed obtaining relay connection")
	}
	return &udpConn{UDPConn: relayConn, clientAddr: clientAddr, dstAddr: dstAddr, lastSeen: time.Now()}, nil
}

type udpConnections struct {
	wg   sync.WaitGroup
	quit chan struct{}
	sync.RWMutex
	clients map[string]*udpConn
}

func (ucs *udpConnections) Add(conn *udpConn) {
	ucs.Lock()
	ucs.clients[fmt.Sprintf("%s,%s", conn.ClientAddr(), conn.DstAddr())] = conn
	ucs.Unlock()
}

func (ucs *udpConnections) Get(clientAddr, dstAddr *net.UDPAddr) (*udpConn, bool) {
	ucs.RLock()
	defer ucs.RUnlock()
	conn, ok := ucs.clients[fmt.Sprintf("%s,%s", clientAddr, dstAddr)]
	return conn, ok
}

func (ucs *udpConnections) Remove(conn *udpConn) {
	ucs.Lock()
	delete(ucs.clients, fmt.Sprintf("%s,%s", conn.ClientAddr(), conn.DstAddr()))
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
	t := time.NewTicker(idleUDPConnectionsTimeout)
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
				if time.Since(conn.lastSeen) > idleUDPConnectionsTimeout {
					conn.Close()
					ucs.RemoveByAddr(k)
				}
			}
			ucs.Unlock()
		}
	}
}

type tproxyServerUDP struct {
	conn    *net.UDPConn
	quit    chan struct{}
	wg      sync.WaitGroup
	p       *proxyapp
	clients *udpConnections
	iface   *net.Interface
	gwConn  *net.UDPConn
	gwDNS   *net.UDPAddr
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
			tsu.p.logger.Fatal().Err(err).Msgf("[udp %s] Failed getting default interface", tsu.p.tproxyMode)
		}
	}
	gw, err := network.GetGatewayIPv4FromInterface(tsu.iface.Name)
	if err != nil {
		tsu.p.logger.Fatal().Err(err).Msgf("[udp %s] failed getting gateway from %s", tsu.p.tproxyMode, tsu.iface.Name)
	}
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
	return tsu
}

func (tsu *tproxyServerUDP) handleDNSConnections() {
	tsu.wg.Add(1)
	defer tsu.wg.Done()
	buf := make([]byte, 4096)
	for {
		select {
		case <-tsu.quit:
			return
		default:
			n, srcAddr, err := tsu.gwConn.ReadFromUDP(buf)
			if err != nil {
				tsu.p.logger.Error().Err(err).Msgf("[udp %s] Failed reading UDP message", tsu.p.tproxyMode)
				continue
			}
			tsu.p.logger.Debug().Msgf("[udp %s] Got connection from %s", tsu.p.tproxyMode, srcAddr)
			conn, err := net.DialUDP("udp", nil, googleDNSAddr)
			if err != nil {
				tsu.p.logger.Error().
					Err(err).
					Msgf("[udp %s] Failed creating connection from %s to %s", tsu.p.tproxyMode, srcAddr, googleDNSAddr)
				continue
			}
			_, err = conn.Write(buf[:n])
			if err != nil {
				tsu.p.logger.Error().
					Err(err).
					Msgf("[udp %s] Failed writing message from %s to %s", tsu.p.tproxyMode, srcAddr, googleDNSAddr)
				continue
			}
			go tsu.handleDNSConnection(conn, srcAddr)
		}
	}
}

func (tsu *tproxyServerUDP) ListenAndServe() {
	tsu.wg.Add(1)
	defer tsu.wg.Done()
	go tsu.clients.Cleanup()
	go tsu.handleDNSConnections()
	buf := make([]byte, 4096)
	oob := make([]byte, 1500)
	for {
		select {
		case <-tsu.quit:
			return
		default:
			n, oobn, _, srcAddr, err := tsu.conn.ReadMsgUDP(buf, oob)
			if err != nil {
				tsu.p.logger.Error().Err(err).Msgf("[udp %s] Failed reading UDP message", tsu.p.tproxyMode)
				continue
			}
			tsu.p.logger.Debug().Msgf("[udp %s] Got connection from %s", tsu.p.tproxyMode, srcAddr)
			dstAddr, err := tsu.getOriginalDst(oob[:oobn])
			if err != nil {
				tsu.p.logger.Error().Err(err).Msgf("[udp %s] Failed getting original destination", tsu.p.tproxyMode)
				continue
			}
			tsu.p.logger.Debug().Msgf("[udp %s] IP_TRANSPARENT %s", tsu.p.tproxyMode, dstAddr)
			conn, found := tsu.clients.Get(srcAddr, dstAddr)
			if !found {
				sockDialer, _, err := tsu.p.getSocks()
				if err != nil {
					tsu.p.logger.Error().Err(err).Msgf("[udp %s] Failed getting SOCKS5 client", tsu.p.tproxyMode)
					continue
				}
				conn, err = newUDPConn(srcAddr, dstAddr, sockDialer)
				if err != nil {
					tsu.p.logger.Error().
						Err(err).
						Msgf("[udp %s] Failed creating UDP connection for %s", tsu.p.tproxyMode, srcAddr)
					continue
				}
				tsu.clients.Add(conn)
				go tsu.handleConnection(conn)
			} else {
				tsu.p.logger.Debug().Msgf("[udp %s] Found connection for %s", tsu.p.tproxyMode, srcAddr)
			}
			_, err = conn.WriteToUDP(buf[:n], dstAddr)
			if err != nil {
				tsu.p.logger.Error().
					Err(err).
					Msgf("[udp %s] failed sending message from %s to %s", tsu.p.tproxyMode, srcAddr, dstAddr)
				continue
			}
			tsu.clients.UpdateLastSeen(conn)
		}
	}
}

func (tsu *tproxyServerUDP) handleConnection(conn *udpConn) {
	tsu.wg.Add(1)
	defer tsu.wg.Done()
	buf := make([]byte, 4096)
	var written int64
readLoop:
	for {
		select {
		case <-tsu.quit:
			return
		default:
			er := conn.SetReadDeadline(time.Now().Add(readTimeout))
			if er != nil {
				if errors.Is(er, net.ErrClosed) {
					return
				}
				tsu.p.logger.Debug().Err(er).Msgf("[udp %s] failed setting read deadline %s→ %s", tsu.p.tproxyMode, conn.dstAddr, conn.clientAddr)
				break readLoop
			}
			nr, er := conn.Read(buf)
			if nr > 0 {
				er := tsu.conn.SetWriteDeadline(time.Now().Add(writeTimeout))
				if er != nil {
					tsu.p.logger.Debug().Err(er).Msgf("[udp %s] failed setting write deadline %s→ %s", tsu.p.tproxyMode, tsu.conn.LocalAddr(), conn.clientAddr)
					break readLoop
				}
				nw, ew := tsu.conn.WriteToUDP(buf[0:nr], conn.clientAddr)
				if nw < 0 || nr < nw {
					nw = 0
					if ew == nil {
						ew = errInvalidWrite
					}
				}
				written += int64(nw)
				if ew != nil {
					if errors.Is(ew, net.ErrClosed) {
						return
					}
					if ne, ok := ew.(net.Error); ok && ne.Timeout() {
						break readLoop
					}
				}
				if nr != nw {
					tsu.p.logger.Debug().Err(io.ErrShortWrite).Msgf("[udp %s] failed sending message %s→ %s", tsu.p.tproxyMode, tsu.conn.LocalAddr(), conn.clientAddr)
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
				if er == io.EOF {
					break readLoop
				}
				break readLoop
			}
		}
	}
	conn.Close()
	tsu.clients.Remove(conn)
}

func (tsu *tproxyServerUDP) handleDNSConnection(conn *net.UDPConn, srcAddr *net.UDPAddr) {
	tsu.wg.Add(1)
	defer tsu.wg.Done()
	defer conn.Close()
	buf := make([]byte, 4096)
	var written int64
	er := conn.SetReadDeadline(time.Now().Add(readTimeout))
	if er != nil {
		tsu.p.logger.Debug().
			Err(er).
			Msgf("[udp %s] failed setting read deadline %s→ %s", tsu.p.tproxyMode, googleDNSAddr, conn.LocalAddr())
		return
	}
	nr, er := conn.Read(buf)
	if nr > 0 {
		er := tsu.conn.SetWriteDeadline(time.Now().Add(writeTimeout))
		if er != nil {
			tsu.p.logger.Debug().
				Err(er).
				Msgf("[udp %s] failed setting write deadline %s→ %s", tsu.p.tproxyMode, googleDNSAddr, srcAddr)
			return
		}
		nw, ew := tsu.gwConn.WriteToUDP(buf[0:nr], srcAddr)
		if nw < 0 || nr < nw {
			nw = 0
			if ew == nil {
				ew = errInvalidWrite
			}
		}
		written += int64(nw)
		if ew != nil {
			return
		}
		if nr != nw {
			tsu.p.logger.Debug().
				Err(io.ErrShortWrite).
				Msgf("[udp %s] failed sending message %s→ %s", tsu.p.tproxyMode, googleDNSAddr, conn.LocalAddr())
			return
		}
	}
	if er != nil {
		return
	}
}

func (tsu *tproxyServerUDP) Shutdown() {
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

func (tsu *tproxyServerUDP) applyRedirectRules(opts map[string]string) {
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
		iptables -t nat -D PREROUTING -p udp -j GOHPTS_UDP 2>/dev/null || true
        iptables -t nat -F GOHPTS_UDP 2>/dev/null || true
        iptables -t nat -X GOHPTS_UDP 2>/dev/null || true
        `, setex))
		cmdClear.Stdout = os.Stdout
		cmdClear.Stderr = os.Stderr
		if err := cmdClear.Run(); err != nil {
			tsu.p.logger.Fatal().Err(err).Msg("Failed while configuring iptables. Are you root?")
		}
		prefix, err := network.GetIPv4PrefixFromInterface(tsu.iface)
		if err != nil {
			tsu.p.logger.Fatal().Err(err).Msgf("failed getting host from %s", tsu.iface.Name)
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

func (tsu *tproxyServerUDP) clearRedirectRules() error {
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
