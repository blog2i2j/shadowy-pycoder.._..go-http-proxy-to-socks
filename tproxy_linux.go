//go:build linux
// +build linux

package gohpts

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"github.com/shadowy-pycoder/colors"
	"github.com/shadowy-pycoder/mshark/layers"
	"golang.org/x/net/proxy"
	"golang.org/x/sys/unix"
)

type tproxyServer struct {
	listener net.Listener
	quit     chan struct{}
	wg       sync.WaitGroup
	pa       *proxyapp
}

func newTproxyServer(pa *proxyapp) *tproxyServer {
	ts := &tproxyServer{
		quit: make(chan struct{}),
		pa:   pa,
	}
	// https://iximiuz.com/en/posts/go-net-http-setsockopt-example/
	lc := net.ListenConfig{
		Control: func(network, address string, conn syscall.RawConn) error {
			var operr error
			if err := conn.Control(func(fd uintptr) {
				operr = unix.SetsockoptInt(int(fd), unix.IPPROTO_TCP, unix.TCP_USER_TIMEOUT, int(timeout.Milliseconds()))
				operr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEADDR, 1)
				if ts.pa.tproxyMode == "tproxy" {
					operr = unix.SetsockoptInt(int(fd), unix.SOL_IP, unix.IP_TRANSPARENT, 1)
				}
			}); err != nil {
				return err
			}
			return operr
		},
	}

	ln, err := lc.Listen(context.Background(), "tcp4", ts.pa.tproxyAddr)
	if err != nil {
		var msg string
		if errors.Is(err, unix.EPERM) {
			msg = "try `sudo setcap 'cap_net_admin+ep` for the binary or run with sudo:"
		}
		ts.pa.logger.Fatal().Err(err).Msg(msg)
	}
	ts.listener = ln
	return ts
}

func (ts *tproxyServer) ListenAndServe() {
	ts.wg.Add(1)
	go ts.serve()
}

func (ts *tproxyServer) serve() {
	defer ts.wg.Done()

	for {
		conn, err := ts.listener.Accept()
		if err != nil {
			select {
			case <-ts.quit:
				return
			default:
				ts.pa.logger.Error().Err(err).Msg("")
			}
		} else {
			ts.wg.Add(1)
			err := conn.SetDeadline(time.Now().Add(timeout))
			if err != nil {
				ts.pa.logger.Error().Err(err).Msg("")
			}
			go func() {
				ts.handleConnection(conn)
				ts.wg.Done()
			}()
		}
	}
}

func getsockopt(s int, level int, optname int, optval unsafe.Pointer, optlen *uint32) (err error) {
	_, _, e := unix.Syscall6(
		unix.SYS_GETSOCKOPT,
		uintptr(s),
		uintptr(level),
		uintptr(optname),
		uintptr(optval),
		uintptr(unsafe.Pointer(optlen)),
		0,
	)
	if e != 0 {
		return e
	}
	return nil
}

func (ts *tproxyServer) getOriginalDst(rawConn syscall.RawConn) (string, error) {
	var originalDst unix.RawSockaddrInet4
	err := rawConn.Control(func(fd uintptr) {
		optlen := uint32(unsafe.Sizeof(originalDst))
		err := getsockopt(int(fd), unix.SOL_IP, unix.SO_ORIGINAL_DST, unsafe.Pointer(&originalDst), &optlen)
		if err != nil {
			ts.pa.logger.Error().Err(err).Msg("[tproxy] getsockopt SO_ORIGINAL_DST failed")
		}
	})
	if err != nil {
		ts.pa.logger.Error().Err(err).Msg("[tproxy] Failed invoking control connection")
		return "", err
	}
	dstHost := netip.AddrFrom4(originalDst.Addr)
	dstPort := uint16(originalDst.Port<<8) | originalDst.Port>>8
	return fmt.Sprintf("%s:%d", dstHost, dstPort), nil
}

func (ts *tproxyServer) handleConnection(srcConn net.Conn) {
	var (
		dstConn net.Conn
		dst     string
		err     error
	)
	defer srcConn.Close()
	switch ts.pa.tproxyMode {
	case "redirect":
		rawConn, err := srcConn.(*net.TCPConn).SyscallConn()
		if err != nil {
			ts.pa.logger.Error().Err(err).Msg("[tproxy] Failed to get raw connection")
			return
		}
		dst, err = ts.getOriginalDst(rawConn)
		if err != nil {
			ts.pa.logger.Error().Err(err).Msg("[tproxy] Failed to get destination address")
			return
		}
		ts.pa.logger.Debug().Msgf("[tproxy] getsockopt SO_ORIGINAL_DST %s", dst)
	case "tproxy":
		dst = srcConn.LocalAddr().String()
		ts.pa.logger.Debug().Msgf("[tproxy] IP_TRANSPARENT %s", dst)
	default:
		ts.pa.logger.Fatal().Msg("Unknown tproxyMode")
	}
	if isLocalAddress(dst) {
		dstConn, err = getBaseDialer(timeout, ts.pa.mark).Dial("tcp", dst)
		if err != nil {
			ts.pa.logger.Error().Err(err).Msgf("[tproxy] Failed connecting to %s", dst)
			return
		}
	} else {
		sockDialer, _, err := ts.pa.getSocks()
		if err != nil {
			ts.pa.logger.Error().Err(err).Msg("[tproxy] Failed getting SOCKS5 client")
			return
		}
		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		defer cancel()
		dstConn, err = sockDialer.(proxy.ContextDialer).DialContext(ctx, "tcp", dst)
		if err != nil {
			ts.pa.logger.Error().Err(err).Msgf("[tproxy] Failed connecting to %s", dst)
			return
		}
	}
	defer dstConn.Close()

	dstConnStr := fmt.Sprintf("%s->%s->%s", dstConn.LocalAddr().String(), dstConn.RemoteAddr().String(), dst)
	srcConnStr := fmt.Sprintf("%s->%s", srcConn.RemoteAddr().String(), srcConn.LocalAddr().String())

	ts.pa.logger.Debug().Msgf("[tproxy] src: %s - dst: %s", srcConnStr, dstConnStr)

	reqChan := make(chan layers.Layer)
	respChan := make(chan layers.Layer)
	var wg sync.WaitGroup
	wg.Add(2)
	go ts.pa.transfer(&wg, dstConn, srcConn, dstConnStr, srcConnStr, reqChan)
	go ts.pa.transfer(&wg, srcConn, dstConn, srcConnStr, dstConnStr, respChan)
	if ts.pa.sniff {
		wg.Add(1)
		sniffheader := make([]string, 0, 6)
		id := ts.pa.getID()
		if ts.pa.json {
			sniffheader = append(
				sniffheader,
				fmt.Sprintf(
					"{\"connection\":{\"tproxy_mode\":%s,\"src_remote\":%s,\"src_local\":%s,\"dst_local\":%s,\"dst_remote\":%s,\"original_dst\":%s}}",
					ts.pa.tproxyMode,
					srcConn.RemoteAddr(),
					srcConn.LocalAddr(),
					dstConn.LocalAddr(),
					dstConn.RemoteAddr(),
					dst,
				),
			)
		} else {
			var sb strings.Builder
			if ts.pa.nocolor {
				sb.WriteString(id)
				sb.WriteString(fmt.Sprintf(" Src: %s->%s -> Dst: %s->%s Orig: %s", srcConn.RemoteAddr(), srcConn.LocalAddr(), dstConn.LocalAddr(), dstConn.RemoteAddr(), dst))
			} else {
				sb.WriteString(id)
				sb.WriteString(colors.Green(fmt.Sprintf(" Src: %s->%s", srcConn.RemoteAddr(), srcConn.LocalAddr())).String())
				sb.WriteString(colors.Magenta(" -> ").String())
				sb.WriteString(colors.Blue(fmt.Sprintf("Dst: %s->%s ", dstConn.LocalAddr(), dstConn.RemoteAddr())).String())
				sb.WriteString(colors.BeigeBg(fmt.Sprintf("Orig Dst: %s", dst)).String())
			}
			sniffheader = append(sniffheader, sb.String())
		}
		go ts.pa.sniffreporter(&wg, &sniffheader, reqChan, respChan, id)
	}
	wg.Wait()
}

func (ts *tproxyServer) Shutdown() {
	close(ts.quit)
	ts.listener.Close()
	done := make(chan struct{})
	go func() {
		ts.wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		ts.pa.logger.Info().Msg("[tproxy] Server gracefully shutdown")
		return
	case <-time.After(timeout):
		ts.pa.logger.Error().Msg("[tproxy] Server timed out waiting for connections to finish")
		return
	}
}

func getBaseDialer(timeout time.Duration, mark uint) *net.Dialer {
	var dialer *net.Dialer
	if mark > 0 {
		dialer = &net.Dialer{
			Timeout: timeout,
			Control: func(_, _ string, c syscall.RawConn) error {
				return c.Control(func(fd uintptr) {
					unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_MARK, int(mark))
				})
			},
		}
	} else {
		dialer = &net.Dialer{Timeout: timeout}
	}
	return dialer
}

func getDefaultInterface() (*net.Interface, error) {
	f, err := os.Open("/proc/net/route")
	if err != nil {
		return nil, err
	}
	defer f.Close()

	defaultInterface := ""
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		fields := strings.Fields(line)
		if len(fields) >= 2 && fields[1] == "00000000" {
			defaultInterface = fields[0]
			break
		}
	}
	return net.InterfaceByName(defaultInterface)
}
