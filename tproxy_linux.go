//go:build linux
// +build linux

package gohpts

import (
	"context"
	"errors"
	"fmt"
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
	"golang.org/x/sys/unix"
)

type tproxyServer struct {
	listener     net.Listener
	quit         chan struct{}
	wg           sync.WaitGroup
	p            *proxyapp
	startingFlag atomic.Bool
}

func newTproxyServer(p *proxyapp) *tproxyServer {
	ts := &tproxyServer{
		quit: make(chan struct{}),
		p:    p,
	}
	// https://iximiuz.com/en/posts/go-net-http-setsockopt-example/
	lc := net.ListenConfig{
		Control: func(network, address string, conn syscall.RawConn) error {
			var operr error
			if err := conn.Control(func(fd uintptr) {
				operr = unix.SetsockoptInt(int(fd), unix.IPPROTO_TCP, unix.TCP_USER_TIMEOUT, int(timeout.Milliseconds()))
				operr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEADDR, 1)
				if ts.p.tproxyMode == "tproxy" {
					operr = unix.SetsockoptInt(int(fd), unix.SOL_IP, unix.IP_TRANSPARENT, 1)
				}
			}); err != nil {
				return err
			}
			return operr
		},
	}

	ln, err := lc.Listen(context.Background(), "tcp4", ts.p.tproxyAddr)
	if err != nil {
		var msg string
		if errors.Is(err, unix.EPERM) {
			msg = "try `sudo setcap 'cap_net_admin+ep` for the binary or run with sudo:"
		}
		ts.p.logger.Fatal().Err(err).Msg(msg)
	}
	ts.listener = ln
	return ts
}

func (ts *tproxyServer) ListenAndServe() {
	ts.startingFlag.Store(true)
	ts.wg.Add(1)
	go ts.serve()
	ts.startingFlag.Store(false)
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
				ts.p.logger.Error().Err(err).Msg("Failed accepting connection")
			}
		} else {
			ts.wg.Add(1)
			err := conn.SetDeadline(time.Now().Add(timeout))
			if err != nil {
				ts.p.logger.Error().Err(err).Msg("")
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
			ts.p.logger.Error().Err(err).Msgf("[tcp %s] getsockopt SO_ORIGINAL_DST failed", ts.p.tproxyMode)
		}
	})
	if err != nil {
		ts.p.logger.Error().Err(err).Msgf("[tcp %s] Failed invoking control connection", ts.p.tproxyMode)
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
	switch ts.p.tproxyMode {
	case "redirect":
		rawConn, err := srcConn.(*net.TCPConn).SyscallConn()
		if err != nil {
			ts.p.logger.Error().Err(err).Msgf("[tcp %s] Failed to get raw connection", ts.p.tproxyMode)
			return
		}
		dst, err = ts.getOriginalDst(rawConn)
		if err != nil {
			ts.p.logger.Error().Err(err).Msgf("[tcp %s] Failed to get destination address", ts.p.tproxyMode)
			return
		}
	case "tproxy":
		dst = srcConn.LocalAddr().String()
	default:
		ts.p.logger.Fatal().Msg("Unknown tproxyMode")
	}
	if network.IsLocalAddress(dst) {
		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		defer cancel()
		dstConn, err = getBaseDialer(timeout, ts.p.mark).DialContext(ctx, "tcp", dst)
		if err != nil {
			ts.p.logger.Error().Err(err).Msgf("[tcp %s] Failed connecting to %s", ts.p.tproxyMode, dst)
			return
		}
	} else {
		sockDialer, _, err := ts.p.getSocks()
		if err != nil {
			ts.p.logger.Error().Err(err).Msgf("[tcp %s] Failed getting SOCKS5 client", ts.p.tproxyMode)
			return
		}
		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		defer cancel()
		dstConn, err = sockDialer.DialContext(ctx, "tcp", dst)
		if err != nil {
			ts.p.logger.Error().Err(err).Msgf("[tcp %s] Failed connecting to %s", ts.p.tproxyMode, dst)
			return
		}
	}
	defer dstConn.Close()

	dstConnStr := fmt.Sprintf("%s→ %s→ %s", dstConn.LocalAddr().String(), dstConn.RemoteAddr().String(), dst)
	srcConnStr := fmt.Sprintf("%s→ %s", srcConn.RemoteAddr().String(), srcConn.LocalAddr().String())

	ts.p.logger.Debug().Msgf("[tcp %s] src: %s - dst: %s", ts.p.tproxyMode, srcConnStr, dstConnStr)

	reqChan := make(chan layers.Layer)
	respChan := make(chan layers.Layer)
	var wg sync.WaitGroup
	wg.Add(2)
	go ts.p.transfer(&wg, dstConn, srcConn, dstConnStr, srcConnStr, reqChan)
	go ts.p.transfer(&wg, srcConn, dstConn, srcConnStr, dstConnStr, respChan)
	if ts.p.sniff {
		wg.Add(1)
		sniffheader := make([]string, 0, 6)
		id := getID(ts.p.nocolor)
		if ts.p.json {
			sniffheader = append(
				sniffheader,
				fmt.Sprintf(
					"{\"connection\":{\"tproxy_mode\":%s,\"src_remote\":%s,\"src_local\":%s,\"dst_local\":%s,\"dst_remote\":%s,\"original_dst\":%s}}",
					ts.p.tproxyMode,
					srcConn.RemoteAddr(),
					srcConn.LocalAddr(),
					dstConn.LocalAddr(),
					dstConn.RemoteAddr(),
					dst,
				),
			)
		} else {
			connections := colorizeConnectionsTransparent(
				srcConn.RemoteAddr(),
				srcConn.LocalAddr(),
				dstConn.RemoteAddr(),
				dstConn.LocalAddr(),
				dst, id, ts.p.nocolor)
			sniffheader = append(sniffheader, connections)
		}
		go ts.p.sniffreporter(&wg, &sniffheader, reqChan, respChan, id)
	}
	wg.Wait()
}

func (ts *tproxyServer) Shutdown() {
	for ts.startingFlag.Load() {
		time.Sleep(50 * time.Millisecond)
	}
	close(ts.quit)
	ts.listener.Close()
	done := make(chan struct{})
	go func() {
		ts.wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		ts.p.logger.Info().Msgf("[tcp %s] Server gracefully shutdown", ts.p.tproxyMode)
		return
	case <-time.After(shutdownTimeout):
		ts.p.logger.Error().Msgf("[tcp %s] Server timed out waiting for connections to finish", ts.p.tproxyMode)
		return
	}
}

func (ts *tproxyServer) ApplyRedirectRules(opts map[string]string) {
	_, tproxyPort, _ := net.SplitHostPort(ts.p.tproxyAddr)
	var setex string
	if ts.p.debug {
		setex = "set -ex"
	}
	switch ts.p.tproxyMode {
	case "redirect":
		cmdClear := exec.Command("bash", "-c", fmt.Sprintf(`
        %s
        iptables -t nat -D PREROUTING -p tcp -j GOHPTS 2>/dev/null || true
        iptables -t nat -D OUTPUT -p tcp -j GOHPTS 2>/dev/null || true
        iptables -t nat -F GOHPTS 2>/dev/null || true
        iptables -t nat -X GOHPTS 2>/dev/null || true
        `, setex))
		cmdClear.Stdout = os.Stdout
		cmdClear.Stderr = os.Stderr
		if err := cmdClear.Run(); err != nil {
			ts.p.logger.Fatal().Err(err).Msgf("[tcp %s] Failed while configuring iptables. Are you root?", ts.p.tproxyMode)
		}
		cmdInit := exec.Command("bash", "-c", fmt.Sprintf(`
		%s
        iptables -t nat -N GOHPTS 2>/dev/null
        iptables -t nat -F GOHPTS

        iptables -t nat -A GOHPTS -p tcp -d 127.0.0.0/8 -j RETURN
        iptables -t nat -A GOHPTS -p tcp --dport 22 -j RETURN
        `, setex))
		cmdInit.Stdout = os.Stdout
		cmdInit.Stderr = os.Stderr
		if err := cmdInit.Run(); err != nil {
			ts.p.logger.Fatal().Err(err).Msgf("[tcp %s] Failed while configuring iptables. Are you root?", ts.p.tproxyMode)
		}
		if ts.p.httpServerAddr != "" {
			_, httpPort, _ := net.SplitHostPort(ts.p.httpServerAddr)
			cmdHTTP := exec.Command("bash", "-c", fmt.Sprintf(`
            %s
            iptables -t nat -A GOHPTS -p tcp --dport %s -j RETURN
            `, setex, httpPort))
			cmdHTTP.Stdout = os.Stdout
			cmdHTTP.Stderr = os.Stderr
			if err := cmdHTTP.Run(); err != nil {
				ts.p.logger.Fatal().Err(err).Msgf("[tcp %s] Failed while configuring iptables. Are you root?", ts.p.tproxyMode)
			}
		}
		if ts.p.mark > 0 {
			cmdMark := exec.Command("bash", "-c", fmt.Sprintf(`
            %s
            iptables -t nat -A GOHPTS -p tcp -m mark --mark %d -j RETURN
            `, setex, ts.p.mark))
			cmdMark.Stdout = os.Stdout
			cmdMark.Stderr = os.Stderr
			if err := cmdMark.Run(); err != nil {
				ts.p.logger.Fatal().Err(err).Msgf("[tcp %s] Failed while configuring iptables. Are you root?", ts.p.tproxyMode)
			}
		} else {
			cmd0 := exec.Command("bash", "-c", fmt.Sprintf(`
            %s
            iptables -t nat -A GOHPTS -p tcp --dport %s -j RETURN
            `, setex, tproxyPort))
			cmd0.Stdout = os.Stdout
			cmd0.Stderr = os.Stderr
			if err := cmd0.Run(); err != nil {
				ts.p.logger.Fatal().Err(err).Msgf("[tcp %s] Failed while configuring iptables. Are you root?", ts.p.tproxyMode)
			}
			if len(ts.p.proxylist) > 0 {
				for _, pr := range ts.p.proxylist {
					_, port, _ := net.SplitHostPort(pr.Address)
					cmd1 := exec.Command("bash", "-c", fmt.Sprintf(`
                    %s
                    iptables -t nat -A GOHPTS -p tcp --dport %s -j RETURN
                    `, setex, port))
					cmd1.Stdout = os.Stdout
					cmd1.Stderr = os.Stderr
					if err := cmd1.Run(); err != nil {
						ts.p.logger.Fatal().Err(err).Msgf("[tcp %s] Failed while configuring iptables. Are you root?", ts.p.tproxyMode)
					}
					if ts.p.proxychain.Type == "strict" {
						break
					}
				}
			}
		}
		cmdDocker := exec.Command("bash", "-c", fmt.Sprintf(`
        %s
        if command -v docker >/dev/null 2>&1
        then
            for subnet in $(docker network inspect $(docker network ls -q) --format '{{range .IPAM.Config}}{{.Subnet}}{{end}}'); do
              iptables -t nat -A GOHPTS -p tcp -d "$subnet" -j RETURN
            done
        fi

        iptables -t nat -A GOHPTS -p tcp -j REDIRECT --to-ports %s

        iptables -t nat -C PREROUTING -p tcp -j GOHPTS 2>/dev/null || \
        iptables -t nat -A PREROUTING -p tcp -j GOHPTS

        iptables -t nat -C OUTPUT -p tcp -j GOHPTS 2>/dev/null || \
        iptables -t nat -A OUTPUT -p tcp -j GOHPTS
        `, setex, tproxyPort))
		cmdDocker.Stdout = os.Stdout
		cmdDocker.Stderr = os.Stderr
		if err := cmdDocker.Run(); err != nil {
			ts.p.logger.Fatal().Err(err).Msgf("[tcp %s] Failed while configuring iptables. Are you root?", ts.p.tproxyMode)
		}
	case "tproxy":
		cmdClear := exec.Command("bash", "-c", fmt.Sprintf(`
        %s
        iptables -t mangle -D PREROUTING -p tcp -m socket -j DIVERT 2>/dev/null || true
        iptables -t mangle -D PREROUTING -p tcp -j GOHPTS 2>/dev/null || true
        iptables -t mangle -F GOHPTS 2>/dev/null || true
        iptables -t mangle -X GOHPTS 2>/dev/null || true
        `, setex))
		cmdClear.Stdout = os.Stdout
		cmdClear.Stderr = os.Stderr
		if err := cmdClear.Run(); err != nil {
			ts.p.logger.Fatal().Err(err).Msgf("[tcp %s] Failed while configuring iptables. Are you root?", ts.p.tproxyMode)
		}
		cmdInit0 := exec.Command("bash", "-c", fmt.Sprintf(`
        %s
        iptables -t mangle -N GOHPTS 2>/dev/null || true
        iptables -t mangle -F GOHPTS

        iptables -t mangle -A GOHPTS -p tcp -d 127.0.0.0/8 -j RETURN
        iptables -t mangle -A GOHPTS -p tcp -d 224.0.0.0/4 -j RETURN
        iptables -t mangle -A GOHPTS -p tcp -d 255.255.255.255/32 -j RETURN
        `, setex))
		cmdInit0.Stdout = os.Stdout
		cmdInit0.Stderr = os.Stderr
		if err := cmdInit0.Run(); err != nil {
			ts.p.logger.Fatal().Err(err).Msgf("[tcp %s] Failed while configuring iptables. Are you root?", ts.p.tproxyMode)
		}
		cmdDocker := exec.Command("bash", "-c", fmt.Sprintf(`
        %s
        if command -v docker >/dev/null 2>&1
        then
            for subnet in $(docker network inspect $(docker network ls -q) --format '{{range .IPAM.Config}}{{.Subnet}}{{end}}'); do
              iptables -t mangle -A GOHPTS -p tcp -d "$subnet" -j RETURN
            done
        fi`, setex))
		cmdDocker.Stdout = os.Stdout
		cmdDocker.Stderr = os.Stderr
		if err := cmdDocker.Run(); err != nil {
			ts.p.logger.Fatal().Err(err).Msgf("[tcp %s] Failed while configuring iptables. Are you root?", ts.p.tproxyMode)
		}
		cmdInit := exec.Command("bash", "-c", fmt.Sprintf(`
        %s
        iptables -t mangle -A GOHPTS -p tcp -m mark --mark %d -j RETURN
        iptables -t mangle -A GOHPTS -p tcp -j TPROXY --on-port %s --tproxy-mark 1

        iptables -t mangle -A PREROUTING -p tcp -m socket -j DIVERT
        iptables -t mangle -A PREROUTING -p tcp -j GOHPTS
        `, setex, ts.p.mark, tproxyPort))
		cmdInit.Stdout = os.Stdout
		cmdInit.Stderr = os.Stderr
		if err := cmdInit.Run(); err != nil {
			ts.p.logger.Fatal().Err(err).Msgf("[tcp %s] Failed while configuring iptables. Are you root?", ts.p.tproxyMode)
		}
	default:
		ts.p.logger.Fatal().Msgf("Unreachable, unknown mode: %s", ts.p.tproxyMode)
	}
	cmdCheckBBR := exec.Command("bash", "-c", fmt.Sprintf(`
    %s
	lsmod | grep -q '^tcp_bbr' || modprobe tcp_bbr
    `, setex))
	cmdCheckBBR.Stdout = os.Stdout
	cmdCheckBBR.Stderr = os.Stderr
	if !ts.p.debug {
		cmdCheckBBR.Stdout = nil
	}
	_ = cmdCheckBBR.Run()
	_ = createSysctlOptCmd("net.ipv4.tcp_congestion_control", "bbr", setex, opts, ts.p.debug).Run()
	_ = createSysctlOptCmd("net.core.default_qdisc", "fq", setex, opts, ts.p.debug).Run()
	_ = createSysctlOptCmd("net.ipv4.tcp_tw_reuse", "1", setex, opts, ts.p.debug).Run()
	_ = createSysctlOptCmd("net.ipv4.tcp_fin_timeout", "15", setex, opts, ts.p.debug).Run()
}

func (ts *tproxyServer) ClearRedirectRules() error {
	var setex string
	if ts.p.debug {
		setex = "set -ex"
	}
	var cmd *exec.Cmd
	switch ts.p.tproxyMode {
	case "redirect":
		cmd = exec.Command("bash", "-c", fmt.Sprintf(`
        %s
        iptables -t nat -D PREROUTING -p tcp -j GOHPTS 2>/dev/null || true
        iptables -t nat -D OUTPUT -p tcp -j GOHPTS 2>/dev/null || true
        iptables -t nat -F GOHPTS 2>/dev/null || true
        iptables -t nat -X GOHPTS 2>/dev/null || true
        `, setex))
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
	case "tproxy":
		cmd = exec.Command("bash", "-c", fmt.Sprintf(`
        %s
        iptables -t mangle -D PREROUTING -p tcp -m socket -j DIVERT 2>/dev/null || true
        iptables -t mangle -D PREROUTING -p tcp -j GOHPTS 2>/dev/null || true
        iptables -t mangle -F GOHPTS 2>/dev/null || true
        iptables -t mangle -X GOHPTS 2>/dev/null || true
        `, setex))
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		if !ts.p.debug {
			cmd.Stdout = nil
		}
	}
	return cmd.Run()
}
