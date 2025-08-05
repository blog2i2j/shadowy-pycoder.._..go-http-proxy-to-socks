// Package gohpts transform SOCKS5 proxy into HTTP(S) proxy with support for Transparent Proxy (Redirect and TProxy), Proxychains and Traffic Sniffing
package gohpts

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"maps"
	"math/rand"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/goccy/go-yaml"
	"github.com/rs/zerolog"
	"github.com/shadowy-pycoder/mshark/arpspoof"
	"github.com/shadowy-pycoder/mshark/layers"
	"github.com/shadowy-pycoder/mshark/network"
	"github.com/wzshiming/socks5"
)

const (
	readTimeout              time.Duration = 30 * time.Second
	writeTimeout             time.Duration = 30 * time.Second
	timeout                  time.Duration = 10 * time.Second
	shutdownTimeout          time.Duration = 30 * time.Second
	hopTimeout               time.Duration = 3 * time.Second
	flushTimeout             time.Duration = 10 * time.Millisecond
	availProxyUpdateInterval time.Duration = 30 * time.Second
	rrIndexMax               uint32        = 1_000_000
	maxBodySize              int64         = 2 << 15
)

var (
	supportedChainTypes  = []string{"strict", "dynamic", "random", "round_robin"}
	SupportedTProxyModes = []string{"redirect", "tproxy"}
	errInvalidWrite      = errors.New("invalid write result")
)

type Config struct {
	AddrHTTP       string
	AddrSOCKS      string
	User           string
	Pass           string
	ServerUser     string
	ServerPass     string
	CertFile       string
	KeyFile        string
	Interface      string
	ServerConfPath string
	TProxy         string
	TProxyOnly     string
	TProxyUDP      string
	TProxyMode     string
	Auto           bool
	Mark           uint
	ARPSpoof       string
	LogFilePath    string
	Debug          bool
	JSON           bool
	Sniff          bool
	SniffLogFile   string
	NoColor        bool
	Body           bool
}

type logWriter struct {
	file *os.File
}

func (writer logWriter) Write(bytes []byte) (int, error) {
	return fmt.Fprintf(writer.file, "%s ERR %s", time.Now().Format(time.RFC3339), string(bytes))
}

type jsonLogWriter struct {
	file *os.File
}

func (writer jsonLogWriter) Write(bytes []byte) (int, error) {
	return fmt.Fprintf(writer.file, "{\"level\":\"error\",\"time\":\"%s\",\"message\":\"%s\"}\n",
		time.Now().Format(time.RFC3339), strings.TrimRight(string(bytes), "\n"))
}

type proxyEntry struct {
	Address  string `yaml:"address"`
	Username string `yaml:"username,omitempty"`
	Password string `yaml:"password,omitempty"`
}

func (pe proxyEntry) String() string {
	return pe.Address
}

type server struct {
	Address   string `yaml:"address"`
	Interface string `yaml:"interface,omitempty"`
	Username  string `yaml:"username,omitempty"`
	Password  string `yaml:"password,omitempty"`
	CertFile  string `yaml:"cert_file,omitempty"`
	KeyFile   string `yaml:"key_file,omitempty"`
}
type chain struct {
	Type   string `yaml:"type"`
	Length int    `yaml:"length"`
}

type serverConfig struct {
	Chain     chain        `yaml:"chain"`
	ProxyList []proxyEntry `yaml:"proxy_list"`
	Server    server       `yaml:"server"`
}
type proxyapp struct {
	httpServer     *http.Server
	sockClient     *http.Client
	httpClient     *http.Client
	sockDialer     *socks5.Dialer
	logger         *zerolog.Logger
	snifflogger    *zerolog.Logger
	certFile       string
	keyFile        string
	httpServerAddr string
	iface          *net.Interface
	tproxyAddr     string
	tproxyAddrUDP  string
	tproxyMode     string
	auto           bool
	mark           uint
	arpspoofer     *arpspoof.ARPSpoofer
	user           string
	pass           string
	proxychain     chain
	proxylist      []proxyEntry
	rrIndex        uint32
	rrIndexReset   uint32
	sniff          bool
	nocolor        bool
	body           bool
	json           bool
	debug          bool
	closeConn      chan bool

	mu             sync.RWMutex
	availProxyList []proxyEntry
}

func New(conf *Config) *proxyapp {
	var logger, snifflogger zerolog.Logger
	var p proxyapp
	logfile := os.Stdout
	var snifflog *os.File
	var err error
	p.sniff = conf.Sniff
	p.body = conf.Body
	p.json = conf.JSON
	if conf.LogFilePath != "" {
		f, err := os.OpenFile(conf.LogFilePath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
		if err != nil {
			log.Fatalf("Failed to open log file: %v", err)
		}
		logfile = f
	}
	if conf.SniffLogFile != "" && conf.SniffLogFile != conf.LogFilePath {
		f, err := os.OpenFile(conf.SniffLogFile, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
		if err != nil {
			log.Fatalf("Failed to open sniff log file: %v", err)
		}
		snifflog = f
	} else {
		snifflog = logfile
	}
	p.nocolor = conf.JSON || conf.NoColor
	if conf.JSON {
		log.SetFlags(0)
		jsonWriter := jsonLogWriter{file: logfile}
		log.SetOutput(jsonWriter)
		logger = zerolog.New(logfile).With().Timestamp().Logger()
		snifflogger = zerolog.New(snifflog).With().Timestamp().Logger()
	} else {
		log.SetFlags(0)
		logWriter := logWriter{file: logfile}
		log.SetOutput(logWriter)
		output := zerolog.ConsoleWriter{Out: logfile, NoColor: p.nocolor}

		output.FormatTimestamp = func(i any) string {
			ts, _ := time.Parse(time.RFC3339, i.(string))
			return colorizeTimestamp(ts, p.nocolor)
		}
		output.FormatMessage = func(i any) string {
			if i == nil || i == "" {
				return ""
			}
			return colorizeLogMessage(i.(string), p.nocolor)
		}

		output.FormatErrFieldName = func(i any) string {
			return fmt.Sprintf("%s", i)
		}

		output.FormatErrFieldValue = func(i any) string {
			s := i.(string)
			return colorizeErrMessage(s, p.nocolor)
		}
		logger = zerolog.New(output).With().Timestamp().Logger()
		sniffoutput := zerolog.ConsoleWriter{Out: snifflog, TimeFormat: time.RFC3339, NoColor: p.nocolor, PartsExclude: []string{"level"}}
		sniffoutput.FormatTimestamp = func(i any) string {
			ts, _ := time.Parse(time.RFC3339, i.(string))
			return colorizeTimestamp(ts, p.nocolor)
		}
		sniffoutput.FormatMessage = func(i any) string {
			if i == nil || i == "" {
				return ""
			}
			return fmt.Sprintf("%s", i)
		}
		sniffoutput.FormatErrFieldName = func(i any) string {
			return fmt.Sprintf("%s", i)
		}

		sniffoutput.FormatErrFieldValue = func(i any) string {
			return colorizeErrMessage(i.(string), p.nocolor)
		}
		snifflogger = zerolog.New(sniffoutput).With().Timestamp().Logger()
	}
	zerolog.SetGlobalLevel(zerolog.DebugLevel)
	lvl := zerolog.InfoLevel
	if conf.Debug {
		lvl = zerolog.DebugLevel
	}
	p.debug = conf.Debug
	// the only way I found to make debug level independent between loggers
	l := logger.Level(lvl)
	sl := snifflogger.Level(lvl)
	p.logger = &l
	p.snifflogger = &sl
	if runtime.GOOS == "linux" && conf.TProxy != "" && conf.TProxyOnly != "" {
		p.logger.Fatal().Msg("Cannot specify TPRoxy and TProxyOnly at the same time")
	} else if runtime.GOOS == "linux" && conf.TProxyMode != "" && !slices.Contains(SupportedTProxyModes, conf.TProxyMode) {
		p.logger.Fatal().Msg("Incorrect TProxyMode provided")
	} else if runtime.GOOS != "linux" && (conf.TProxy != "" || conf.TProxyOnly != "" || conf.TProxyMode != "" || conf.TProxyUDP != "") {
		conf.TProxy = ""
		conf.TProxyOnly = ""
		conf.TProxyMode = ""
		conf.TProxyUDP = ""
		p.logger.Warn().Msgf("[%s] functionality only available on linux systems", conf.TProxyMode)
	}
	p.tproxyMode = conf.TProxyMode
	tproxyonly := conf.TProxyOnly != ""
	var tAddr string
	if tproxyonly {
		tAddr = conf.TProxyOnly
	} else {
		tAddr = conf.TProxy
	}
	if p.tproxyMode != "" {
		p.tproxyAddr, err = getFullAddress(tAddr, "", true)
		if err != nil {
			p.logger.Fatal().Err(err).Msg("")
		}
		if conf.TProxyUDP != "" {
			if p.tproxyMode != "tproxy" {
				p.logger.Warn().Msgf("[%s] transparent UDP server only supports tproxy mode", conf.TProxyMode)
			}
			p.tproxyAddrUDP, err = getFullAddress(conf.TProxyUDP, "", true)
			if err != nil {
				p.logger.Fatal().Err(err).Msg("")
			}
		}
	} else {
		p.tproxyAddr, err = getFullAddress(tAddr, "", false)
		if err != nil {
			p.logger.Fatal().Err(err).Msg("")
		}
	}
	p.auto = conf.Auto
	if p.auto && runtime.GOOS != "linux" {
		p.logger.Fatal().Msg("Auto setup is available only on linux systems")
	}
	p.mark = conf.Mark
	if p.mark > 0 && runtime.GOOS != "linux" {
		p.logger.Fatal().Msg("SO_MARK is available only on linux systems")
	}
	if p.mark > 0xFFFFFFFF {
		p.logger.Fatal().Msg("SO_MARK is out of range")
	}
	if p.mark == 0 && p.tproxyMode == "tproxy" {
		p.mark = 100
	}
	var addrHTTP, addrSOCKS, certFile, keyFile string
	if conf.ServerConfPath != "" {
		var sconf serverConfig
		yamlFile, err := os.ReadFile(expandPath(conf.ServerConfPath))
		if err != nil {
			p.logger.Fatal().Err(err).Msg("[yaml config] Parsing failed")
		}
		err = yaml.Unmarshal(yamlFile, &sconf)
		if err != nil {
			p.logger.Fatal().Err(err).Msg("[yaml config] Parsing failed")
		}
		if !tproxyonly {
			if sconf.Server.Address == "" {
				p.logger.Fatal().Err(err).Msg("[yaml config] Server address is empty")
			}
			if sconf.Server.Interface != "" {
				p.iface, err = net.InterfaceByName(sconf.Server.Interface)
				if err != nil {
					if ifIdx, err := strconv.Atoi(sconf.Server.Interface); err == nil {
						p.iface, err = net.InterfaceByIndex(ifIdx)
						if err != nil {
							p.logger.Warn().Err(err).Msgf("Failed binding to %s, using default interface", sconf.Server.Interface)
						}
					} else {
						p.logger.Warn().Msgf("Failed binding to %s, using default interface", sconf.Server.Interface)
					}
				}
			}
			iAddr, err := getAddressFromInterface(p.iface)
			if err != nil {
				p.iface = nil
				p.logger.Warn().Err(err).Msgf("Failed binding to %s, using default interface", sconf.Server.Interface)
			}
			addrHTTP, err = getFullAddress(sconf.Server.Address, iAddr, false)
			if err != nil {
				p.logger.Fatal().Err(err).Msg("")
			}
			p.httpServerAddr = addrHTTP
			certFile = expandPath(sconf.Server.CertFile)
			keyFile = expandPath(sconf.Server.KeyFile)
			p.user = sconf.Server.Username
			p.pass = sconf.Server.Password
		}
		p.proxychain = sconf.Chain
		p.proxylist = sconf.ProxyList
		p.availProxyList = make([]proxyEntry, 0, len(p.proxylist))
		if len(p.proxylist) == 0 {
			p.logger.Fatal().Msg("[yaml config] Proxy list is empty")
		}
		seen := make(map[string]struct{})
		for idx, pr := range p.proxylist {
			addr, err := getFullAddress(pr.Address, "", false)
			if err != nil {
				p.logger.Fatal().Err(err).Msg("")
			}
			if _, ok := seen[addr]; !ok {
				seen[addr] = struct{}{}
				p.proxylist[idx].Address = addr
			} else {
				p.logger.Fatal().Msgf("[yaml config] Duplicate entry `%s`", addr)
			}
		}
		addrSOCKS = p.printProxyChain(p.proxylist)
		chainType := p.proxychain.Type
		if !slices.Contains(supportedChainTypes, chainType) {
			p.logger.Fatal().Msgf("[yaml config] Chain type `%s` is not supported", chainType)
		}
		p.rrIndexReset = rrIndexMax
	} else {
		if !tproxyonly {
			if conf.Interface != "" {
				p.iface, err = net.InterfaceByName(conf.Interface)
				if err != nil {
					if ifIdx, err := strconv.Atoi(conf.Interface); err == nil {
						p.iface, err = net.InterfaceByIndex(ifIdx)
						if err != nil {
							p.logger.Warn().Err(err).Msgf("Failed binding to %s, using default interface", conf.Interface)
						}
					} else {
						p.logger.Warn().Msgf("Failed binding to %s, using default interface", conf.Interface)
					}
				}
			}
			iAddr, err := getAddressFromInterface(p.iface)
			if err != nil {
				p.logger.Warn().Err(err).Msgf("Failed binding to %s, using default interface", conf.Interface)
				p.iface = nil
			}
			addrHTTP, err = getFullAddress(conf.AddrHTTP, iAddr, false)
			if err != nil {
				p.logger.Fatal().Err(err).Msg("")
			}
			p.httpServerAddr = addrHTTP
			certFile = expandPath(conf.CertFile)
			keyFile = expandPath(conf.KeyFile)
			p.user = conf.ServerUser
			p.pass = conf.ServerPass
		}
		addrSOCKS, err = getFullAddress(conf.AddrSOCKS, "", false)
		if err != nil {
			p.logger.Fatal().Err(err).Msg("")
		}
		auth := Auth{
			User:     conf.User,
			Password: conf.Pass,
		}
		dialer, err := newSOCKS5Dialer(addrSOCKS, &auth, getBaseDialer(timeout, p.mark))
		if err != nil {
			p.logger.Fatal().Err(err).Msg("Unable to create SOCKS5 dialer")
		}
		p.sockDialer = dialer
		if !tproxyonly {
			p.sockClient = &http.Client{
				Transport: &http.Transport{
					DialContext: dialer.DialContext,
				},
				CheckRedirect: func(req *http.Request, via []*http.Request) error {
					return http.ErrUseLastResponse
				},
			}
		}
	}
	if !tproxyonly {
		hs := &http.Server{
			Addr:           addrHTTP,
			ReadTimeout:    readTimeout,
			WriteTimeout:   writeTimeout,
			MaxHeaderBytes: 1 << 20,
			Protocols:      new(http.Protocols),
			TLSConfig: &tls.Config{
				MinVersion:       tls.VersionTLS12,
				CurvePreferences: []tls.CurveID{tls.CurveP521, tls.CurveP384, tls.CurveP256},
				CipherSuites: []uint16{
					tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
					tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
					tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
					tls.TLS_RSA_WITH_AES_256_CBC_SHA,
				},
			},
		}
		hs.TLSNextProto = make(map[string]func(*http.Server, *tls.Conn, http.Handler))
		hs.Protocols.SetHTTP1(true)
		p.httpServer = hs
		p.httpClient = &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
				DialContext:     getBaseDialer(timeout, p.mark).DialContext,
			},
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
			Timeout: timeout,
		}
	}
	if conf.ARPSpoof != "" {
		if runtime.GOOS != "linux" {
			p.logger.Fatal().Msg("ARP spoof setup is available only on linux systems")
		}
		if !p.auto {
			p.logger.Warn().Msg("ARP spoof setup requires iptables configuration")
		}
		asc, err := arpspoof.NewARPSpoofConfig(conf.ARPSpoof, p.logger)
		if err != nil {
			p.logger.Fatal().Err(err).Msg("Failed creating arp spoofer")
		}
		asc.Interface = ""
		asc.Gateway = nil
		if p.iface != nil {
			asc.Interface = p.iface.Name
		}
		p.arpspoofer, err = arpspoof.NewARPSpoofer(asc)
		if err != nil {
			p.logger.Fatal().Err(err).Msg("Failed creating arp spoofer")
		}
	}
	if conf.ServerConfPath != "" {
		p.logger.Info().Msgf("SOCKS5 Proxy [%s] chain: %s", p.proxychain.Type, addrSOCKS)
	} else {
		p.logger.Info().Msgf("SOCKS5 Proxy: %s", addrSOCKS)
	}
	if !tproxyonly {
		if certFile != "" && keyFile != "" {
			p.certFile = certFile
			p.keyFile = keyFile
			p.logger.Info().Msgf("HTTPS Proxy: %s", p.httpServerAddr)
		} else {
			p.logger.Info().Msgf("HTTP Proxy: %s", p.httpServerAddr)
		}
	}
	if p.tproxyAddr != "" {
		if p.tproxyMode == "tproxy" {
			p.logger.Info().Msgf("TPROXY: %s", p.tproxyAddr)
		} else {
			p.logger.Info().Msgf("REDIRECT: %s", p.tproxyAddr)
		}
	}
	if p.tproxyAddrUDP != "" {
		p.logger.Info().Msgf("TPROXY (UDP): %s", p.tproxyAddrUDP)
	}
	return &p
}

func (p *proxyapp) Run() {
	done := make(chan bool)
	quit := make(chan os.Signal, 1)
	p.closeConn = make(chan bool)
	signal.Notify(quit, os.Interrupt)
	if p.arpspoofer != nil {
		go p.arpspoofer.Start()
	}
	var tproxyServer *tproxyServer
	opts := make(map[string]string, 5)
	if p.auto {
		p.applyCommonRedirectRules(opts)
	}
	if p.tproxyAddr != "" {
		tproxyServer = newTproxyServer(p)
		if p.auto {
			tproxyServer.ApplyRedirectRules(opts)
		}
	}
	var tproxyServerUDP *tproxyServerUDP
	if p.tproxyAddrUDP != "" {
		tproxyServerUDP = newTproxyServerUDP(p)
		if p.auto {
			tproxyServerUDP.ApplyRedirectRules(opts)
		}
	}
	if p.proxylist != nil {
		chainType := p.proxychain.Type
		ctl := colorizeChainType(chainType, p.nocolor)
		go func() {
			for {
				p.logger.Debug().Msgf("%s Updating available proxy", ctl)
				p.updateSocksList()
				time.Sleep(availProxyUpdateInterval)
			}
		}()
	}
	if p.httpServer != nil {
		go func() {
			<-quit
			if p.arpspoofer != nil {
				err := p.arpspoofer.Stop()
				if err != nil {
					p.logger.Error().Err(err).Msg("Failed stopping arp spoofer")
				}
			}
			close(p.closeConn)
			if tproxyServer != nil {
				p.logger.Info().Msgf("[tcp %s] Server is shutting down...", p.tproxyMode)
				if p.auto {
					err := tproxyServer.ClearRedirectRules()
					if err != nil {
						p.logger.Error().Err(err).Msg("Failed clearing iptables rules")
					}
				}
				tproxyServer.Shutdown()
			}
			if tproxyServerUDP != nil {
				p.logger.Info().Msgf("[udp %s] Server is shutting down...", p.tproxyMode)
				if p.auto {
					err := tproxyServerUDP.ClearRedirectRules()
					if err != nil {
						p.logger.Error().Err(err).Msg("Failed clearing iptables rules")
					}
				}
				tproxyServerUDP.Shutdown()
			}
			if p.auto {
				err := p.clearCommonRedirectRules(opts)
				if err != nil {
					p.logger.Error().Err(err).Msg("Failed clearing iptables rules")
				}
			}
			p.logger.Info().Msg("Server is shutting down...")
			ctx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)

			defer cancel()
			p.httpServer.SetKeepAlivesEnabled(false)
			if err := p.httpServer.Shutdown(ctx); err != nil {
				p.logger.Fatal().Err(err).Msg("Could not gracefully shutdown the server")
			}
			close(done)
		}()
		if tproxyServer != nil {
			go tproxyServer.ListenAndServe()
		}
		if tproxyServerUDP != nil {
			go tproxyServerUDP.ListenAndServe()
		}
		if p.user != "" && p.pass != "" {
			p.httpServer.Handler = p.proxyAuth(p.handler())
		} else {
			p.httpServer.Handler = p.handler()
		}
		if p.certFile != "" && p.keyFile != "" {
			if err := p.httpServer.ListenAndServeTLS(p.certFile, p.keyFile); err != nil && err != http.ErrServerClosed {
				p.logger.Fatal().Err(err).Msg("Unable to start HTTPS server")
			}
		} else {
			if err := p.httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				p.logger.Fatal().Err(err).Msg("Unable to start HTTP server")
			}
		}
		p.logger.Info().Msg("Server stopped")
	} else {
		go func() {
			<-quit
			if p.arpspoofer != nil {
				err := p.arpspoofer.Stop()
				if err != nil {
					p.logger.Error().Err(err).Msg("Failed stopping arp spoofer")
				}
			}
			close(p.closeConn)
			if tproxyServer != nil {
				p.logger.Info().Msgf("[tcp %s] Server is shutting down...", p.tproxyMode)
				if p.auto {
					err := tproxyServer.ClearRedirectRules()
					if err != nil {
						p.logger.Error().Err(err).Msg("Failed clearing iptables rules")
					}
				}
				tproxyServer.Shutdown()
			}
			if tproxyServerUDP != nil {
				p.logger.Info().Msgf("[udp %s] Server is shutting down...", p.tproxyMode)
				if p.auto {
					err := tproxyServerUDP.ClearRedirectRules()
					if err != nil {
						p.logger.Error().Err(err).Msg("Failed clearing iptables rules")
					}
				}
				tproxyServerUDP.Shutdown()
			}
			if p.auto {
				err := p.clearCommonRedirectRules(opts)
				if err != nil {
					p.logger.Error().Err(err).Msg("Failed clearing iptables rules")
				}
			}
			close(done)
		}()
		if tproxyServer != nil && tproxyServerUDP != nil {
			go tproxyServerUDP.ListenAndServe()
			tproxyServer.ListenAndServe()
		} else if tproxyServer != nil {
			tproxyServer.ListenAndServe()
		} else {
			tproxyServerUDP.ListenAndServe()
		}
	}
	<-done
}

func (p *proxyapp) handler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodConnect {
			p.handleTunnel(w, r)
		} else {
			p.handleForward(w, r)
		}
	}
}

func (p *proxyapp) handleForward(w http.ResponseWriter, r *http.Request) {
	var reqBodySaved []byte
	if p.sniff && p.body {
		reqBodySaved, _ = io.ReadAll(io.LimitReader(r.Body, maxBodySize))
		r.Body = io.NopCloser(io.MultiReader(bytes.NewReader(reqBodySaved), r.Body))
	}
	req, err := http.NewRequest(r.Method, r.URL.String(), r.Body)
	if err != nil {
		p.logger.Error().Err(err).Msgf("Error during NewRequest() %s: %s", r.URL.String(), err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	req.RequestURI = ""
	copyHeader(req.Header, r.Header)
	delConnectionHeaders(req.Header)
	delHopHeaders(req.Header)
	if clientIP, _, err := net.SplitHostPort(req.RemoteAddr); err == nil {
		appendHostToXForwardHeader(req.Header, clientIP)
	}
	var resp *http.Response
	var chunked bool
	var respBodySaved []byte
	p.httpClient.Timeout = timeout
	if network.IsLocalAddress(r.Host) {
		resp = p.doReq(w, req, nil)
	} else {
		_, sockClient, err := p.getSocks()
		if err != nil {
			p.logger.Error().Err(err).Msg("Failed getting SOCKS5 client")
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		resp = p.doReq(w, req, sockClient)
	}
	if resp == nil {
		return
	}
	chunked = slices.Contains(resp.TransferEncoding, "chunked")
	if p.sniff {
		if p.body {
			if chunked {
				buf := make([]byte, maxBodySize)
				n, _ := resp.Body.Read(buf)
				respBodySaved = buf[:n]
				resp.Body = io.NopCloser(io.MultiReader(bytes.NewReader(buf[:n]), resp.Body))
			} else {
				respBodySaved, _ = io.ReadAll(io.LimitReader(resp.Body, maxBodySize))
				resp.Body = io.NopCloser(io.MultiReader(bytes.NewReader(respBodySaved), resp.Body))
			}
			if resp.Header.Get("Content-Encoding") == "gzip" {
				gzr, err := gzip.NewReader(bytes.NewReader(respBodySaved))
				if err == nil {
					respBodySaved, _ = io.ReadAll(gzr)
				}
			}
			reqBodySaved = bytes.Trim(reqBodySaved, "\r\n\t ")
			respBodySaved = bytes.Trim(respBodySaved, "\r\n\t ")
		}
		if p.json {
			sniffdata := make([]string, 0, 4)
			j, err := json.Marshal(&layers.HTTPMessage{Request: r})
			if err == nil {
				sniffdata = append(sniffdata, string(j))
			}
			j, err = json.Marshal(&layers.HTTPMessage{Response: resp})
			if err == nil {
				sniffdata = append(sniffdata, string(j))
			}
			if p.body && len(reqBodySaved) > 0 {
				sniffdata = append(sniffdata, fmt.Sprintf("{\"req_body\":%s}", reqBodySaved))
			}
			if p.body && len(respBodySaved) > 0 {
				sniffdata = append(sniffdata, fmt.Sprintf("{\"resp_body\":%s}", respBodySaved))
			}
			p.snifflogger.Log().Msg(fmt.Sprintf("[%s]", strings.Join(sniffdata, ",")))
		} else {
			id := getID(p.nocolor)
			p.snifflogger.Log().Msg(colorizeHTTP(req, resp, &reqBodySaved, &respBodySaved, id, false, p.body, p.nocolor))
		}
	}
	defer resp.Body.Close()
	done := make(chan bool)
	if chunked {
		rc := http.NewResponseController(w)
		go func() {
			for {
				select {
				case <-time.Tick(flushTimeout):
					err := rc.Flush()
					if err != nil {
						p.logger.Error().Err(err).Msg("Failed flushing buffer")
						return
					}
					err = rc.SetReadDeadline(time.Now().Add(readTimeout))
					if err != nil {
						p.logger.Error().Err(err).Msg("Failed setting read deadline")
						return
					}
					err = rc.SetWriteDeadline(time.Now().Add(writeTimeout))
					if err != nil {
						p.logger.Error().Err(err).Msg("Failed setting write deadline")
						return
					}
				case <-done:
					return
				}
			}
		}()
	}
	announcedTrailers := len(resp.Trailer)
	if announcedTrailers > 0 {
		trailerKeys := make([]string, 0, announcedTrailers)
		for k := range resp.Trailer {
			trailerKeys = append(trailerKeys, k)
		}
		w.Header().Add("Trailer", strings.Join(trailerKeys, ", "))
	}
	delConnectionHeaders(resp.Header)
	delHopHeaders(resp.Header)
	copyHeader(w.Header(), resp.Header)
	w.WriteHeader(resp.StatusCode)
	n, err := io.Copy(w, resp.Body)
	if err != nil {
		p.logger.Error().Err(err).Msgf("Error during Copy() %s: %s", r.URL.String(), err)
		close(done)
		return
	}
	written := prettifyBytes(n)
	if chunked {
		written = fmt.Sprintf("%s - chunked", written)
	}
	status := resp.Status
	if !p.nocolor {
		status = colorizeStatus(resp.StatusCode, status, false)
	}
	p.logger.Debug().Msgf("%s - %s - %s - %s - %s", r.Proto, r.Method, r.Host, status, written)
	if len(resp.Trailer) == announcedTrailers {
		copyHeader(w.Header(), resp.Trailer)
	}
	for key, values := range resp.Trailer {
		key = http.TrailerPrefix + key
		for _, v := range values {
			w.Header().Add(key, v)
		}
	}
	close(done)
}

func (p *proxyapp) handleTunnel(w http.ResponseWriter, r *http.Request) {
	var dstConn net.Conn
	var err error
	if network.IsLocalAddress(r.Host) {
		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		defer cancel()
		dstConn, err = getBaseDialer(timeout, p.mark).DialContext(ctx, "tcp", r.Host)
		if err != nil {
			p.logger.Error().Err(err).Msgf("Failed connecting to %s", r.Host)
			http.Error(w, err.Error(), http.StatusServiceUnavailable)
			return
		}
	} else {
		sockDialer, _, err := p.getSocks()
		if err != nil {
			p.logger.Error().Err(err).Msg("Failed getting SOCKS5 client")
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		defer cancel()
		dstConn, err = sockDialer.DialContext(ctx, "tcp", r.Host)
		if err != nil {
			p.logger.Error().Err(err).Msgf("Failed connecting to %s", r.Host)
			http.Error(w, err.Error(), http.StatusServiceUnavailable)
			return
		}
	}
	defer dstConn.Close()
	w.WriteHeader(http.StatusOK)

	hj, ok := w.(http.Hijacker)
	if !ok {
		p.logger.Error().Msg("webserver doesn't support hijacking")
		http.Error(w, "webserver doesn't support hijacking", http.StatusInternalServerError)
		return
	}
	srcConn, _, err := hj.Hijack()
	if err != nil {
		p.logger.Error().Err(err).Msg("Failed hijacking src connection")
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer srcConn.Close()

	dstConnStr := fmt.Sprintf("%s→ %s→ %s", dstConn.LocalAddr().String(), dstConn.RemoteAddr().String(), r.Host)
	srcConnStr := fmt.Sprintf("%s→ %s", srcConn.RemoteAddr().String(), srcConn.LocalAddr().String())

	p.logger.Debug().Msgf("%s - %s - %s", r.Proto, r.Method, r.Host)
	p.logger.Debug().Msgf("src: %s - dst: %s", srcConnStr, dstConnStr)
	reqChan := make(chan layers.Layer)
	respChan := make(chan layers.Layer)
	var wg sync.WaitGroup
	wg.Add(2)
	go p.transfer(&wg, dstConn, srcConn, dstConnStr, srcConnStr, reqChan)
	go p.transfer(&wg, srcConn, dstConn, srcConnStr, dstConnStr, respChan)
	if p.sniff {
		wg.Add(1)
		sniffdata := make([]string, 0, 6)
		id := getID(p.nocolor)
		if p.json {
			sniffdata = append(
				sniffdata,
				fmt.Sprintf("{\"connection\":{\"src_remote\":%s,\"src_local\":%s,\"dst_local\":%s,\"dst_remote\":%s}}",
					srcConn.RemoteAddr(), srcConn.LocalAddr(), dstConn.LocalAddr(), dstConn.RemoteAddr()),
			)
			j, err := json.Marshal(&layers.HTTPMessage{Request: r})
			if err == nil {
				sniffdata = append(sniffdata, string(j))
			}
		} else {
			connections := colorizeConnections(srcConn.RemoteAddr(), srcConn.LocalAddr(), dstConn.RemoteAddr(), dstConn.LocalAddr(), id, r, p.nocolor)
			sniffdata = append(sniffdata, connections)
		}
		go p.sniffreporter(&wg, &sniffdata, reqChan, respChan, id)
	}
	wg.Wait()
}

func (p *proxyapp) printProxyChain(pc []proxyEntry) string {
	var sb strings.Builder
	sb.WriteString("client →  ")
	if p.httpServerAddr != "" {
		sb.WriteString(p.httpServerAddr)
		if p.tproxyAddr != "" {
			sb.WriteString(" | ")
			sb.WriteString(p.tproxyAddr)
			sb.WriteString(fmt.Sprintf(" (%s)", p.tproxyMode))
		}
	} else if p.tproxyAddr != "" {
		sb.WriteString(p.tproxyAddr)
		sb.WriteString(fmt.Sprintf(" (%s)", p.tproxyMode))
	}
	sb.WriteString(" →  ")
	for _, pe := range pc {
		sb.WriteString(pe.String())
		sb.WriteString(" →  ")
	}
	sb.WriteString("target")
	return sb.String()
}

func (p *proxyapp) updateSocksList() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.availProxyList = p.availProxyList[:0]
	var dialer *socks5.Dialer
	var err error
	failed := 0
	chainType := p.proxychain.Type
	ctl := colorizeChainType(chainType, p.nocolor)
	for _, pr := range p.proxylist {
		auth := Auth{
			User:     pr.Username,
			Password: pr.Password,
		}
		dialer, err = newSOCKS5Dialer(pr.Address, &auth, getBaseDialer(timeout, p.mark))
		if err != nil {
			p.logger.Error().Err(err).Msgf("%s Unable to create SOCKS5 dialer %s", ctl, pr.Address)
			failed++
			continue
		}
		ctx, cancel := context.WithTimeout(context.Background(), hopTimeout)
		defer cancel()
		conn, err := dialer.DialContext(ctx, "tcp", pr.Address)
		if err != nil && !errors.Is(err, io.EOF) { // check for EOF to include localhost SOCKS5 in the chain
			p.logger.Error().Err(err).Msgf("%s Unable to connect to %s", ctl, pr.Address)
			failed++
			if conn != nil {
				conn.Close()
			}
			continue
		} else {
			p.availProxyList = append(p.availProxyList, proxyEntry{Address: pr.Address, Username: pr.Username, Password: pr.Password})
			if conn != nil {
				conn.Close()
			}
			break
		}
	}
	if failed == len(p.proxylist) {
		p.logger.Error().Err(err).Msgf("%s No SOCKS5 Proxy available", ctl)
		return
	}
	currentDialer := dialer
	for _, pr := range p.proxylist[failed+1:] {
		auth := Auth{
			User:     pr.Username,
			Password: pr.Password,
		}
		dialer, err = newSOCKS5Dialer(pr.Address, &auth, currentDialer)
		if err != nil {
			p.logger.Error().Err(err).Msgf("%s Unable to create SOCKS5 dialer %s", ctl, pr.Address)
			continue
		}
		// https://github.com/golang/go/issues/37549#issuecomment-1178745487
		ctx, cancel := context.WithTimeout(context.Background(), hopTimeout)
		defer cancel()
		conn, err := dialer.DialContext(ctx, "tcp", pr.Address)
		if err != nil {
			p.logger.Error().Err(err).Msgf("%s Unable to connect to %s", ctl, pr.Address)
			if conn != nil {
				conn.Close()
			}
			continue
		}
		conn.Close()
		currentDialer = dialer
		p.availProxyList = append(p.availProxyList, proxyEntry{Address: pr.Address, Username: pr.Username, Password: pr.Password})
	}
	p.logger.Debug().Msgf("%s Available SOCKS5 Proxy [%d/%d]: %s", ctl,
		len(p.availProxyList), len(p.proxylist), p.printProxyChain(p.availProxyList))
}

// https://www.calhoun.io/how-to-shuffle-arrays-and-slices-in-go/
func shuffle(vals []proxyEntry) {
	r := rand.New(rand.NewSource(time.Now().Unix()))
	for len(vals) > 0 {
		n := len(vals)
		randIndex := r.Intn(n)
		vals[n-1], vals[randIndex] = vals[randIndex], vals[n-1]
		vals = vals[:n-1]
	}
}

func (p *proxyapp) getSocks() (*socks5.Dialer, *http.Client, error) {
	if p.proxylist == nil {
		return p.sockDialer, p.sockClient, nil
	}
	p.mu.RLock()
	defer p.mu.RUnlock()
	chainType := p.proxychain.Type
	ctl := colorizeChainType(chainType, p.nocolor)
	if len(p.availProxyList) == 0 {
		p.logger.Error().Msgf("%s No SOCKS5 Proxy available", ctl)
		return nil, nil, fmt.Errorf("no socks5 proxy available")
	}
	var chainLength int
	if p.proxychain.Length > len(p.availProxyList) || p.proxychain.Length <= 0 {
		chainLength = len(p.availProxyList)
	} else {
		chainLength = p.proxychain.Length
	}
	copyProxyList := make([]proxyEntry, 0, len(p.availProxyList))
	switch chainType {
	case "strict", "dynamic":
		copyProxyList = p.availProxyList
	case "random":
		copyProxyList = append(copyProxyList, p.availProxyList...)
		shuffle(copyProxyList)
		copyProxyList = copyProxyList[:chainLength]
	case "round_robin":
		var start uint32
		for {
			start = atomic.LoadUint32(&p.rrIndex)
			next := start + 1
			if start >= p.rrIndexReset {
				p.logger.Debug().Msg("Resetting round robin index")
				next = 0
			}
			if atomic.CompareAndSwapUint32(&p.rrIndex, start, next) {
				break
			}
		}
		startIdx := int(start % uint32(len(p.availProxyList)))
		for i := range chainLength {
			idx := (startIdx + i) % len(p.availProxyList)
			copyProxyList = append(copyProxyList, p.availProxyList[idx])
		}
	default:
		p.logger.Fatal().Msg("Unreachable")
	}
	if len(copyProxyList) == 0 {
		p.logger.Error().Msgf("%s No SOCKS5 Proxy available", ctl)
		return nil, nil, fmt.Errorf("no socks5 proxy available")
	}
	if p.proxychain.Type == "strict" && len(copyProxyList) != len(p.proxylist) {
		p.logger.Error().Msgf("%s Not all SOCKS5 Proxy available", ctl)
		return nil, nil, fmt.Errorf("not all socks5 proxy available")
	}
	var dialer *socks5.Dialer
	var err error
	for i, pr := range copyProxyList {
		auth := Auth{
			User:     pr.Username,
			Password: pr.Password,
		}
		if i > 0 {
			dialer, err = newSOCKS5Dialer(pr.Address, &auth, dialer)
		} else {
			dialer, err = newSOCKS5Dialer(pr.Address, &auth, getBaseDialer(timeout, p.mark))
		}
		if err != nil {
			p.logger.Error().Err(err).Msgf("%s Unable to create SOCKS5 dialer %s", ctl, pr.Address)
			return nil, nil, err
		}
	}
	socks := &http.Client{
		Transport: &http.Transport{
			DialContext: dialer.DialContext,
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	p.logger.Debug().Msgf("%s Request chain: %s", ctl, p.printProxyChain(copyProxyList))
	return dialer, socks, nil
}

func (p *proxyapp) doReq(w http.ResponseWriter, r *http.Request, sock *http.Client) *http.Response {
	var (
		resp   *http.Response
		err    error
		msg    string
		client *http.Client
	)
	if sock != nil {
		client = sock
		msg = "Connection to SOCKS5 server failed"
	} else {
		client = p.httpClient
		msg = "Connection failed"
	}
	resp, err = client.Do(r)
	if err != nil {
		p.logger.Error().Err(err).Msg(msg)
		w.WriteHeader(http.StatusServiceUnavailable)
		return nil
	}
	if resp == nil {
		p.logger.Error().Msg(msg)
		w.WriteHeader(http.StatusServiceUnavailable)
		return nil
	}
	return resp
}

func (p *proxyapp) transfer(
	wg *sync.WaitGroup,
	dst net.Conn,
	src net.Conn,
	destName, srcName string,
	msgChan chan<- layers.Layer,
) {
	defer func() {
		wg.Done()
		close(msgChan)
	}()
	n, err := p.copyWithTimeout(dst, src, msgChan)
	if err != nil {
		p.logger.Error().Err(err).Msgf("Error during copy from %s to %s: %v", srcName, destName, err)
	}
	if n > 0 {
		p.logger.Debug().Msgf("copied %s from %s to %s", prettifyBytes(n), srcName, destName)
	}
	src.Close()
}

func (p *proxyapp) gatherSniffData(req, resp layers.Layer, sniffdata *[]string, id string) error {
	switch reqt := req.(type) {
	case *layers.HTTPMessage:
		var reqBodySaved, respBodySaved []byte
		rest := resp.(*layers.HTTPMessage)
		if p.body {
			reqBodySaved, _ = io.ReadAll(reqt.Request.Body)
			respBodySaved, _ = io.ReadAll(rest.Response.Body)
			reqBodySaved = bytes.Trim(reqBodySaved, "\r\n\t ")
			respBodySaved = bytes.Trim(respBodySaved, "\r\n\t ")
		}
		if p.json {
			j1, err := json.Marshal(reqt)
			if err != nil {
				return err
			}
			j2, err := json.Marshal(rest)
			if err != nil {
				return err
			}
			*sniffdata = append(*sniffdata, string(j1), string(j2))
			if p.body && len(reqBodySaved) > 0 {
				*sniffdata = append(*sniffdata, fmt.Sprintf("{\"req_body\":%s}", reqBodySaved))
			}
			if p.body && len(respBodySaved) > 0 {
				*sniffdata = append(*sniffdata, fmt.Sprintf("{\"resp_body\":%s}", respBodySaved))
			}
		} else {
			*sniffdata = append(*sniffdata, colorizeHTTP(reqt.Request, rest.Response, &reqBodySaved, &respBodySaved, id, true, p.body, p.nocolor))
		}
	case *layers.TLSMessage:
		var chs *layers.TLSClientHello
		var shs *layers.TLSServerHello
		hsrec := reqt.Records[0]                         // len(Records) > 0 after dispatch
		if hsrec.ContentType == layers.HandshakeTLSVal { // TODO: add more cases, parse all records
			switch parser := layers.HSTLSParserByType(hsrec.Data[0]).(type) {
			case *layers.TLSClientHello:
				err := parser.ParseHS(hsrec.Data)
				if err != nil {
					return err
				}
				chs = parser
			}
		}
		rest := resp.(*layers.TLSMessage)
		hsrec = rest.Records[0]
		if hsrec.ContentType == layers.HandshakeTLSVal {
			switch parser := layers.HSTLSParserByType(hsrec.Data[0]).(type) {
			case *layers.TLSServerHello:
				err := parser.ParseHS(hsrec.Data)
				if err != nil {
					return err
				}
				shs = parser
			}
		}
		if chs != nil && shs != nil {
			if p.json {
				j1, err := json.Marshal(chs)
				if err != nil {
					return err
				}
				j2, err := json.Marshal(shs)
				if err != nil {
					return err
				}
				*sniffdata = append(*sniffdata, string(j1), string(j2))
			} else {
				*sniffdata = append(*sniffdata, colorizeTLS(chs, shs, id, p.nocolor))
			}
		}
	}
	return nil
}

func (p *proxyapp) sniffreporter(wg *sync.WaitGroup, sniffdata *[]string, reqChan, respChan <-chan layers.Layer, id string) {
	defer wg.Done()
	sniffdatalen := len(*sniffdata)
	var reqTLSQueue, respTLSQueue, reqHTTPQueue, respHTTPQueue []layers.Layer
	for {
		select {
		case req, ok := <-reqChan:
			if !ok {
				return
			} else {
				switch req.(type) {
				case *layers.TLSMessage:
					reqTLSQueue = append(reqTLSQueue, req)
				case *layers.HTTPMessage:
					reqHTTPQueue = append(reqHTTPQueue, req)
				}
			}
		case resp, ok := <-respChan:
			if !ok {
				return
			} else {
				switch resp.(type) {
				case *layers.TLSMessage:
					// request comes first or response arrived first
					if len(reqTLSQueue) > 0 || len(respTLSQueue) == 0 {
						respTLSQueue = append(respTLSQueue, resp)
						// remove unmatched response if still no requests
					} else if len(reqTLSQueue) == 0 && len(respTLSQueue) == 1 {
						respTLSQueue = respTLSQueue[1:]
					}
				case *layers.HTTPMessage:
					if len(reqHTTPQueue) > 0 || len(respHTTPQueue) == 0 {
						respHTTPQueue = append(respHTTPQueue, resp)
					} else if len(reqHTTPQueue) == 0 && len(respHTTPQueue) == 1 {
						respHTTPQueue = respHTTPQueue[1:]
					}
				}
			}
		}
		if len(reqHTTPQueue) > 0 && len(respHTTPQueue) > 0 {
			req := reqHTTPQueue[0]
			resp := respHTTPQueue[0]
			reqHTTPQueue = reqHTTPQueue[1:]
			respHTTPQueue = respHTTPQueue[1:]

			err := p.gatherSniffData(req, resp, sniffdata, id)
			if err == nil && len(*sniffdata) > sniffdatalen {
				if p.json {
					p.snifflogger.Log().Msg(fmt.Sprintf("[%s]", strings.Join(*sniffdata, ",")))
				} else {
					p.snifflogger.Log().Msg(strings.Join(*sniffdata, "\n"))
				}
			}
			*sniffdata = (*sniffdata)[:sniffdatalen]
		}
		if len(reqTLSQueue) > 0 && len(respTLSQueue) > 0 {
			req := reqTLSQueue[0]
			resp := respTLSQueue[0]
			reqTLSQueue = reqTLSQueue[1:]
			respTLSQueue = respTLSQueue[1:]

			err := p.gatherSniffData(req, resp, sniffdata, id)
			if err == nil && len(*sniffdata) > sniffdatalen {
				if p.json {
					p.snifflogger.Log().Msg(fmt.Sprintf("[%s]", strings.Join(*sniffdata, ",")))
				} else {
					p.snifflogger.Log().Msg(strings.Join(*sniffdata, "\n"))
				}
			}
			*sniffdata = (*sniffdata)[:sniffdatalen]
		}
	}
}

func dispatch(data []byte) (layers.Layer, error) {
	// TODO: check if it is http or tls beforehand
	h := &layers.HTTPMessage{}
	if err := h.Parse(data); err == nil && !h.IsEmpty() {
		return h, nil
	}
	m := &layers.TLSMessage{}
	if err := m.Parse(data); err == nil && len(m.Records) > 0 {
		return m, nil
	}
	return nil, fmt.Errorf("failed sniffing traffic")
}

func (p *proxyapp) copyWithTimeout(dst net.Conn, src net.Conn, msgChan chan<- layers.Layer) (written int64, err error) {
	buf := make([]byte, 32*1024)
readLoop:
	for {
		select {
		case <-p.closeConn:
			break readLoop
		default:
			er := src.SetReadDeadline(time.Now().Add(readTimeout))
			if er != nil {
				if errors.Is(er, net.ErrClosed) {
					break readLoop
				}
				err = er
				break readLoop
			}
			nr, er := src.Read(buf)
			if nr > 0 {
				er := dst.SetWriteDeadline(time.Now().Add(writeTimeout))
				if er != nil {
					if errors.Is(er, net.ErrClosed) {
						break readLoop
					}
					err = er
					break readLoop
				}
				if p.sniff {
					l, err := dispatch(buf[0:nr])
					if err == nil {
						msgChan <- l
					}
				}
				nw, ew := dst.Write(buf[0:nr])
				if nw < 0 || nr < nw {
					nw = 0
					if ew == nil {
						ew = errInvalidWrite
					}
				}
				written += int64(nw)
				if ew != nil {
					if ne, ok := ew.(net.Error); ok && ne.Timeout() {
						break readLoop
					}
					if errors.Is(ew, net.ErrClosed) {
						break readLoop
					}
				}
				if nr != nw {
					err = io.ErrShortWrite
					break readLoop
				}
			}
			if er != nil {
				if ne, ok := er.(net.Error); ok && ne.Timeout() {
					continue // support long-lived connections (SSE, WebSockets, etc)
				}
				if errors.Is(er, net.ErrClosed) {
					break readLoop
				}
				if er == io.EOF {
					break readLoop
				}
				err = er
				break readLoop
			}
		}
	}
	return written, err
}

func (p *proxyapp) proxyAuth(next http.HandlerFunc) http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Proxy-Authorization")
		r.Header.Del("Proxy-Authorization")
		username, password, ok := parseProxyAuth(auth)
		if ok {
			usernameHash := sha256.Sum256([]byte(username))
			passwordHash := sha256.Sum256([]byte(password))
			expectedUsernameHash := sha256.Sum256([]byte(p.user))
			expectedPasswordHash := sha256.Sum256([]byte(p.pass))

			usernameMatch := (subtle.ConstantTimeCompare(usernameHash[:], expectedUsernameHash[:]) == 1)
			passwordMatch := (subtle.ConstantTimeCompare(passwordHash[:], expectedPasswordHash[:]) == 1)

			if usernameMatch && passwordMatch {
				next.ServeHTTP(w, r)
				return
			}
		}
		w.Header().Set("Proxy-Authenticate", `Basic realm="restricted", charset="UTF-8"`)
		http.Error(w, "Proxy Authentication Required", http.StatusProxyAuthRequired)
	})
}

func (p *proxyapp) applyCommonRedirectRules(opts map[string]string) {
	var setex string
	if p.debug {
		setex = "set -ex"
	}
	if p.tproxyMode == "tproxy" {
		cmdClear := exec.Command("bash", "-c", fmt.Sprintf(`
        %s
        iptables -t mangle -F DIVERT 2>/dev/null || true
        iptables -t mangle -X DIVERT 2>/dev/null || true

        ip rule del fwmark 1 lookup 100 2>/dev/null || true
        ip route flush table 100 2>/dev/null || true
        `, setex))
		cmdClear.Stdout = os.Stdout
		cmdClear.Stderr = os.Stderr
		if err := cmdClear.Run(); err != nil {
			p.logger.Fatal().Err(err).Msg("Failed while configuring iptables. Are you root?")
		}
		cmdInit0 := exec.Command("bash", "-c", fmt.Sprintf(`
        %s
        ip rule add fwmark 1 lookup 100 2>/dev/null || true
        ip route add local 0.0.0.0/0 dev lo table 100 2>/dev/null || true

        iptables -t mangle -N DIVERT 2>/dev/null || true
        iptables -t mangle -F DIVERT 2>/dev/null || true
        iptables -t mangle -A DIVERT -j MARK --set-mark 1
        iptables -t mangle -A DIVERT -j ACCEPT
        `, setex))
		cmdInit0.Stdout = os.Stdout
		cmdInit0.Stderr = os.Stderr
		if err := cmdInit0.Run(); err != nil {
			p.logger.Fatal().Err(err).Msg("Failed while configuring iptables. Are you root?")
		}
	}

	_ = createSysctlOptCmd("net.ipv4.ip_forward", "1", setex, opts, p.debug).Run()
	cmdClearForward := exec.Command("bash", "-c", fmt.Sprintf(`
	%s
	iptables -t filter -F GOHPTS 2>/dev/null || true
	iptables -t filter -D FORWARD -j GOHPTS  2>/dev/null || true
	iptables -t filter -X GOHPTS  2>/dev/null || true
	`, setex))
	cmdClearForward.Stdout = os.Stdout
	cmdClearForward.Stderr = os.Stderr
	if err := cmdClearForward.Run(); err != nil {
		p.logger.Fatal().Err(err).Msg("Failed while configuring iptables. Are you root?")
	}
	var iface *net.Interface
	var err error
	if p.iface != nil {
		iface = p.iface
	} else {
		iface, err = network.GetDefaultInterface()
		if err != nil {
			p.logger.Fatal().Err(err).Msg("failed getting default network interface")
		}
	}
	cmdForwardFilter := exec.Command("bash", "-c", fmt.Sprintf(`
	%s
	iptables -t filter -N GOHPTS 2>/dev/null
	iptables -t filter -F GOHPTS
	iptables -t filter -A FORWARD -j GOHPTS
	iptables -t filter -A GOHPTS -i %s -j ACCEPT
	iptables -t filter -A GOHPTS -o %s -j ACCEPT
	`, setex, iface.Name, iface.Name))
	cmdForwardFilter.Stdout = os.Stdout
	cmdForwardFilter.Stderr = os.Stderr
	if err := cmdForwardFilter.Run(); err != nil {
		p.logger.Fatal().Err(err).Msg("Failed while configuring iptables. Are you root?")
	}
}

func (p *proxyapp) clearCommonRedirectRules(opts map[string]string) error {
	var setex string
	if p.debug {
		setex = "set -ex"
	}
	cmdClear := exec.Command("bash", "-c", fmt.Sprintf(`
	%s
	iptables -t filter -F GOHPTS 2>/dev/null || true
	iptables -t filter -D FORWARD -j GOHPTS  2>/dev/null || true
	iptables -t filter -X GOHPTS  2>/dev/null || true
	`, setex))
	cmdClear.Stdout = os.Stdout
	cmdClear.Stderr = os.Stderr
	if err := cmdClear.Run(); err != nil {
		p.logger.Fatal().Err(err).Msg("Failed while configuring iptables. Are you root?")
	}
	cmds := make([]string, 0, len(opts))
	for _, cmd := range slices.Sorted(maps.Keys(opts)) {
		cmds = append(cmds, fmt.Sprintf("sysctl -w %s=%s", cmd, opts[cmd]))
	}
	cmdRestoreOpts := exec.Command("bash", "-c", fmt.Sprintf(`
        %s
		%s
        `, setex, strings.Join(cmds, "\n")))
	cmdRestoreOpts.Stdout = os.Stdout
	cmdRestoreOpts.Stderr = os.Stderr
	if !p.debug {
		cmdRestoreOpts.Stdout = nil
	}
	_ = cmdRestoreOpts.Run()
	if p.tproxyMode == "tproxy" {
		cmd := exec.Command("bash", "-c", fmt.Sprintf(`
        %s
        iptables -t mangle -F DIVERT 2>/dev/null || true
        iptables -t mangle -X DIVERT 2>/dev/null || true

        ip rule del fwmark 1 lookup 100 2>/dev/null || true
        ip route flush table 100 2>/dev/null || true
        `, setex))
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		if !p.debug {
			cmd.Stdout = nil
		}
		if err := cmd.Run(); err != nil {
			return err
		}
	}
	return nil
}
