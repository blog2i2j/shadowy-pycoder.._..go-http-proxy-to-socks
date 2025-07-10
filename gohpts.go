// Package gohpts transform SOCKS5 proxy into HTTP(S) proxy with support for Transparent Proxy (Redirect and TProxy), Proxychains and Traffic Sniffing
package gohpts

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"regexp"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/goccy/go-yaml"
	"github.com/google/uuid"
	"github.com/rs/zerolog"
	"github.com/shadowy-pycoder/colors"
	"github.com/shadowy-pycoder/mshark/layers"
	"golang.org/x/net/proxy"
)

const (
	readTimeout              time.Duration = 3 * time.Second
	writeTimeout             time.Duration = 3 * time.Second
	timeout                  time.Duration = 10 * time.Second
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
	ipPortPattern        = regexp.MustCompile(
		`\b(?:\d{1,3}\.){3}\d{1,3}(?::(6553[0-5]|655[0-2]\d|65[0-4]\d{2}|6[0-4]\d{3}|[1-5]?\d{1,4}))?\b`,
	)
	domainPattern = regexp.MustCompile(
		`\b(?:[a-zA-Z0-9-]{1,63}\.)+(?:com|net|org|io|co|uk|ru|de|edu|gov|info|biz|dev|app|ai)(?::(6553[0-5]|655[0-2]\d|65[0-4]\d{2}|6[0-4]\d{3}|[1-5]?\d{1,4}))?\b`,
	)
	jwtPattern  = regexp.MustCompile(`\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b`)
	authPattern = regexp.MustCompile(
		`(?i)(?:"|')?(authorization|auth[_-]?token|access[_-]?token|api[_-]?key|secret|token)(?:"|')?\s*[:=]\s*(?:"|')?([^\s"'&]+)`,
	)
	credsPattern = regexp.MustCompile(
		`(?i)(?:"|')?(username|user|login|email|password|pass|pwd)(?:"|')?\s*[:=]\s*(?:"|')?([^\s"'&]+)`,
	)
)

// Hop-by-hop headers
// https://datatracker.ietf.org/doc/html/rfc2616#section-13.5.1
var hopHeaders = []string{
	"Connection",
	"Keep-Alive",
	"Proxy-Authenticate",
	"Proxy-Authorization",
	"Te", // canonicalized version of "TE"
	"TE",
	"Trailer",
	"Transfer-Encoding",
	"Upgrade",
}

type Config struct {
	AddrHTTP       string
	AddrSOCKS      string
	User           string
	Pass           string
	ServerUser     string
	ServerPass     string
	CertFile       string
	KeyFile        string
	ServerConfPath string
	TProxy         string
	TProxyOnly     string
	TProxyMode     string
	Auto           bool
	Mark           uint
	ARP            bool
	LogFilePath    string
	Debug          bool
	JSON           bool
	Sniff          bool
	SniffLogFile   string
	NoColor        bool
	Body           bool
}

type proxyapp struct {
	httpServer     *http.Server
	sockClient     *http.Client
	httpClient     *http.Client
	sockDialer     proxy.Dialer
	logger         *zerolog.Logger
	snifflogger    *zerolog.Logger
	certFile       string
	keyFile        string
	httpServerAddr string
	tproxyAddr     string
	tproxyMode     string
	auto           bool
	mark           uint
	arp            bool
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
	closeConn      chan bool

	mu             sync.RWMutex
	availProxyList []proxyEntry
}

var rColors = []func(string) *colors.Color{
	colors.Beige,
	colors.Blue,
	colors.Gray,
	colors.Green,
	colors.LightBlue,
	colors.Magenta,
	colors.Red,
	colors.Yellow,
	colors.BeigeBg,
	colors.BlueBg,
	colors.GrayBg,
	colors.GreenBg,
	colors.LightBlueBg,
	colors.MagentaBg,
	colors.RedBgDark,
	colors.YellowBg,
}

func randColor() func(string) *colors.Color {
	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	randIndex := r.Intn(len(rColors))
	return rColors[randIndex]
}

func (p *proxyapp) getID() string {
	id := uuid.New()
	if p.nocolor {
		return colors.WrapBrackets(id.String())
	}
	return randColor()(colors.WrapBrackets(id.String())).String()
}

func (p *proxyapp) colorizeStatus(code int, status string, bg bool) string {
	if bg {
		if code < 300 {
			status = colors.GreenBg(status).String()
		} else if code < 400 {
			status = colors.YellowBg(status).String()
		} else {
			status = colors.RedBgDark(status).String()
		}
	} else {
		if code < 300 {
			status = colors.Green(status).String()
		} else if code < 400 {
			status = colors.Yellow(status).String()
		} else {
			status = colors.Red(status).String()
		}
	}
	return status
}

func (p *proxyapp) colorizeHTTP(
	req *http.Request,
	resp *http.Response,
	reqBodySaved, respBodySaved *[]byte,
	id string,
	ts bool,
) string {
	var sb strings.Builder
	if ts {
		sb.WriteString(fmt.Sprintf("%s ", p.colorizeTimestamp()))
	}
	if p.nocolor {
		sb.WriteString(id)
		sb.WriteString(fmt.Sprintf(" %s %s %s ", req.Method, req.URL, req.Proto))
		if req.UserAgent() != "" {
			sb.WriteString(colors.WrapBrackets(req.UserAgent()))
		}
		if req.ContentLength > 0 {
			sb.WriteString(fmt.Sprintf(" Len: %d", req.ContentLength))
		}
		sb.WriteString(" -> ")
		sb.WriteString(fmt.Sprintf("%s %s ", resp.Proto, resp.Status))
		if resp.ContentLength > 0 {
			sb.WriteString(fmt.Sprintf("Len: %d", resp.ContentLength))
		}
		if p.body && len(*reqBodySaved) > 0 {
			b := p.colorizeBody(reqBodySaved)
			if b != "" {
				sb.WriteString("\n")
				sb.WriteString(fmt.Sprintf("%s ", p.colorizeTimestamp()))
				sb.WriteString(id)
				sb.WriteString(fmt.Sprintf(" req_body: %s", b))
			}
		}
		if p.body && len(*respBodySaved) > 0 {
			b := p.colorizeBody(respBodySaved)
			if b != "" {
				sb.WriteString("\n")
				sb.WriteString(fmt.Sprintf("%s ", p.colorizeTimestamp()))
				sb.WriteString(id)
				sb.WriteString(fmt.Sprintf(" resp_body: %s", b))
			}
		}
	} else {
		sb.WriteString(id)
		sb.WriteString(colors.Gray(fmt.Sprintf(" %s ", req.Method)).String())
		sb.WriteString(colors.YellowBg(fmt.Sprintf("%s ", req.URL)).String())
		sb.WriteString(colors.BlueBg(fmt.Sprintf("%s ", req.Proto)).String())
		if req.UserAgent() != "" {
			sb.WriteString(colors.Gray(colors.WrapBrackets(req.UserAgent())).String())
		}
		if req.ContentLength > 0 {
			sb.WriteString(colors.BeigeBg(fmt.Sprintf(" Len: %d", req.ContentLength)).String())
		}
		sb.WriteString(colors.MagentaBg(" -> ").String())
		sb.WriteString(colors.BlueBg(fmt.Sprintf("%s ", resp.Proto)).String())
		sb.WriteString(p.colorizeStatus(resp.StatusCode, fmt.Sprintf("%s ", resp.Status), true))
		if resp.ContentLength > 0 {
			sb.WriteString(colors.BeigeBg(fmt.Sprintf("Len: %d", resp.ContentLength)).String())
		}
		if p.body && len(*reqBodySaved) > 0 {
			b := p.colorizeBody(reqBodySaved)
			if b != "" {
				sb.WriteString("\n")
				sb.WriteString(fmt.Sprintf("%s ", p.colorizeTimestamp()))
				sb.WriteString(id)
				sb.WriteString(colors.RedBgDark(" req_body: ").String())
				sb.WriteString(b)
			}
		}
		if p.body && len(*respBodySaved) > 0 {
			b := p.colorizeBody(respBodySaved)
			if b != "" {
				sb.WriteString("\n")
				sb.WriteString(fmt.Sprintf("%s ", p.colorizeTimestamp()))
				sb.WriteString(id)
				sb.WriteString(colors.RedBgDark(" resp_body: ").String())
				sb.WriteString(b)
			}
		}
	}
	return sb.String()
}

func (p *proxyapp) colorizeTLS(req *layers.TLSClientHello, resp *layers.TLSServerHello, id string) string {
	var sb strings.Builder
	if p.nocolor {
		sb.WriteString(fmt.Sprintf("%s ", p.colorizeTimestamp()))
		sb.WriteString(id)
		sb.WriteString(fmt.Sprintf(" %s ", req.TypeDesc))
		if req.Length > 0 {
			sb.WriteString(fmt.Sprintf(" Len: %d", req.Length))
		}
		if req.ServerName != nil && req.ServerName.SNName != "" {
			sb.WriteString(fmt.Sprintf(" SNI: %s", req.ServerName.SNName))
		}
		if req.Version != nil && req.Version.Desc != "" {
			sb.WriteString(fmt.Sprintf(" Ver: %s", req.Version.Desc))
		}
		if req.ALPN != nil {
			sb.WriteString(fmt.Sprintf(" ALPN: %v", req.ALPN))
		}
		sb.WriteString(" -> ")
		sb.WriteString("\n")
		sb.WriteString(fmt.Sprintf("%s ", p.colorizeTimestamp()))
		sb.WriteString(id)
		sb.WriteString(fmt.Sprintf(" %s ", resp.TypeDesc))
		if resp.Length > 0 {
			sb.WriteString(fmt.Sprintf(" Len: %d", resp.Length))
		}
		if resp.SessionID != "" {
			sb.WriteString(fmt.Sprintf(" SID: %s", resp.SessionID))
		}
		if resp.CipherSuite != nil && resp.CipherSuite.Desc != "" {
			sb.WriteString(fmt.Sprintf(" CS: %s", resp.CipherSuite.Desc))
		}
		if resp.SupportedVersion != nil && resp.SupportedVersion.Desc != "" {
			sb.WriteString(fmt.Sprintf(" Ver: %s", resp.SupportedVersion.Desc))
		}
		if resp.ExtensionLength > 0 {
			sb.WriteString(fmt.Sprintf(" ExtLen: %d", resp.ExtensionLength))
		}
	} else {
		sb.WriteString(fmt.Sprintf("%s ", p.colorizeTimestamp()))
		sb.WriteString(id)
		sb.WriteString(colors.Magenta(fmt.Sprintf(" %s ", req.TypeDesc)).Bold())
		if req.Length > 0 {
			sb.WriteString(colors.BeigeBg(fmt.Sprintf(" Len: %d", req.Length)).String())
		}
		if req.ServerName != nil && req.ServerName.SNName != "" {
			sb.WriteString(colors.YellowBg(fmt.Sprintf(" SNI: %s", req.ServerName.SNName)).String())
		}
		if req.Version != nil && req.Version.Desc != "" {
			sb.WriteString(colors.GreenBg(fmt.Sprintf(" Ver: %s", req.Version.Desc)).String())
		}
		if req.ALPN != nil {
			sb.WriteString(colors.BlueBg(fmt.Sprintf(" ALPN: %v", req.ALPN)).String())
		}
		sb.WriteString(colors.MagentaBg(" -> ").String())
		sb.WriteString("\n")
		sb.WriteString(fmt.Sprintf("%s ", p.colorizeTimestamp()))
		sb.WriteString(id)
		sb.WriteString(colors.LightBlue(fmt.Sprintf(" %s ", resp.TypeDesc)).Bold())
		if resp.Length > 0 {
			sb.WriteString(colors.BeigeBg(fmt.Sprintf(" Len: %d", resp.Length)).String())
		}
		if resp.SessionID != "" {
			sb.WriteString(colors.Gray(fmt.Sprintf(" SID: %s", resp.SessionID)).String())
		}
		if resp.CipherSuite != nil && resp.CipherSuite.Desc != "" {
			sb.WriteString(colors.Yellow(fmt.Sprintf(" CS: %s", resp.CipherSuite.Desc)).Bold())
		}
		if resp.SupportedVersion != nil && resp.SupportedVersion.Desc != "" {
			sb.WriteString(colors.GreenBg(fmt.Sprintf(" Ver: %s", resp.SupportedVersion.Desc)).String())
		}
		if resp.ExtensionLength > 0 {
			sb.WriteString(colors.BeigeBg(fmt.Sprintf(" ExtLen: %d", resp.ExtensionLength)).String())
		}
	}
	return sb.String()
}

func (p *proxyapp) highlightPatterns(line string) (string, bool) {
	matched := false

	// TODO: make this configurable
	// line, matched = p.replace(line, ipPortPattern, colors.YellowBg, matched)
	// line, matched = p.replace(line, domainPattern, colors.YellowBg, matched)
	line, matched = p.replace(line, jwtPattern, colors.Magenta, matched)
	line, matched = p.replace(line, authPattern, colors.Magenta, matched)
	line, matched = p.replace(line, credsPattern, colors.GreenBg, matched)

	return line, matched
}

func (p *proxyapp) replace(line string, re *regexp.Regexp, color func(string) *colors.Color, matched bool) (string, bool) {
	if re.MatchString(line) {
		matched = true
		if !p.nocolor {
			line = re.ReplaceAllStringFunc(line, func(s string) string {
				return color(s).String()
			})
		}
	}
	return line, matched
}

func (p *proxyapp) colorizeBody(b *[]byte) string {
	matches := make([]string, 0, 3)
	scanner := bufio.NewScanner(bytes.NewReader(*b))
	for scanner.Scan() {
		line := scanner.Text()
		if highlighted, ok := p.highlightPatterns(line); ok {
			matches = append(matches, strings.Trim(highlighted, "\r\n\t "))
		}
	}
	return strings.Join(matches, "\n")
}

func (p *proxyapp) colorizeTimestamp() string {
	ts := time.Now()
	if p.nocolor {
		return colors.WrapBrackets(ts.Format(time.TimeOnly))
	}
	return colors.Gray(colors.WrapBrackets(ts.Format(time.TimeOnly))).String()
}

func (p *proxyapp) colorizeTunnel(req, resp layers.Layer, sniffheader *[]string, id string) error {
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
			*sniffheader = append(*sniffheader, string(j1), string(j2))
			if p.body && len(reqBodySaved) > 0 {
				*sniffheader = append(*sniffheader, fmt.Sprintf("{\"req_body\":%s}", reqBodySaved))
			}
			if p.body && len(respBodySaved) > 0 {
				*sniffheader = append(*sniffheader, fmt.Sprintf("{\"resp_body\":%s}", respBodySaved))
			}
		} else {
			*sniffheader = append(*sniffheader, p.colorizeHTTP(reqt.Request, rest.Response, &reqBodySaved, &respBodySaved, id, true))
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
				*sniffheader = append(*sniffheader, string(j1), string(j2))
			} else {
				*sniffheader = append(*sniffheader, p.colorizeTLS(chs, shs, id))
			}
		}
	}
	return nil
}

// https://stackoverflow.com/a/1094933/1333724
func prettifyBytes(b int64) string {
	bf := float64(b)
	for _, unit := range []string{"", "K", "M", "G", "T", "P", "E", "Z"} {
		if bf < 1000.0 {
			return fmt.Sprintf("%3.1f%sB", bf, unit)
		}
		bf /= 1000.0
	}
	return fmt.Sprintf("%.1fYB", bf)
}

func copyHeader(dst, src http.Header) {
	for k, vv := range src {
		for _, v := range vv {
			dst.Add(k, v)
		}
	}
}

func delHopHeaders(header http.Header) {
	for _, h := range hopHeaders {
		header.Del(h)
	}
}

// delConnectionHeaders removes hop-by-hop headers listed in the "Connection" header
// https://datatracker.ietf.org/doc/html/rfc7230#section-6.1
func delConnectionHeaders(h http.Header) {
	for _, f := range h["Connection"] {
		for sf := range strings.SplitSeq(f, ",") {
			if sf = strings.TrimSpace(sf); sf != "" {
				h.Del(sf)
			}
		}
	}
}

func appendHostToXForwardHeader(header http.Header, host string) {
	if prior, ok := header["X-Forwarded-For"]; ok {
		host = strings.Join(prior, ", ") + ", " + host
	}
	header.Set("X-Forwarded-For", host)
}

func isLocalAddress(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		host = addr
	}
	ip := net.ParseIP(host)
	if ip != nil {
		return ip.IsLoopback()
	}
	host = strings.ToLower(host)
	return strings.HasSuffix(host, ".local") || host == "localhost"
}

func (p *proxyapp) printProxyChain(pc []proxyEntry) string {
	var sb strings.Builder
	sb.WriteString("client -> ")
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
	sb.WriteString(" -> ")
	for _, pe := range pc {
		sb.WriteString(pe.String())
		sb.WriteString(" -> ")
	}
	sb.WriteString("target")
	return sb.String()
}

func (p *proxyapp) updateSocksList() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.availProxyList = p.availProxyList[:0]
	var base proxy.Dialer = getBaseDialer(timeout, p.mark)
	var dialer proxy.Dialer
	var err error
	failed := 0
	chainType := p.proxychain.Type
	var ctl string
	if p.nocolor {
		ctl = colors.WrapBrackets(chainType)
	} else {
		ctl = colors.WrapBrackets(colors.LightBlueBg(chainType).String())
	}
	for _, pr := range p.proxylist {
		auth := proxy.Auth{
			User:     pr.Username,
			Password: pr.Password,
		}
		dialer, err = proxy.SOCKS5("tcp", pr.Address, &auth, base)
		if err != nil {
			p.logger.Error().Err(err).Msgf("%s Unable to create SOCKS5 dialer %s", ctl, pr.Address)
			failed++
			continue
		}
		ctx, cancel := context.WithTimeout(context.Background(), hopTimeout)
		defer cancel()
		conn, err := dialer.(proxy.ContextDialer).DialContext(ctx, "tcp", pr.Address)
		if err != nil && !errors.Is(err, io.EOF) { // check for EOF to include localhost SOCKS5 in the chain
			p.logger.Error().Err(err).Msgf("%s Unable to connect to %s", ctl, pr.Address)
			failed++
			continue
		} else {
			if conn != nil {
				conn.Close()
			}
			p.availProxyList = append(p.availProxyList, proxyEntry{Address: pr.Address, Username: pr.Username, Password: pr.Password})
			break
		}
	}
	if failed == len(p.proxylist) {
		p.logger.Error().Err(err).Msgf("%s No SOCKS5 Proxy available", ctl)
		return
	}
	currentDialer := dialer
	for _, pr := range p.proxylist[failed+1:] {
		auth := proxy.Auth{
			User:     pr.Username,
			Password: pr.Password,
		}
		dialer, err = proxy.SOCKS5("tcp", pr.Address, &auth, currentDialer)
		if err != nil {
			p.logger.Error().Err(err).Msgf("%s Unable to create SOCKS5 dialer %s", ctl, pr.Address)
			continue
		}
		// https://github.com/golang/go/issues/37549#issuecomment-1178745487
		ctx, cancel := context.WithTimeout(context.Background(), hopTimeout)
		defer cancel()
		conn, err := dialer.(proxy.ContextDialer).DialContext(ctx, "tcp", pr.Address)
		if err != nil {
			p.logger.Error().Err(err).Msgf("%s Unable to connect to %s", ctl, pr.Address)
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

func (p *proxyapp) getSocks() (proxy.Dialer, *http.Client, error) {
	if p.proxylist == nil {
		return p.sockDialer, p.sockClient, nil
	}
	p.mu.RLock()
	defer p.mu.RUnlock()
	chainType := p.proxychain.Type
	var ctl string
	if p.nocolor {
		ctl = colors.WrapBrackets(chainType)
	} else {
		ctl = colors.WrapBrackets(colors.LightBlueBg(chainType).String())
	}
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
	var dialer proxy.Dialer = getBaseDialer(timeout, p.mark)
	var err error
	for _, pr := range copyProxyList {
		auth := proxy.Auth{
			User:     pr.Username,
			Password: pr.Password,
		}
		dialer, err = proxy.SOCKS5("tcp", pr.Address, &auth, dialer)
		if err != nil {
			p.logger.Error().Err(err).Msgf("%s Unable to create SOCKS5 dialer %s", ctl, pr.Address)
			return nil, nil, err
		}
	}
	socks := &http.Client{
		Transport: &http.Transport{
			Dial: dialer.Dial,
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
	if isLocalAddress(r.Host) {
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
			sniffheader := make([]string, 0, 4)
			j, err := json.Marshal(&layers.HTTPMessage{Request: r})
			if err == nil {
				sniffheader = append(sniffheader, string(j))
			}
			j, err = json.Marshal(&layers.HTTPMessage{Response: resp})
			if err == nil {
				sniffheader = append(sniffheader, string(j))
			}
			if p.body && len(reqBodySaved) > 0 {
				sniffheader = append(sniffheader, fmt.Sprintf("{\"req_body\":%s}", reqBodySaved))
			}
			if p.body && len(respBodySaved) > 0 {
				sniffheader = append(sniffheader, fmt.Sprintf("{\"resp_body\":%s}", respBodySaved))
			}
			p.snifflogger.Log().Msg(fmt.Sprintf("[%s]", strings.Join(sniffheader, ",")))
		} else {
			id := p.getID()
			p.snifflogger.Log().Msg(p.colorizeHTTP(req, resp, &reqBodySaved, &respBodySaved, id, false))
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
		status = p.colorizeStatus(resp.StatusCode, status, false)
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
	if isLocalAddress(r.Host) {
		dstConn, err = getBaseDialer(timeout, p.mark).Dial("tcp", r.Host)
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
		dstConn, err = sockDialer.(proxy.ContextDialer).DialContext(ctx, "tcp", r.Host)
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

	dstConnStr := fmt.Sprintf("%s->%s->%s", dstConn.LocalAddr().String(), dstConn.RemoteAddr().String(), r.Host)
	srcConnStr := fmt.Sprintf("%s->%s", srcConn.RemoteAddr().String(), srcConn.LocalAddr().String())

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
		sniffheader := make([]string, 0, 6)
		id := p.getID()
		if p.json {
			sniffheader = append(
				sniffheader,
				fmt.Sprintf("{\"connection\":{\"src_remote\":%s,\"src_local\":%s,\"dst_local\":%s,\"dst_remote\":%s}}",
					srcConn.RemoteAddr(), srcConn.LocalAddr(), dstConn.LocalAddr(), dstConn.RemoteAddr()),
			)
			j, err := json.Marshal(&layers.HTTPMessage{Request: r})
			if err == nil {
				sniffheader = append(sniffheader, string(j))
			}
		} else {
			var sb strings.Builder
			if p.nocolor {
				sb.WriteString(id)
				sb.WriteString(fmt.Sprintf(" Src: %s->%s -> Dst: %s->%s", srcConn.RemoteAddr(), srcConn.LocalAddr(), dstConn.LocalAddr(), dstConn.RemoteAddr()))
				sb.WriteString("\n")
				sb.WriteString(fmt.Sprintf("%s ", p.colorizeTimestamp()))
				sb.WriteString(id)
				sb.WriteString(fmt.Sprintf(" %s %s %s ", r.Method, r.Host, r.Proto))
			} else {
				sb.WriteString(id)
				sb.WriteString(colors.Green(fmt.Sprintf(" Src: %s->%s", srcConn.RemoteAddr(), srcConn.LocalAddr())).String())
				sb.WriteString(colors.Magenta(" -> ").String())
				sb.WriteString(colors.Blue(fmt.Sprintf("Dst: %s->%s", dstConn.LocalAddr(), dstConn.RemoteAddr())).String())
				sb.WriteString("\n")
				sb.WriteString(fmt.Sprintf("%s ", p.colorizeTimestamp()))
				sb.WriteString(id)
				sb.WriteString(colors.Gray(fmt.Sprintf(" %s ", r.Method)).String())
				sb.WriteString(colors.YellowBg(fmt.Sprintf("%s ", r.Host)).String())
				sb.WriteString(colors.BlueBg(fmt.Sprintf("%s ", r.Proto)).String())
			}
			sniffheader = append(sniffheader, sb.String())
		}
		go p.sniffreporter(&wg, &sniffheader, reqChan, respChan, id)
	}
	wg.Wait()
}

func (p *proxyapp) sniffreporter(wg *sync.WaitGroup, sniffheader *[]string, reqChan, respChan <-chan layers.Layer, id string) {
	defer wg.Done()
	sniffheaderlen := len(*sniffheader)
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

			err := p.colorizeTunnel(req, resp, sniffheader, id)
			if err == nil && len(*sniffheader) > sniffheaderlen {
				if p.json {
					p.snifflogger.Log().Msg(fmt.Sprintf("[%s]", strings.Join(*sniffheader, ",")))
				} else {
					p.snifflogger.Log().Msg(strings.Join(*sniffheader, "\n"))
				}
			}
			*sniffheader = (*sniffheader)[:sniffheaderlen]
		}
		if len(reqTLSQueue) > 0 && len(respTLSQueue) > 0 {
			req := reqTLSQueue[0]
			resp := respTLSQueue[0]
			reqTLSQueue = reqTLSQueue[1:]
			respTLSQueue = respTLSQueue[1:]

			err := p.colorizeTunnel(req, resp, sniffheader, id)
			if err == nil && len(*sniffheader) > sniffheaderlen {
				if p.json {
					p.snifflogger.Log().Msg(fmt.Sprintf("[%s]", strings.Join(*sniffheader, ",")))
				} else {
					p.snifflogger.Log().Msg(strings.Join(*sniffheader, "\n"))
				}
			}
			*sniffheader = (*sniffheader)[:sniffheaderlen]
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
				err = er
				break readLoop
			}
			nr, er := src.Read(buf)
			if nr > 0 {
				er := dst.SetWriteDeadline(time.Now().Add(writeTimeout))
				if er != nil {
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
						err = ne
						break readLoop
					}
				}
				if nr != nw {
					err = io.ErrShortWrite
					break readLoop
				}
			}
			if er != nil {
				if ne, ok := err.(net.Error); ok && ne.Timeout() {
					err = er
					break readLoop
				}
				if er == io.EOF {
					break readLoop
				}
			}
		}
	}
	return written, err
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
	p.logger.Debug().Msgf("copied %s from %s to %s", prettifyBytes(n), srcName, destName)
}

func parseProxyAuth(auth string) (username, password string, ok bool) {
	if auth == "" {
		return "", "", false
	}
	const prefix = "Basic "
	if len(auth) < len(prefix) || !strings.EqualFold(prefix, auth[:len(prefix)]) {
		return "", "", false
	}
	c, err := base64.StdEncoding.DecodeString(auth[len(prefix):])
	if err != nil {
		return "", "", false
	}
	cs := string(c)
	username, password, ok = strings.Cut(cs, ":")
	if !ok {
		return "", "", false
	}
	return username, password, true
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

func (p *proxyapp) handler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodConnect {
			p.handleTunnel(w, r)
		} else {
			p.handleForward(w, r)
		}
	}
}

func (p *proxyapp) applyRedirectRules() string {
	_, tproxyPort, _ := net.SplitHostPort(p.tproxyAddr)
	switch p.tproxyMode {
	case "redirect":
		cmdClear := exec.Command("bash", "-c", `
        set -ex
        iptables -t nat -D PREROUTING -p tcp -j GOHPTS 2>/dev/null || true
        iptables -t nat -D OUTPUT -p tcp -j GOHPTS 2>/dev/null || true
        iptables -t nat -F GOHPTS 2>/dev/null || true
        iptables -t nat -X GOHPTS 2>/dev/null || true
        `)
		cmdClear.Stdout = os.Stdout
		cmdClear.Stderr = os.Stderr
		if err := cmdClear.Run(); err != nil {
			p.logger.Fatal().Err(err).Msg("Failed while configuring iptables. Are you root?")
		}
		cmdInit := exec.Command("bash", "-c", `
        set -ex
        iptables -t nat -N GOHPTS 2>/dev/null
        iptables -t nat -F GOHPTS

        iptables -t nat -A GOHPTS -d 127.0.0.0/8 -j RETURN
        iptables -t nat -A GOHPTS -p tcp --dport 22 -j RETURN
        `)
		cmdInit.Stdout = os.Stdout
		cmdInit.Stderr = os.Stderr
		if err := cmdInit.Run(); err != nil {
			p.logger.Fatal().Err(err).Msg("Failed while configuring iptables. Are you root?")
		}
		if p.httpServerAddr != "" {
			_, httpPort, _ := net.SplitHostPort(p.httpServerAddr)
			cmdHTTP := exec.Command("bash", "-c", fmt.Sprintf(`
            set -ex
            iptables -t nat -A GOHPTS -p tcp --dport %s -j RETURN
            `, httpPort))
			cmdHTTP.Stdout = os.Stdout
			cmdHTTP.Stderr = os.Stderr
			if err := cmdHTTP.Run(); err != nil {
				p.logger.Fatal().Err(err).Msg("Failed while configuring iptables. Are you root?")
			}
		}
		if p.mark > 0 {
			cmdMark := exec.Command("bash", "-c", fmt.Sprintf(`
            set -ex
            iptables -t nat -A GOHPTS -p tcp -m mark --mark %d -j RETURN
            `, p.mark))
			cmdMark.Stdout = os.Stdout
			cmdMark.Stderr = os.Stderr
			if err := cmdMark.Run(); err != nil {
				p.logger.Fatal().Err(err).Msg("Failed while configuring iptables. Are you root?")
			}
		} else {
			cmd0 := exec.Command("bash", "-c", fmt.Sprintf(`
            set -ex
            iptables -t nat -A GOHPTS -p tcp --dport %s -j RETURN
            `, tproxyPort))
			cmd0.Stdout = os.Stdout
			cmd0.Stderr = os.Stderr
			if err := cmd0.Run(); err != nil {
				p.logger.Fatal().Err(err).Msg("Failed while configuring iptables. Are you root?")
			}
			if len(p.proxylist) > 0 {
				for _, pr := range p.proxylist {
					_, port, _ := net.SplitHostPort(pr.Address)
					cmd1 := exec.Command("bash", "-c", fmt.Sprintf(`
                    set -ex
                    iptables -t nat -A GOHPTS -p tcp --dport %s -j RETURN
                    `, port))
					cmd1.Stdout = os.Stdout
					cmd1.Stderr = os.Stderr
					if err := cmd1.Run(); err != nil {
						p.logger.Fatal().Err(err).Msg("Failed while configuring iptables. Are you root?")
					}
					if p.proxychain.Type == "strict" {
						break
					}
				}
			}
		}
		cmdDocker := exec.Command("bash", "-c", fmt.Sprintf(`
        set -ex
        if command -v docker >/dev/null 2>&1
        then
            for subnet in $(docker network inspect $(docker network ls -q) --format '{{range .IPAM.Config}}{{.Subnet}}{{end}}'); do
              iptables -t nat -A GOHPTS -d "$subnet" -j RETURN
            done
        fi

        iptables -t nat -A GOHPTS -p tcp -j REDIRECT --to-ports %s

        iptables -t nat -C PREROUTING -p tcp -j GOHPTS 2>/dev/null || \
        iptables -t nat -A PREROUTING -p tcp -j GOHPTS

        iptables -t nat -C OUTPUT -p tcp -j GOHPTS 2>/dev/null || \
        iptables -t nat -A OUTPUT -p tcp -j GOHPTS
        `, tproxyPort))
		cmdDocker.Stdout = os.Stdout
		cmdDocker.Stderr = os.Stderr
		if err := cmdDocker.Run(); err != nil {
			p.logger.Fatal().Err(err).Msg("Failed while configuring iptables. Are you root?")
		}
	case "tproxy":
		cmdClear := exec.Command("bash", "-c", `
        set -ex
        iptables -t mangle -D PREROUTING -p tcp -m socket -j DIVERT 2>/dev/null || true
        iptables -t mangle -D PREROUTING -p tcp -j GOHPTS 2>/dev/null || true
        iptables -t mangle -F DIVERT 2>/dev/null || true
        iptables -t mangle -F GOHPTS 2>/dev/null || true
        iptables -t mangle -X DIVERT 2>/dev/null || true
        iptables -t mangle -X GOHPTS 2>/dev/null || true

        ip rule del fwmark 1 lookup 100 2>/dev/null || true
        ip route flush table 100 || true
        `)
		cmdClear.Stdout = os.Stdout
		cmdClear.Stderr = os.Stderr
		if err := cmdClear.Run(); err != nil {
			p.logger.Fatal().Err(err).Msg("Failed while configuring iptables. Are you root?")
		}
		cmdInit0 := exec.Command("bash", "-c", `
        set -ex
        ip rule add fwmark 1 lookup 100 2>/dev/null || true
        ip route add local 0.0.0.0/0 dev lo table 100 2>/dev/null || true

        iptables -t mangle -N DIVERT 2>/dev/null || true
        iptables -t mangle -F DIVERT
        iptables -t mangle -A DIVERT -j MARK --set-mark 1
        iptables -t mangle -A DIVERT -j ACCEPT

        iptables -t mangle -N GOHPTS 2>/dev/null || true
        iptables -t mangle -F GOHPTS
        iptables -t mangle -A GOHPTS -d 127.0.0.0/8 -j RETURN
        iptables -t mangle -A GOHPTS -d 224.0.0.0/4 -j RETURN
        iptables -t mangle -A GOHPTS -d 255.255.255.255/32 -j RETURN
        `)
		cmdInit0.Stdout = os.Stdout
		cmdInit0.Stderr = os.Stderr
		if err := cmdInit0.Run(); err != nil {
			p.logger.Fatal().Err(err).Msg("Failed while configuring iptables. Are you root?")
		}
		cmdDocker := exec.Command("bash", "-c", `
        set -ex
        if command -v docker >/dev/null 2>&1
        then
            for subnet in $(docker network inspect $(docker network ls -q) --format '{{range .IPAM.Config}}{{.Subnet}}{{end}}'); do
              iptables -t mangle -A GOHPTS -d "$subnet" -j RETURN
            done
        fi`)
		cmdDocker.Stdout = os.Stdout
		cmdDocker.Stderr = os.Stderr
		if err := cmdDocker.Run(); err != nil {
			p.logger.Fatal().Err(err).Msg("Failed while configuring iptables. Are you root?")
		}
		cmdInit := exec.Command("bash", "-c", fmt.Sprintf(`
        set -ex
        iptables -t mangle -A GOHPTS -p tcp -m mark --mark %d -j RETURN
        iptables -t mangle -A GOHPTS -p tcp -j TPROXY --on-port %s --tproxy-mark 1

        iptables -t mangle -A PREROUTING -p tcp -m socket -j DIVERT
        iptables -t mangle -A PREROUTING -p tcp -j GOHPTS
        `, p.mark, tproxyPort))
		cmdInit.Stdout = os.Stdout
		cmdInit.Stderr = os.Stderr
		if err := cmdInit.Run(); err != nil {
			p.logger.Fatal().Err(err).Msg("Failed while configuring iptables. Are you root?")
		}
	default:
		p.logger.Fatal().Msgf("Unreachable, unknown mode: %s", p.tproxyMode)
	}
	cmdCat := exec.Command("bash", "-c", `
    cat /proc/sys/net/ipv4/ip_forward
    `)
	output, err := cmdCat.CombinedOutput()
	if err != nil {
		p.logger.Fatal().Err(err).Msg("Failed while configuring iptables. Are you root?")
	}
	cmdForward := exec.Command("bash", "-c", `
    set -ex
    sysctl -w net.ipv4.ip_forward=1
    `)
	cmdForward.Stdout = os.Stdout
	cmdForward.Stderr = os.Stderr
	_ = cmdForward.Run()
	if p.arp {
		cmdClear := exec.Command("bash", "-c", `
		set -ex
		iptables -t filter -F GOHPTS 2>/dev/null || true
		iptables -t filter -D FORWARD -j GOHPTS  2>/dev/null || true
		iptables -t filter -X GOHPTS  2>/dev/null || true
        `)
		cmdClear.Stdout = os.Stdout
		cmdClear.Stderr = os.Stderr
		if err := cmdClear.Run(); err != nil {
			p.logger.Fatal().Err(err).Msg("Failed while configuring iptables. Are you root?")
		}
		iface, err := getDefaultInterface()
		if err != nil {
			p.logger.Fatal().Err(err).Msg("failed getting default network interface")
		}
		cmdForward := exec.Command("bash", "-c", fmt.Sprintf(`
		set -ex
		iptables -t filter -N GOHPTS 2>/dev/null
		iptables -t filter -F GOHPTS
		iptables -t filter -A FORWARD -j GOHPTS
		iptables -t filter -A GOHPTS -i %s -j ACCEPT
		iptables -t filter -A GOHPTS -o %s -j ACCEPT
		`, iface.Name, iface.Name))
		cmdForward.Stdout = os.Stdout
		cmdForward.Stderr = os.Stderr
		if err := cmdForward.Run(); err != nil {
			p.logger.Fatal().Err(err).Msg("Failed while configuring iptables. Are you root?")
		}
	}
	return string(output)
}

func (p *proxyapp) clearRedirectRules(output string) error {
	if p.arp {
		cmdClear := exec.Command("bash", "-c", `
		set -ex
		iptables -t filter -F GOHPTS 2>/dev/null || true
		iptables -t filter -D FORWARD -j GOHPTS  2>/dev/null || true
		iptables -t filter -X GOHPTS  2>/dev/null || true
        `)
		cmdClear.Stdout = os.Stdout
		cmdClear.Stderr = os.Stderr
		if err := cmdClear.Run(); err != nil {
			p.logger.Fatal().Err(err).Msg("Failed while configuring iptables. Are you root?")
		}
	}
	var cmd *exec.Cmd
	switch p.tproxyMode {
	case "redirect":
		cmd = exec.Command("bash", "-c", fmt.Sprintf(`
        set -ex
        iptables -t nat -D PREROUTING -p tcp -j GOHPTS 2>/dev/null || true
        iptables -t nat -D OUTPUT -p tcp -j GOHPTS 2>/dev/null || true
        iptables -t nat -F GOHPTS 2>/dev/null || true
        iptables -t nat -X GOHPTS 2>/dev/null || true
        sysctl -w net.ipv4.ip_forward=%s
        `, output))
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
	case "tproxy":
		cmd = exec.Command("bash", "-c", fmt.Sprintf(`
        set -ex
        iptables -t mangle -D PREROUTING -p tcp -m socket -j DIVERT 2>/dev/null || true
        iptables -t mangle -D PREROUTING -p tcp -j GOHPTS 2>/dev/null || true
        iptables -t mangle -F DIVERT 2>/dev/null || true
        iptables -t mangle -F GOHPTS 2>/dev/null || true
        iptables -t mangle -X DIVERT 2>/dev/null || true
        iptables -t mangle -X GOHPTS 2>/dev/null || true

        ip rule del fwmark 1 lookup 100 2>/dev/null || true
        ip route flush table 100 || true
        sysctl -w net.ipv4.ip_forward=%s
        `, output))
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
	}
	return cmd.Run()
}

func (p *proxyapp) Run() {
	done := make(chan bool)
	quit := make(chan os.Signal, 1)
	p.closeConn = make(chan bool)
	signal.Notify(quit, os.Interrupt)
	var tproxyServer *tproxyServer
	if p.tproxyAddr != "" {
		tproxyServer = newTproxyServer(p)
	}
	var output string
	if p.auto {
		output = p.applyRedirectRules()
	}
	if p.proxylist != nil {
		chainType := p.proxychain.Type
		var ctl string
		if p.nocolor {
			ctl = colors.WrapBrackets(chainType)
		} else {
			ctl = colors.WrapBrackets(colors.LightBlueBg(chainType).String())
		}
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
			if p.auto {
				err := p.clearRedirectRules(output)
				if err != nil {
					p.logger.Error().Err(err).Msg("Failed clearing iptables rules")
				}
			}
			close(p.closeConn)
			if tproxyServer != nil {
				p.logger.Info().Msg("[tproxy] Server is shutting down...")
				tproxyServer.Shutdown()
			}
			p.logger.Info().Msg("Server is shutting down...")
			ctx, cancel := context.WithTimeout(context.Background(), timeout)

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
			if p.auto {
				err := p.clearRedirectRules(output)
				if err != nil {
					p.logger.Error().Err(err).Msg("Failed clearing iptables rules")
				}
			}
			close(p.closeConn)
			p.logger.Info().Msg("[tproxy] Server is shutting down...")
			tproxyServer.Shutdown()
			close(done)
		}()
		tproxyServer.ListenAndServe()
	}
	<-done
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
	Address  string `yaml:"address"`
	Username string `yaml:"username,omitempty"`
	Password string `yaml:"password,omitempty"`
	CertFile string `yaml:"cert_file,omitempty"`
	KeyFile  string `yaml:"key_file,omitempty"`
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

func getFullAddress(v string, all bool) (string, error) {
	if v == "" {
		return "", nil
	}
	ip := "127.0.0.1"
	if all {
		ip = "0.0.0.0"
	}
	if port, err := strconv.Atoi(v); err == nil {
		return fmt.Sprintf("%s:%d", ip, port), nil
	}
	host, port, err := net.SplitHostPort(v)
	if err != nil {
		return "", err
	}
	if host != "" && port == "" {
		return "", fmt.Errorf("port is missing")
	}
	if host != "" && port != "" {
		return v, nil
	} else if port != "" {
		return fmt.Sprintf("%s:%s", ip, port), nil
	}
	return "", fmt.Errorf("failed parsing address")
}

func expandPath(p string) string {
	p = os.ExpandEnv(p)
	if strings.HasPrefix(p, "~") {
		if home, err := os.UserHomeDir(); err == nil {
			return strings.Replace(p, "~", home, 1)
		}
	}
	return p
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
			if p.nocolor {
				return colors.WrapBrackets(ts.Format(time.TimeOnly))
			}
			return colors.Gray(colors.WrapBrackets(ts.Format(time.TimeOnly))).String()
		}
		output.FormatMessage = func(i any) string {
			if i == nil || i == "" {
				return ""
			}
			s := i.(string)
			if p.nocolor {
				return s
			}
			result := ipPortPattern.ReplaceAllStringFunc(s, func(match string) string {
				return colors.Gray(match).String()
			})
			result = domainPattern.ReplaceAllStringFunc(result, func(match string) string {
				return colors.Yellow(match).String()
			})
			return result
		}

		output.FormatErrFieldName = func(i any) string {
			return fmt.Sprintf("%s", i)
		}

		output.FormatErrFieldValue = func(i any) string {
			s := i.(string)
			if p.nocolor {
				return s
			}
			result := ipPortPattern.ReplaceAllStringFunc(s, func(match string) string {
				return colors.Red(match).String()
			})
			result = domainPattern.ReplaceAllStringFunc(result, func(match string) string {
				return colors.Red(match).String()
			})
			return result
		}
		logger = zerolog.New(output).With().Timestamp().Logger()
		sniffoutput := zerolog.ConsoleWriter{Out: snifflog, TimeFormat: time.RFC3339, NoColor: p.nocolor, PartsExclude: []string{"level"}}
		sniffoutput.FormatTimestamp = func(i any) string {
			ts, _ := time.Parse(time.RFC3339, i.(string))
			if p.nocolor {
				return colors.WrapBrackets(ts.Format(time.TimeOnly))
			}
			return colors.Gray(colors.WrapBrackets(ts.Format(time.TimeOnly))).String()
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
			s := i.(string)
			if p.nocolor {
				return s
			}
			result := ipPortPattern.ReplaceAllStringFunc(s, func(match string) string {
				return colors.Red(match).String()
			})
			result = domainPattern.ReplaceAllStringFunc(result, func(match string) string {
				return colors.Red(match).String()
			})
			return result
		}
		snifflogger = zerolog.New(sniffoutput).With().Timestamp().Logger()
	}
	zerolog.SetGlobalLevel(zerolog.InfoLevel)
	if conf.Debug {
		zerolog.SetGlobalLevel(zerolog.DebugLevel)
	}
	p.logger = &logger
	p.snifflogger = &snifflogger
	if runtime.GOOS == "linux" && conf.TProxy != "" && conf.TProxyOnly != "" {
		p.logger.Fatal().Msg("Cannot specify TPRoxy and TProxyOnly at the same time")
	} else if runtime.GOOS == "linux" && conf.TProxyMode != "" && !slices.Contains(SupportedTProxyModes, conf.TProxyMode) {
		p.logger.Fatal().Msg("Incorrect TProxyMode provided")
	} else if runtime.GOOS != "linux" && (conf.TProxy != "" || conf.TProxyOnly != "" || conf.TProxyMode != "") {
		conf.TProxy = ""
		conf.TProxyOnly = ""
		conf.TProxyMode = ""
		p.logger.Warn().Msg("[tproxy] functionality only available on linux system")
	}
	p.tproxyMode = conf.TProxyMode
	tproxyonly := conf.TProxyOnly != ""
	if tproxyonly {
		if p.tproxyMode != "" {
			p.tproxyAddr, err = getFullAddress(conf.TProxyOnly, true)
			if err != nil {
				p.logger.Fatal().Err(err).Msg("")
			}
		} else {
			p.tproxyAddr, err = getFullAddress(conf.TProxyOnly, false)
			if err != nil {
				p.logger.Fatal().Err(err).Msg("")
			}
		}
	} else {
		if p.tproxyMode != "" {
			p.tproxyAddr, err = getFullAddress(conf.TProxy, true)
			if err != nil {
				p.logger.Fatal().Err(err).Msg("")
			}
		} else {
			p.tproxyAddr, err = getFullAddress(conf.TProxy, false)
			if err != nil {
				p.logger.Fatal().Err(err).Msg("")
			}
		}
	}
	p.auto = conf.Auto
	if p.auto && runtime.GOOS != "linux" {
		p.logger.Fatal().Msg("Auto setup is available only for linux system")
	}
	p.mark = conf.Mark
	if p.mark > 0 && runtime.GOOS != "linux" {
		p.logger.Fatal().Msg("SO_MARK is available only for linux system")
	}
	if p.mark > 0xFFFFFFFF {
		p.logger.Fatal().Msg("SO_MARK is out of range")
	}
	if p.mark == 0 && p.tproxyMode == "tproxy" {
		p.mark = 100
	}
	p.arp = conf.ARP
	if p.arp && runtime.GOOS != "linux" {
		p.logger.Fatal().Msg("ARP setup is available only for linux system")
	} else if p.arp && !p.auto {
		p.logger.Fatal().Msg("ARP setup requires auto configuration")
	}
	var addrHTTP, addrSOCKS, certFile, keyFile string
	if conf.ServerConfPath != "" {
		var sconf serverConfig
		yamlFile, err := os.ReadFile(expandPath(conf.ServerConfPath))
		if err != nil {
			p.logger.Fatal().Err(err).Msg("[server config] Parsing failed")
		}
		err = yaml.Unmarshal(yamlFile, &sconf)
		if err != nil {
			p.logger.Fatal().Err(err).Msg("[server config] Parsing failed")
		}
		if !tproxyonly {
			if sconf.Server.Address == "" {
				p.logger.Fatal().Err(err).Msg("[server config] Server address is empty")
			}
			addrHTTP, err = getFullAddress(sconf.Server.Address, false)
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
			p.logger.Fatal().Msg("[server config] Proxy list is empty")
		}
		seen := make(map[string]struct{})
		for idx, pr := range p.proxylist {
			addr, err := getFullAddress(pr.Address, false)
			if err != nil {
				p.logger.Fatal().Err(err).Msg("")
			}
			if _, ok := seen[addr]; !ok {
				seen[addr] = struct{}{}
				p.proxylist[idx].Address = addr
			} else {
				p.logger.Fatal().Msgf("[server config] Duplicate entry `%s`", addr)
			}
		}
		addrSOCKS = p.printProxyChain(p.proxylist)
		chainType := p.proxychain.Type
		if !slices.Contains(supportedChainTypes, chainType) {
			p.logger.Fatal().Msgf("[server config] Chain type `%s` is not supported", chainType)
		}
		p.rrIndexReset = rrIndexMax
	} else {
		if !tproxyonly {
			addrHTTP, err = getFullAddress(conf.AddrHTTP, false)
			if err != nil {
				p.logger.Fatal().Err(err).Msg("")
			}
			p.httpServerAddr = addrHTTP
			certFile = expandPath(conf.CertFile)
			keyFile = expandPath(conf.KeyFile)
			p.user = conf.ServerUser
			p.pass = conf.ServerPass
		}
		addrSOCKS, err = getFullAddress(conf.AddrSOCKS, false)
		if err != nil {
			p.logger.Fatal().Err(err).Msg("")
		}
		auth := proxy.Auth{
			User:     conf.User,
			Password: conf.Pass,
		}
		dialer, err := proxy.SOCKS5("tcp", addrSOCKS, &auth, getBaseDialer(timeout, p.mark))
		if err != nil {
			p.logger.Fatal().Err(err).Msg("Unable to create SOCKS5 dialer")
		}
		p.sockDialer = dialer
		if !tproxyonly {
			p.sockClient = &http.Client{
				Transport: &http.Transport{
					Dial: dialer.Dial,
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
	return &p
}
