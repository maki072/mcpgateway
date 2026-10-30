package main

import (
	"context"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"syscall"
	"time"
)

// Network tools (HTTP, TCP, UDP, DNS). Every connection goes through a dialer whose Control hook
// validates the final resolved IP, so redirects and DNS tricks cannot reach forbidden addresses:
//   - addresses inside net_allow_cidrs: any port;
//   - public addresses: only TCP 80/443 (HTTP tool);
//   - never: loopback, link-local, multicast, unspecified, or an address of this gateway.

const (
	netMaxBody    = 256 << 10
	netDefBody    = 8 << 10
	netMaxTimeout = 60
)

func (a *App) selfIPs() map[string]bool {
	m := map[string]bool{}
	ifs, _ := net.InterfaceAddrs()
	for _, ia := range ifs {
		if n, ok := ia.(*net.IPNet); ok {
			m[n.IP.String()] = true
		}
	}
	return m
}

func isPublic(ip net.IP) bool {
	return ip.IsGlobalUnicast() && !ip.IsPrivate() && !ip.IsLoopback() && !ip.IsLinkLocalUnicast()
}

// checkDest decides whether the gateway may connect to ip:port over network ("tcp"/"udp").
func (a *App) checkDest(network string, ip net.IP, port int) error {
	switch {
	case ip == nil || ip.IsUnspecified() || ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsMulticast():
		return fmt.Errorf("destination %v is not allowed", ip)
	case a.selfIPs()[ip.String()]:
		return errors.New("connecting to the gateway itself is not allowed")
	case inNets(ip, a.netNets):
		return nil
	case isPublic(ip) && strings.HasPrefix(network, "tcp") && (port == 80 || port == 443):
		return nil
	}
	return fmt.Errorf("destination %v:%d is outside net_allow_cidrs (public addresses: tcp 80/443 only)", ip, port)
}

func (a *App) dialer(timeout time.Duration) *net.Dialer {
	return &net.Dialer{
		Timeout: timeout,
		Control: func(network, address string, _ syscall.RawConn) error {
			h, p, err := net.SplitHostPort(address)
			if err != nil {
				return err
			}
			port := 0
			fmt.Sscanf(p, "%d", &port)
			return a.checkDest(network, net.ParseIP(h), port)
		},
	}
}

func clampTimeout(t int) time.Duration {
	if t <= 0 {
		t = 10
	}
	if t > netMaxTimeout {
		t = netMaxTimeout
	}
	return time.Duration(t) * time.Second
}

func validHost(h string) bool {
	if h == "" || len(h) > 253 || strings.ContainsAny(h, " /\\@?#\x00") {
		return false
	}
	return true
}

// render returns text, or a hex dump summary when the data is not valid text.
func render(b []byte) string {
	if len(b) == 0 {
		return "(empty)"
	}
	if strings.IndexByte(string(b), 0) < 0 && strings.ToValidUTF8(string(b), "") == string(b) {
		return string(b)
	}
	if len(b) > 512 {
		return fmt.Sprintf("[binary, %d bytes; first 512 as hex]\n%s", len(b), hex.EncodeToString(b[:512]))
	}
	return "[binary]\n" + hex.EncodeToString(b)
}

func needWrite(mode, reason, backup string) (bool, error) {
	if mode != "" && mode != "read" && mode != "write" {
		return false, errors.New(`mode must be "read" or "write"`)
	}
	if mode == "write" {
		return true, checkWrite(reason, backup)
	}
	return false, nil
}

// ---- HTTP ----

type httpArgs struct {
	URL             string            `json:"url"`
	Method          string            `json:"method"`
	Headers         map[string]string `json:"headers"`
	Body            string            `json:"body"`
	TimeoutSec      int               `json:"timeout_sec"`
	MaxBytes        int               `json:"max_bytes"`
	FollowRedirects bool              `json:"follow_redirects"`
	InsecureTLS     bool              `json:"insecure_tls"`
	Mode            string            `json:"mode"`
	Reason          string            `json:"reason"`
	BackupNote      string            `json:"backup_note"`
}

func (a *App) netHTTP(ctx context.Context, x httpArgs) (string, error) {
	u, err := url.Parse(x.URL)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || !validHost(u.Hostname()) || u.User != nil {
		return "", errors.New("url must be http(s)://host[:port]/path without credentials")
	}
	m := strings.ToUpper(x.Method)
	if m == "" {
		m = "GET"
	}
	safe := m == "GET" || m == "HEAD" || m == "OPTIONS"
	if !map[string]bool{"GET": true, "HEAD": true, "OPTIONS": true, "POST": true, "PUT": true, "PATCH": true, "DELETE": true}[m] {
		return "", errors.New("unsupported method")
	}
	write, err := needWrite(x.Mode, x.Reason, x.BackupNote)
	if err != nil {
		return "", err
	}
	if !safe && !write {
		return "", errors.New(m + " can change state: repeat with mode=write, reason and backup_note")
	}
	if len(x.Body) > 1<<20 {
		return "", errors.New("body too large")
	}
	max := x.MaxBytes
	if max <= 0 {
		max = netDefBody
	}
	if max > netMaxBody {
		max = netMaxBody
	}
	to := clampTimeout(x.TimeoutSec)
	tr := &http.Transport{
		DialContext:           a.dialer(to).DialContext,
		TLSClientConfig:       &tls.Config{InsecureSkipVerify: x.InsecureTLS, MinVersion: tls.VersionTLS12}, //nolint:gosec // opt-in for LAN devices with self-signed certificates
		TLSHandshakeTimeout:   to,
		ResponseHeaderTimeout: to,
		DisableKeepAlives:     true,
		Proxy:                 nil,
	}
	cl := &http.Client{Transport: tr, Timeout: to}
	hops := 0
	cl.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		hops++
		if !x.FollowRedirects || hops > 5 {
			return http.ErrUseLastResponse
		}
		return nil
	}
	var body io.Reader
	if x.Body != "" {
		body = strings.NewReader(x.Body)
	}
	req, err := http.NewRequestWithContext(ctx, m, u.String(), body)
	if err != nil {
		return "", err
	}
	req.Header.Set("User-Agent", "mcpgw/"+version)
	for k, v := range x.Headers {
		if strings.EqualFold(k, "host") || strings.ContainsAny(k+v, "\r\n") {
			return "", errors.New("invalid header")
		}
		req.Header.Set(k, v)
	}
	start := time.Now()
	resp, err := cl.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, int64(max)+1))
	trunc := len(data) > max
	if trunc {
		data = data[:max]
	}
	var sb strings.Builder
	fmt.Fprintf(&sb, "%s %s\nstatus: %s (%d ms)\n", m, u.Redacted(), resp.Status, time.Since(start).Milliseconds())
	var hk []string
	for k := range resp.Header {
		hk = append(hk, k)
	}
	sort.Strings(hk)
	for _, k := range hk {
		if strings.EqualFold(k, "Set-Cookie") {
			fmt.Fprintf(&sb, "%s: [%d cookie(s) hidden]\n", k, len(resp.Header[k]))
			continue
		}
		fmt.Fprintf(&sb, "%s: %s\n", k, clip(strings.Join(resp.Header[k], ", "), 300))
	}
	sb.WriteString("\n" + render(data))
	if trunc {
		fmt.Fprintf(&sb, "\n[body truncated at %d bytes]", max)
	}
	return sb.String(), nil
}

// ---- TCP / UDP ----

type tcpArgs struct {
	Host       string `json:"host"`
	Port       int    `json:"port"`
	Ports      []int  `json:"ports"`
	Send       string `json:"send"`
	SendHex    string `json:"send_hex"`
	ReadBytes  int    `json:"read_bytes"`
	TimeoutSec int    `json:"timeout_sec"`
	Mode       string `json:"mode"`
	Reason     string `json:"reason"`
	BackupNote string `json:"backup_note"`
}

func payload(s, h string) ([]byte, error) {
	if h != "" {
		b, err := hex.DecodeString(strings.ReplaceAll(h, " ", ""))
		if err != nil {
			return nil, errors.New("send_hex is not valid hex")
		}
		return b, nil
	}
	return []byte(s), nil
}

func (a *App) netTCP(ctx context.Context, x tcpArgs) (string, error) {
	write, err := needWrite(x.Mode, x.Reason, x.BackupNote)
	if err != nil {
		return "", err
	}
	data, err := payload(x.Send, x.SendHex)
	if err != nil {
		return "", err
	}
	if len(data) > 64<<10 {
		return "", errors.New("payload too large (64 KiB max)")
	}
	if len(data) > 0 && !write {
		return "", errors.New("sending data can change state: repeat with mode=write, reason and backup_note (connect-only checks need no mode)")
	}
	if !validHost(x.Host) {
		return "", errors.New("invalid host")
	}
	ports := x.Ports
	if len(ports) == 0 {
		ports = []int{x.Port}
	}
	if len(ports) > 50 || (len(ports) > 1 && len(data) > 0) {
		return "", errors.New("at most 50 ports, and no payload when checking several ports")
	}
	to := clampTimeout(x.TimeoutSec)
	var sb strings.Builder
	for _, p := range ports {
		if p < 1 || p > 65535 {
			return "", errors.New("port must be 1-65535")
		}
		start := time.Now()
		addr := net.JoinHostPort(x.Host, fmt.Sprint(p))
		c, err := a.dialer(to).DialContext(ctx, "tcp", addr)
		if err != nil {
			fmt.Fprintf(&sb, "%s: closed/unreachable (%v)\n", addr, shortErr(err))
			continue
		}
		fmt.Fprintf(&sb, "%s: open (connect %d ms)", addr, time.Since(start).Milliseconds())
		if len(ports) == 1 {
			_ = c.SetDeadline(time.Now().Add(to))
			if len(data) > 0 {
				if _, err := c.Write(data); err != nil {
					c.Close()
					return sb.String() + "\nwrite failed: " + err.Error(), nil
				}
			}
			n := x.ReadBytes
			if n <= 0 {
				n = 4096
			}
			if n > netMaxBody {
				n = netMaxBody
			}
			_ = c.SetReadDeadline(time.Now().Add(minDur(to, 3*time.Second)))
			buf, _ := io.ReadAll(io.LimitReader(c, int64(n)))
			fmt.Fprintf(&sb, "\nreceived %d bytes:\n%s", len(buf), render(buf))
		}
		c.Close()
		sb.WriteString("\n")
	}
	return sb.String(), nil
}

func minDur(a, b time.Duration) time.Duration {
	if a < b {
		return a
	}
	return b
}

func shortErr(err error) string {
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return "timeout"
	}
	s := err.Error()
	for _, marker := range []string{"destination ", "connecting to the gateway"} {
		if i := strings.Index(s, marker); i >= 0 {
			return s[i:] // policy denial: keep the full reason
		}
	}
	if i := strings.LastIndex(s, ": "); i >= 0 {
		s = s[i+2:]
	}
	return s
}

type udpArgs struct {
	Host       string `json:"host"`
	Port       int    `json:"port"`
	Send       string `json:"send"`
	SendHex    string `json:"send_hex"`
	TimeoutSec int    `json:"timeout_sec"`
	Mode       string `json:"mode"`
	Reason     string `json:"reason"`
	BackupNote string `json:"backup_note"`
}

func (a *App) netUDP(ctx context.Context, x udpArgs) (string, error) {
	write, err := needWrite(x.Mode, x.Reason, x.BackupNote)
	if err != nil {
		return "", err
	}
	if !write {
		return "", errors.New("UDP sends a datagram (it can change state): use mode=write, reason and backup_note")
	}
	data, err := payload(x.Send, x.SendHex)
	if err != nil || len(data) == 0 || len(data) > 8192 {
		return "", errors.New("payload required (send or send_hex), max 8192 bytes")
	}
	if x.Port < 1 || x.Port > 65535 || !validHost(x.Host) {
		return "", errors.New("invalid host or port")
	}
	to := clampTimeout(x.TimeoutSec)
	c, err := a.dialer(to).DialContext(ctx, "udp", net.JoinHostPort(x.Host, fmt.Sprint(x.Port)))
	if err != nil {
		return "", err
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(to))
	if _, err := c.Write(data); err != nil {
		return "", err
	}
	buf := make([]byte, 8192)
	n, err := c.Read(buf)
	if err != nil {
		return fmt.Sprintf("sent %d bytes to %s; no reply within %s (%s)", len(data), c.RemoteAddr(), to, shortErr(err)), nil
	}
	return fmt.Sprintf("sent %d bytes to %s; reply %d bytes:\n%s", len(data), c.RemoteAddr(), n, render(buf[:n])), nil
}

func (a *App) netDNS(ctx context.Context, name, typ string) (string, error) {
	if !validHost(name) {
		return "", errors.New("invalid name")
	}
	r := net.DefaultResolver
	var out []string
	switch strings.ToUpper(typ) {
	case "", "A", "AAAA":
		ips, err := r.LookupIPAddr(ctx, name)
		if err != nil {
			return "", err
		}
		for _, ip := range ips {
			out = append(out, ip.IP.String())
		}
	case "TXT":
		v, err := r.LookupTXT(ctx, name)
		if err != nil {
			return "", err
		}
		out = v
	case "MX":
		v, err := r.LookupMX(ctx, name)
		if err != nil {
			return "", err
		}
		for _, m := range v {
			out = append(out, fmt.Sprintf("%d %s", m.Pref, m.Host))
		}
	case "CNAME":
		v, err := r.LookupCNAME(ctx, name)
		if err != nil {
			return "", err
		}
		out = []string{v}
	case "NS":
		v, err := r.LookupNS(ctx, name)
		if err != nil {
			return "", err
		}
		for _, n := range v {
			out = append(out, n.Host)
		}
	case "PTR":
		v, err := r.LookupAddr(ctx, name)
		if err != nil {
			return "", err
		}
		out = v
	default:
		return "", errors.New("type must be A, AAAA, TXT, MX, CNAME, NS or PTR")
	}
	if len(out) == 0 {
		return "no records", nil
	}
	return strings.Join(out, "\n"), nil
}

func netTools() []tool {
	wr := map[string]any{
		"mode":        map[string]any{"type": "string", "enum": []string{"read", "write"}, "description": "write is required for anything that can change state"},
		"reason":      prop("string", "write mode: why"),
		"backup_note": prop("string", "write mode: backup/rollback in place"),
	}
	with := func(m map[string]any) map[string]any {
		for k, v := range wr {
			m[k] = v
		}
		return m
	}
	return []tool{
		{Name: "net_http", Destructive: true,
			Description: "HTTP(S) request from the gateway to allowed LAN hosts (net_allow_cidrs) or public sites. GET/HEAD/OPTIONS need no mode; POST/PUT/PATCH/DELETE need mode=write with reason and backup_note. Redirects are not followed unless follow_redirects. insecure_tls skips certificate checks (self-signed LAN devices). Body is capped (default 64 KiB, max 256 KiB).",
			Schema: obj(with(map[string]any{
				"url": prop("string", "http(s)://host[:port]/path"), "method": prop("string", "GET (default), HEAD, OPTIONS, POST, PUT, PATCH, DELETE"),
				"headers": map[string]any{"type": "object", "additionalProperties": map[string]any{"type": "string"}}, "body": prop("string", "request body, max 1 MiB"),
				"timeout_sec": prop("integer", "1-60"), "max_bytes": prop("integer", "response bytes to return, max 262144"),
				"follow_redirects": prop("boolean", "follow up to 5 redirects"), "insecure_tls": prop("boolean", "skip TLS verification")}), "url"),
			Run: func(ctx context.Context, a *App, raw json.RawMessage) (string, map[string]any, error) {
				var x httpArgs
				if err := decode(raw, &x); err != nil {
					return "", nil, err
				}
				lf := map[string]any{"url": clip(x.URL, 200), "method": x.Method, "mode": x.Mode, "reason": x.Reason, "backup_note": x.BackupNote, "insecure_tls": x.InsecureTLS}
				s, err := a.netHTTP(ctx, x)
				return s, lf, err
			}},
		{Name: "net_tcp", Destructive: true,
			Description: "TCP from the gateway to allowed hosts. Connect-only (no payload): reports open/closed and the banner; 'ports' checks up to 50 ports. Sending a payload (send/send_hex) needs mode=write with reason and backup_note. Reads up to read_bytes (default 4096) for a few seconds.",
			Schema: obj(with(map[string]any{"host": prop("string", "IP or name"), "port": prop("integer", "1-65535"),
				"ports": map[string]any{"type": "array", "items": map[string]any{"type": "integer"}, "description": "check several ports (connect only)"},
				"send":  prop("string", "text payload"), "send_hex": prop("string", "binary payload as hex"),
				"read_bytes": prop("integer", "max bytes to read, up to 262144"), "timeout_sec": prop("integer", "1-60")}), "host"),
			Run: func(ctx context.Context, a *App, raw json.RawMessage) (string, map[string]any, error) {
				var x tcpArgs
				if err := decode(raw, &x); err != nil {
					return "", nil, err
				}
				lf := map[string]any{"host": x.Host, "port": x.Port, "ports": len(x.Ports), "payload_bytes": len(x.Send) + len(x.SendHex)/2, "mode": x.Mode, "reason": x.Reason, "backup_note": x.BackupNote}
				s, err := a.netTCP(ctx, x)
				return s, lf, err
			}},
		{Name: "net_udp", Destructive: true,
			Description: "Send one UDP datagram to an allowed host and wait for a reply (e.g. DNS/SNMP/NTP/syslog tests). Always mode=write with reason and backup_note.",
			Schema: obj(with(map[string]any{"host": prop("string", "IP or name"), "port": prop("integer", "1-65535"),
				"send": prop("string", "text payload"), "send_hex": prop("string", "binary payload as hex"), "timeout_sec": prop("integer", "1-60")}), "host", "port", "mode", "reason", "backup_note"),
			Run: func(ctx context.Context, a *App, raw json.RawMessage) (string, map[string]any, error) {
				var x udpArgs
				if err := decode(raw, &x); err != nil {
					return "", nil, err
				}
				lf := map[string]any{"host": x.Host, "port": x.Port, "payload_bytes": len(x.Send) + len(x.SendHex)/2, "mode": x.Mode, "reason": x.Reason, "backup_note": x.BackupNote}
				s, err := a.netUDP(ctx, x)
				return s, lf, err
			}},
		{Name: "net_dns", ReadOnly: true,
			Description: "Resolve a name with the gateway's resolver (A/AAAA/TXT/MX/CNAME/NS/PTR). Useful to compare split-DNS answers.",
			Schema:      obj(map[string]any{"name": prop("string", "host name, or IP for PTR"), "type": prop("string", "record type, default A")}, "name"),
			Run: func(ctx context.Context, a *App, raw json.RawMessage) (string, map[string]any, error) {
				var x struct{ Name, Type string }
				if err := decode(raw, &x); err != nil {
					return "", nil, err
				}
				c, cancel := context.WithTimeout(ctx, 10*time.Second)
				defer cancel()
				s, err := a.netDNS(c, x.Name, x.Type)
				return s, map[string]any{"name": x.Name, "type": x.Type}, err
			}},
	}
}
