package scanner

import (
	"context"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

func Scan(ctx context.Context, target string, opt Options) (Report, error) {
	if opt.Port == 0 {
		opt.Port = 443
	}
	if opt.Timeout == 0 {
		opt.Timeout = 5 * time.Second
	}
	if opt.Port < 1 || opt.Port > 65535 {
		return Report{}, fmt.Errorf("port must be between 1 and 65535")
	}
	if opt.Timeout <= 0 || opt.Timeout > time.Minute {
		return Report{}, fmt.Errorf("timeout must be between 1ns and 1m")
	}
	ctx, cancel := context.WithTimeout(ctx, opt.Timeout*8)
	defer cancel()
	host, err := cleanHost(target)
	if err != nil {
		return Report{}, err
	}
	addr := net.JoinHostPort(host, strconv.Itoa(opt.Port))
	cfg := &tls.Config{ServerName: serverName(host), InsecureSkipVerify: true, MinVersion: tls.VersionTLS10} // inspection intentionally accepts invalid certificates
	conn, err := dialContext(ctx, addr, cfg, opt.Timeout)
	if err != nil {
		return Report{}, fmt.Errorf("connect to %s: %w", addr, err)
	}
	defer conn.Close()
	state := conn.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		return Report{}, fmt.Errorf("%s did not present a certificate", host)
	}
	scannedAt := time.Now().UTC()
	r := Report{Host: host, Port: opt.Port, ScannedAt: scannedAt, Certificate: certificate(state.PeerCertificates[0], scannedAt), CipherSuite: tls.CipherSuiteName(state.CipherSuite), PresentedCertificates: len(state.PeerCertificates)}
	r.Certificate.Verified, r.Certificate.VerificationError = verifyCertificate(state.PeerCertificates, host)
	for _, probe := range []struct {
		v    uint16
		name string
	}{{tls.VersionTLS10, "1.0"}, {tls.VersionTLS11, "1.1"}, {tls.VersionTLS12, "1.2"}, {tls.VersionTLS13, "1.3"}} {
		if supportsVersion(ctx, addr, host, probe.v, opt.Timeout) {
			r.TLSVersions = append(r.TLSVersions, probe.name)
		}
	}
	r.WeakCiphers = probeWeakCiphers(ctx, addr, host, opt.Timeout)
	r.Headers = fetchHeaders(ctx, host, opt.Port, opt.Timeout)
	Score(&r, r.ScannedAt)
	return r, nil
}
func dialContext(ctx context.Context, addr string, cfg *tls.Config, timeout time.Duration) (*tls.Conn, error) {
	d := &tls.Dialer{NetDialer: &net.Dialer{Timeout: timeout}, Config: cfg}
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}
	return conn.(*tls.Conn), nil
}
func cleanHost(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if !strings.Contains(raw, "://") {
		raw = "https://" + raw
	}
	u, err := url.Parse(raw)
	if err != nil || u.Hostname() == "" {
		return "", fmt.Errorf("invalid host %q", raw)
	}
	return u.Hostname(), nil
}
func serverName(host string) string {
	if net.ParseIP(host) != nil {
		return ""
	}
	return host
}
func certificate(c *x509.Certificate, now time.Time) Certificate {
	r := Certificate{Subject: c.Subject.CommonName, Issuer: c.Issuer.CommonName, NotBefore: c.NotBefore, NotAfter: c.NotAfter, ExpiresInDays: int(c.NotAfter.Sub(now).Hours() / 24), SignatureAlgorithm: c.SignatureAlgorithm.String(), DNSNames: c.DNSNames}
	switch key := c.PublicKey.(type) {
	case *rsa.PublicKey:
		r.KeyType = "RSA"
		r.KeyBits = key.N.BitLen()
	case *ecdsa.PublicKey:
		r.KeyType = "ECDSA"
		r.KeyBits = key.Params().BitSize
	default:
		r.KeyType = fmt.Sprintf("%T", key)
	}
	return r
}
func verifyCertificate(peer []*x509.Certificate, host string) (bool, string) {
	if len(peer) == 0 {
		return false, "server presented no certificates"
	}
	intermediates := x509.NewCertPool()
	for _, cert := range peer[1:] {
		intermediates.AddCert(cert)
	}
	_, err := peer[0].Verify(x509.VerifyOptions{DNSName: host, Intermediates: intermediates})
	if err != nil {
		return false, err.Error()
	}
	return true, ""
}
func supportsVersion(ctx context.Context, addr, host string, version uint16, timeout time.Duration) bool {
	c, err := dialContext(ctx, addr, &tls.Config{ServerName: serverName(host), InsecureSkipVerify: true, MinVersion: version, MaxVersion: version}, timeout)
	if err == nil {
		c.Close()
		return true
	}
	return false
}
func probeWeakCiphers(ctx context.Context, addr, host string, timeout time.Duration) []string {
	probes := []struct {
		id   uint16
		name string
	}{{tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA, "TLS_RSA_WITH_3DES_EDE_CBC_SHA"}, {tls.TLS_RSA_WITH_RC4_128_SHA, "TLS_RSA_WITH_RC4_128_SHA"}}
	var got []string
	for _, p := range probes {
		c, err := dialContext(ctx, addr, &tls.Config{ServerName: serverName(host), InsecureSkipVerify: true, MinVersion: tls.VersionTLS10, MaxVersion: tls.VersionTLS12, CipherSuites: []uint16{p.id}}, timeout)
		if err == nil {
			got = append(got, p.name)
			c.Close()
		}
	}
	return got
}
func fetchHeaders(ctx context.Context, host string, port int, timeout time.Duration) Headers {
	transport := &http.Transport{TLSClientConfig: &tls.Config{ServerName: serverName(host), InsecureSkipVerify: true}}
	client := &http.Client{Transport: transport, Timeout: timeout, CheckRedirect: func(req *http.Request, via []*http.Request) error { return http.ErrUseLastResponse }}
	endpoint := fmt.Sprintf("https://%s", net.JoinHostPort(host, strconv.Itoa(port)))
	if port == 443 {
		endpoint = "https://" + host
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodHead, endpoint, nil)
	if err != nil {
		return Headers{Error: err.Error()}
	}
	resp, err := client.Do(req)
	if err != nil {
		return Headers{Error: err.Error()}
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusMethodNotAllowed || resp.StatusCode == http.StatusNotImplemented {
		resp.Body.Close()
		req, err = http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
		if err != nil {
			return Headers{Error: err.Error()}
		}
		resp, err = client.Do(req)
		if err != nil {
			return Headers{Error: err.Error()}
		}
		defer resp.Body.Close()
	}
	return Headers{HSTS: resp.Header.Get("Strict-Transport-Security"), CSP: resp.Header.Get("Content-Security-Policy"), StatusCode: resp.StatusCode, Location: resp.Header.Get("Location")}
}
