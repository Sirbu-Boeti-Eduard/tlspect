package scanner

import (
	"context"
	"crypto/tls"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"testing"
	"time"
)

func TestScanCollectsTLSAndHeadersFromLocalServer(t *testing.T) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}

	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		w.Header().Set("Content-Security-Policy", "default-src 'self'")
		w.WriteHeader(http.StatusNoContent)
	}))
	server.Listener = listener
	server.Config.ErrorLog = log.New(io.Discard, "", 0)
	server.TLS = &tls.Config{MinVersion: tls.VersionTLS12}
	server.StartTLS()
	defer server.Close()

	u, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	_, portText, err := net.SplitHostPort(u.Host)
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.Atoi(portText)
	if err != nil {
		t.Fatal(err)
	}

	report, err := Scan(context.Background(), "https://"+u.Host+"/ignored-path", Options{Port: port, Timeout: time.Second})
	if err != nil {
		t.Fatalf("Scan returned an error: %v", err)
	}
	if report.Host != "127.0.0.1" {
		t.Fatalf("host = %q, want loopback address", report.Host)
	}
	if report.Certificate.NotAfter.IsZero() {
		t.Fatal("expected certificate metadata")
	}
	if report.Headers.HSTS == "" || report.Headers.CSP == "" {
		t.Fatalf("expected security headers, got %+v", report.Headers)
	}
	if !has(report.TLSVersions, "1.2") {
		t.Fatalf("TLS 1.2 was not recorded: %v", report.TLSVersions)
	}
	if report.Certificate.Verified {
		t.Fatal("httptest's self-signed certificate must not be reported as trusted")
	}
	if !findingNamed(report.Findings, "Certificate trust or hostname verification failed") {
		t.Fatalf("missing trust finding: %+v", report.Findings)
	}
}

func TestHeaderProbeDoesNotFollowRedirects(t *testing.T) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/secure" {
			w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
			w.Header().Set("Content-Security-Policy", "default-src 'self'")
			w.WriteHeader(http.StatusNoContent)
			return
		}
		http.Redirect(w, r, "/secure", http.StatusFound)
	}))
	server.Listener = listener
	server.Config.ErrorLog = log.New(io.Discard, "", 0)
	server.StartTLS()
	defer server.Close()

	u, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	_, portText, err := net.SplitHostPort(u.Host)
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.Atoi(portText)
	if err != nil {
		t.Fatal(err)
	}
	headers := fetchHeaders(context.Background(), "127.0.0.1", port, time.Second)
	if headers.Location != "/secure" {
		t.Fatalf("redirect location = %q, want /secure", headers.Location)
	}
	if headers.HSTS != "" || headers.CSP != "" {
		t.Fatalf("headers from redirect destination leaked into result: %+v", headers)
	}
}

func TestDialContextCancelsTLSHandshake(t *testing.T) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	accepted := make(chan net.Conn, 1)
	go func() {
		conn, acceptErr := listener.Accept()
		if acceptErr == nil {
			accepted <- conn
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, err = dialContext(ctx, listener.Addr().String(), &tls.Config{InsecureSkipVerify: true}, 5*time.Second)
	if err == nil {
		t.Fatal("expected cancelled TLS handshake")
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("cancellation took %s", elapsed)
	}
	select {
	case conn := <-accepted:
		conn.Close()
	case <-time.After(time.Second):
		t.Fatal("server never accepted test connection")
	}
}

func TestScanRejectsInvalidOptionsBeforeNetworkAccess(t *testing.T) {
	for _, options := range []Options{{Port: -1, Timeout: time.Second}, {Port: 65536, Timeout: time.Second}, {Port: 443, Timeout: -time.Second}, {Port: 443, Timeout: time.Minute + time.Second}} {
		if _, err := Scan(context.Background(), "example.com", options); err == nil {
			t.Fatalf("Scan accepted invalid options: %+v", options)
		}
	}
}
