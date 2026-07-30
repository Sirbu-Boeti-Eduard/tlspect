package output

import (
	"bytes"
	"errors"
	"strings"
	"testing"
	"time"
	"tlspect/cmd/tlspect/scanner"
)

func TestTerminalIsASCIIWhenColorDisabled(t *testing.T) {
	r := scanner.Report{Host: "example.com", Port: 443, ScannedAt: time.Now(), Certificate: scanner.Certificate{NotAfter: time.Now().AddDate(1, 0, 0), KeyType: "RSA", KeyBits: 2048, SignatureAlgorithm: "SHA256-RSA"}, TLSVersions: []string{"1.2", "1.3"}, Headers: scanner.Headers{HSTS: "max-age=1", CSP: "default-src 'self'"}, Score: 100, Grade: "A"}
	var b bytes.Buffer
	if err := Terminal(&b, r, false); err != nil {
		t.Fatal(err)
	}
	out := b.String()
	if strings.Contains(out, "\x1b[") {
		t.Fatal("unexpected ANSI color")
	}
	for _, want := range []string{"[ CERTIFICATE ]", "[ TLS VERSIONS ]", "[x]"} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing %q", want)
		}
	}
	for _, r := range out {
		if r > 127 {
			t.Fatalf("non-ASCII rune %q", r)
		}
	}
}

type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) { return 0, errors.New("write failed") }

func TestTerminalPropagatesWriteFailure(t *testing.T) {
	if err := Terminal(failingWriter{}, scanner.Report{}, false); err == nil {
		t.Fatal("expected write error")
	}
}

func TestTerminalFlagsAcceptedDeprecatedProtocol(t *testing.T) {
	r := scanner.Report{Host: "example.com", Port: 443, ScannedAt: time.Now(), TLSVersions: []string{"1.0", "1.2"}}
	var b bytes.Buffer
	if err := Terminal(&b, r, false); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(b.String(), "[!] TLS 1.0 (deprecated protocol accepted)") {
		t.Fatalf("legacy acceptance was not visibly flagged: %s", b.String())
	}
}

func TestTerminalSanitizesServerControlledText(t *testing.T) {
	r := scanner.Report{Host: "example.com", Port: 443, ScannedAt: time.Now(), Certificate: scanner.Certificate{Subject: "bad\x1b]52;clipboard\a", NotAfter: time.Now().Add(time.Hour), Verified: true}}
	var b bytes.Buffer
	if err := Terminal(&b, r, false); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(b.String(), "\x1b") {
		t.Fatalf("terminal escape sequence leaked into output: %q", b.String())
	}
}

func TestTerminalWarnsForWeakHSTS(t *testing.T) {
	r := scanner.Report{Host: "example.com", Port: 443, ScannedAt: time.Now(), Headers: scanner.Headers{HSTS: "max-age=300"}}
	var b bytes.Buffer
	if err := Terminal(&b, r, false); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(b.String(), "[!] HSTS: max-age=300") {
		t.Fatalf("weak HSTS did not receive warning marker: %s", b.String())
	}
}
