package scanner

import (
	"testing"
	"time"
)

func TestScoreSecureReport(t *testing.T) {
	now := time.Date(2026, 7, 30, 0, 0, 0, 0, time.UTC)
	r := Report{Certificate: Certificate{NotAfter: now.AddDate(1, 0, 0), KeyType: "RSA", KeyBits: 2048, SignatureAlgorithm: "SHA256-RSA", Verified: true}, TLSVersions: []string{"1.2", "1.3"}, Headers: Headers{HSTS: "max-age=31536000; includeSubDomains", CSP: "default-src 'self'"}}
	Score(&r, now)
	if r.Score != 100 || r.Grade != "A" || len(r.Findings) != 0 {
		t.Fatalf("unexpected secure score: %+v", r)
	}
}
func TestScoreAppliesRubric(t *testing.T) {
	now := time.Date(2026, 7, 30, 0, 0, 0, 0, time.UTC)
	r := Report{Certificate: Certificate{NotAfter: now.Add(-time.Hour), KeyType: "RSA", KeyBits: 1024, SignatureAlgorithm: "SHA1-RSA"}, TLSVersions: []string{"1.0", "1.1"}, WeakCiphers: []string{"TLS_RSA_WITH_3DES_EDE_CBC_SHA"}}
	Score(&r, now)
	if r.Score != 0 || r.Grade != "F" {
		t.Fatalf("got %d/%s, want 0/F", r.Score, r.Grade)
	}
	if len(r.Findings) != 9 {
		t.Fatalf("got %d findings, want 9", len(r.Findings))
	}
}

func TestScoreRejectsNotYetValidAndUntrustedCertificate(t *testing.T) {
	now := time.Date(2026, 7, 30, 0, 0, 0, 0, time.UTC)
	r := Report{Certificate: Certificate{NotBefore: now.Add(time.Hour), NotAfter: now.AddDate(1, 0, 0)}, Headers: Headers{Error: "probe failed"}}
	Score(&r, now)
	if r.Score != 20 {
		t.Fatalf("score = %d, want 20", r.Score)
	}
	if !findingNamed(r.Findings, "Certificate is not yet valid") || !findingNamed(r.Findings, "Certificate trust or hostname verification failed") {
		t.Fatalf("missing certificate findings: %+v", r.Findings)
	}
	if findingNamed(r.Findings, "HSTS header is missing") || findingNamed(r.Findings, "Content-Security-Policy header is missing") {
		t.Fatalf("probe failure was misreported as missing headers: %+v", r.Findings)
	}
}

func TestScoreRequiresStrongHSTS(t *testing.T) {
	now := time.Date(2026, 7, 30, 0, 0, 0, 0, time.UTC)
	r := Report{Certificate: Certificate{NotAfter: now.AddDate(1, 0, 0), Verified: true}, TLSVersions: []string{"1.2"}, Headers: Headers{HSTS: "max-age=300", CSP: "default-src 'self'"}}
	Score(&r, now)
	if r.Score != 90 || !findingNamed(r.Findings, "HSTS policy is too weak") {
		t.Fatalf("weak HSTS result = %+v", r)
	}
}

func TestValidHSTS(t *testing.T) {
	for _, value := range []string{"max-age=31536000; includeSubDomains", "INCLUDESUBDOMAINS; MAX-AGE=63072000"} {
		if !validHSTS(value) {
			t.Fatalf("validHSTS(%q) = false", value)
		}
	}
	for _, value := range []string{"", "max-age=31535999; includeSubDomains", "max-age=31536000", "max-age=oops; includeSubDomains"} {
		if validHSTS(value) {
			t.Fatalf("validHSTS(%q) = true", value)
		}
	}
}

func findingNamed(findings []Finding, title string) bool {
	for _, finding := range findings {
		if finding.Title == title {
			return true
		}
	}
	return false
}
