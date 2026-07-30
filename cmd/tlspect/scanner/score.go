package scanner

import (
	"strconv"
	"strings"
	"time"
)

func Score(r *Report, now time.Time) {
	findings := make([]Finding, 0)
	add := func(priority, title, detail string, deduction int) {
		findings = append(findings, Finding{priority, title, detail, deduction})
	}
	if r.Certificate.NotBefore.After(now) {
		add("HIGH", "Certificate is not yet valid", "Deploy a certificate whose validity period has started.", 40)
	} else if r.Certificate.NotAfter.Before(now) {
		add("HIGH", "Certificate has expired", "Renew and deploy a valid certificate immediately.", 40)
	} else if r.Certificate.NotAfter.Before(now.AddDate(0, 0, 30)) {
		add("LOW", "Certificate expires in under 30 days", "Renew the certificate before its expiration date.", 15)
	}
	if !r.Certificate.Verified {
		add("HIGH", "Certificate trust or hostname verification failed", "Present a certificate that chains to a trusted root and matches the target hostname.", 40)
	}
	if strings.Contains(strings.ToUpper(r.Certificate.SignatureAlgorithm), "SHA1") {
		add("HIGH", "Certificate uses SHA-1", "Replace the certificate with one signed using SHA-256 or stronger.", 20)
	}
	if r.Certificate.KeyType == "RSA" && r.Certificate.KeyBits > 0 && r.Certificate.KeyBits < 2048 {
		add("HIGH", "RSA key is under 2048 bits", "Replace the certificate with an RSA 2048-bit or stronger key.", 20)
	}
	if has(r.TLSVersions, "1.0") {
		add("HIGH", "TLS 1.0 is accepted", "Disable TLS 1.0 in the server configuration.", 20)
	}
	if has(r.TLSVersions, "1.1") {
		add("MEDIUM", "TLS 1.1 is accepted", "Disable TLS 1.1 in the server configuration.", 10)
	}
	for _, cipher := range r.WeakCiphers {
		add("MEDIUM", "Weak cipher accepted", "Remove "+cipher+" from the server cipher list.", 15)
	}
	if r.Headers.Error != "" {
		add("LOW", "HTTP security headers could not be checked", "Resolve the HTTP probe error before treating header results as conclusive.", 0)
	} else if r.Headers.HSTS == "" {
		add("MEDIUM", "HSTS header is missing", "Add Strict-Transport-Security with a one-year max-age and includeSubDomains.", 10)
	} else {
		r.Headers.HSTSStrong = validHSTS(r.Headers.HSTS)
		if !r.Headers.HSTSStrong {
			add("MEDIUM", "HSTS policy is too weak", "Use a max-age of at least 31536000 seconds and includeSubDomains.", 10)
		}
	}
	if r.Headers.Error == "" && r.Headers.CSP == "" {
		add("LOW", "Content-Security-Policy header is missing", "Define a Content-Security-Policy appropriate for this application.", 5)
	}
	r.Findings = findings
	r.Score = 100
	for _, f := range findings {
		r.Score -= f.Deduction
	}
	if r.Score < 0 {
		r.Score = 0
	}
	switch {
	case r.Score >= 90:
		r.Grade = "A"
	case r.Score >= 80:
		r.Grade = "B"
	case r.Score >= 70:
		r.Grade = "C"
	case r.Score >= 60:
		r.Grade = "D"
	default:
		r.Grade = "F"
	}
}

func validHSTS(value string) bool {
	var maxAge int64 = -1
	includeSubDomains := false
	for _, directive := range strings.Split(value, ";") {
		parts := strings.SplitN(strings.TrimSpace(directive), "=", 2)
		name := strings.ToLower(strings.TrimSpace(parts[0]))
		switch name {
		case "max-age":
			if len(parts) == 2 {
				parsed, err := strconv.ParseInt(strings.TrimSpace(parts[1]), 10, 64)
				if err == nil {
					maxAge = parsed
				}
			}
		case "includesubdomains":
			includeSubDomains = len(parts) == 1
		}
	}
	return maxAge >= 31536000 && includeSubDomains
}
func has(values []string, target string) bool {
	for _, v := range values {
		if v == target {
			return true
		}
	}
	return false
}
