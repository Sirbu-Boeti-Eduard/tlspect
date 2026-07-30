package output

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"tlspect/cmd/tlspect/scanner"
)

func JSON(w io.Writer, r scanner.Report) error { return json.NewEncoder(w).Encode(r) }
func Terminal(w io.Writer, r scanner.Report, color bool) error {
	var out strings.Builder
	mark := func(ok bool) string {
		if ok {
			return paint("[x]", "32", color)
		}
		return paint("[ ]", "31", color)
	}
	warn := paint("[!]", "33", color)
	validNow := !r.Certificate.NotBefore.After(r.ScannedAt) && r.Certificate.NotAfter.After(r.ScannedAt)
	fmt.Fprintf(&out, "TLSPECT / TLS SECURITY AUDIT\n========================================\nTARGET: %s:%d\nVALIDATION DATE: %s\n\n", safe(r.Host), r.Port, r.ScannedAt.Local().Format("2006-01-02 15:04 MST"))
	fmt.Fprintln(&out, "[ CERTIFICATE ]")
	fmt.Fprintf(&out, "%s Subject: %s\n%s Valid: %s to %s (%d days)\n%s Trust and hostname: %s\n%s Key: %s %d bits\n%s Signature: %s\n\n", mark(validNow), safe(r.Certificate.Subject), mark(validNow), r.Certificate.NotBefore.Format("2006-01-02"), r.Certificate.NotAfter.Format("2006-01-02"), r.Certificate.ExpiresInDays, mark(r.Certificate.Verified), trustLabel(r.Certificate), mark(r.Certificate.KeyBits >= 2048 || r.Certificate.KeyType == "ECDSA"), safe(r.Certificate.KeyType), r.Certificate.KeyBits, mark(!strings.Contains(strings.ToUpper(r.Certificate.SignatureAlgorithm), "SHA1")), safe(r.Certificate.SignatureAlgorithm))
	fmt.Fprintln(&out, "[ TLS VERSIONS ]")
	for _, v := range []string{"1.3", "1.2", "1.1", "1.0"} {
		accepted, deprecated := contains(r.TLSVersions, v), v == "1.0" || v == "1.1"
		switch {
		case accepted && deprecated:
			fmt.Fprintf(&out, "%s TLS %s (deprecated protocol accepted)\n", warn, v)
		case accepted:
			fmt.Fprintf(&out, "%s TLS %s\n", mark(true), v)
		case deprecated:
			fmt.Fprintf(&out, "%s TLS %s (not accepted)\n", mark(true), v)
		default:
			fmt.Fprintf(&out, "%s TLS %s (not accepted)\n", mark(false), v)
		}
	}
	fmt.Fprintln(&out, "\n[ HTTP HEADERS ]")
	if r.Headers.Error != "" {
		fmt.Fprintf(&out, "%s Header probe: %s\n", warn, safe(r.Headers.Error))
	} else {
		hstsMark := mark(false)
		if r.Headers.HSTSStrong {
			hstsMark = mark(true)
		} else if r.Headers.HSTS != "" {
			hstsMark = warn
		}
		fmt.Fprintf(&out, "%s HSTS%s\n%s Content-Security-Policy%s\n", hstsMark, value(r.Headers.HSTS), mark(r.Headers.CSP != ""), value(r.Headers.CSP))
	}
	fmt.Fprintf(&out, "\n[ SECURITY SCORE ] %d/100  GRADE: %s\n========================================\n", r.Score, paint(r.Grade, "32", color))
	if len(r.Findings) == 0 {
		fmt.Fprintln(&out, "[x] No recommendations.")
		return write(w, out.String())
	}
	fmt.Fprintln(&out, "[ RECOMMENDATIONS ]")
	for _, f := range r.Findings {
		fmt.Fprintf(&out, "%s %s: %s\n    %s\n", warn, safe(f.Priority), safe(f.Title), safe(f.Detail))
	}
	return write(w, out.String())
}
func contains(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}
func value(v string) string {
	if v == "" {
		return " (not present)"
	}
	return ": " + safe(v)
}
func trustLabel(c scanner.Certificate) string {
	if c.Verified {
		return "verified"
	}
	return "not verified: " + safe(c.VerificationError)
}
func safe(value string) string {
	return strings.Map(func(r rune) rune {
		switch r {
		case '\u2018', '\u2019':
			return '\''
		case '\u201c', '\u201d':
			return '"'
		case '\u2013', '\u2014':
			return '-'
		}
		if r < 32 || r > 126 || r == 127 {
			return '?'
		}
		return r
	}, value)
}
func write(w io.Writer, value string) error { _, err := io.WriteString(w, value); return err }
func paint(s, code string, on bool) string {
	if !on {
		return s
	}
	return "\x1b[" + code + "m" + s + "\x1b[0m"
}
