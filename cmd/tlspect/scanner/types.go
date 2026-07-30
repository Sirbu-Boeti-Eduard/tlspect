package scanner

import "time"

type Options struct {
	Port    int
	Timeout time.Duration
}

type Certificate struct {
	Subject            string    `json:"subject"`
	Issuer             string    `json:"issuer"`
	NotBefore          time.Time `json:"not_before"`
	NotAfter           time.Time `json:"not_after"`
	ExpiresInDays      int       `json:"expires_in_days"`
	SignatureAlgorithm string    `json:"signature_algorithm"`
	KeyType            string    `json:"key_type"`
	KeyBits            int       `json:"key_bits"`
	DNSNames           []string  `json:"dns_names"`
	Verified           bool      `json:"verified"`
	VerificationError  string    `json:"verification_error,omitempty"`
}
type Headers struct {
	HSTS       string `json:"hsts,omitempty"`
	HSTSStrong bool   `json:"hsts_strong"`
	CSP        string `json:"csp,omitempty"`
	StatusCode int    `json:"status_code,omitempty"`
	Error      string `json:"error,omitempty"`
	Location   string `json:"location,omitempty"`
}
type Finding struct {
	Priority  string `json:"priority"`
	Title     string `json:"title"`
	Detail    string `json:"detail"`
	Deduction int    `json:"deduction"`
}
type Report struct {
	Host                  string      `json:"host"`
	Port                  int         `json:"port"`
	ScannedAt             time.Time   `json:"scanned_at"`
	Certificate           Certificate `json:"certificate"`
	TLSVersions           []string    `json:"tls_versions"`
	CipherSuite           string      `json:"cipher_suite"`
	WeakCiphers           []string    `json:"weak_ciphers"`
	PresentedCertificates int         `json:"presented_certificates"`
	Headers               Headers     `json:"headers"`
	Score                 int         `json:"score"`
	Grade                 string      `json:"grade"`
	Findings              []Finding   `json:"findings"`
}
