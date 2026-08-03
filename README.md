# tlspect

tlspect is a local TLS configuration auditor for one public endpoint. It turns certificate, protocol, cipher, chain, and HTTP-header evidence into a 0-100 score, letter grade, and prioritised remediation list.

It is deliberately small, uses only the Go standard library, and makes outbound connections only to the hostname supplied on the command line. It does not retain scan results or send them to a third party.

## Security checks

- Certificate expiry, signature algorithm, public-key type, and public-key size.
- TLS 1.0 through TLS 1.3 support, tested with a separate handshake for each version.
- A focused probe for legacy RC4 and 3DES cipher suites.
- Presence of `Strict-Transport-Security` and `Content-Security-Policy` headers.
- Whether the TLS handshake included at least one additional certificate after the leaf certificate.
- A transparent 0-100 scoring rubric and an ordered list of fixes.

Status markers are ANSI-coloured `[x]`, `[!]`, and `[ ]`; pass `--no-color` for entirely plain ASCII output.

## Run

```sh
go run ./cmd/tlspect example.com
go run ./cmd/tlspect --no-color example.com
go run ./cmd/tlspect --json example.com
go run ./cmd/tlspect --port 8443 --timeout 8 example.com
go run ./cmd/tlspect --fail-under 80 example.com
```

The input can be a hostname, IP address, or an `https://` URL. Only the host is used; a path is ignored. Port 443 is the default.

`--fail-under` makes tlspect exit with status 1 when the score is below the supplied threshold, which is useful when a caller wants to gate a script or deployment. Without it, an insecure report is informational and exits successfully.

## Install Go and build tlspect

tlspect supports macOS, Linux, and Windows when compiled for that operating system and CPU architecture. Install Go using the [official installation guide](https://go.dev/doc/install), then confirm it is available:

```sh
go version
```

For development, `go run` builds and runs the program in one step. To produce a native executable:

```sh
# macOS or Linux
go build -o tlspect ./cmd/tlspect

# Windows 64-bit executable, built from macOS or Linux
GOOS=windows GOARCH=amd64 go build -o tlspect.exe ./cmd/tlspect
```

On Windows, build natively with:

```powershell
go build -o tlspect.exe .\cmd\tlspect
```

## Validation

All automated checks run locally and do not need internet access:

```sh
go test ./...
go vet ./...
go build ./cmd/tlspect
```

The unit tests cover the scoring rubric and terminal-output contract. The scanner test creates a local TLS server, performs a real handshake against it, and verifies that certificate and response-header data are collected. This gives a reproducible end-to-end validation without depending on a public domain that can change its configuration.

For manual exploratory scans, [badssl.com](https://badssl.com/) provides endpoints made specifically for TLS-client testing. Their behaviour can change, so treat these as examples rather than fixed test assertions:

| Target | Useful for |
| --- | --- |
| `mozilla-modern.badssl.com` | A modern cipher/protocol-policy baseline; HTTP headers are still assessed separately. |
| `expired.badssl.com` | An expired leaf certificate. |
| `self-signed.badssl.com` | A self-signed certificate. |
| `sha1-intermediate.badssl.com` | A SHA-1-signed intermediate certificate. |
| `tls-v1-0.badssl.com` | Legacy TLS 1.0 behaviour. |
| `tls-v1-1.badssl.com` | Legacy TLS 1.1 behaviour. |
| `rc4.badssl.com` | Legacy RC4 cipher behaviour, where still reachable from your environment. |

Example:

```sh
go run ./cmd/tlspect --no-color expired.badssl.com
```

## Scoring

tlspect starts each report at 100 and deducts for confirmed findings. The current deductions are: certificate not yet valid (-40), expired certificate (-40), expiry within 30 days (-15), failed certificate trust or hostname verification (-40), SHA-1 signature (-20), RSA key below 2048 bits (-20), TLS 1.0 (-20), TLS 1.1 (-10), each accepted weak cipher (-15), missing or weak HSTS (-10), and missing CSP (-5). If the HTTP header probe fails, it reports that result without claiming the headers are absent.

Grades are `A` (90-100), `B` (80-89), `C` (70-79), `D` (60-69), and `F` (below 60).

## Continuous integration

The included GitHub Actions workflow runs `go test ./...`, `go vet ./...`, and a build on pushes and pull requests once this project is placed in a GitHub repository. It does not publish releases or contact test domains.

## Limitations

tlspect is a focused auditor, not a replacement for a full TLS assessment. It does not enumerate every possible cipher suite, validate revocation status, test OCSP stapling, inspect CT logs, or test protocol vulnerabilities such as Heartbleed. It records how many certificates the server presents and separately performs normal trust and hostname verification; it does not claim that certificate count alone proves whether a chain is complete.

## License

MIT License.
