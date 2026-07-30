"use client";

import { FormEvent, useState } from "react";

const checks = [
  ["Certificate", "Valid until Sep 18, 2026", "pass"],
  ["Signature", "SHA256-RSA", "pass"],
  ["Key strength", "RSA 2048 bits", "pass"],
  ["Chain", "3 certificates presented", "pass"],
] as const;

const versions = [
  ["TLS 1.3", "Negotiated", "pass"],
  ["TLS 1.2", "Supported", "pass"],
  ["TLS 1.1", "Not accepted", "pass"],
  ["TLS 1.0", "Not accepted", "pass"],
] as const;

export default function Home() {
  const [target, setTarget] = useState("cloudflare.com");
  const [scanning, setScanning] = useState(false);
  const [scannedTarget, setScannedTarget] = useState("cloudflare.com");

  function scan(event: FormEvent) {
    event.preventDefault();
    if (!target.trim()) return;
    setScanning(true);
    window.setTimeout(() => {
      setScannedTarget(target.trim().replace(/^https?:\/\//, "").replace(/\/$/, ""));
      setScanning(false);
    }, 700);
  }

  return (
    <main>
      <nav className="topbar" aria-label="Main navigation">
        <a className="brand" href="#top" aria-label="tlspect home"><span>tls</span>pect</a>
        <div className="nav-meta">TLS CONFIGURATION AUDITOR <i>v0.1.0</i></div>
        <a className="docs" href="#methodology">[ documentation ]</a>
      </nav>

      <section className="hero" id="top">
        <div className="hero-copy">
          <p className="eyebrow">// QUICK, OPINIONATED, ACTIONABLE</p>
          <h1>Know what your<br/><em>TLS</em> is saying.</h1>
          <p className="intro">A focused security audit for the public face of your service. One grade, the evidence behind it, and the next thing to fix.</p>
        </div>
        <form className="scan-form" onSubmit={scan}>
          <label htmlFor="domain">TARGET HOSTNAME</label>
          <div className="input-row">
            <span className="prompt">›</span>
            <input id="domain" value={target} onChange={(event) => setTarget(event.target.value)} placeholder="example.com" spellCheck="false" />
            <button type="submit" disabled={scanning}>{scanning ? "SCANNING..." : "RUN AUDIT"}</button>
          </div>
          <p>Port 443 by default · no data retained · scans public endpoints only</p>
        </form>
      </section>

      <section className="report-wrap" aria-live="polite">
        <header className="report-header">
          <div>
            <p className="eyebrow">AUDIT REPORT / {scannedTarget.toUpperCase()}</p>
            <h2>Security posture</h2>
          </div>
          <div className="audit-time"><span>LAST VALIDATED</span><strong>JUL 30, 2026 · 14:32 EEST</strong></div>
        </header>

        <div className="score-grid">
          <article className="score-card">
            <p>OVERALL SCORE</p>
            <div className="score"><b>92</b><span>/100</span></div>
            <div className="meter"><span /></div>
            <small>Excellent baseline. Two improvements remain.</small>
          </article>
          <article className="grade-card">
            <p>SECURITY GRADE</p>
            <div className="grade">A<span>−</span></div>
            <small>Production ready</small>
          </article>
          <article className="summary-card">
            <p>SCAN SUMMARY</p>
            <div className="summary-row"><b className="status pass">[ x ]</b><span>8 checks passed</span></div>
            <div className="summary-row"><b className="status warn">[ ! ]</b><span>2 recommendations</span></div>
            <div className="summary-row"><b className="status pass">[ x ]</b><span>0 critical findings</span></div>
          </article>
        </div>

        <div className="findings-grid">
          <AuditPanel ascii="[ CERTIFICATE ]" title="Identity & validity" items={checks} />
          <AuditPanel ascii="[ TLS VERSIONS ]" title="Protocol support" items={versions} />
          <article className="panel">
            <div className="panel-label">[ CIPHER SUITES ]</div><h3>Encryption strength</h3>
            <div className="cipher-count"><b>12</b><span>secure ciphers accepted</span></div>
            <div className="cipher-pill"><span className="status pass">[ x ]</span> TLS_AES_256_GCM_SHA384</div>
            <div className="cipher-pill"><span className="status pass">[ x ]</span> TLS_CHACHA20_POLY1305_SHA256</div>
            <p className="panel-note">No NULL, EXPORT, RC4, 3DES, or anonymous ciphers observed.</p>
          </article>
          <article className="panel">
            <div className="panel-label">[ HTTP HEADERS ]</div><h3>Browser protections</h3>
            <div className="header-check"><span className="status pass">[ x ]</span><div><b>HSTS</b><small>max-age=31536000; includeSubDomains</small></div></div>
            <div className="header-check"><span className="status warn">[ ! ]</span><div><b>Content-Security-Policy</b><small>Not present</small></div></div>
            <p className="panel-note">HSTS is correctly configured for a one-year policy.</p>
          </article>
        </div>

        <section className="recommendations">
          <div className="rec-intro"><p className="eyebrow">[ NEXT ACTIONS ]</p><h2>Fix the small gaps.</h2></div>
          <ol>
            <li><span className="priority med">MEDIUM</span><div><b>Add a Content-Security-Policy header</b><p>Define trusted content sources to reduce the impact of client-side injection.</p></div><span className="arrow">→</span></li>
            <li><span className="priority low">LOW</span><div><b>Enable OCSP stapling</b><p>Improve certificate revocation checks and lower connection overhead for visitors.</p></div><span className="arrow">→</span></li>
          </ol>
        </section>
      </section>

      <section className="method" id="methodology"><p>[ HOW TLSPECT SCORES ]</p><span>Certificates, protocol versions, cipher strength, headers, and chain delivery — reduced to an auditable score out of 100.</span></section>
      <footer><span>tlspect / built for clear decisions</span><span>PUBLIC ENDPOINTS ONLY</span></footer>
    </main>
  );
}

function AuditPanel({ ascii, title, items }: { ascii: string; title: string; items: readonly (readonly [string, string, string])[] }) {
  return <article className="panel"><div className="panel-label">{ascii}</div><h3>{title}</h3><div className="check-list">{items.map(([name, value, type]) => <div className="check-row" key={name}><span className={`status ${type}`}>[ x ]</span><b>{name}</b><span>{value}</span></div>)}</div></article>;
}
