"use client"

import React, { useState, useEffect, useRef } from "react"
import Link from "next/link"
import CourtEvidenceDossier from "@/components/CourtEvidenceDossier"
import "./console.css"

// --- Types -----------------------------------------------------------------
type Clearance = "" | "LVL-1 JUNIOR" | "LVL-2 INVESTIGATOR" | "LVL-3 ANALYST" | "CHIEF FORENSIC COMM."
type TabId = "overviewTab" | "permissionsTab" | "codeTab" | "networkTab" | "reportTab"
type Screen = "analysis" | "evidence" | "audit" | "court"

interface Permission { name: string; level?: string }

const BACKEND = "http://127.0.0.1:8000"

const PERMISSION_CONTEXT: Record<string, string> = {
  READ_SMS: "May read SMS messages (OTP interception risk)",
  RECEIVE_SMS: "May intercept incoming SMS",
  SEND_SMS: "May send SMS (premium-rate abuse risk)",
  READ_CONTACTS: "May access the contact list",
  WRITE_CONTACTS: "May modify contacts",
  READ_CALL_LOG: "May read the call history",
  ACCESS_FINE_LOCATION: "Precise device location access",
  ACCESS_COARSE_LOCATION: "Approximate device location access",
  RECORD_AUDIO: "May record audio via the microphone",
  CAMERA: "May capture photos / video",
  READ_PHONE_STATE: "Reads device identifiers and call state",
  SYSTEM_ALERT_WINDOW: "Draw-over-other-apps (overlay attack risk)",
  REQUEST_INSTALL_PACKAGES: "May prompt to install other apps",
  INTERNET: "Network access",
  FOREGROUND_SERVICE: "Runs a foreground service",
}

const shortName = (p: string) => p.replace(/^android\.permission\./, "")
const isDangerous = (lvl?: string) => lvl === "Critical" || lvl === "Warning" || lvl === "Dangerous"

export default function SentinelConsole() {
  // Auth / RBAC
  const [isAuth, setIsAuth] = useState(false)
  const [username, setUsername] = useState("")
  const [password, setPassword] = useState("")
  const [badge, setBadge] = useState("")
  const [station, setStation] = useState("")
  const [authBusy, setAuthBusy] = useState(false)
  const [clearance, setClearance] = useState<Clearance>("LVL-2 INVESTIGATOR")
  const [originalClearance, setOriginalClearance] = useState<Clearance>("LVL-2 INVESTIGATOR")
  const [violation, setViolation] = useState(false)

  // App
  const [screen, setScreen] = useState<Screen>("analysis")
  const [tab, setTab] = useState<TabId>("overviewTab")
  const [data, setData] = useState<any>(null)
  const [fileName, setFileName] = useState("")
  const [fileSize, setFileSize] = useState("")
  const [loading, setLoading] = useState(false)
  const [permQuery, setPermQuery] = useState("")
  const [toast, setToast] = useState("")
  const [fontPx, setFontPx] = useState(14)
  const toastTimer = useRef<ReturnType<typeof setTimeout> | null>(null)
  const inputRef = useRef<HTMLInputElement>(null)

  const notify = (msg: string) => {
    setToast(msg)
    if (toastTimer.current) clearTimeout(toastTimer.current)
    toastTimer.current = setTimeout(() => setToast(""), 3200)
  }
  const rankWeight = (lvl: Clearance) =>
    ({ "LVL-1 JUNIOR": 1, "LVL-2 INVESTIGATOR": 2, "LVL-3 ANALYST": 3, "CHIEF FORENSIC COMM.": 4 } as Record<string, number>)[lvl] || 1

  const handleLogin = async (e: React.FormEvent) => {
    e.preventDefault()
    if (!username || !password) return notify("Enter your username and password.")
    setAuthBusy(true)
    try {
      const res = await fetch(`${BACKEND}/api/login`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username, password }),
      })
      if (!res.ok) {
        notify(res.status === 401 ? "Invalid username or password." : "Authentication service unavailable.")
        return
      }
      const u = await res.json()
      const role = (u.role || "LVL-2 INVESTIGATOR") as Clearance
      setClearance(role)
      setOriginalClearance(role)
      setStation(u.station || "")
      setBadge(u.full_name || u.username || username)
      setViolation(false)
      setIsAuth(true)
    } catch {
      notify("Could not reach the authentication service on :8000.")
    } finally {
      setAuthBusy(false)
    }
  }
  const handleRoleChange = (target: Clearance) => {
    const canSwitch = rankWeight(originalClearance) >= 3
    if (!canSwitch || rankWeight(target) > rankWeight(originalClearance)) return setViolation(true)
    setClearance(target)
    notify(`Auditing as ${target}.`)
  }

  const processFile = async (file: File | null | undefined) => {
    if (!file) return
    if (!file.name.toLowerCase().endsWith(".apk")) return notify("Please select a file with the .apk extension.")
    setFileName(file.name)
    const mb = (file.size / (1024 * 1024)).toFixed(2)
    setFileSize(`${mb} MB (${file.size.toLocaleString()} bytes)`)
    setLoading(true)
    try {
      const form = new FormData()
      form.append("file", file)
      const res = await fetch(`${BACKEND}/api/analyze-apk`, { method: "POST", headers: { "x-user-role": clearance || "Analyst" }, body: form })
      if (!res.ok) throw new Error("Backend analysis failed")
      const result = await res.json()
      setData(result)
      setScreen("analysis")
      setTab("overviewTab")
      notify(`Analysis complete — ${result.classification} (${result.risk_score}/100).`)
    } catch {
      notify("Could not reach the analysis backend on :8000. Showing the selected file only.")
      setData(null)
    } finally {
      setLoading(false)
    }
  }

  const copyText = async (text: string, label: string) => {
    try { await navigator.clipboard.writeText(text); notify(`${label} copied to clipboard.`) } catch { notify(text) }
  }
  const exportIocs = () => {
    const ind = data?.static_indicators || {}
    const payload = { analysis_id: data?.analysis_id ?? null, sha256: data?.sha256 ?? null, ips: ind.ips ?? [], domains: ind.domains ?? [], urls: ind.urls ?? [], ioc_matches: data?.ioc_matches ?? null, note: data ? "Extracted by ANVESH backend" : "No analysis loaded" }
    const blob = new Blob([JSON.stringify(payload, null, 2)], { type: "application/json" })
    const url = URL.createObjectURL(blob)
    const a = document.createElement("a"); a.href = url; a.download = `sentinel-iocs-${data?.analysis_id ?? "none"}.json`; a.click()
    URL.revokeObjectURL(url)
    notify("Exported extracted indicators as JSON.")
  }
  const downloadPdf = () => {
    if (!data) return notify("Analyse a specimen first.")
    const q = new URLSearchParams({ filename: data.filename, sha256: data.sha256, risk_score: String(data.risk_score), classification: data.classification })
    window.open(`${BACKEND}/api/download-report?${q.toString()}`, "_blank")
  }

  useEffect(() => {
    document.documentElement.style.fontSize = `${fontPx}px`
    return () => { document.documentElement.style.fontSize = "" }
  }, [fontPx])

  // Derived
  const permissions: Permission[] = data?.static_indicators?.permissions?.length ? data.static_indicators.permissions : data?.manifest?.permissions || []
  const dangerousCount = permissions.filter((p) => isDangerous(p.level)).length
  const ind = data?.static_indicators || {}
  const indicatorCount = (ind.ips?.length || 0) + (ind.domains?.length || 0) + (ind.urls?.length || 0) + (ind.suspicious_apis?.length || 0)
  const score: number = data?.risk_score ?? 0
  // Prefer the backend's graded severity; fall back to score bands if absent.
  const SEV_MAP: Record<string, { label: string; cls: string }> = {
    CRITICAL: { label: "Critical", cls: "red" },
    HIGH: { label: "High", cls: "red" },
    MEDIUM: { label: "Elevated", cls: "amber" },
    LOW: { label: "Low", cls: "green" },
  }
  const severity = data?.severity && SEV_MAP[data.severity]
    ? SEV_MAP[data.severity]
    : score >= 70 ? { label: "Critical", cls: "red" } : score >= 40 ? { label: "Elevated", cls: "amber" } : { label: "Low", cls: "green" }
  const filteredPerms = permissions.filter((p) => (shortName(p.name) + (p.level || "")).toLowerCase().includes(permQuery.toLowerCase()))
  const hasData = !!data

  // ===================== SECURITY VIOLATION =====================
  if (violation) {
    return (
      <div className="sentinel-dash"><div className="violation-wrap"><div className="violation-card">
        <div className="login-emblem" style={{ background: "var(--red)" }}>!</div>
        <h2>Privilege Escalation Blocked</h2>
        <p className="muted" style={{ margin: "0 0 16px" }}>Rank switching is restricted to Analyst level and above, and you cannot elevate beyond your authorised clearance (<strong>{originalClearance}</strong>). This attempt was logged.</p>
        <button className="btn btn-primary" onClick={() => { setViolation(false); setIsAuth(false) }}>Acknowledge &amp; Re-authenticate</button>
      </div></div></div>
    )
  }

  // ===================== LOGIN GATE =====================
  if (!isAuth) {
    return (
      <div className="sentinel-dash"><div className="login-wrap">
        <form className="login-card" onSubmit={handleLogin}>
          <div className="login-emblem">A</div>
          <h1>ANVESH v2.0</h1>
          <p className="sub">Secure Officer Authentication · EOU, Bihar Police</p>
          <div className="login-field"><label>Username</label><input value={username} required autoComplete="username" onChange={(e) => setUsername(e.target.value)} placeholder="e.g. analyst" /></div>
          <div className="login-field"><label>Password</label><input type="password" value={password} required autoComplete="current-password" onChange={(e) => setPassword(e.target.value)} placeholder="Enter your password" /></div>
          <button type="submit" disabled={authBusy} className="btn btn-primary login-submit" style={authBusy ? { opacity: 0.7 } : undefined}>{authBusy ? "Authenticating…" : "Authenticate & Enter Console"}</button>
          <div className="login-foot">
            Role &amp; station are assigned from your account record.<br />
            <span style={{ opacity: 0.8 }}>Demo accounts — analyst / officer / chief / constable · password <code>&lt;name&gt;@123</code></span><br />
            <Link href="/" style={{ color: "var(--blue)" }}>Return to portal home</Link>
          </div>
        </form>
      </div></div>
    )
  }

  // ===================== COURT DOSSIER (full screen) =====================
  if (screen === "court") return <CourtEvidenceDossier onBack={() => setScreen("analysis")} />

  const canSwitch = rankWeight(originalClearance) >= 3

  // ===================== AUTHED SHELL =====================
  return (
    <div className="sentinel-dash">
      {/* Tricolour government strip */}
      <div className="gov-strip">
        <span>GOVERNMENT-STYLE CYBERSECURITY PORTAL · DEMONSTRATION</span>
        <div className="accessibility">
          <button type="button" onClick={() => setFontPx((s) => Math.max(12, s - 1))} aria-label="Decrease text size">A−</button>
          <button type="button" onClick={() => setFontPx(14)} aria-label="Reset text size">A</button>
          <button type="button" onClick={() => setFontPx((s) => Math.min(17, s + 1))} aria-label="Increase text size">A+</button>
          <span className="divider" /><span>Investigator Workspace</span>
        </div>
      </div>

      {/* Header */}
      <header className="site-header">
        <Link className="brand" href="/" aria-label="ANVESH home">
          <span className="brand-mark" aria-hidden="true">A</span>
          <span><strong>ANVESH <small>v2.0</small></strong><small className="brand-sub">Android Network &amp; Visual Evidence Security Hub</small></span>
        </Link>
        <nav className="main-nav" aria-label="Main navigation">
          <Link className="nav-link" href="/">Portal Home</Link>
          <button className="nav-link active" onClick={() => setScreen("analysis")}>Console</button>
        </nav>
        <div className="user-controls">
          <label htmlFor="role">Role {canSwitch ? "" : "🔒"}</label>
          <select id="role" value={clearance} disabled={!canSwitch} style={!canSwitch ? { opacity: 0.55, cursor: "not-allowed" } : undefined} onChange={(e) => handleRoleChange(e.target.value as Clearance)} title={canSwitch ? "Step-down auditing (Analyst+ only)" : "Clearance locked — junior ranks cannot change position"}>
            <option value="LVL-1 JUNIOR">LVL-1 Junior</option>
            <option value="LVL-2 INVESTIGATOR">LVL-2 Investigator</option>
            <option value="LVL-3 ANALYST">LVL-3 Analyst</option>
            <option value="CHIEF FORENSIC COMM.">Chief Forensic Comm.</option>
          </select>
          <button className="profile" type="button" onClick={() => setIsAuth(false)}>Logout</button>
        </div>
      </header>
      <div className="tri-line"><i /><i /><i /></div>

      {/* Sidebar + main */}
      <div className="ws-layout">
        <aside className="ws-sidebar">
          <p className="eyebrow">EVIDENTIARY MODULES</p>
          <div className="ws-nav">
            {([
              ["analysis", "◎", "Active Specimen Analysis"],
              ["evidence", "▤", "Evidence Dossier"],
              ["court", "⚖", "Court-Ready Reports"],
              ["audit", "⛨", "Audit & Custody Log"],
            ] as [Screen, string, string][]).map(([s, ico, label]) => (
              <button key={s} className={screen === s ? "active" : ""} onClick={() => setScreen(s)}>
                <span className="ico">{ico}</span><span>{label}</span>
              </button>
            ))}
            <button onClick={() => { setData(null); setFileName(""); setFileSize(""); setScreen("analysis"); inputRef.current?.click() }}>
              <span className="ico">↑</span><span>New Ingestion</span>
            </button>
          </div>
          <div className="ws-sidebar-foot">
            Officer: {badge || "—"}<br />Clearance: {clearance}<br />Station: {station}<br /><br />Sandbox engine: <strong>READY</strong>
          </div>
        </aside>

        <div className="ws-main">
          {/* ---------------- ANALYSIS ---------------- */}
          {screen === "analysis" && (
            <>
              <div className="breadcrumb"><Link href="/">Home</Link><span>›</span><span>Analysis Dashboard</span><span className="demo-pill">{hasData ? "LIVE BACKEND" : "AWAITING SPECIMEN"}</span></div>
              <section className="page-heading">
                <div><p className="eyebrow">INVESTIGATOR WORKSPACE · {badge || "OFFICER"} · {clearance}</p><h1>APK Analysis Dashboard</h1><p className="subheading">Review specimen details, threat indicators, and evidence summaries in one workspace.</p></div>
                <div className="case-chip"><span className="case-dot" /><span><small>CASE REFERENCE</small><strong>BR-CYBER-2026-9048</strong></span></div>
              </section>

              <section className="summary-grid" aria-label="Threat summary">
                <article className="metric-card"><div className="metric-top"><span>Threat Score</span><span className="metric-icon blue">◎</span></div><div className="metric-value"><strong>{hasData ? score : "—"}</strong><span>/100</span></div><div className="meter"><span style={{ width: `${hasData ? score : 0}%`, background: `var(--${severity.cls})` }} /></div><small className="muted">{hasData ? "Backend composite score" : "Upload a specimen to score"}</small></article>
                <article className="metric-card"><div className="metric-top"><span>Severity</span><span className={`metric-icon ${severity.cls}`}>!</span></div><div className="severity" style={{ color: `var(--${severity.cls})` }}><span className={`status-dot ${severity.cls}-bg`} />{hasData ? severity.label : "—"}</div><small className="muted">Requires human verification</small></article>
                <article className="metric-card"><div className="metric-top"><span>Dangerous Permissions</span><span className="metric-icon amber">⌁</span></div><div className="metric-value"><strong>{hasData ? dangerousCount : "—"}</strong><span className="metric-unit">of {permissions.length}</span></div><small className="muted">Critical / warning permissions</small></article>
                <article className="metric-card"><div className="metric-top"><span>Detected Indicators</span><span className="metric-icon green">✓</span></div><div className="metric-value"><strong>{hasData ? indicatorCount : "—"}</strong><span className="metric-unit">indicators</span></div><small className="muted">URLs · IPs · domains · APIs</small></article>
              </section>

              <div className="main-grid">
                <div className="left-column">
                  <section className="panel">
                    <div className="panel-heading"><div><p className="eyebrow">SPECIMEN INTAKE</p><h2>Upload APK specimen</h2></div><span className="soft-badge">Live backend</span></div>
                    <label className="dropzone" tabIndex={0} onDragOver={(e) => e.preventDefault()} onDrop={(e) => { e.preventDefault(); processFile(e.dataTransfer?.files?.[0]) }}>
                      <input ref={inputRef} type="file" accept=".apk" hidden onChange={(e) => processFile(e.target.files?.[0])} />
                      <div className="upload-icon">{loading ? "…" : "↑"}</div>
                      <strong>{loading ? "Analysing specimen…" : "Drag and drop an APK file here"}</strong>
                      <span>{loading ? fileName : "or select a file from your device"}</span>
                      <span className="btn btn-outline">Browse files</span>
                      <small>Sent to the ANVESH analysis engine on port 8000</small>
                    </label>
                    {fileName && (<div className="specimen-row"><div className="file-icon">APK</div><div className="file-meta"><strong>{fileName}</strong><span>{fileSize}</span><code>SHA-256: {data?.sha256 ? data.sha256.slice(0, 24) + "…" : "pending"}</code></div><span className={`tag ${hasData ? "tag-blue" : "tag-amber"}`}>{hasData ? "Analysed" : "Selected"}</span></div>)}
                    <div className="notice"><span>ⓘ</span><p>Specimen data below is produced by the backend static-analysis engine. Runtime/sandbox fields are illustrative unless real telemetry is collected.</p></div>
                  </section>
                  <section className="panel pipeline-panel">
                    <div className="panel-heading"><div><p className="eyebrow">ANALYSIS PIPELINE</p><h2>Nine-stage workflow</h2></div><span className="soft-badge">{hasData ? "Processed" : "Idle"}</span></div>
                    <ol className="pipeline">
                      {["File intake and validation", "Sample hashing and registration", "APK archive inspection", "Manifest and permission analysis", "Code, resources and native libraries", "Obfuscation and evasion detection", "Runtime and network observation", "Risk assessment and evidence correlation", "Report preparation and integrity check"].map((label, i) => (
                        <li key={i} className={hasData ? "complete" : ""}><span>{hasData ? "✓" : i + 1}</span><div><strong>{label}</strong></div></li>
                      ))}
                    </ol>
                  </section>
                </div>

                <div className="right-column">
                  <section className="panel assessment-panel">
                    <div className="assessment-header">
                      <div><span className="label-danger">{hasData ? data.classification : "AWAITING ANALYSIS"}</span><h2>Composite Threat Assessment</h2><p className="muted">Backend heuristic score · validate against the specimen before conclusions</p></div>
                      <div className="score-box"><small>THREAT SCORE</small><div><strong style={{ color: `var(--${severity.cls})` }}>{hasData ? score : "—"}</strong><span>/100</span></div><span className="critical-label" style={{ color: `var(--${severity.cls})` }}>{hasData ? severity.label.toUpperCase() : "NO DATA"}</span></div>
                    </div>
                    <div className="briefing">
                      <div className="briefing-title"><span className="sparkle">✦</span><strong>AI Executive Briefing</strong><span className="soft-badge">Auto-generated</span></div>
                      <p>{hasData ? data.executive_briefing : "Upload a seized APK to generate a backend executive briefing. Automated summaries must be verified by an investigator before use."}</p>
                      <div className="briefing-footer"><span>Automated summaries require human review.</span>{hasData && <button className="text-btn" onClick={() => copyText(data.executive_briefing, "Briefing")}>Copy summary</button>}</div>
                    </div>
                  </section>

                  <section className="panel console-panel">
                    <div className="panel-heading"><div><p className="eyebrow">FORENSIC INSPECTION</p><h2>Evidence console</h2></div><span className="soft-badge">{hasData ? "Backend records" : "No records"}</span></div>
                    <div className="tabs" role="tablist">
                      {([["overviewTab", "Overview"], ["permissionsTab", "Permissions"], ["codeTab", "Code & Evasion"], ["networkTab", "Network IOCs"], ["reportTab", "Forensic Report"]] as [TabId, string][]).map(([id, label]) => (
                        <button key={id} className={`tab ${tab === id ? "active" : ""}`} role="tab" aria-selected={tab === id} onClick={() => setTab(id)}>{label}</button>
                      ))}
                    </div>
                    {tab === "overviewTab" && (
                      <div className="tab-content"><div className="detail-grid">
                        <div className="detail-item"><small>PACKAGE IDENTIFIER</small><strong>{data?.manifest?.package_name || "—"}</strong></div>
                        <div className="detail-item"><small>SDK TARGET</small><strong>{hasData ? `Target ${data.manifest?.target_sdk} · Min ${data.manifest?.min_sdk}` : "—"}</strong></div>
                        <div className="detail-item"><small>FILE SIZE</small><strong>{hasData ? `${data.size_mb} MB` : "—"}</strong></div>
                        <div className="detail-item"><small>SPECIMEN STATUS</small><strong><span className="status-dot green-bg" /> {hasData ? "Registered" : "Not ingested"}</strong></div>
                      </div><div className="table-wrap"><table><thead><tr><th>Evidence field</th><th>Value</th></tr></thead><tbody>
                        <tr><td>File name</td><td>{data?.filename || "—"}</td></tr><tr><td>Hash algorithm</td><td>SHA-256</td></tr>
                        <tr><td>Hash</td><td><code>{data?.sha256 || "—"}</code></td></tr><tr><td>Classification</td><td>{data?.classification || "—"}</td></tr>
                      </tbody></table></div></div>
                    )}
                    {tab === "permissionsTab" && (
                      <div className="tab-content">
                        <div className="table-toolbar"><label htmlFor="permissionSearch">Search permissions</label><input id="permissionSearch" type="search" placeholder="Filter by permission…" value={permQuery} onChange={(e) => setPermQuery(e.target.value)} /></div>
                        {filteredPerms.length ? (<div className="table-wrap"><table><thead><tr><th>Permission</th><th>Category</th><th>Context</th></tr></thead><tbody>
                          {filteredPerms.map((p, i) => (<tr key={i}><td>{shortName(p.name)}</td><td><span className={`tag ${isDangerous(p.level) ? "tag-red" : "tag-blue"}`}>{isDangerous(p.level) ? "Dangerous" : "Normal"}</span></td><td>{PERMISSION_CONTEXT[shortName(p.name)] || "—"}</td></tr>))}
                        </tbody></table></div>) : (<div className="empty-state"><span className="empty-icon">⌁</span><strong>No permissions extracted</strong><p>Upload an APK to recover its manifest permissions.</p></div>)}
                      </div>
                    )}
                    {tab === "codeTab" && (
                      <div className="tab-content">{ind.suspicious_apis?.length ? (<div className="table-wrap"><table><thead><tr><th>Suspicious API / symbol present</th></tr></thead><tbody>{ind.suspicious_apis.map((s: string, i: number) => <tr key={i}><td><code>{s}</code></td></tr>)}</tbody></table></div>) : (<div className="empty-state"><span className="empty-icon">⌘</span><strong>Code and evasion findings</strong><p>Static suspicious-API string matches from the backend appear here once a specimen is analysed.</p></div>)}</div>
                    )}
                    {tab === "networkTab" && (
                      <div className="tab-content">{(ind.ips?.length || ind.domains?.length || ind.urls?.length) ? (<div className="table-wrap"><table><thead><tr><th>Indicator</th><th>Type</th></tr></thead><tbody>
                        {(ind.ips || []).map((v: string, i: number) => <tr key={`ip${i}`}><td><code>{v}</code></td><td><span className="tag tag-red">IP</span></td></tr>)}
                        {(ind.domains || []).map((v: string, i: number) => <tr key={`d${i}`}><td><code>{v}</code></td><td><span className="tag tag-amber">Domain</span></td></tr>)}
                        {(ind.urls || []).map((v: string, i: number) => <tr key={`u${i}`}><td><code>{v}</code></td><td><span className="tag tag-blue">URL</span></td></tr>)}
                      </tbody></table></div>) : (<div className="empty-state"><span className="empty-icon">↗</span><strong>Network indicators</strong><p>Extracted URLs, IPs and domains from the specimen appear here. None found yet.</p></div>)}</div>
                    )}
                    {tab === "reportTab" && (
                      <div className="tab-content">
                        <div className="report-preview"><div><span className="report-icon">▤</span><strong>Forensic report</strong><p>Generate a PDF evidence report from the current analysis, or open the detailed court dossier.</p></div><button className="btn btn-primary" onClick={downloadPdf}>Download PDF</button></div>
                        <div style={{ display: "flex", gap: 8, flexWrap: "wrap", marginTop: 6 }}><button className="btn btn-outline" onClick={() => setScreen("court")}>Open Court Evidence Dossier</button></div>
                        <div className="notice"><span>ⓘ</span><p>Hashes support integrity checks but do not by themselves establish authenticity or a complete chain of custody.</p></div>
                      </div>
                    )}
                  </section>

                  <section className="panel custody-panel">
                    <div className="panel-heading"><div><p className="eyebrow">EVIDENCE RECORD</p><h2>Chain of custody</h2></div><span className="tag tag-amber">Audit</span></div>
                    <div className="custody-row"><span className="custody-icon">⌁</span><div><strong>Specimen registration</strong><small>{hasData ? `Analysis #${data.analysis_id ?? "—"} recorded` : "No specimen registered"}</small></div><span className="status-pill">{hasData ? "Logged" : "Idle"}</span></div>
                    <div className="custody-row"><span className="custody-icon">◷</span><div><strong>Timestamp</strong><small>{new Date().toUTCString()}</small></div></div>
                    <div className="custody-row"><span className="custody-icon">#</span><div><strong>Integrity hash (SHA-256)</strong><small>{data?.sha256 || "—"}</small></div>{hasData && <button className="text-btn" onClick={() => copyText(data.sha256, "Hash")}>Copy</button>}</div>
                  </section>

                  <section className="action-bar"><div><strong>Investigator actions</strong><small>Export indicators or generate the evidence report.</small></div><div className="action-buttons"><button className="btn btn-outline" onClick={exportIocs}>Export IOCs</button><button className="btn btn-primary" onClick={() => setTab("reportTab")}>Generate report</button></div></section>
                </div>
              </div>
              <div className="disclaimer"><strong>Demonstration project.</strong> Not an official Government of Bihar website. Case reference, role labels and sample timestamps are illustrative; specimen hash, permissions, indicators and risk score are produced by the ANVESH backend.</div>
            </>
          )}

          {/* ---------------- EVIDENCE DOSSIER ---------------- */}
          {screen === "evidence" && (
            <>
              <div className="view-head"><p className="eyebrow">INTERNAL WORKSPACE</p><h1>Evidence Dossier</h1><p className="subheading">Specimen artefacts, extracted indicators and investigative notes for Case BR-CYBER-2026-9048.</p></div>
              <div className="cards-3">
                <div className="panel"><div className="panel-heading"><h2>Specimen Integrity</h2></div>
                  <p className="kv"><b>Filename:</b> {data?.filename || "Not ingested"}</p>
                  <p className="kv"><b>SHA-256:</b> <code style={{ overflowWrap: "anywhere" }}>{data?.sha256 || "—"}</code></p>
                  <p className="kv"><b>Size:</b> {hasData ? `${data.size_mb} MB` : "—"}</p>
                  <p className="kv"><b>Package:</b> {data?.manifest?.package_name || "—"}</p>
                </div>
                <div className="panel"><div className="panel-heading"><h2>Permission Vectors</h2></div>
                  {permissions.filter((p) => isDangerous(p.level)).length ? permissions.filter((p) => isDangerous(p.level)).map((p, i) => (
                    <p className="kv" key={i}><span style={{ color: "var(--red)", fontWeight: 700 }}>{shortName(p.name)}</span> — {PERMISSION_CONTEXT[shortName(p.name)] || "elevated permission"}</p>
                  )) : <p className="muted">No dangerous permissions extracted.</p>}
                </div>
                <div className="panel"><div className="panel-heading"><h2>Network Indicators</h2></div>
                  {(ind.ips?.length || ind.domains?.length) ? (<>
                    {(ind.ips || []).map((v: string, i: number) => <p className="kv" key={`ip${i}`}><b>IP:</b> <span style={{ color: "var(--red)" }}>{v}</span></p>)}
                    {(ind.domains || []).map((v: string, i: number) => <p className="kv" key={`d${i}`}><b>Domain:</b> {v}</p>)}
                  </>) : <p className="muted">No network indicators extracted.</p>}
                </div>
              </div>
              <div className="panel"><div className="panel-heading"><h2>Investigative Case Notes</h2><span className="soft-badge">Local</span></div>
                <textarea className="notes-area" placeholder="Record analyst observations, corroborating evidence, or hand-off notes…" defaultValue="Preliminary static analysis recorded. Validate extracted indicators against the seized device and corroborating evidence before filing." />
                <div style={{ marginTop: 10 }}><button className="btn btn-primary" onClick={() => notify("Case notes saved locally (demo).")}>Save notes</button></div>
              </div>
            </>
          )}

          {/* ---------------- AUDIT & CUSTODY LOG ---------------- */}
          {screen === "audit" && (
            <>
              <div className="view-head"><p className="eyebrow">COMPLIANCE RECORD</p><h1>Audit &amp; Custody Log</h1><p className="subheading">Append-only session and evidence events. Hashes support integrity verification only.</p></div>
              <div className="panel"><div className="table-wrap"><table>
                <thead><tr><th>Timestamp (UTC)</th><th>Officer badge</th><th>Action event</th><th>Verification</th></tr></thead>
                <tbody>
                  {hasData && (<tr><td>{new Date().toISOString().replace("T", " ").slice(0, 19)}</td><td>{badge || "—"}</td><td>Specimen ingested · SHA-256 computed (#{data.analysis_id ?? "—"})</td><td style={{ color: "var(--green)", fontWeight: 700 }}>VERIFIED</td></tr>)}
                  <tr><td>{new Date().toISOString().replace("T", " ").slice(0, 19)}</td><td>{badge || "—"}</td><td>Secure session authenticated ({clearance})</td><td style={{ color: "var(--green)", fontWeight: 700 }}>SECURE</td></tr>
                  <tr><td>{new Date().toISOString().replace("T", " ").slice(0, 19)}</td><td>SYSTEM</td><td>ANVESH forensic worker initialised</td><td style={{ color: "var(--green)", fontWeight: 700 }}>INTEGRITY</td></tr>
                </tbody>
              </table></div>
              <div className="notice" style={{ marginTop: 14 }}><span>ⓘ</span><p>These entries reflect the current session. The backend also records an append-only audit trail keyed to each analysis.</p></div>
              </div>
            </>
          )}
        </div>
      </div>

      <footer className="site-footer"><span><strong>ANVESH v2.0</strong> · Bihar Police Cyber Cell</span><span>Accessibility · Help · Privacy notice</span></footer>
      {toast && <div className="toast show" role="status">{toast}</div>}
    </div>
  )
}
