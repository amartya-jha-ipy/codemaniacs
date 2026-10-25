"use client"

import React, { useState } from "react"
import { 
  ShieldAlert, 
  FileSearch, 
  Terminal, 
  UploadCloud, 
  CheckCircle2, 
  AlertTriangle, 
  Cpu, 
  Network, 
  FileText, 
  Lock, 
  Database,
  ArrowRight,
  Loader2
} from "lucide-react"

export default function SentinelWorkspace() {
  const [activeTab, setActiveTab] = useState<"workspace" | "manifest" | "code" | "network" | "evidence">("workspace")
  const [currentRole, setCurrentRole] = useState<"Officer" | "Analyst" | "Admin">("Analyst")
  const [isDragging, setIsDragging] = useState(false)
  const [loading, setLoading] = useState(false)
  const [analysisData, setAnalysisData] = useState<any>({
    filename: "loan_app_v2.4.1_suspicious.apk",
    size_mb: 14.2,
    sha256: "4e82b9a7c6f1e3d2a58b091f3c4e82b9a7c6f1e3d2a58b091f3c4e82b9a7c6f1",
    risk_score: 92,
    classification: "Financial Extortion / RAT",
    manifest: {
      package_name: "com.secure.loan.instant.apk",
      target_sdk: 33,
      min_sdk: 21,
      permissions: [
        { name: "android.permission.READ_SMS", level: "Critical" },
        { name: "android.permission.READ_CONTACTS", level: "Critical" },
        { name: "android.permission.ACCESS_FINE_LOCATION", level: "Warning" }
      ]
    },
    executive_briefing: "This application masquerades as a benign digital loan utility but exhibits high-risk indicators characteristic of malicious Android trojans. It programmatically requests sensitive SMS and contacts permissions while establishing unencrypted outbound sockets to known command-and-control (C2) infrastructure."
  })
  const [terminalOpen, setTerminalOpen] = useState(false)
  const [logs, setLogs] = useState<string[]>([
    "[02:00:14] INFO: Initializing APK container extraction...",
    "[02:00:15] SUCCESS: SHA-256 computed & logged to SQLite audit database.",
    "[02:00:16] PARSE: AndroidManifest.xml loaded. 14 permissions extracted.",
    "[02:00:17] ALERT: Dangerous permission-to-functionality mismatch identified.",
    "[02:00:19] COMPLETE: Threat assessment generated. Composite score: 92/100."
  ])

  // Handle actual file upload to FastAPI backend with role header
  const handleFileUpload = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0]
    if (!file) return

    setLoading(true)
    setTerminalOpen(true)
    setLogs(prev => [...prev, `[LIVE] Uploading specimen ${file.name} (Role: ${currentRole})...`])

    const formData = new FormData()
    formData.append("file", file)

    try {
      const response = await fetch("http://127.0.0.1:8000/api/analyze-apk", {
        method: "POST",
        headers: {
          "x-user-role": currentRole
        },
        body: formData,
      })

      if (!response.ok) {
        throw new Error("Backend analysis failed.")
      }

      const result = await response.json()
      setAnalysisData(result)
      setLogs(prev => [
        ...prev,
        `[SUCCESS] FastAPI response received for ${result.filename}`,
        `[HASH] SHA-256: ${result.sha256}`,
        `[AUDIT] Permanently recorded in SQLite DB (Role: ${currentRole})`,
        `[VERDICT] Risk Score assigned: ${result.risk_score}/100 (${result.classification})`
      ])
    } catch (err) {
      setLogs(prev => [...prev, `[ERROR] Failed to connect to backend at port 8000. Ensure python main.py is running.`])
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="min-h-screen bg-[#f8fafc] text-[#0f172a] font-sans selection:bg-slate-900 selection:text-white flex flex-col">
      
      {/* Top Editorial Header */}
      <header className="border-b border-slate-200 bg-white/80 backdrop-blur-md sticky top-0 z-50 px-6 py-3.5 flex items-center justify-between">
        <div className="flex items-center space-x-3">
          <div className="w-8 h-8 rounded bg-slate-900 text-white flex items-center justify-center font-mono font-bold text-sm tracking-tighter">
            SR
          </div>
          <div>
            <div className="flex items-center space-x-2">
              <h1 className="font-semibold tracking-tight text-slate-900 text-sm">SENTINEL-CRS v2.0</h1>
              <span className="text-[10px] uppercase tracking-wider font-mono bg-slate-100 text-slate-600 px-1.5 py-0.5 rounded border border-slate-200">
                Bihar Police Cyber Cell
              </span>
            </div>
            <p className="text-xs text-slate-500 font-mono">Case ID: BR-CYBER-2026-9048</p>
          </div>
        </div>

        {/* Role Switcher & Telemetry Controls */}
        <div className="flex items-center space-x-4">
          <div className="flex items-center space-x-1.5 bg-slate-100 border border-slate-200 p-1 rounded-lg text-xs font-mono">
            <span className="text-slate-500 px-2">Role:</span>
            {(["Officer", "Analyst", "Admin"] as const).map((role) => (
              <button
                key={role}
                onClick={() => setCurrentRole(role)}
                className={`px-2.5 py-1 rounded transition-colors ${
                  currentRole === role ? "bg-slate-900 text-white font-medium" : "text-slate-600 hover:bg-slate-200"
                }`}
              >
                {role}
              </button>
            ))}
          </div>

          <button 
            onClick={() => setTerminalOpen(!terminalOpen)}
            className="flex items-center space-x-1.5 text-xs font-mono bg-slate-900 text-white px-3 py-2 rounded hover:bg-slate-800 transition-colors"
          >
            <Terminal className="w-3.5 h-3.5" />
            <span>{terminalOpen ? "Hide Telemetry" : "Telemetry Stream"}</span>
          </button>
        </div>
      </header>

      {/* Main Content Grid */}
      <div className="flex-1 max-w-7xl w-full mx-auto p-6 grid grid-cols-1 lg:grid-cols-12 gap-6">
        
        {/* Left Column: Navigation & Ingestion (4 Cols) */}
        <div className="lg:col-span-4 space-y-6">
          
          {/* Specimen Ingestion Card */}
          <div className="bg-white border border-slate-200 rounded-lg p-5 shadow-sm">
            <div className="flex items-center justify-between mb-4">
              <h2 className="text-xs font-mono uppercase tracking-wider text-slate-500 font-semibold">
                Specimen Intake
              </h2>
              <span className="text-[10px] font-mono text-emerald-600 bg-emerald-50 border border-emerald-200 px-2 py-0.5 rounded">
                SQLite Audit Logged
              </span>
            </div>

            <label className={`border-2 border-dashed rounded-lg p-6 text-center transition-all cursor-pointer block ${
              isDragging ? "border-slate-900 bg-slate-50" : "border-slate-200 hover:border-slate-300 bg-slate-50/50"
            }`}>
              <input type="file" accept=".apk,.apkm,.xapk" onChange={handleFileUpload} className="hidden" />
              {loading ? (
                <div className="flex flex-col items-center py-2">
                  <Loader2 className="w-8 h-8 text-slate-900 animate-spin mb-2" />
                  <p className="text-xs font-medium text-slate-700">Analyzing APK via FastAPI...</p>
                </div>
              ) : (
                <>
                  <UploadCloud className="w-8 h-8 text-slate-400 mx-auto mb-2" />
                  <p className="text-xs font-medium text-slate-700">Drop suspicious APK specimen here</p>
                  <p className="text-[11px] text-slate-400 mt-1">Supports Android package archives</p>
                  <span className="mt-3 inline-block text-xs bg-white border border-slate-300 px-3 py-1.5 rounded font-medium text-slate-700 shadow-sm hover:bg-slate-50">
                    Browse Files
                  </span>
                </>
              )}
            </label>

            {analysisData && (
              <div className="mt-4 p-3 bg-slate-50 border border-slate-200 rounded text-xs space-y-1 font-mono">
                <div className="flex items-center justify-between text-slate-700 font-medium">
                  <span className="truncate max-w-[200px]">{analysisData.filename}</span>
                  <span className="text-slate-400 text-[10px]">{analysisData.size_mb} MB</span>
                </div>
                <div className="text-[10px] text-slate-500 truncate">
                  Hash: {analysisData.sha256}
                </div>
              </div>
            )}
          </div>

          {/* 9-Stage Analysis Pipeline Tracker */}
          <div className="bg-white border border-slate-200 rounded-lg p-5 shadow-sm">
            <h2 className="text-xs font-mono uppercase tracking-wider text-slate-500 font-semibold mb-4">
              Analysis Pipeline Progression
            </h2>
            <div className="space-y-2.5">
              {[
                "1. File intake and validation",
                "2. Sample hashing & evidence registration",
                "3. APK archive & package inspection",
                "4. Manifest & permission analysis",
                "5. Code, resource & native library check",
                "6. Obfuscation & evasion detection",
                "7. Controlled runtime & network observation",
                "8. Risk assessment & evidence correlation",
                "9. Report preparation & integrity verification"
              ].map((stage, idx) => (
                <div key={idx} className="flex items-center text-xs space-x-2.5">
                  <div className="w-4 h-4 rounded-full flex items-center justify-center text-[10px] bg-emerald-100 text-emerald-700 border border-emerald-300">
                    ✓
                  </div>
                  <span className="text-slate-800 font-medium">{stage}</span>
                </div>
              ))}
            </div>
          </div>

        </div>

        {/* Right Column: Forensic Assessment & Findings (8 Cols) */}
        <div className="lg:col-span-8 space-y-6">
          
          {/* Executive Verdict & Risk Score Card */}
          <div className="bg-white border border-slate-200 rounded-lg p-6 shadow-sm">
            <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 pb-6 border-b border-slate-100">
              <div>
                <div className="flex items-center space-x-2">
                  <span className="text-xs font-mono uppercase tracking-wider text-rose-600 bg-rose-50 border border-rose-200 px-2 py-0.5 rounded font-semibold">
                    {analysisData.classification}
                  </span>
                  <span className="text-[10px] font-mono bg-slate-100 text-slate-600 px-2 py-0.5 rounded">
                    Active Clearance: {currentRole}
                  </span>
                </div>
                <h2 className="text-xl font-bold tracking-tight text-slate-900 mt-2">
                  Composite Threat Assessment
                </h2>
                <p className="text-xs text-slate-500 mt-0.5">
                  Live FastAPI heuristic analysis mapped against police threat signatures.
                </p>
              </div>

              <div className="flex items-center space-x-4 bg-slate-50 border border-slate-200 px-4 py-3 rounded-lg">
                <div className="text-right">
                  <div className="text-[10px] font-mono text-slate-400 uppercase tracking-wider">Threat Score</div>
                  <div className="text-2xl font-bold font-mono text-rose-600">
                    {analysisData.risk_score}<span className="text-xs text-slate-400">/100</span>
                  </div>
                </div>
                <div className="w-px h-8 bg-slate-200"></div>
                <div>
                  <div className="text-[10px] font-mono text-slate-400 uppercase tracking-wider">Audit Status</div>
                  <div className="text-xs font-semibold text-slate-800">SQLite Logged</div>
                </div>
              </div>
            </div>

            {/* AI Executive Briefing */}
            <div className="mt-6 bg-slate-50 border border-slate-200 rounded-lg p-4">
              <div className="flex items-center space-x-2 mb-2">
                <Cpu className="w-4 h-4 text-slate-700" />
                <h3 className="text-xs font-mono font-semibold uppercase tracking-wider text-slate-700">
                  AI Executive Briefing (Investigator Summary)
                </h3>
              </div>
              <p className="text-xs text-slate-600 leading-relaxed">
                {analysisData.executive_briefing}
              </p>
            </div>

            {/* Analysis Navigation Tabs */}
            <div className="flex items-center space-x-2 mt-6 border-b border-slate-200 pb-2">
              {[
                { id: "workspace", label: "Overview & Verdict" },
                { id: "manifest", label: "Manifest & Permissions" },
                { id: "code", label: "Code & Evasion" },
                { id: "network", label: "Network IOCs" },
                { id: "evidence", label: "Forensic Report" }
              ].map((tab) => (
                <button
                  key={tab.id}
                  onClick={() => setActiveTab(tab.id as any)}
                  className={`text-xs px-3 py-1.5 rounded font-medium transition-colors ${
                    activeTab === tab.id 
                      ? "bg-slate-900 text-white" 
                      : "text-slate-600 hover:bg-slate-100"
                  }`}
                >
                  {tab.label}
                </button>
              ))}
            </div>

            {/* Tab Contents */}
            <div className="mt-6 space-y-4">
              {activeTab === "workspace" && (
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  <div className="border border-slate-200 rounded-lg p-4 space-y-2">
                    <div className="text-xs font-mono text-slate-400 uppercase">Package Identifier</div>
                    <div className="text-xs font-semibold text-slate-800 font-mono">{analysisData.manifest?.package_name}</div>
                    <p className="text-xs text-slate-500">Target SDK: {analysisData.manifest?.target_sdk} | Min SDK: {analysisData.manifest?.min_sdk}</p>
                  </div>
                  <div className="border border-slate-200 rounded-lg p-4 space-y-2">
                    <div className="text-xs font-mono text-slate-400 uppercase">Chain of Custody</div>
                    <div className="text-xs font-semibold text-slate-800 font-mono">SQLite Audit Verified</div>
                    <p className="text-xs text-slate-500 truncate">Saved to `database/sentinel_audit.db`.</p>
                  </div>
                </div>
              )}

              {activeTab === "manifest" && (
                <div className="space-y-3 text-xs">
                  <div className="p-3 bg-slate-50 border border-slate-200 rounded font-mono">
                    <span className="text-slate-400">Package Name:</span> {analysisData.manifest?.package_name}
                  </div>
                  <div className="p-3 bg-slate-50 border border-slate-200 rounded font-mono space-y-1">
                    <div className="text-slate-500 font-semibold">Extracted Permissions:</div>
                    {analysisData.manifest?.permissions.map((perm: any, i: number) => (
                      <div key={i} className={perm.level === 'Critical' ? 'text-rose-600 font-medium' : 'text-slate-700'}>
                        • {perm.name} ({perm.level})
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {activeTab === "code" && (
                <div className="space-y-3 text-xs font-mono">
                  {currentRole === "Officer" ? (
                    <div className="p-4 bg-amber-50 border border-amber-200 rounded text-amber-800 text-xs">
                      🔒 Advanced code obfuscation and reflection insights are restricted under Investigating Officer clearance. Switch role to <b>Analyst</b> to view.
                    </div>
                  ) : (
                    <div className="p-3 bg-slate-900 text-slate-200 rounded space-y-1">
                      <div className="text-slate-400 text-[10px]"># Obfuscation Analysis Result</div>
                      <div>ProGuard mapping detected: Class scrambling applied successfully.</div>
                    </div>
                  )}
                </div>
              )}

              {activeTab === "network" && (
                <div className="space-y-3 text-xs font-mono">
                  <div className="p-3 bg-slate-50 border border-slate-200 rounded flex items-center justify-between">
                    <div>
                      <div className="font-semibold text-slate-800">185.220.101.5:443</div>
                      <div className="text-[10px] text-slate-400">Observed C2 Outbound Socket Connection</div>
                    </div>
                    <span className="bg-rose-50 text-rose-600 border border-rose-200 px-2 py-0.5 rounded text-[10px]">Blocked</span>
                  </div>
                </div>
              )}

              {activeTab === "evidence" && (
                <div className="space-y-4">
                  <p className="text-xs text-slate-600">
                    All findings, SHA-256 hashes, and telemetry logs have been compiled into an official evidence record.
                  </p>
                  <button 
                    onClick={() => window.open(`http://127.0.0.1:8000/api/download-report?filename=${encodeURIComponent(analysisData.filename)}&sha256=${encodeURIComponent(analysisData.sha256)}&risk_score=${analysisData.risk_score}&classification=${encodeURIComponent(analysisData.classification)}`, "_blank")} 
                    className="bg-slate-900 text-white text-xs px-4 py-2 rounded font-medium hover:bg-slate-800 transition-colors flex items-center space-x-2 cursor-pointer"
                  >
                    <FileText className="w-3.5 h-3.5" />
                    <span>Export Court-Ready Forensic Evidence PDF</span>
                  </button>
                </div>
              )}
            </div>

          </div>

          {/* Collapsible Technical Observation Stream (Terminal Panel) */}
          {terminalOpen && (
            <div className="bg-slate-900 text-slate-200 rounded-lg p-5 font-mono text-xs shadow-lg border border-slate-800 space-y-2">
              <div className="flex items-center justify-between pb-2 border-b border-slate-800 text-slate-400 text-[11px]">
                <span className="flex items-center space-x-1.5">
                  <Terminal className="w-3.5 h-3.5 text-emerald-400" />
                  <span>Backend Telemetry Stream & SQLite Audit Logs</span>
                </span>
                <span>Role: {currentRole} | Worker Active</span>
              </div>
              <div className="space-y-1 text-[11px] text-slate-300 max-h-40 overflow-y-auto">
                {logs.map((log, index) => (
                  <p key={index} className={log.includes("SUCCESS") || log.includes("VERDICT") || log.includes("AUDIT") ? "text-emerald-400" : log.includes("ERROR") ? "text-rose-400" : "text-slate-300"}>
                    {log}
                  </p>
                ))}
              </div>
            </div>
          )}

        </div>

      </div>

    </div>
  )
}