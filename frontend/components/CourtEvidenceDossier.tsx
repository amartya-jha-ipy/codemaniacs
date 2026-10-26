"use client";

import React, { useState } from "react";
import {
  Gavel,
  ShieldCheck,
  Scale,
  BookOpen,
  FileText,
  Printer,
  Download,
  ArrowLeft,
  Info,
  CheckCircle2,
  AlertOctagon,
  Copy,
  Check,
  Lock,
  QrCode,
  Search,
  ExternalLink,
  ShieldAlert,
  HelpCircle,
  Smartphone,
  Eye,
  Radio,
  FileCode,
} from "lucide-react";

interface CourtEvidenceDossierProps {
  onBack?: () => void;
}

export default function CourtEvidenceDossier({ onBack }: CourtEvidenceDossierProps) {
  const [activeTab, setActiveTab] = useState<"certificate" | "findings" | "glossary">("certificate");
  const [copiedHash, setCopiedHash] = useState(false);
  const [searchGlossary, setSearchGlossary] = useState("");

  const copyHash = (text: string) => {
    navigator.clipboard.writeText(text);
    setCopiedHash(true);
    setTimeout(() => setCopiedHash(false), 2000);
  };

  // Plain-English translations of every technical term used in the evidentiary dossier
  const judicialGlossary = [
    {
      term: "APK (Android Package Kit)",
      legalMeaning: "The Software Installation File",
      explanation:
        "Think of an APK as an installation envelope or container for a mobile app. Just like an '.exe' file installs software on a Windows computer, an '.apk' installs the entire application and its operational instructions onto an Android smartphone.",
      relevance:
        "Proves that the fraudulent file was packaged and delivered as a complete application ready to take over the victim's device.",
    },
    {
      term: "SHA-256 Cryptographic Checksum",
      legalMeaning: "The Immutable Digital Fingerprint",
      explanation:
        "A mathematical algorithm that generates a unique 64-character fingerprint of a file. If even a single punctuation mark, letter, or byte inside the 14.8 MB file is altered, the fingerprint changes completely.",
      relevance:
        "Satisfies BSA 2023 Section 63 proof of integrity: guarantees that the evidence presented in court today is the EXACT identical specimen seized by police, without tampering or alteration.",
    },
    {
      term: "Trojan Horse / Banking Malware",
      legalMeaning: "Deceptive Impersonation for Theft",
      explanation:
        "Derived from the classic Greek myth. Software that pretends to be a helpful government portal (paying vehicle traffic challans) to trick the user into installing it. Once installed, its real function is criminal: raiding bank accounts.",
      relevance:
        "Establishes fraudulent intent (Mens Rea) and cheating by personation under Section 66D IT Act and Section 420 IPC / 318(4) BNS.",
    },
    {
      term: "Accessibility Service Abuse",
      legalMeaning: "Covert Digital Wiretapping & Keylogging",
      explanation:
        "Accessibility services are designed to assist disabled users (e.g., reading text aloud or clicking buttons for motor-impaired individuals). The malware exploits this permission to silently read every password, MPIN, and text typed by the victim on their phone.",
      relevance:
        "Demonstrates unauthorized interception and intrusion into computer systems under Section 43/66 of the Information Technology Act, 2000.",
    },
    {
      term: "SMS Interception & Suppression",
      legalMeaning: "Gagging 2FA Bank Alerts",
      explanation:
        "When money is withdrawn, banks send a One-Time Password (OTP) or debit alert via SMS. The malware uses an internal program hook to intercept and read this OTP, and immediately silences the phone notification so the victim has no idea the bank alert arrived.",
      relevance:
        "Explains how criminal funds were transferred without the victim receiving warning alerts or suspecting fraudulent activity.",
    },
    {
      term: "Screen Overlay Attack",
      legalMeaning: "Digital Forgery of Banking Windows",
      explanation:
        "When the victim opens legitimate apps like SBI YONO or PNB One, the malware detects this and instantly drops a counterfeit, see-through duplicate form over the screen. The victim believes they are typing into their bank's app, but their credentials go directly to the attacker.",
      relevance:
        "Conclusive proof of fraudulent misrepresentation and credential harvesting.",
    },
    {
      term: "C2 (Command and Control) Server",
      legalMeaning: "Overseas Headquarters / Syndicate Controller",
      explanation:
        "A centralized computer server maintained by cyber criminals (in this case, in the Republic of Seychelles). The malware on the victim's phone dials this server to send stolen bank details and receive updated instructions.",
      relevance:
        "Connects the local seized device to an international cyber fraud conspiracy, indicating cross-border organized crime.",
    },
    {
      term: "DEX (Dalvik Executable) Dynamic Loading",
      legalMeaning: "Concealed Secondary Weapons",
      explanation:
        "To bypass initial police or antivirus inspection, the malware hides its most dangerous attack code in an encrypted compartment. It only unpacks and runs this code inside phone memory once the user opens the application.",
      relevance:
        "Proves calculated premeditation to evade forensic scrutiny and law enforcement detection.",
    },
  ];

  const filteredGlossary = judicialGlossary.filter(
    (item) =>
      item.term.toLowerCase().includes(searchGlossary.toLowerCase()) ||
      item.legalMeaning.toLowerCase().includes(searchGlossary.toLowerCase()) ||
      item.explanation.toLowerCase().includes(searchGlossary.toLowerCase())
  );

  return (
    <div className="min-h-screen bg-[#070a12] text-[#dfe2ee] font-sans antialiased p-4 md:p-8">
      {/* Top Navigation & Action Strip */}
      <div className="max-w-6xl mx-auto mb-6 flex flex-wrap items-center justify-between gap-4 border-b border-white/10 pb-4 print:hidden">
        <button
          onClick={onBack}
          className="flex items-center gap-2 bg-[#121826] hover:bg-[#1a2336] text-cyan-400 font-mono text-xs px-3.5 py-2 rounded transition-colors border border-cyan-500/20"
        >
          <ArrowLeft className="w-4 h-4" />
          <span>Return to Active Investigation Console</span>
        </button>

        <div className="flex items-center gap-2">
          {/* Tab switches */}
          <div className="bg-[#121826] border border-white/10 rounded p-1 flex items-center font-mono text-xs">
            <button
              onClick={() => setActiveTab("certificate")}
              className={`px-3 py-1.5 rounded transition-all ${
                activeTab === "certificate"
                  ? "bg-cyan-500 text-[#090d16] font-bold shadow"
                  : "text-white/60 hover:text-white"
              }`}
            >
              Sec 63 BSA Certificate
            </button>
            <button
              onClick={() => setActiveTab("findings")}
              className={`px-3 py-1.5 rounded transition-all ${
                activeTab === "findings"
                  ? "bg-cyan-500 text-[#090d16] font-bold shadow"
                  : "text-white/60 hover:text-white"
              }`}
            >
              Layman Modus Operandi
            </button>
            <button
              onClick={() => setActiveTab("glossary")}
              className={`px-3 py-1.5 rounded transition-all flex items-center gap-1.5 ${
                activeTab === "glossary"
                  ? "bg-cyan-500 text-[#090d16] font-bold shadow"
                  : "text-white/60 hover:text-white"
              }`}
            >
              <BookOpen className="w-3.5 h-3.5" />
              <span>Judicial Terms Decoder ({judicialGlossary.length})</span>
            </button>
          </div>

          <button
            onClick={() => window.print()}
            className="flex items-center gap-1.5 bg-[#121826] hover:bg-[#1a2336] text-white font-mono text-xs px-3.5 py-2 rounded border border-white/10 transition-colors"
          >
            <Printer className="w-4 h-4 text-cyan-400" />
            <span>Print Dossier</span>
          </button>

          <button
            onClick={() => alert("Downloading Cryptographically Signed PDF Dossier (CIPA/BSA Sealed)...")}
            className="flex items-center gap-1.5 bg-cyan-500 hover:bg-cyan-400 text-[#090d16] font-mono text-xs font-bold px-4 py-2 rounded transition-colors shadow-lg shadow-cyan-500/20"
          >
            <Download className="w-4 h-4" />
            <span>Download Signed Court PDF</span>
          </button>
        </div>
      </div>

      {/* Main Legal Document Sheet */}
      <div className="max-w-5xl mx-auto bg-[#0d121f] border border-white/15 rounded-lg shadow-2xl p-6 md:p-12 print:bg-white print:text-black print:border-none print:p-0 print:shadow-none">
        
        {/* ============================================================== */}
        {/* TAB 1: FORMAL SECTION 63 BSA CERTIFICATE                       */}
        {/* ============================================================== */}
        {activeTab === "certificate" && (
          <div className="flex flex-col gap-6">
            {/* Judicial Header Emblem & Jurisdiction */}
            <div className="text-center flex flex-col items-center border-b border-white/10 pb-6 print:border-black/20">
              <div className="w-14 h-14 rounded-full bg-cyan-500/10 border border-cyan-500/30 flex items-center justify-center text-cyan-400 mb-3 print:border-black print:text-black">
                <Scale className="w-8 h-8" />
              </div>
              <span className="font-mono text-xs tracking-widest uppercase text-white/50 print:text-black/60">
                IN THE COURT OF THE CHIEF JUDICIAL MAGISTRATE, PATNA, BIHAR
              </span>
              <h1 className="text-xl md:text-2xl font-bold font-sans mt-1 text-white tracking-tight print:text-black">
                CERTIFICATE OF ADMISSIBILITY FOR ELECTRONIC EVIDENCE
              </h1>
              <span className="font-mono text-xs text-cyan-400 font-semibold mt-1 print:text-black">
                [Under Section 63 of Bharatiya Sakshya Adhiniyam, 2023 (BSA)]
              </span>
              <span className="text-[11px] font-mono text-white/40 mt-0.5 print:text-black/50">
                (Erstwhile Section 65B of the Indian Evidence Act, 1872)
              </span>
            </div>

            {/* Matter Reference & Police Station Records */}
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4 bg-[#080b14] p-4 rounded border border-white/5 font-mono text-xs print:bg-gray-50 print:border-black/20 print:text-black">
              <div className="flex flex-col gap-1.5">
                <div>
                  <span className="text-white/40 print:text-black/60">POLICE STATION: </span>
                  <span className="text-white font-semibold print:text-black">Cyber Crime PS, Kotwali, Patna</span>
                </div>
                <div>
                  <span className="text-white/40 print:text-black/60">FIR REFERENCE: </span>
                  <span className="text-cyan-400 font-bold print:text-black">FIR No. 119/2024 dated 14.11.2024</span>
                </div>
                <div>
                  <span className="text-white/40 print:text-black/60">CHARGES / SECTIONS: </span>
                  <span className="text-rose-400 font-semibold print:text-black">Sec 66D IT Act, 2000 &amp; Sec 420 IPC</span>
                </div>
              </div>

              <div className="flex flex-col gap-1.5 md:text-right">
                <div>
                  <span className="text-white/40 print:text-black/60">EXAMINING OFFICER: </span>
                  <span className="text-white font-semibold print:text-black">Insp. Rajesh Kumar (Cyber Cell)</span>
                </div>
                <div>
                  <span className="text-white/40 print:text-black/60">LABORATORY / TERMINAL: </span>
                  <span className="text-white print:text-black">Sentinel-CRS Lab Console Station-04</span>
                </div>
                <div>
                  <span className="text-white/40 print:text-black/60">DATE &amp; TIME OF CERTIFICATION: </span>
                  <span className="text-white font-semibold print:text-black">23 February 2025 // 14:26:00 IST</span>
                </div>
              </div>
            </div>

            {/* Statutory Statement by IO */}
            <div className="space-y-4 text-xs md:text-sm text-white/80 leading-relaxed print:text-black">
              <p>
                I, <strong>Rajesh Kumar</strong>, Inspector of Police, Cyber Crime Investigation Division, Patna, do hereby
                solemnly verify, state, and certify as required under <strong>Section 63(4) of the Bharatiya Sakshya Adhiniyam, 2023</strong>:
              </p>

              <ol className="list-decimal list-outside ml-5 space-y-2 text-xs md:text-sm text-white/70 print:text-black/80">
                <li>
                  That I am the digital forensic analyst in lawful command of the electronic forensic workstation (Sentinel-CRS
                  v2.0, Workstation #04) utilized for decompressing, disassembling, and analyzing the digital artifact
                  hereinafter described.
                </li>
                <li>
                  That the specimen analyzed, namely Android application file{" "}
                  <code className="bg-[#161f33] px-1.5 py-0.5 rounded text-cyan-300 font-mono print:bg-gray-100 print:text-black">
                    e-Challan_BiharGov_v2.4.apk
                  </code>
                  , was retrieved from seized physical exhibit item (OnePlus Nord CE, IMEI: 869102049182711) deposited under
                  Evidence Vault Reference <strong>#EV-2025-0914</strong> in unbroken chain of custody.
                </li>
                <li>
                  That throughout the forensic extraction and analysis period, the digital computing environment and forensic
                  hypervisors were operating properly without malfunction, error, or unauthorized external interference.
                </li>
                <li>
                  That the cryptographic digest generated below establishes that the contents of this electronic record are an
                  unmodified, tamper-evident, and faithful representation of the original specimen recovered from the suspect.
                </li>
              </ol>
            </div>

            {/* Cryptographic Specimen Identification Card */}
            <div className="bg-[#080b14] border border-cyan-500/20 rounded-lg p-5 flex flex-col gap-3 print:bg-white print:border-black">
              <div className="flex items-center justify-between">
                <span className="font-mono text-xs text-cyan-400 font-bold uppercase tracking-wider print:text-black">
                  SCHEDULE A: CRYPTOGRAPHIC HASH DIGEST
                </span>
                <span className="bg-cyan-500/10 text-cyan-300 border border-cyan-500/30 font-mono text-[10px] px-2 py-0.5 rounded print:hidden">
                  TAMPER-PROOF VERIFIED
                </span>
              </div>

              <div className="flex flex-col gap-1.5 font-mono text-xs">
                <div className="flex flex-col sm:flex-row sm:items-center justify-between bg-[#121826] p-2.5 rounded border border-white/5 print:bg-gray-50 print:border-black/20">
                  <span className="text-white/40 print:text-black/60">SPECIMEN NAME:</span>
                  <span className="text-white font-bold print:text-black">e-Challan_BiharGov_v2.4.apk</span>
                </div>

                <div className="flex flex-col sm:flex-row sm:items-center justify-between bg-[#121826] p-2.5 rounded border border-white/5 print:bg-gray-50 print:border-black/20">
                  <span className="text-white/40 print:text-black/60">FILE SIZE:</span>
                  <span className="text-white print:text-black">15,518,920 bytes (14.8 MB)</span>
                </div>

                <div className="flex flex-col bg-[#121826] p-2.5 rounded border border-white/5 gap-1 print:bg-gray-50 print:border-black/20">
                  <div className="flex items-center justify-between">
                    <span className="text-white/40 print:text-black/60">ALGORITHM: SHA-256 (Primary Digital Fingerprint)</span>
                    <button
                      onClick={() => copyHash("7d8f3a9e4b1c20849204fae8902d512cebb9103f6789a2b0e91402316e625a1b")}
                      className="text-cyan-400 hover:text-cyan-300 text-[10px] flex items-center gap-1 print:hidden"
                    >
                      {copiedHash ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                      <span>{copiedHash ? "COPIED" : "COPY"}</span>
                    </button>
                  </div>
                  <span className="text-cyan-400 font-bold break-all print:text-black text-[11px]">
                    7d8f3a9e4b1c20849204fae8902d512cebb9103f6789a2b0e91402316e625a1b
                  </span>
                </div>

                <div className="flex flex-col sm:flex-row sm:items-center justify-between bg-[#121826] p-2.5 rounded border border-white/5 print:bg-gray-50 print:border-black/20">
                  <span className="text-white/40 print:text-black/60">ALGORITHM: MD5 CHECKSUM</span>
                  <span className="text-white/80 print:text-black">9a81f0814b6c31a78e8b340156d9812a</span>
                </div>
              </div>
            </div>

            {/* Quick Judicial Primer Box (For Judge) */}
            <div className="bg-[#121826] border-l-4 border-cyan-400 p-4 rounded text-xs leading-relaxed text-white/80 print:bg-gray-100 print:text-black print:border-black">
              <h4 className="font-bold text-cyan-300 font-sans text-sm mb-1 print:text-black flex items-center gap-1.5">
                <Info className="w-4 h-4 text-cyan-400 print:text-black" />
                Note for the Learned Presiding Judge:
              </h4>
              <p>
                The cryptographic SHA-256 value above serves as the specimen's unique digital signature. Any defense counsel
                or independent forensic laboratory can recalculate the hash of the preserved master disk. If even a single
                byte has been added or removed, the number will fail to match. A matching number is scientific and incontrovertible
                proof that this evidence is pure and intact.
              </p>
            </div>

            {/* Signature & Custody Stamp */}
            <div className="pt-6 border-t border-white/10 flex flex-col sm:flex-row items-start sm:items-center justify-between gap-6 print:border-black/20">
              <div className="flex items-center gap-3">
                <div className="w-16 h-16 bg-white p-1 rounded flex items-center justify-center text-black">
                  <QrCode className="w-14 h-14" />
                </div>
                <div className="flex flex-col text-[11px] font-mono text-white/50 print:text-black/70">
                  <span className="text-white font-bold print:text-black">BIHAR POLICE CIPA VALIDATION SEAL</span>
                  <span>TOKEN ID: SEC63-BHR-2025-0842-8819</span>
                  <span>VERIFICATION: https://police.bihar.gov.in/cipa/verify</span>
                </div>
              </div>

              <div className="text-right flex flex-col items-end">
                <div className="h-10 border-b border-dashed border-white/40 w-48 mb-1 print:border-black" />
                <span className="font-bold text-xs text-white print:text-black font-sans">Rajesh Kumar, IPS / Insp.</span>
                <span className="text-[11px] font-mono text-white/50 print:text-black/60">
                  Investigating Officer, Cyber Crime PS
                </span>
                <span className="text-[10px] font-mono text-cyan-400 print:text-black">
                  Digitally Signed &amp; Timestamped (2025.02.23)
                </span>
              </div>
            </div>
          </div>
        )}

        {/* ============================================================== */}
        {/* TAB 2: PLAIN-ENGLISH FINDINGS & MODUS OPERANDI FOR THE COURT   */}
        {/* ============================================================== */}
        {activeTab === "findings" && (
          <div className="flex flex-col gap-6">
            <div className="border-b border-white/10 pb-4">
              <span className="font-mono text-xs text-cyan-400 uppercase tracking-widest font-semibold">
                SCHEDULE B: INVESTIGATIVE FINDINGS FOR THE BENCH
              </span>
              <h2 className="text-xl font-bold text-white mt-1">
                Plain-English Translation of Accused's Digital Modus Operandi
              </h2>
              <p className="text-xs text-white/60 mt-1">
                Prepared by the Cyber Cell for the Court of Chief Judicial Magistrate, Patna.
              </p>
            </div>

            {/* Plain-English 4-Step Narrative */}
            <div className="grid grid-cols-1 gap-4 text-xs md:text-sm">
              {/* Step 1 */}
              <div className="bg-[#080b14] border border-white/10 rounded-lg p-5 flex flex-col gap-2">
                <div className="flex items-center gap-2">
                  <span className="w-6 h-6 rounded-full bg-cyan-500/20 text-cyan-400 font-mono font-bold flex items-center justify-center text-xs">
                    1
                  </span>
                  <h3 className="font-bold text-white text-sm font-sans">
                    The Deception: Fake Government Fine Payment Portal (Cheating &amp; Personation)
                  </h3>
                </div>
                <div className="ml-8 text-white/70 leading-relaxed space-y-1.5">
                  <p>
                    The accused created an application titled{" "}
                    <strong className="text-white">"e-Challan BiharGov Transport"</strong> using the official state emblem
                    and Bihar Transport Department color schemes.
                  </p>
                  <p>
                    Victims received SMS messages stating that their vehicle had an outstanding traffic fine with a link to
                    download this APK. In reality, the application had no connection with the Bihar Government and was an
                    unauthorized counterfeit instrument.
                  </p>
                  <div className="bg-[#121826] p-2.5 rounded font-mono text-[11px] text-amber-400 border border-amber-500/20 mt-1">
                    LEGAL OFFENCE: Cheating by personation using computer resource under Section 66D IT Act &amp; Section 420 IPC.
                  </div>
                </div>
              </div>

              {/* Step 2 */}
              <div className="bg-[#080b14] border border-white/10 rounded-lg p-5 flex flex-col gap-2">
                <div className="flex items-center gap-2">
                  <span className="w-6 h-6 rounded-full bg-rose-500/20 text-rose-400 font-mono font-bold flex items-center justify-center text-xs">
                    2
                  </span>
                  <h3 className="font-bold text-white text-sm font-sans">
                    The Wiretap: Hijacking Accessibility &amp; Secret Keylogging
                  </h3>
                </div>
                <div className="ml-8 text-white/70 leading-relaxed space-y-1.5">
                  <p>
                    Once installed, the app urgently prompts the victim to enable "Accessibility Permissions" under the false
                    pretense of "Security Updates".
                  </p>
                  <p>
                    The moment the victim agrees, the malware gains complete control over the smartphone display. It logs every
                    keystroke, reads the screen in real-time, and captures User IDs and passwords typed into banking applications
                    including <strong>State Bank of India (YONO), Punjab National Bank, and HDFC</strong>.
                  </p>
                  <div className="bg-[#121826] p-2.5 rounded font-mono text-[11px] text-rose-400 border border-rose-500/20 mt-1">
                    LEGAL OFFENCE: Unauthorized extraction and copying of data under Section 43(a) &amp; Section 66 IT Act.
                  </div>
                </div>
              </div>

              {/* Step 3 */}
              <div className="bg-[#080b14] border border-white/10 rounded-lg p-5 flex flex-col gap-2">
                <div className="flex items-center gap-2">
                  <span className="w-6 h-6 rounded-full bg-rose-500/20 text-rose-400 font-mono font-bold flex items-center justify-center text-xs">
                    3
                  </span>
                  <h3 className="font-bold text-white text-sm font-sans">
                    The Hijack: Interception and Silence of 2FA Banking OTPs
                  </h3>
                </div>
                <div className="ml-8 text-white/70 leading-relaxed space-y-1.5">
                  <p>
                    When the cyber syndicate initiates fraudulent money transfers from the victim's account, the bank issues a
                    One-Time Password (OTP) via SMS to verify the transaction.
                  </p>
                  <p>
                    The malware contains an automated hook (
                    <code className="text-rose-400 font-mono">android.permission.RECEIVE_SMS</code>) that snatches the OTP
                    before the phone's inbox can display it. Simultaneously, it instructs the phone's sound card to mute the
                    inbound alert sound, ensuring the victim does not look at the phone while money is being siphoned.
                  </p>
                  <div className="bg-[#121826] p-2.5 rounded font-mono text-[11px] text-rose-400 border border-rose-500/20 mt-1">
                    LEGAL OFFENCE: Tampering with computer source documents and destructive interference under Section 65 &amp; 66 IT Act.
                  </div>
                </div>
              </div>

              {/* Step 4 */}
              <div className="bg-[#080b14] border border-white/10 rounded-lg p-5 flex flex-col gap-2">
                <div className="flex items-center gap-2">
                  <span className="w-6 h-6 rounded-full bg-cyan-500/20 text-cyan-400 font-mono font-bold flex items-center justify-center text-xs">
                    4
                  </span>
                  <h3 className="font-bold text-white text-sm font-sans">
                    The Exfiltration: Transmission to Overseas Syndicate C2 and Telegram Bot
                  </h3>
                </div>
                <div className="ml-8 text-white/70 leading-relaxed space-y-1.5">
                  <p>
                    The captured banking passwords, MPINs, and intercepted OTPs are immediately packaged and transmitted via an
                    encrypted internet tunnel to an overseas IP address (
                    <code className="text-cyan-400 font-mono">185.220.101.42</code>, registered in Seychelles) and a linked
                    Telegram Bot channel (<code className="text-cyan-400 font-mono">chat_id: -1002049182</code>).
                  </p>
                  <p>
                    This transmission was scientifically recorded and corroborated in the live dynamic Dalvik sandbox trace
                    annexed to this charge sheet.
                  </p>
                  <div className="bg-[#121826] p-2.5 rounded font-mono text-[11px] text-cyan-400 border border-cyan-500/20 mt-1">
                    LEGAL OFFENCE: Criminal conspiracy and cross-border digital financial fraud under Section 120B IPC &amp; 66D IT Act.
                  </div>
                </div>
              </div>
            </div>
          </div>
        )}

        {/* ============================================================== */}
        {/* TAB 3: JUDICIAL TERMS DECODER (GLOSSARY FOR NON-TECHNICAL JUDGE) */}
        {/* ============================================================== */}
        {activeTab === "glossary" && (
          <div className="flex flex-col gap-6">
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-white/10 pb-4">
              <div>
                <span className="font-mono text-xs text-cyan-400 uppercase tracking-widest font-semibold">
                  SCHEDULE C: JUDICIAL TERMS DECODER
                </span>
                <h2 className="text-xl font-bold text-white mt-1">
                  Plain-Language Legal Glossary for the Bench
                </h2>
                <p className="text-xs text-white/60">
                  Every technical term used in this report, translated into ordinary courtroom language.
                </p>
              </div>

              {/* Glossary Search Box */}
              <div className="relative w-full sm:w-64">
                <Search className="w-4 h-4 text-white/40 absolute left-3 top-2.5" />
                <input
                  type="text"
                  placeholder="Search technical term..."
                  value={searchGlossary}
                  onChange={(e) => setSearchGlossary(e.target.value)}
                  className="w-full bg-[#080b14] border border-white/10 rounded pl-9 pr-3 py-1.5 font-mono text-xs text-white focus:outline-none focus:border-cyan-400"
                />
              </div>
            </div>

            {/* Glossary Term Cards */}
            <div className="grid grid-cols-1 gap-4">
              {filteredGlossary.length === 0 ? (
                <div className="text-center py-12 text-white/40 font-mono text-xs">
                  No matching technical terms found in the judicial glossary.
                </div>
              ) : (
                filteredGlossary.map((item, index) => (
                  <div
                    key={index}
                    className="bg-[#080b14] border border-white/10 rounded-lg p-5 flex flex-col gap-3 hover:border-cyan-500/30 transition-colors"
                  >
                    <div className="flex flex-wrap items-center justify-between gap-2 border-b border-white/5 pb-2">
                      <div className="flex items-center gap-2">
                        <BookOpen className="w-4 h-4 text-cyan-400" />
                        <span className="font-mono text-sm font-bold text-white">{item.term}</span>
                      </div>
                      <span className="bg-[#121826] text-amber-400 border border-amber-500/20 font-mono text-[11px] px-2.5 py-0.5 rounded font-semibold">
                        Court Meaning: {item.legalMeaning}
                      </span>
                    </div>

                    <div className="text-xs text-white/80 leading-relaxed">
                      <strong className="text-white/40 block mb-0.5 font-mono uppercase text-[10px]">
                        Simple Explanation:
                      </strong>
                      {item.explanation}
                    </div>

                    <div className="bg-[#121826] p-2.5 rounded text-xs text-cyan-300/90 leading-relaxed border border-cyan-500/10">
                      <strong className="text-cyan-400 block mb-0.5 font-mono uppercase text-[10px]">
                        Evidentiary Relevance for the Trial:
                      </strong>
                      {item.relevance}
                    </div>
                  </div>
                ))
              )}
            </div>
          </div>
        )}
      </div>
    </div>
  );
}