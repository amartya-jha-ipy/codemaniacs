"use client"

import React, { useState, useEffect, useCallback } from "react"
import Link from "next/link"
import {
  ChevronLeft, ChevronRight, ShieldCheck, UploadCloud, FileText, Lock,
  Phone, Mail, MapPin, ArrowRight, ScanSearch, PackageOpen, FlaskConical, Radar,
  GitCompareArrows, FileCheck2, Siren, ExternalLink, Fingerprint,
} from "lucide-react"

// National Emblem of India (served from /public/emblem.svg).
function Emblem({ className = "w-9 h-9" }: { className?: string }) {
  // eslint-disable-next-line @next/next/no-img-element
  return <img src="/emblem.svg" alt="State Emblem of India" className={`object-contain ${className}`} />
}

const SLIDES = [
  {
    title: "Android Malware Forensics for the Bihar Cyber Police",
    text: "Submit a seized APK and get static analysis, anti-evasion unpacking and a behavioural sandbox in a single, auditable pipeline.",
    cta: "Launch Analysis Console",
    image: "/slide1.jpg",
  },
  {
    title: "Court-Ready Digital Evidence",
    text: "Findings are compiled into a signed PDF evidence record, with a tamper-evident, hash-chained audit log preserving the chain of custody.",
    cta: "Open the Console",
    image: "/slide2.jpg",
  },
  {
    title: "From Specimen to Risk Score",
    text: "Permissions, suspicious APIs, network indicators and similarity to known samples are correlated into a single composite risk assessment.",
    cta: "Analyse a Specimen",
    image: "/slide1.jpg",
  },
]

const CAPABILITIES = [
  { icon: ScanSearch, t: "Static Manifest & Permission Analysis", d: "Recovers requested permissions, suspicious API strings and package metadata directly from the APK." },
  { icon: PackageOpen, t: "Anti-Evasion Unpacking", d: "Flags manifest padding, hidden encrypted payloads, dynamic code loading and string encryption." },
  { icon: FlaskConical, t: "Behavioural Sandbox (Simulated)", d: "Models runtime behaviour to escalate the composite risk score from low to critical." },
  { icon: Radar, t: "IOC Matching", d: "Cross-references extracted IPs, domains and file hashes against a local indicator database." },
  { icon: GitCompareArrows, t: "Similarity & Clustering", d: "Compares a specimen's static features against previously analysed APKs to surface related samples." },
  { icon: FileCheck2, t: "Court-Ready Report & Audit Trail", d: "Exports a signed PDF evidence package backed by an append-only, hash-chained audit log." },
]

const STEPS = [
  { n: "1", t: "Ingest & Hash", d: "APK is validated and fingerprinted with SHA-256 for chain of custody." },
  { n: "2", t: "Static & Anti-Evasion", d: "Manifest, permissions, strings and evasion techniques are extracted." },
  { n: "3", t: "Sandbox Simulation", d: "Behavioural indicators are modelled and correlated with IOCs." },
  { n: "4", t: "Risk Score & Report", d: "A composite score is graded and a court-ready PDF is generated." },
]

const NAV = [
  { label: "Home", href: "#top" },
  { label: "About", href: "#about" },
  { label: "Capabilities", href: "#capabilities" },
  { label: "How it Works", href: "#how" },
  { label: "Report Cybercrime", href: "https://cybercrime.gov.in", external: true },
  { label: "Bihar Police", href: "https://police.bihar.gov.in", external: true },
  { label: "Feedback", href: "/feedback" },
  { label: "Contact", href: "#contact" },
]

export default function DigitalPoliceLanding() {
  const [slide, setSlide] = useState(0)
  const [fontScale, setFontScale] = useState(1)

  const next = useCallback(() => setSlide(s => (s + 1) % SLIDES.length), [])
  const prev = useCallback(() => setSlide(s => (s - 1 + SLIDES.length) % SLIDES.length), [])
  useEffect(() => { const t = setInterval(next, 6000); return () => clearInterval(t) }, [next])

  const active = SLIDES[slide]

  return (
    <div id="top" className="min-h-screen bg-white text-[#1a2340] font-sans flex flex-col selection:bg-[#ff9933] selection:text-white"
         style={{ fontSize: `${fontScale}rem` }}>

      {/* Utility strip */}
      <div className="w-full text-[11px] flex items-center justify-between px-5 py-1.5"
           style={{ background: "linear-gradient(90deg,#ff9933 0%,#f4ead2 50%,#138808 100%)" }}>
        <span className="font-semibold tracking-wide text-[#1a2340]">
          बिहार सरकार · गृह विभाग (आरक्षी) &nbsp;|&nbsp; GOVERNMENT OF BIHAR · HOME (POLICE) DEPARTMENT
        </span>
        <div className="flex items-center space-x-3 text-[#1a2340] font-medium">
          <a href="#main" className="hover:underline">Skip to Main Content</a>
          <span className="opacity-40">|</span>
          <div className="flex items-center space-x-1">
            <button onClick={() => setFontScale(s => Math.min(1.25, +(s + 0.1).toFixed(2)))} className="hover:underline font-bold" aria-label="Increase text size">A+</button>
            <button onClick={() => setFontScale(1)} className="hover:underline" aria-label="Reset text size">A</button>
            <button onClick={() => setFontScale(s => Math.max(0.85, +(s - 0.1).toFixed(2)))} className="hover:underline" aria-label="Decrease text size">A−</button>
          </div>
        </div>
      </div>

      {/* Masthead */}
      <header className="bg-white border-b border-slate-200">
        <div className="max-w-7xl mx-auto px-6 py-3 flex items-center justify-between gap-4">
          <div className="flex items-center space-x-4">
            <Emblem className="h-14 w-auto" />
            <div className="border-l border-slate-200 pl-4">
              <div className="text-lg font-extrabold tracking-tight text-[#0b2e6b] leading-none">ANVESH</div>
              <div className="text-[12px] font-semibold text-[#1a2340] mt-1">Android Network &amp; Visual Evidence Security Hub</div>
              <div className="text-[11px] text-slate-500">Economic Offences Unit (EOU) · Bihar Police</div>
            </div>
          </div>
          <div className="flex items-center gap-4">
            {/* eslint-disable-next-line @next/next/no-img-element */}
            <img src="/bihar-police.png" alt="Bihar Police" className="h-12 object-contain hidden sm:block" />
            <Link href="/console"
              className="inline-flex items-center space-x-2 text-white text-sm font-semibold px-4 py-2 rounded-md shadow-sm hover:opacity-90 transition"
              style={{ background: "linear-gradient(90deg,#0b2e6b,#133d86)" }}>
              <Lock className="w-4 h-4" /><span>Officer Login</span>
            </Link>
          </div>
        </div>
      </header>

      {/* Primary navigation */}
      <nav className="bg-[#0b2e6b] text-white" aria-label="Primary">
        <div className="max-w-7xl mx-auto px-4 flex items-center flex-wrap">
          {NAV.map((item) => item.external ? (
            <a key={item.label} href={item.href} target="_blank" rel="noopener noreferrer"
               className="px-4 py-3 text-sm font-medium hover:bg-white/10 inline-flex items-center gap-1.5 transition-colors">
              {item.label} <ExternalLink className="w-3 h-3 opacity-70" />
            </a>
          ) : (
            <a key={item.label} href={item.href}
               className="px-4 py-3 text-sm font-medium hover:bg-white/10 transition-colors">{item.label}</a>
          ))}
        </div>
      </nav>

      {/* Hero carousel */}
      <section id="main" className="relative w-full overflow-hidden bg-[#050814]">
        {SLIDES.map((s, i) => (
          <div key={i} className={`absolute inset-0 bg-cover bg-center transition-opacity duration-700 ${i === slide ? "opacity-100" : "opacity-0"}`}
               style={{ backgroundImage: `url(${s.image})` }} />
        ))}
        <div className="absolute inset-0" style={{ background: "linear-gradient(90deg, rgba(5,8,20,.9) 0%, rgba(5,8,20,.65) 45%, rgba(5,8,20,.35) 100%)" }} />

        <div className="relative max-w-7xl mx-auto px-6 min-h-[440px] flex items-center">
          <div className="max-w-2xl py-16">
            <div className="inline-flex items-center gap-2 text-[11px] font-semibold uppercase tracking-wider text-[#ffcf99] mb-3">
              <ShieldCheck className="w-4 h-4" /> Authorised Investigator Platform
            </div>
            <h1 className="text-3xl md:text-4xl font-extrabold text-white leading-tight drop-shadow">{active.title}</h1>
            <p className="text-sm md:text-base text-slate-200 mt-3 leading-relaxed">{active.text}</p>
            <div className="flex flex-wrap items-center gap-3 mt-6">
              <Link href="/console" className="inline-flex items-center space-x-2 text-white text-sm font-semibold px-5 py-2.5 rounded-md shadow hover:opacity-90 transition"
                    style={{ background: "linear-gradient(90deg,#ff9933,#e67e22)" }}>
                <span>{active.cta}</span><ArrowRight className="w-4 h-4" />
              </Link>
              <a href="tel:1930" className="inline-flex items-center space-x-2 text-white text-sm font-semibold px-5 py-2.5 rounded-md border border-white/40 hover:bg-white/10 transition">
                <Siren className="w-4 h-4" /><span>Cyber Helpline 1930</span>
              </a>
            </div>
          </div>
        </div>

        <button onClick={prev} aria-label="Previous slide" className="absolute left-3 top-1/2 -translate-y-1/2 w-10 h-10 rounded-full bg-white/20 hover:bg-white/40 backdrop-blur flex items-center justify-center text-white z-10"><ChevronLeft className="w-6 h-6" /></button>
        <button onClick={next} aria-label="Next slide" className="absolute right-3 top-1/2 -translate-y-1/2 w-10 h-10 rounded-full bg-white/20 hover:bg-white/40 backdrop-blur flex items-center justify-center text-white z-10"><ChevronRight className="w-6 h-6" /></button>
        <div className="absolute bottom-5 left-1/2 -translate-x-1/2 flex items-center space-x-2 z-10">
          {SLIDES.map((_, i) => (
            <button key={i} onClick={() => setSlide(i)} aria-label={`Go to slide ${i + 1}`}
              className={`h-2 rounded-full transition-all ${i === slide ? "w-6 bg-[#ff9933]" : "w-2 bg-white/60"}`} />
          ))}
        </div>
        <div className="h-[4px] w-full flex relative z-10"><div className="flex-1 bg-[#ff9933]" /><div className="flex-1 bg-white" /><div className="flex-1 bg-[#138808]" /></div>
      </section>

      {/* About */}
      <section id="about" className="max-w-7xl mx-auto px-6 py-14 grid grid-cols-1 lg:grid-cols-3 gap-10">
        <div className="lg:col-span-2 space-y-4">
          <p className="text-[11px] font-bold uppercase tracking-wider text-[#138808]">About the Portal</p>
          <h2 className="text-2xl font-extrabold text-[#0b2e6b]">Forensic triage for seized Android applications</h2>
          <p className="text-sm text-slate-700 leading-relaxed">
            ANVESH is a workspace for the Economic Offences Unit (EOU) and district cyber cells of
            Bihar Police to submit seized Android application packages (APKs) for forensic triage. Each
            specimen is hashed, statically parsed, checked for evasion techniques and scored — with the
            full chain of custody preserved for judicial use.
          </p>
          <p className="text-sm text-slate-700 leading-relaxed">
            The platform does not execute arbitrary code on investigator machines; analysis is static and
            sandbox behaviour is simulated. Every stage writes an immutable, hash‑chained audit entry, and
            findings are compiled into a court‑ready PDF evidence package.
          </p>
          <div className="flex items-center space-x-2 text-[#138808] text-xs font-semibold pt-1">
            <Lock className="w-4 h-4" /><span>Tamper‑evident · Chain‑of‑custody preserved</span>
          </div>
          <div className="grid grid-cols-3 gap-3 pt-3 text-xs">
            <div className="border border-slate-200 rounded-lg p-3"><div className="font-bold text-[#0b2e6b]">Nodal Agency</div><div className="text-slate-600 mt-0.5">Economic Offences Unit (EOU)</div></div>
            <div className="border border-slate-200 rounded-lg p-3"><div className="font-bold text-[#0b2e6b]">Headquarters</div><div className="text-slate-600 mt-0.5">Bihar Police, Patna</div></div>
            <div className="border border-slate-200 rounded-lg p-3"><div className="font-bold text-[#0b2e6b]">Jurisdiction</div><div className="text-slate-600 mt-0.5">State of Bihar · 38 districts</div></div>
          </div>
        </div>
        <div className="border border-[#ff9933]/40 rounded-xl p-6 bg-[#fff8ec]">
          <h3 className="text-base font-bold text-[#0b2e6b] mb-4">A SMART Policing Initiative</h3>
          <div className="grid grid-cols-3 gap-3 text-center">
            {[{ k: "Upload", I: UploadCloud }, { k: "Analyse", I: ShieldCheck }, { k: "Prosecute", I: FileText }].map(({ k, I }) => (
              <div key={k} className="bg-white border border-orange-100 rounded-lg py-4 flex flex-col items-center space-y-2">
                <I className="w-5 h-5 text-[#ff9933]" /><div className="text-xs font-semibold text-[#0b2e6b]">{k}</div>
              </div>
            ))}
          </div>
          <Link href="/console" className="inline-flex items-center space-x-2 mt-5 text-sm font-semibold text-[#0b2e6b] hover:text-[#e67e22]">
            <span>Open the Analysis Console</span><ArrowRight className="w-4 h-4" />
          </Link>
        </div>
      </section>

      {/* Capabilities */}
      <section id="capabilities" className="bg-[#f7f9fc] border-y border-slate-200">
        <div className="max-w-7xl mx-auto px-6 py-14">
          <p className="text-[11px] font-bold uppercase tracking-wider text-[#138808]">Capabilities</p>
          <h2 className="text-2xl font-extrabold text-[#0b2e6b] mb-8">What the analysis engine does</h2>
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-5">
            {CAPABILITIES.map(({ icon: Icon, t, d }) => (
              <div key={t} className="bg-white border border-slate-200 rounded-xl p-5 hover:shadow-md transition-shadow">
                <div className="w-10 h-10 rounded-lg bg-[#fff1e0] text-[#e67e22] flex items-center justify-center mb-3"><Icon className="w-5 h-5" /></div>
                <h3 className="text-sm font-bold text-[#0b2e6b]">{t}</h3>
                <p className="text-xs text-slate-600 leading-relaxed mt-1.5">{d}</p>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* How it works */}
      <section id="how" className="max-w-7xl mx-auto px-6 py-14">
        <p className="text-[11px] font-bold uppercase tracking-wider text-[#138808]">Workflow</p>
        <h2 className="text-2xl font-extrabold text-[#0b2e6b] mb-8">How a specimen is processed</h2>
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-5">
          {STEPS.map((s, i) => (
            <div key={s.n} className="relative bg-white border border-slate-200 rounded-xl p-5">
              <div className="w-9 h-9 rounded-full bg-[#0b2e6b] text-white font-bold flex items-center justify-center mb-3">{s.n}</div>
              <h3 className="text-sm font-bold text-[#0b2e6b]">{s.t}</h3>
              <p className="text-xs text-slate-600 leading-relaxed mt-1.5">{s.d}</p>
              {i < STEPS.length - 1 && <ArrowRight className="hidden lg:block absolute -right-3.5 top-1/2 -translate-y-1/2 w-5 h-5 text-slate-300" />}
            </div>
          ))}
        </div>
      </section>

      {/* Citizen helpline band */}
      <section className="bg-[#0b2e6b]">
        <div className="max-w-7xl mx-auto px-6 py-8 flex flex-col md:flex-row items-center justify-between gap-5 text-white">
          <div className="flex items-center gap-4">
            <div className="w-12 h-12 rounded-full bg-[#ff9933]/20 border border-[#ff9933]/40 flex items-center justify-center text-[#ff9933] shrink-0"><Siren className="w-6 h-6" /></div>
            <div>
              <h3 className="text-lg font-bold">Victim of cyber fraud or a malicious app?</h3>
              <p className="text-sm text-slate-300">Report to the Bihar Cyber Cell via the National Cyber Crime Reporting Portal, or call the 24×7 helpline.</p>
            </div>
          </div>
          <div className="flex items-center gap-3">
            <a href="tel:1930" className="inline-flex items-center gap-2 bg-[#ff9933] text-[#1a2340] text-sm font-bold px-5 py-2.5 rounded-md hover:bg-[#e67e22] transition"><Phone className="w-4 h-4" />Dial 1930</a>
            <a href="https://cybercrime.gov.in" target="_blank" rel="noopener noreferrer" className="inline-flex items-center gap-2 border border-white/40 text-sm font-semibold px-5 py-2.5 rounded-md hover:bg-white/10 transition">cybercrime.gov.in <ExternalLink className="w-3.5 h-3.5" /></a>
          </div>
        </div>
      </section>

      {/* Footer */}
      <footer id="contact" className="bg-[#081f49] text-slate-300 mt-auto">
        <div className="h-[3px] w-full flex"><div className="flex-1 bg-[#ff9933]" /><div className="flex-1 bg-white" /><div className="flex-1 bg-[#138808]" /></div>
        <div className="max-w-7xl mx-auto px-6 py-10 grid grid-cols-1 md:grid-cols-4 gap-8 text-xs">
          <div className="md:col-span-2">
            <div className="flex items-center space-x-2 mb-3">
              <Emblem className="w-7 h-7 invert" />
              <span className="font-bold text-white text-sm">ANVESH · EOU, Bihar Police</span>
            </div>
            <p className="leading-relaxed max-w-md">A Cyber Crime &amp; Digital Forensics suite of the Economic Offences Unit (EOU), Bihar Police — static APK analysis, anti‑evasion unpacking, behavioural sandboxing, IOC matching and court‑ready evidence generation for investigations across Bihar.</p>
            <div className="flex items-center gap-2 mt-3 text-[#9db4d6]"><Fingerprint className="w-4 h-4" /><span>Evidence integrity by SHA‑256 hashing &amp; hash‑chained audit log.</span></div>
          </div>
          <div>
            <div className="font-semibold text-white uppercase tracking-wider text-[11px] mb-3">Portal</div>
            <ul className="space-y-1.5">
              {[["About", "#about"], ["Capabilities", "#capabilities"], ["How it Works", "#how"], ["Analysis Console", "/console"]].map(([l, h]) => (
                <li key={l}><a href={h} className="hover:text-[#ff9933]">{l}</a></li>
              ))}
            </ul>
          </div>
          <div>
            <div className="font-semibold text-white uppercase tracking-wider text-[11px] mb-3">Resources &amp; Contact</div>
            <ul className="space-y-1.5">
              <li><a href="https://police.bihar.gov.in" target="_blank" rel="noopener noreferrer" className="hover:text-[#ff9933] inline-flex items-center gap-1">Bihar Police Portal <ExternalLink className="w-3 h-3" /></a></li>
              <li><a href="https://cybercrime.gov.in" target="_blank" rel="noopener noreferrer" className="hover:text-[#ff9933] inline-flex items-center gap-1">National Cyber Crime Portal <ExternalLink className="w-3 h-3" /></a></li>
              <li className="flex items-center space-x-2"><Phone className="w-3.5 h-3.5 text-[#ff9933]" /><span>Cyber Helpline: 1930</span></li>
              <li className="flex items-start space-x-2"><MapPin className="w-3.5 h-3.5 text-[#ff9933] mt-0.5" /><span>EOU, Bihar Police HQ, Patna – 800001</span></li>
            </ul>
          </div>
        </div>
        <div className="border-t border-white/10 text-[11px] text-slate-400 px-6 py-4 flex flex-col md:flex-row items-center justify-between gap-2 max-w-7xl mx-auto">
          <span><strong className="text-amber-300">Demonstration project.</strong> Not an official Government of Bihar website.</span>
          <span>Content owned by Economic Offences Unit (EOU), Bihar Police · Developed by Team codemaniacs · Last updated 26 Oct 2026</span>
        </div>
      </footer>
    </div>
  )
}
