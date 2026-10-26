"use client"

import React, { useState } from "react"
import Link from "next/link"
import { CheckCircle2, MessageSquare, Send, Phone, Mail, MapPin, ExternalLink } from "lucide-react"

// National Emblem of India (served from /public/emblem.svg).
function Emblem({ className = "w-9 h-9" }: { className?: string }) {
  // eslint-disable-next-line @next/next/no-img-element
  return <img src="/emblem.svg" alt="State Emblem of India" className={`object-contain ${className}`} />
}

export default function FeedbackPage() {
  const [fontScale, setFontScale] = useState(1)
  const [submitted, setSubmitted] = useState(false)
  const [form, setForm] = useState({ name: "", email: "", role: "", category: "General Feedback", message: "" })

  const update = (k: keyof typeof form) => (
    e: React.ChangeEvent<HTMLInputElement | HTMLTextAreaElement | HTMLSelectElement>
  ) => setForm(prev => ({ ...prev, [k]: e.target.value }))

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault()
    // Demonstration project: feedback is captured client-side only.
    setSubmitted(true)
  }

  const navItems = [
    { label: "Home", href: "/" },
    { label: "About", href: "/#about" },
    { label: "Capabilities", href: "/#capabilities" },
    { label: "Console", href: "/console" },
    { label: "Feedback", href: "/feedback" },
  ]

  return (
    <div className="min-h-screen bg-white text-[#1a2340] font-sans flex flex-col selection:bg-[#ff9933] selection:text-white"
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
          <Link href="/" className="flex items-center space-x-4">
            <Emblem className="h-14 w-auto" />
            <div className="border-l border-slate-200 pl-4">
              <div className="text-lg font-extrabold tracking-tight text-[#0b2e6b] leading-none">ANVESH</div>
              <div className="text-[12px] font-semibold text-[#1a2340] mt-1">Android Network &amp; Visual Evidence Security Hub</div>
              <div className="text-[11px] text-slate-500">Economic Offences Unit (EOU) · Bihar Police</div>
            </div>
          </Link>
          <nav className="hidden md:flex items-center space-x-1">
            {navItems.map((item) => (
              <Link key={item.label} href={item.href}
                className={`text-sm px-4 py-2 rounded-md font-medium transition-colors ${
                  item.label === "Feedback" ? "text-white shadow-sm" : "text-[#1a2340] hover:bg-orange-50"
                }`}
                style={item.label === "Feedback" ? { background: "linear-gradient(90deg,#9bbf3a,#5f8a22)" } : undefined}>
                {item.label}
              </Link>
            ))}
          </nav>
        </div>
        <div className="h-[3px] w-full flex"><div className="flex-1 bg-[#ff9933]" /><div className="flex-1 bg-white" /><div className="flex-1 bg-[#138808]" /></div>
      </header>

      {/* Hero banner */}
      <section id="main" className="border-b border-orange-100" style={{ background: "linear-gradient(135deg,#fff8ec 0%,#ffffff 45%,#f2f9f2 100%)" }}>
        <div className="max-w-7xl mx-auto px-6 py-8">
          <div className="inline-flex items-center space-x-2 bg-white border border-orange-200 rounded-full px-3 py-1 mb-3">
            <MessageSquare className="w-3.5 h-3.5 text-[#ff9933]" />
            <span className="text-[11px] font-semibold text-[#0b2e6b] uppercase tracking-wider">Feedback &amp; Grievance</span>
          </div>
          <h1 className="text-2xl md:text-3xl font-bold tracking-tight text-[#0b2e6b]">Share Your Feedback</h1>
          <p className="text-sm text-slate-600 mt-2 max-w-2xl leading-relaxed">
            Help us improve the ANVESH forensics portal. Report an issue, suggest a feature or raise a
            grievance — submissions are reviewed by the EOU Cyber Cell team.
          </p>
        </div>
      </section>

      {/* Feedback form */}
      <section className="flex-1 max-w-3xl w-full mx-auto px-6 py-10">
        {submitted ? (
          <div className="bg-white border border-green-200 rounded-xl p-8 shadow-sm text-center">
            <CheckCircle2 className="w-12 h-12 text-[#138808] mx-auto mb-3" />
            <h2 className="text-xl font-bold text-[#0b2e6b]">Thank you for your feedback</h2>
            <p className="text-sm text-slate-600 mt-2 max-w-md mx-auto leading-relaxed">
              Your submission has been recorded. The Cyber Crime &amp; Digital Forensics team will review it and
              follow up where required.
            </p>
            <div className="mt-6 flex items-center justify-center gap-3">
              <button
                onClick={() => { setSubmitted(false); setForm({ name: "", email: "", role: "", category: "General Feedback", message: "" }) }}
                className="text-sm font-semibold text-[#0b2e6b] border border-slate-300 px-4 py-2 rounded-md hover:bg-orange-50">
                Submit another response
              </button>
              <Link href="/" className="text-white text-sm font-semibold px-4 py-2 rounded-md shadow hover:opacity-90 transition"
                style={{ background: "linear-gradient(90deg,#ff9933,#e67e22)" }}>
                Back to Home
              </Link>
            </div>
          </div>
        ) : (
          <form onSubmit={handleSubmit} className="bg-white border border-slate-200 rounded-xl p-6 md:p-8 shadow-sm space-y-5">
            <div className="grid grid-cols-1 md:grid-cols-2 gap-5">
              <div>
                <label htmlFor="name" className="block text-xs font-semibold text-[#0b2e6b] uppercase tracking-wider mb-1.5">Full Name</label>
                <input id="name" type="text" required value={form.name} onChange={update("name")}
                  className="w-full text-sm border border-slate-300 rounded-md px-3 py-2 focus:outline-none focus:ring-2 focus:ring-[#ff9933]/50 focus:border-[#ff9933]"
                  placeholder="e.g. Inspector A. Kumar" />
              </div>
              <div>
                <label htmlFor="email" className="block text-xs font-semibold text-[#0b2e6b] uppercase tracking-wider mb-1.5">Email</label>
                <input id="email" type="email" required value={form.email} onChange={update("email")}
                  className="w-full text-sm border border-slate-300 rounded-md px-3 py-2 focus:outline-none focus:ring-2 focus:ring-[#ff9933]/50 focus:border-[#ff9933]"
                  placeholder="name@biharpolice.gov.in" />
              </div>
              <div>
                <label htmlFor="role" className="block text-xs font-semibold text-[#0b2e6b] uppercase tracking-wider mb-1.5">Designation <span className="text-slate-400 normal-case font-normal">(optional)</span></label>
                <input id="role" type="text" value={form.role} onChange={update("role")}
                  className="w-full text-sm border border-slate-300 rounded-md px-3 py-2 focus:outline-none focus:ring-2 focus:ring-[#ff9933]/50 focus:border-[#ff9933]"
                  placeholder="e.g. Cyber Cell Analyst" />
              </div>
              <div>
                <label htmlFor="category" className="block text-xs font-semibold text-[#0b2e6b] uppercase tracking-wider mb-1.5">Category</label>
                <select id="category" value={form.category} onChange={update("category")}
                  className="w-full text-sm border border-slate-300 rounded-md px-3 py-2 bg-white focus:outline-none focus:ring-2 focus:ring-[#ff9933]/50 focus:border-[#ff9933]">
                  <option>General Feedback</option>
                  <option>Bug Report</option>
                  <option>Feature Request</option>
                  <option>Grievance</option>
                </select>
              </div>
            </div>
            <div>
              <label htmlFor="message" className="block text-xs font-semibold text-[#0b2e6b] uppercase tracking-wider mb-1.5">Your Message</label>
              <textarea id="message" required rows={6} value={form.message} onChange={update("message")}
                className="w-full text-sm border border-slate-300 rounded-md px-3 py-2 focus:outline-none focus:ring-2 focus:ring-[#ff9933]/50 focus:border-[#ff9933] resize-y"
                placeholder="Describe your feedback, issue or suggestion in detail..." />
            </div>
            <div className="flex items-center justify-between pt-1">
              <p className="text-[11px] text-slate-400">Demonstration project — submissions are captured locally only.</p>
              <button type="submit"
                className="inline-flex items-center space-x-2 text-white text-sm font-semibold px-5 py-2.5 rounded-md shadow hover:opacity-90 transition"
                style={{ background: "linear-gradient(90deg,#ff9933,#e67e22)" }}>
                <Send className="w-4 h-4" /><span>Submit Feedback</span>
              </button>
            </div>
          </form>
        )}
      </section>

      {/* Footer (matches the landing) */}
      <footer className="bg-[#081f49] text-slate-300 mt-auto">
        <div className="h-[3px] w-full flex"><div className="flex-1 bg-[#ff9933]" /><div className="flex-1 bg-white" /><div className="flex-1 bg-[#138808]" /></div>
        <div className="max-w-7xl mx-auto px-6 py-10 grid grid-cols-1 md:grid-cols-3 gap-8 text-xs">
          <div>
            <div className="flex items-center space-x-2 mb-2"><Emblem className="w-7 h-7 invert" /><span className="font-bold text-white text-sm">ANVESH · EOU, Bihar Police</span></div>
            <p className="leading-relaxed">Cyber Crime &amp; Digital Forensics suite of the Economic Offences Unit (EOU), Bihar Police.</p>
          </div>
          <div>
            <div className="font-semibold text-white uppercase tracking-wider text-[11px] mb-2">Portal</div>
            <ul className="space-y-1.5">
              <li><Link href="/#about" className="hover:text-[#ff9933]">About</Link></li>
              <li><Link href="/#capabilities" className="hover:text-[#ff9933]">Capabilities</Link></li>
              <li><Link href="/console" className="hover:text-[#ff9933]">Analysis Console</Link></li>
            </ul>
          </div>
          <div>
            <div className="font-semibold text-white uppercase tracking-wider text-[11px] mb-2">Resources &amp; Contact</div>
            <ul className="space-y-1.5">
              <li><a href="https://police.bihar.gov.in" target="_blank" rel="noopener noreferrer" className="hover:text-[#ff9933] inline-flex items-center gap-1">Bihar Police Portal <ExternalLink className="w-3 h-3" /></a></li>
              <li className="flex items-center space-x-2"><Phone className="w-3.5 h-3.5 text-[#ff9933]" /><span>Cyber Helpline: 1930</span></li>
              <li className="flex items-start space-x-2"><MapPin className="w-3.5 h-3.5 text-[#ff9933] mt-0.5" /><span>EOU, Bihar Police HQ, Patna – 800001</span></li>
            </ul>
          </div>
        </div>
        <div className="border-t border-white/10 text-[11px] text-slate-400 px-6 py-4 flex flex-col md:flex-row items-center justify-between gap-2 max-w-7xl mx-auto">
          <span><strong className="text-amber-300">Demonstration project.</strong> Not an official Government of Bihar website.</span>
          <span>Content owned by EOU, Bihar Police · Developed by Team codemaniacs</span>
        </div>
      </footer>
    </div>
  )
}
