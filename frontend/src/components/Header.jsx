import { useEffect, useState } from 'react'
import { BookOpen, Database, RotateCcw, ShieldCheck } from 'lucide-react'
import { useLocation } from 'react-router-dom'
import { api } from '../lib/api'

const titles = {
  '/': ['Security Overview', 'Live view of analyzed network telemetry'],
  '/threats': ['Threat Explorer', 'Search and investigate explainable detections'],
  '/pcap': ['PCAP Analyzer', 'Extract HTTP telemetry from authorized captures'],
  '/ip': ['IP Intelligence', 'Local risk intelligence from observed traffic'],
  '/analytics': ['Security Analytics', 'Trends, targets, sources, and outcomes'],
  '/operations': ['Production Operations', 'Authorized log ingestion and model governance'],
  '/settings': ['Settings', 'Demo controls and learning resources'],
}

export default function Header({ onArchitecture, onRefresh }) {
  const location = useLocation()
  const [system, setSystem] = useState({ environment: 'demo', mode: 'OBSERVATION' })
  const key = location.pathname.startsWith('/threats/') ? '/threats' : location.pathname
  const [title, subtitle] = titles[key] || titles['/']

  useEffect(() => {
    api.get('/api/operations/status').then(({ data }) => setSystem(data)).catch(() => {})
  }, [location.pathname])

  return <header className="sticky top-0 z-10 border-b border-blue-400/10 bg-[#050b14]/86 px-4 py-4 backdrop-blur-xl md:px-7">
    <div className="flex flex-wrap items-center justify-between gap-4">
      <div>
        <div className="eyebrow">ByteForce · Cyber Threat Analytics Platform</div>
        <h1 className="mt-1 text-xl font-black text-white md:text-2xl">{title}</h1>
        <p className="mt-1 text-xs text-slate-500">{subtitle}</p>
      </div>
      <div className="flex flex-wrap items-center gap-2">
        <div className="hidden items-center gap-2 rounded-lg border border-emerald-400/15 bg-emerald-400/5 px-3 py-2 text-xs font-bold text-emerald-300 sm:flex"><ShieldCheck size={15}/>Engine Online</div>
        <div className="flex items-center gap-2 rounded-lg border border-cyan-400/15 bg-cyan-400/5 px-3 py-2 text-xs font-bold uppercase text-cyan-200"><Database size={14}/>{system.environment} · {system.mode}</div>
        <button className="btn-secondary !p-2.5" onClick={onRefresh} title="Refresh dashboard data"><RotateCcw size={16}/></button>
        <button className="btn-secondary flex items-center gap-2" onClick={onArchitecture}><BookOpen size={16}/>How it works</button>
      </div>
    </div>
  </header>
}
