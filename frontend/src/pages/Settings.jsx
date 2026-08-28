import { Database, Download, FlaskConical, Info, RotateCcw, ShieldCheck } from 'lucide-react'
import { useState } from 'react'
import { API_BASE, api } from '../lib/api'

export default function Settings({ onRefresh }) {
  const [message, setMessage] = useState('')
  async function action(path) {
    setMessage('Working…')
    try {
      const response = await api.post(path)
      setMessage(response.data.message || 'Operation complete.')
      onRefresh?.()
    } catch (error) {
      setMessage(error.response?.data?.detail || 'Operation failed.')
    }
  }

  return <div className="space-y-5">
    <section className="panel rounded-xl p-6">
      <div className="eyebrow">Environment controls</div>
      <h2 className="mt-1 text-2xl font-black text-white">Settings & Detection Lab</h2>
      <p className="mt-2 max-w-2xl text-sm leading-6 text-slate-500">Use these reproducible demo controls for judging. For authorized access-log ingestion, authentication, model governance, and drift monitoring, open Production Operations.</p>
    </section>
    <div className="grid gap-5 lg:grid-cols-2">
      <section className="panel rounded-xl p-5">
        <div className="flex items-center gap-3"><Database className="text-cyan-300"/><div><h3 className="font-bold text-white">Demo database</h3><p className="text-xs text-slate-500">Populate or reset reproducible synthetic telemetry.</p></div></div>
        <div className="mt-5 flex flex-wrap gap-2"><button onClick={()=>action('/api/dataset/demo/load?limit=1600')} className="btn-primary">Load Demo Dataset</button><button onClick={()=>action('/api/dataset/demo/reset')} className="btn-secondary flex items-center gap-2"><RotateCcw size={15}/>Reset Demo Database</button></div>
        {message&&<p className="mt-4 text-sm text-cyan-200">{message}</p>}
      </section>
      <section className="panel rounded-xl p-5">
        <div className="flex items-center gap-3"><Download className="text-cyan-300"/><div><h3 className="font-bold text-white">Portable evidence exports</h3><p className="text-xs text-slate-500">Download clean records for reporting or judging.</p></div></div>
        <div className="mt-5 flex gap-2"><a href={`${API_BASE}/api/export/csv`} className="btn-secondary">Export CSV</a><a href={`${API_BASE}/api/export/json`} className="btn-secondary">Export JSON</a></div>
      </section>
    </div>
    <section className="panel rounded-xl p-5">
      <h3 className="flex items-center gap-2 font-bold text-white"><FlaskConical className="text-violet-300"/>Engine configuration</h3>
      <div className="mt-5 grid gap-3 sm:grid-cols-2 lg:grid-cols-4">{[['Rule Engine','Enabled','JSON signatures + semantic checks'],['ML Engine','Versioned','Character TF-IDF model'],['Behaviour Engine','Enabled','Windowed source heuristics'],['Success Classifier','Enabled','Evidence-based outcomes']].map(([name,status,detail])=><div key={name} className="rounded-xl border border-blue-400/10 bg-black/15 p-4"><div className="flex items-center justify-between"><strong className="text-sm text-slate-200">{name}</strong><ShieldCheck size={16} className="text-emerald-300"/></div><div className="mt-2 text-xs font-bold text-cyan-300">{status}</div><p className="mt-1 text-[11px] text-slate-600">{detail}</p></div>)}</div>
    </section>
    <section className="rounded-xl border border-blue-400/15 bg-blue-400/5 p-5"><div className="flex items-start gap-3"><Info className="mt-0.5 shrink-0 text-blue-300"/><div><h3 className="font-bold text-white">Defensive boundary</h3><p className="mt-1 text-sm leading-6 text-slate-400">ByteForce analyzes supplied telemetry only. It does not attack, scan, authenticate to, or execute code against a target. Real monitoring requires authorized proxy/application logs. Vulnerable-application testing belongs in an isolated local lab.</p></div></div></section>
  </div>
}
