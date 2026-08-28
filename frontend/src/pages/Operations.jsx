import { useEffect, useRef, useState } from 'react'
import { Activity, AlertTriangle, CheckCircle2, Database, FileText, LogIn, RefreshCw, ShieldCheck, UploadCloud } from 'lucide-react'
import { API_BASE, api } from '../lib/api'

const value = (input) => input ?? 'Not configured'

export default function Operations() {
  const [status, setStatus] = useState(null)
  const [user, setUser] = useState(null)
  const [jobs, setJobs] = useState([])
  const [models, setModels] = useState({ active: null, models: [] })
  const [drift, setDrift] = useState(null)
  const [message, setMessage] = useState('')
  const [file, setFile] = useState(null)
  const [format, setFormat] = useState('auto')
  const [busy, setBusy] = useState(false)
  const [login, setLogin] = useState({ email: '', password: '' })
  const [feedback, setFeedback] = useState({ detectionId: '', reviewed_label: 'BENIGN', outcome_label: '', notes: '' })
  const input = useRef()

  async function refresh() {
    setMessage('')
    try {
      const statusResponse = await api.get('/api/operations/status')
      setStatus(statusResponse.data)
      const me = await api.get('/api/auth/me')
      setUser(me.data)
      const [jobResponse, modelResponse, driftResponse] = await Promise.all([
        api.get('/api/operations/jobs'), api.get('/api/operations/models'), api.get('/api/operations/drift'),
      ])
      setJobs(jobResponse.data); setModels(modelResponse.data); setDrift(driftResponse.data)
    } catch (error) {
      if (error.response?.status === 401) setUser(null)
      else setMessage(error.response?.data?.detail || 'Could not load operations status.')
    }
  }

  useEffect(() => { refresh() }, [])

  async function signIn(event) {
    event.preventDefault(); setBusy(true); setMessage('')
    try { await api.post('/api/auth/login', login); await refresh() }
    catch (error) { setMessage(error.response?.data?.detail || 'Sign-in failed.') }
    finally { setBusy(false) }
  }

  async function upload() {
    if (!file) return
    setBusy(true); setMessage('Queuing authorized access logs…')
    const body = new FormData(); body.append('file', file)
    try {
      const { data } = await api.post(`/api/operations/logs/upload?log_format=${format}`, body)
      setMessage(`${data.message} Job #${data.job.id}`); setFile(null); await refresh()
    } catch (error) { setMessage(error.response?.data?.detail || 'Log ingestion failed.') }
    finally { setBusy(false) }
  }

  async function activate(version) {
    try { const { data } = await api.post(`/api/operations/models/${encodeURIComponent(version)}/activate`); setMessage(data.message); await refresh() }
    catch (error) { setMessage(error.response?.data?.detail || 'Model activation failed.') }
  }

  async function submitFeedback(event) {
    event.preventDefault()
    try {
      const payload = { reviewed_label: feedback.reviewed_label, outcome_label: feedback.outcome_label || null, notes: feedback.notes }
      const { data } = await api.post(`/api/operations/detections/${feedback.detectionId}/feedback`, payload)
      setMessage(data.message); setFeedback({ detectionId: '', reviewed_label: 'BENIGN', outcome_label: '', notes: '' })
    } catch (error) { setMessage(error.response?.data?.detail || 'Review could not be saved.') }
  }

  if (status?.auth_enabled && !user) return <div className="mx-auto max-w-md panel rounded-2xl p-7">
    <LogIn className="text-cyan-300"/><div className="eyebrow mt-4">Protected operations</div><h2 className="mt-1 text-2xl font-black text-white">Sign in to ByteForce</h2>
    <p className="mt-2 text-sm leading-6 text-slate-500">Use the administrator credentials configured on the backend server.</p>
    <form className="mt-6 space-y-3" onSubmit={signIn}><input className="field" type="email" placeholder="Administrator email" value={login.email} onChange={e=>setLogin({...login,email:e.target.value})}/><input className="field" type="password" placeholder="Password" value={login.password} onChange={e=>setLogin({...login,password:e.target.value})}/><button className="btn-primary w-full" disabled={busy}>{busy?'Signing in…':'Sign in'}</button></form>
    {message&&<p className="mt-4 text-sm text-red-200">{message}</p>}
  </div>

  const driftTone = drift?.status === 'DRIFT_DETECTED' ? 'text-amber-300' : 'text-emerald-300'
  return <div className="space-y-5">
    <section className="rounded-xl border border-cyan-400/20 bg-cyan-400/5 p-5"><div className="flex items-start gap-3"><ShieldCheck className="mt-0.5 shrink-0 text-cyan-300"/><div><h2 className="font-black text-white">Observation-only production pilot</h2><p className="mt-1 text-sm leading-6 text-slate-400">ByteForce analyzes telemetry from systems you own or are authorized to monitor. It does not scan, exploit, or block websites. Start here with reverse-proxy or application access logs.</p></div></div></section>
    {message&&<div className="rounded-xl border border-blue-400/20 bg-blue-400/6 p-4 text-sm text-blue-100">{message}</div>}
    <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-4">
      {[[Database,'Database',status?.database],[ShieldCheck,'Environment',status?.environment],[Activity,'Operating mode',status?.mode],[FileText,'Telemetry records',status?.telemetry_records?.toLocaleString()]].map(([Icon,label,item])=><div className="panel rounded-xl p-4" key={label}><Icon size={18} className="text-cyan-300"/><div className="mt-3 text-xs text-slate-500">{label}</div><div className="mt-1 font-black uppercase text-white">{value(item)}</div></div>)}
    </div>
    <div className="grid gap-5 xl:grid-cols-2">
      <section className="panel rounded-xl p-5"><div className="flex items-center gap-3"><UploadCloud className="text-cyan-300"/><div><h3 className="font-bold text-white">Ingest real access logs</h3><p className="text-xs text-slate-500">Nginx/Apache combined format or JSON Lines, from authorized infrastructure.</p></div></div><div className="mt-5 rounded-xl border border-dashed border-cyan-400/20 bg-black/15 p-6 text-center"><p className="text-sm font-bold text-slate-200">{file?.name || 'Choose an access-log file'}</p><input ref={input} className="hidden" type="file" accept=".log,.txt,.json,.jsonl" onChange={e=>setFile(e.target.files[0])}/><div className="mt-4 flex flex-wrap justify-center gap-2"><button className="btn-secondary" onClick={()=>input.current.click()}>Choose file</button><select className="field !w-auto" value={format} onChange={e=>setFormat(e.target.value)}><option value="auto">Auto detect</option><option value="nginx">Nginx combined</option><option value="apache">Apache combined</option><option value="json">JSON Lines</option></select><button className="btn-primary disabled:opacity-40" disabled={!file||busy} onClick={upload}>{busy?'Working…':'Analyze logs'}</button></div></div></section>
      <section className="panel rounded-xl p-5"><div className="flex items-center justify-between"><div><h3 className="font-bold text-white">Model health</h3><p className="text-xs text-slate-500">Active version, validation quality, and telemetry drift.</p></div><button className="btn-secondary !p-2" onClick={refresh}><RefreshCw size={15}/></button></div><div className="mt-5 grid grid-cols-2 gap-3"><div className="rounded-xl border border-blue-400/10 bg-black/15 p-4"><div className="text-xs text-slate-500">Active model</div><div className="mt-1 font-black text-cyan-200">{value(models.active)}</div></div><div className="rounded-xl border border-blue-400/10 bg-black/15 p-4"><div className="text-xs text-slate-500">Drift status</div><div className={`mt-1 font-black ${driftTone}`}>{value(drift?.status)}</div></div></div><p className="mt-4 text-xs leading-5 text-slate-500">{drift?.message || 'A baseline becomes available after a versioned model is trained.'}</p></section>
    </div>
    <section className="panel rounded-xl p-5"><div className="flex items-center justify-between"><div><h3 className="font-bold text-white">Ingestion jobs</h3><p className="text-xs text-slate-500">Background processing results for uploaded and watched access logs.</p></div><button className="btn-secondary" onClick={refresh}>Refresh</button></div><div className="scrollbar mt-4 overflow-x-auto"><table className="w-full min-w-[700px] text-left text-sm"><thead className="text-xs uppercase text-slate-600"><tr>{['Job','Source','Format','Status','Records','Threats','Message'].map(h=><th className="px-3 py-2" key={h}>{h}</th>)}</tr></thead><tbody>{jobs.map(job=><tr className="border-t border-blue-400/8" key={job.id}><td className="px-3 py-3 text-cyan-200">#{job.id}</td><td className="px-3 py-3 text-slate-300">{job.source_name}</td><td className="px-3 py-3 text-slate-500">{job.log_format}</td><td className="px-3 py-3"><span className={job.status==='COMPLETED'?'text-emerald-300':job.status==='FAILED'?'text-red-300':'text-amber-300'}>{job.status}</span></td><td className="px-3 py-3">{job.records_processed}</td><td className="px-3 py-3">{job.attacks_detected}</td><td className="max-w-xs truncate px-3 py-3 text-xs text-slate-500">{job.message}</td></tr>)}</tbody></table>{!jobs.length&&<p className="p-5 text-sm text-slate-600">No ingestion jobs yet.</p>}</div></section>
    <div className="grid gap-5 xl:grid-cols-2">
      <section className="panel rounded-xl p-5"><h3 className="font-bold text-white">Versioned models and rollback</h3><p className="mt-1 text-xs text-slate-500">Activate a validated earlier model without retraining.</p><div className="mt-4 space-y-3">{models.models?.map(model=><div className="flex flex-wrap items-center justify-between gap-3 rounded-xl border border-blue-400/10 bg-black/15 p-4" key={model.version}><div><div className="font-bold text-slate-200">{model.version} {models.active===model.version&&<span className="ml-2 text-xs text-emerald-300">ACTIVE</span>}</div><div className="mt-1 text-xs text-slate-500">F1 {Number(model.metrics?.f1||0).toFixed(3)} · {model.training_source}</div></div><button className="btn-secondary" disabled={models.active===model.version} onClick={()=>activate(model.version)}>Activate</button></div>)}{!models.models?.length&&<p className="text-sm text-slate-600">No trained model is registered. The rule and behaviour engines remain available.</p>}</div></section>
      <section className="panel rounded-xl p-5"><h3 className="font-bold text-white">Analyst feedback</h3><p className="mt-1 text-xs leading-5 text-slate-500">Correct a detection using verified evidence. Reviewed rows can be exported for controlled retraining.</p><form className="mt-4 space-y-3" onSubmit={submitFeedback}><input className="field" type="number" min="1" required placeholder="Detection ID" value={feedback.detectionId} onChange={e=>setFeedback({...feedback,detectionId:e.target.value})}/><div className="grid gap-3 sm:grid-cols-2"><select className="field" value={feedback.reviewed_label} onChange={e=>setFeedback({...feedback,reviewed_label:e.target.value})}>{['BENIGN','SQL_INJECTION','XSS','DIRECTORY_TRAVERSAL','COMMAND_INJECTION','SSRF','LFI','RFI','SCANNER_ACTIVITY','UNKNOWN_SUSPICIOUS'].map(x=><option key={x}>{x}</option>)}</select><select className="field" value={feedback.outcome_label} onChange={e=>setFeedback({...feedback,outcome_label:e.target.value})}><option value="">Outcome unknown</option><option>ATTEMPT</option><option>PROBABLE_SUCCESS</option><option>CONFIRMED_SUCCESS</option></select></div><textarea className="field min-h-24" placeholder="Evidence or review notes" value={feedback.notes} onChange={e=>setFeedback({...feedback,notes:e.target.value})}/><div className="flex flex-wrap gap-2"><button className="btn-primary">Save review</button><a className="btn-secondary" href={`${API_BASE}/api/operations/feedback/training.csv`}>Export reviewed training CSV</a></div></form></section>
    </div>
    <section className="rounded-xl border border-amber-400/15 bg-amber-400/5 p-4 text-sm text-slate-400"><div className="flex gap-3"><AlertTriangle className="shrink-0 text-amber-300" size={19}/><p><strong className="text-amber-100">Important:</strong> encrypted HTTPS URLs are normally visible only in reverse-proxy/application logs or in traffic decrypted by infrastructure you control. Never collect passwords, session tokens, or telemetry without authorization; ByteForce redacts common secret query parameters before storage.</p></div></section>
  </div>
}
