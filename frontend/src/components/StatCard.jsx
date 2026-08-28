import { ArrowUpRight } from 'lucide-react'
export default function StatCard({ title, value, icon: Icon, tone='cyan', detail='Local telemetry' }) {
  const tones={cyan:'text-cyan-300 bg-cyan-400/10 border-cyan-400/15',red:'text-red-300 bg-red-400/10 border-red-400/15',orange:'text-orange-300 bg-orange-400/10 border-orange-400/15',green:'text-emerald-300 bg-emerald-400/10 border-emerald-400/15',blue:'text-blue-300 bg-blue-400/10 border-blue-400/15'}
  return <article className="panel panel-glow rounded-xl p-4"><div className="flex items-start justify-between"><div className={`rounded-lg border p-2.5 ${tones[tone]}`}><Icon size={19}/></div><ArrowUpRight className="text-slate-600" size={15}/></div><div className="mt-5 text-2xl font-black tracking-tight text-white">{Number(value||0).toLocaleString()}</div><div className="mt-1 text-sm font-semibold text-slate-300">{title}</div><div className="mt-1 text-[11px] text-slate-500">{detail}</div></article>
}
