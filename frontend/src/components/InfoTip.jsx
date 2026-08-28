import { Info } from 'lucide-react'
export default function InfoTip({ text }) { return <span className="tooltip-wrap inline-flex"><button type="button" aria-label="More information" className="text-slate-500 hover:text-cyan-300"><Info size={14}/></button><span role="tooltip" className="tooltip-copy">{text}</span></span> }
