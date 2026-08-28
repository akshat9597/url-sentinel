import { label } from '../lib/format'
export default function AttackBadge({ value }) { return <span className="inline-flex whitespace-nowrap rounded-md border border-cyan-400/15 bg-cyan-400/8 px-2 py-1 text-xs font-semibold text-cyan-200">{label(value)}</span> }
