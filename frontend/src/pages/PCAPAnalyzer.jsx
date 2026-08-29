import { AlertTriangle, CheckCircle2, FileScan, UploadCloud } from 'lucide-react'
import { useRef, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { api } from '../lib/api'

function uploadFailureMessage(error) {
  const detail = error.response?.data?.detail
  const body = typeof error.response?.data === 'string' ? error.response.data : ''

  if (error.response?.status === 401) {
    return {
      fallback: false,
      message: 'Sign in is required before uploading capture files.',
    }
  }

  if (error.response?.status === 403 && /forbidden|web application firewall|blocked/i.test(body)) {
    return {
      fallback: true,
      message:
        'Hosted PCAP upload was blocked by the deployment provider before ByteForce could inspect it. Use the bundled safe demo results for the deployed hackathon demo.',
    }
  }

  if (error.code === 'ECONNABORTED') {
    return {
      fallback: true,
      message:
        'Capture upload timed out while the hosted backend was starting. Use the bundled safe demo results, or retry after the service is awake.',
    }
  }

  return {
    fallback: true,
    message: detail || 'Capture analysis failed. You can still demonstrate the pipeline with bundled safe demo results.',
  }
}

export default function PCAPAnalyzer() {
  const [file, setFile] = useState(null)
  const [state, setState] = useState('idle')
  const [result, setResult] = useState(null)
  const input = useRef()
  const navigate = useNavigate()

  async function analyze() {
    if (!file) return
    setState('processing')
    setResult(null)

    const form = new FormData()
    form.append('file', file)

    try {
      const response = await api.post('/api/pcap/upload', form, { timeout: 70000 })
      setResult(response.data)
      setState(response.data.code === 'ZEEK_MISSING' ? 'fallback' : 'done')
    } catch (error) {
      const failure = uploadFailureMessage(error)
      setResult(failure)
      setState(failure.fallback ? 'fallback' : 'error')
    }
  }

  async function demo() {
    setState('processing')
    setResult(null)

    try {
      const response = await api.post('/api/dataset/demo/pcap', undefined, { timeout: 70000 })
      setResult(response.data)
      setState('done')
    } catch (error) {
      setResult({
        message:
          error.response?.data?.detail ||
          'Demo PCAP results could not be loaded. Sign in from Operations and try again.',
      })
      setState('error')
    }
  }

  const metric = (name, value) => (
    <div className="rounded-xl border border-blue-400/10 bg-black/15 p-4">
      <div className="text-2xl font-black text-white">{Number(value || 0).toLocaleString()}</div>
      <div className="mt-1 text-xs text-slate-500">{name}</div>
    </div>
  )

  return (
    <div className="space-y-5">
      <div className="flex items-start gap-3 rounded-xl border border-amber-400/20 bg-amber-400/6 p-4 text-sm leading-6 text-amber-100">
        <AlertTriangle className="mt-0.5 shrink-0 text-amber-300" size={19} />
        <div>
          <strong>HTTPS visibility limitation</strong>
          <p className="text-slate-400">
            Encrypted HTTPS traffic may not expose complete HTTP URLs or request bodies unless decrypted traffic
            or application/proxy logs are available.
          </p>
        </div>
      </div>

      <section className="panel rounded-2xl p-6">
        <div className="text-center">
          <div className="mx-auto grid h-14 w-14 place-items-center rounded-2xl border border-cyan-400/20 bg-cyan-400/8 text-cyan-300">
            <FileScan size={28} />
          </div>
          <div className="eyebrow mt-5">Local capture analysis</div>
          <h2 className="mt-1 text-2xl font-black text-white">Upload .pcap or .pcapng</h2>
          <p className="mx-auto mt-2 max-w-xl text-sm leading-6 text-slate-500">
            Zeek extracts available HTTP records when it is installed on the backend host. The capture is deleted
            after processing and no traffic is replayed.
          </p>
        </div>

        <div
          onDragOver={(event) => event.preventDefault()}
          onDrop={(event) => {
            event.preventDefault()
            setFile(event.dataTransfer.files[0])
          }}
          className="mx-auto mt-7 max-w-3xl rounded-2xl border border-dashed border-cyan-400/25 bg-cyan-400/3 p-10 text-center"
        >
          <UploadCloud className="mx-auto text-cyan-300" size={32} />
          <p className="mt-3 text-sm font-bold text-slate-200">{file ? file.name : 'Drop a capture file here'}</p>
          <p className="mt-1 text-xs text-slate-600">Maximum 50 MB in demo mode</p>
          <input
            ref={input}
            type="file"
            accept=".pcap,.pcapng"
            className="hidden"
            onChange={(event) => setFile(event.target.files[0])}
          />
          <div className="mt-5 flex justify-center gap-2">
            <button className="btn-secondary" onClick={() => input.current.click()}>
              Choose File
            </button>
            <button
              className="btn-primary disabled:cursor-not-allowed disabled:opacity-40"
              disabled={!file || state === 'processing'}
              onClick={analyze}
            >
              {state === 'processing' ? 'Processing capture...' : 'Analyze Capture'}
            </button>
          </div>
        </div>
      </section>

      {state === 'fallback' && (
        <section className="rounded-xl border border-orange-400/20 bg-orange-400/6 p-6 text-center">
          <AlertTriangle className="mx-auto text-orange-300" />
          <h3 className="mt-3 font-black text-white">Hosted PCAP fallback available</h3>
          <p className="mx-auto mt-2 max-w-2xl text-sm leading-6 text-slate-400">
            {result?.message || 'Zeek is not installed on this backend. Demo mode is available.'}
          </p>
          <button onClick={demo} className="btn-primary mt-5">
            Load Demo Results
          </button>
        </section>
      )}

      {state === 'error' && (
        <div className="rounded-xl border border-red-400/20 bg-red-400/6 p-5 text-sm text-red-200">
          {result?.message || 'Analysis failed.'}
        </div>
      )}

      {state === 'done' && (
        <section className="panel rounded-xl p-6">
          <div className="flex items-center gap-3">
            <CheckCircle2 className="text-emerald-300" />
            <div>
              <h3 className="font-black text-white">Capture analysis complete</h3>
              <p className="text-xs text-slate-500">
                {result.mode === 'safe_demo' ? 'Bundled safe telemetry was used.' : 'Zeek-extracted HTTP telemetry was used.'}
              </p>
            </div>
          </div>
          <div className="mt-5 grid gap-3 sm:grid-cols-2 lg:grid-cols-5">
            {metric('Records processed', result.records_processed)}
            {metric('HTTP events extracted', result.http_events_extracted)}
            {metric('Threats detected', result.threats_detected)}
            {metric('Critical alerts', result.critical_alerts)}
            {metric('Unique source IPs', result.unique_source_ips)}
          </div>
          <button className="btn-primary mt-5" onClick={() => navigate('/threats')}>
            View Detected Threats
          </button>
        </section>
      )}
    </div>
  )
}
