import axios from 'axios'

// Same-origin API calls work behind the production reverse proxy. The Vite
// development server forwards /api to localhost:8000.
export const API_BASE = import.meta.env.VITE_API_URL || ''
export const api = axios.create({ baseURL: API_BASE, timeout: 30000, withCredentials: true })

export const loadAllAnalytics = () => Promise.all([
  api.get('/api/analytics/timeline'), api.get('/api/analytics/types'), api.get('/api/analytics/severity'), api.get('/api/analytics/overview'),
]).then(([timeline, types, severity, overview]) => ({ timeline: timeline.data, types: types.data, severity: severity.data, overview: overview.data }))
