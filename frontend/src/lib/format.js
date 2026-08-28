export const attackNames = {
  BENIGN: 'Benign', SQL_INJECTION: 'SQL Injection', XSS: 'Cross-Site Scripting', DIRECTORY_TRAVERSAL: 'Directory Traversal',
  COMMAND_INJECTION: 'Command Injection', SSRF: 'SSRF', LFI: 'Local File Inclusion', RFI: 'Remote File Inclusion',
  HTTP_PARAMETER_POLLUTION: 'HTTP Parameter Pollution', TYPOSQUATTING: 'Typosquatting', WEB_SHELL_REFERENCE: 'Web Shell Reference',
  XXE_INDICATOR: 'XXE Indicator', OPEN_REDIRECT: 'Open Redirect', SCANNER_ACTIVITY: 'Scanner Activity', BRUTE_FORCE: 'Brute Force',
  RECONNAISSANCE_PATTERN: 'Reconnaissance Pattern', UNKNOWN_SUSPICIOUS: 'Unknown Suspicious',
}
export const label = value => attackNames[value] || String(value || 'Unknown').replaceAll('_', ' ').replace(/\b\w/g, c => c.toUpperCase())
export const dateTime = value => value ? new Date(value).toLocaleString() : '—'
