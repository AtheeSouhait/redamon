const INVALID_XML_CHARS = /[\u0000-\u0008\u000B\u000C\u000E-\u001F\uFFFE\uFFFF]/g
const XLSX_MAX_CELL_CHARS = 32767

export function sanitizeXlsxCell(value: unknown): unknown {
  if (typeof value !== 'string') return value
  const cleaned = value.replace(INVALID_XML_CHARS, '')
  return cleaned.length > XLSX_MAX_CELL_CHARS
    ? cleaned.slice(0, XLSX_MAX_CELL_CHARS - 1) + '\u2026'
    : cleaned
}

export function timestampSlug(): string {
  return new Date().toISOString().slice(0, 19).replace(/[T:]/g, '-')
}

export function downloadBlob(content: string, filename: string, mimeType: string) {
  const blob = new Blob([content], { type: mimeType })
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url
  a.download = filename
  document.body.appendChild(a)
  a.click()
  document.body.removeChild(a)
  URL.revokeObjectURL(url)
}

export function flattenCellValue(raw: unknown): string {
  if (raw == null) return ''
  if (Array.isArray(raw)) {
    return raw
      .map(v => (typeof v === 'object' && v !== null ? safeStringify(v) : String(v)))
      .join(', ')
  }
  if (typeof raw === 'object') return safeStringify(raw)
  return String(raw)
}

/** Like flattenCellValue but preserves primitives (number, boolean) so XLSX cells get correct type. */
export function flattenForXlsx(raw: unknown): unknown {
  if (raw == null) return ''
  if (Array.isArray(raw)) {
    return raw
      .map(v => (typeof v === 'object' && v !== null ? safeStringify(v) : String(v)))
      .join(', ')
  }
  if (typeof raw === 'object') return safeStringify(raw)
  return raw
}

function safeStringify(value: unknown): string {
  try {
    return JSON.stringify(value)
  } catch {
    return String(value)
  }
}

export function escapeMarkdownCell(s: string): string {
  return s.replace(/\|/g, '\\|').replace(/\r?\n/g, ' ')
}
