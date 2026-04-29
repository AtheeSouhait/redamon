import {
  sanitizeXlsxCell,
  timestampSlug,
  downloadBlob,
  flattenCellValue,
  flattenForXlsx,
  escapeMarkdownCell,
} from '../../utils/exportHelpers'

export interface RedZoneExportColumn {
  key: string
  header: string
}

export interface RedZoneExportConfig {
  rows: object[]
  sheetName: string
  fileSlug: string
  columns: RedZoneExportColumn[]
}

function buildRowDict(rows: object[], columns: RedZoneExportColumn[]): Record<string, unknown>[] {
  return rows.map(row => {
    const out: Record<string, unknown> = {}
    for (const col of columns) {
      out[col.header] = (row as Record<string, unknown>)[col.key]
    }
    return out
  })
}

export async function exportRedZoneXlsx<T extends object>(
  rows: T[],
  sheetName: string,
  columns: RedZoneExportColumn[],
  fileSlug: string,
) {
  const XLSX = await import('xlsx')
  const wb = XLSX.utils.book_new()
  const data = rows.map(row => {
    const out: Record<string, unknown> = {}
    for (const col of columns) {
      const raw = (row as Record<string, unknown>)[col.key]
      out[col.header] = sanitizeXlsxCell(flattenForXlsx(raw))
    }
    return out
  })
  const ws = XLSX.utils.json_to_sheet(data)
  XLSX.utils.book_append_sheet(wb, ws, sheetName.slice(0, 31))
  XLSX.writeFile(wb, `${fileSlug}-${timestampSlug()}.xlsx`)
}

export function exportRedZoneJson<T extends object>(
  rows: T[],
  _sheetName: string,
  columns: RedZoneExportColumn[],
  fileSlug: string,
) {
  const data = buildRowDict(rows, columns).map(row => {
    const out: Record<string, unknown> = {}
    for (const [k, v] of Object.entries(row)) out[k] = v ?? null
    return out
  })
  downloadBlob(
    JSON.stringify(data, null, 2),
    `${fileSlug}-${timestampSlug()}.json`,
    'application/json;charset=utf-8',
  )
}

export function exportRedZoneMarkdown<T extends object>(
  rows: T[],
  sheetName: string,
  columns: RedZoneExportColumn[],
  fileSlug: string,
) {
  const headers = columns.map(c => c.header)
  const headerLine = `| ${headers.join(' | ')} |`
  const sepLine = `| ${headers.map(() => '---').join(' | ')} |`
  const dataLines = rows.map(row =>
    `| ${columns
      .map(col => escapeMarkdownCell(flattenCellValue((row as Record<string, unknown>)[col.key])))
      .join(' | ')} |`,
  )

  const md = `# ${sheetName}\n\nGenerated: ${new Date().toISOString()}\nRows: ${rows.length}\n\n${headerLine}\n${sepLine}\n${dataLines.join('\n')}\n`
  downloadBlob(md, `${fileSlug}-${timestampSlug()}.md`, 'text/markdown;charset=utf-8')
}

export function runRedZoneExport(
  format: 'xlsx' | 'json' | 'md',
  config: RedZoneExportConfig,
) {
  if (format === 'xlsx') return exportRedZoneXlsx(config.rows, config.sheetName, config.columns, config.fileSlug)
  if (format === 'json') return exportRedZoneJson(config.rows, config.sheetName, config.columns, config.fileSlug)
  return exportRedZoneMarkdown(config.rows, config.sheetName, config.columns, config.fileSlug)
}
