import type { TableRow } from '../hooks/useTableData'
import {
  sanitizeXlsxCell,
  timestampSlug,
  downloadBlob,
  flattenCellValue,
  escapeMarkdownCell,
} from './exportHelpers'

interface NodeExportRow {
  Type: string
  Name: string
  ID: string
  'Connections In': number
  'Connections Out': number
  'Connections In Detail': string
  'Connections Out Detail': string
  'Level 2': number
  'Level 2 Detail': string
  'Level 3': number
  'Level 3 Detail': string
  [extra: string]: unknown
}

function buildExportRows(rows: TableRow[]): NodeExportRow[] {
  return rows.map(row => {
    const base: NodeExportRow = {
      Type: row.node.type,
      Name: row.node.name,
      ID: row.node.id,
      'Connections In': row.connectionsIn.length,
      'Connections Out': row.connectionsOut.length,
      'Connections In Detail': row.connectionsIn
        .map(c => `${c.nodeType}: ${c.nodeName} (${c.relationType})`)
        .join('; '),
      'Connections Out Detail': row.connectionsOut
        .map(c => `${c.nodeType}: ${c.nodeName} (${c.relationType})`)
        .join('; '),
      'Level 2': row.getLevel2().length,
      'Level 2 Detail': row.getLevel2()
        .map(c => `${c.nodeType}: ${c.nodeName}`)
        .join('; '),
      'Level 3': row.getLevel3().length,
      'Level 3 Detail': row.getLevel3()
        .map(c => `${c.nodeType}: ${c.nodeName}`)
        .join('; '),
    }

    for (const [key, value] of Object.entries(row.node.properties)) {
      if (key === 'project_id' || key === 'user_id') continue
      let cellValue: unknown
      if (Array.isArray(value)) {
        cellValue = value
          .map(v => (typeof v === 'object' && v !== null ? JSON.stringify(v) : v))
          .join(', ')
      } else if (typeof value === 'object' && value !== null) {
        try {
          cellValue = JSON.stringify(value)
        } catch {
          cellValue = String(value)
        }
      } else {
        cellValue = value
      }
      base[key] = cellValue
    }

    return base
  })
}

export async function exportToExcel(rows: TableRow[], filename?: string) {
  const XLSX = await import('xlsx')
  const built = buildExportRows(rows)

  const wsData = built.map(row => {
    const cleaned: Record<string, unknown> = {}
    for (const [k, v] of Object.entries(row)) cleaned[k] = sanitizeXlsxCell(v)
    return cleaned
  })

  const ws = XLSX.utils.json_to_sheet(wsData)
  const wb = XLSX.utils.book_new()
  XLSX.utils.book_append_sheet(wb, ws, 'Nodes')

  XLSX.writeFile(wb, `${filename || 'redamon-data'}-${timestampSlug()}.xlsx`)
}

export function exportToJson(rows: TableRow[], filename?: string) {
  const built = buildExportRows(rows)
  const slug = filename || 'redamon-data'
  downloadBlob(
    JSON.stringify(built, null, 2),
    `${slug}-${timestampSlug()}.json`,
    'application/json;charset=utf-8',
  )
}

export function exportToMarkdown(rows: TableRow[], filename?: string) {
  const built = buildExportRows(rows)
  const slug = filename || 'redamon-data'

  // Markdown table headers: union of keys, in order of first appearance
  const headerSet = new Set<string>()
  built.forEach(row => Object.keys(row).forEach(k => headerSet.add(k)))
  const headers = Array.from(headerSet)

  const headerLine = `| ${headers.join(' | ')} |`
  const sepLine = `| ${headers.map(() => '---').join(' | ')} |`
  const dataLines = built.map(row =>
    `| ${headers.map(h => escapeMarkdownCell(flattenCellValue(row[h]))).join(' | ')} |`,
  )

  const md = `# Nodes Export\n\nGenerated: ${new Date().toISOString()}\nRows: ${built.length}\n\n${headerLine}\n${sepLine}\n${dataLines.join('\n')}\n`
  downloadBlob(md, `${slug}-${timestampSlug()}.md`, 'text/markdown;charset=utf-8')
}
