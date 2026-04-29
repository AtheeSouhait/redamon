/**
 * End-to-end smoke tests for every export format on every page table.
 *
 * Validates:
 *   - No exceptions on representative sample data
 *   - Filename slugs and timestamp suffix are correct
 *   - Output payloads (XLSX workbook, JSON object, MD string) are well-formed
 *
 * Browser DOM bits (URL.createObjectURL, anchor click, XLSX.writeFile) are
 * intercepted and the captured content is parsed back to verify structure.
 */
import { describe, test, expect, beforeEach, afterEach, vi } from 'vitest'
import * as XLSX from 'xlsx'

// Mock xlsx so `writeFile` becomes a capturable spy (ESM exports are read-only).
vi.mock('xlsx', async () => {
  const actual = await vi.importActual<typeof XLSX>('xlsx')
  return {
    ...actual,
    writeFile: vi.fn((wb: XLSX.WorkBook, filename: string) => {
      const buf = actual.write(wb, { type: 'buffer', bookType: 'xlsx' })
      const reparsed = actual.read(buf, { type: 'buffer' })
      // Stash on the workbook so the test can fish it back out
      ;(globalThis as any).__lastXlsxDownload = { filename, workbook: reparsed }
    }),
    default: { ...actual, writeFile: vi.fn() },
  }
})

import {
  exportToExcel,
  exportToJson,
  exportToMarkdown,
} from './exportExcel'
import {
  exportRedZoneXlsx,
  exportRedZoneJson,
  exportRedZoneMarkdown,
} from '../components/RedZoneTables/exportXlsx'
import {
  exportJsReconXlsx,
  exportJsReconJson,
  exportJsReconMarkdown,
  type JsReconData,
} from '../components/JsReconTable/JsReconTable'
import type { TableRow } from '../hooks/useTableData'

// ============================================================
// DOM / XLSX interception helpers
// ============================================================

interface CapturedDownload {
  filename: string
  text?: string
  workbook?: XLSX.WorkBook
}

let downloads: CapturedDownload[] = []
let originalCreateObjectURL: typeof URL.createObjectURL
let originalRevokeObjectURL: typeof URL.revokeObjectURL

async function flush() {
  // anchor.click is async (await blob.text()) -- give microtasks one tick
  await Promise.resolve()
  await Promise.resolve()
  // pull XLSX-side capture (set inside the vi.mock above)
  const xlsxCap = (globalThis as any).__lastXlsxDownload
  if (xlsxCap) {
    downloads.push({ filename: xlsxCap.filename, workbook: xlsxCap.workbook })
    ;(globalThis as any).__lastXlsxDownload = undefined
  }
}

beforeEach(() => {
  downloads = []
  ;(globalThis as any).__lastXlsxDownload = undefined

  // Patch URL.createObjectURL: store the Blob so we can read its text later
  const blobs = new Map<string, Blob>()
  originalCreateObjectURL = URL.createObjectURL
  originalRevokeObjectURL = URL.revokeObjectURL
  let counter = 0
  URL.createObjectURL = vi.fn((blob: Blob) => {
    const url = `blob:test/${++counter}`
    blobs.set(url, blob)
    return url
  })
  URL.revokeObjectURL = vi.fn()

  // Intercept anchor click; jsdom's a.click() is a no-op but we still want
  // to capture filename + read blob content
  const originalCreate = document.createElement.bind(document)
  vi.spyOn(document, 'createElement').mockImplementation(((tag: string) => {
    const el = originalCreate(tag)
    if (tag.toLowerCase() === 'a') {
      const a = el as HTMLAnchorElement
      a.click = async () => {
        const blob = blobs.get(a.href)
        if (blob) {
          const text = await blob.text()
          downloads.push({ filename: a.download, text })
        }
      }
    }
    return el
  }) as typeof document.createElement)
})

afterEach(() => {
  URL.createObjectURL = originalCreateObjectURL
  URL.revokeObjectURL = originalRevokeObjectURL
  vi.restoreAllMocks()
})

const TS_SUFFIX_RE = /-\d{4}-\d{2}-\d{2}-\d{2}-\d{2}-\d{2}\.(xlsx|json|md)$/

// ============================================================
// Sample fixtures
// ============================================================

function makeTableRows(): TableRow[] {
  // Two nodes: a Subdomain with binary-ish data + array, and an Endpoint
  return [
    {
      node: {
        id: 'sub-1',
        type: 'Subdomain',
        name: 'admin.example.com',
        properties: {
          subdomain: 'admin.example.com',
          tags: ['live', 'auth'],
          banner: 'HTTP/1.1 200 OK\u0000\u0007 evil-binary',  // contains XML-illegal chars
          response_size: 12345,
          is_alive: true,
          long_text: 'X'.repeat(40000),  // exceeds XLSX cell limit
          project_id: 'should-be-skipped',
          user_id: 'should-be-skipped',
        },
      } as any,
      connectionsIn: [
        { nodeId: 'd-1', nodeName: 'example.com', nodeType: 'Domain', relationType: 'PART_OF' },
      ],
      connectionsOut: [
        { nodeId: 'ep-1', nodeName: '/login', nodeType: 'Endpoint', relationType: 'HAS_ENDPOINT' },
      ],
      getLevel2: () => [
        { nodeId: 'tld-1', nodeName: 'example', nodeType: 'TLD', relationType: '2 hops' },
      ],
      getLevel3: () => [],
    },
    {
      node: {
        id: 'ep-1',
        type: 'Endpoint',
        name: '/login',
        properties: { method: 'POST', path: '/login', is_alive: false },
      } as any,
      connectionsIn: [],
      connectionsOut: [],
      getLevel2: () => [],
      getLevel3: () => [],
    },
  ]
}

function makeRedZoneRows() {
  return [
    {
      severity: 'critical',
      hostname: 'admin.example.com',
      port: 443,
      isCdn: true,
      tags: ['production', 'auth'],
      cveCount: 12,
      lastSeen: null,
      payload: { method: 'GET', path: '/admin' },
      garbled: 'header\u0000binary\u0007junk',
    },
    {
      severity: 'low',
      hostname: 'cdn.example.com',
      port: 80,
      isCdn: false,
      tags: [],
      cveCount: 0,
      lastSeen: '2026-04-29',
      payload: null,
      garbled: 'normal text',
    },
  ]
}

const RED_ZONE_COLUMNS = [
  { key: 'severity', header: 'Severity' },
  { key: 'hostname', header: 'Hostname' },
  { key: 'port', header: 'Port' },
  { key: 'isCdn', header: 'CDN' },
  { key: 'tags', header: 'Tags' },
  { key: 'cveCount', header: 'CVEs' },
  { key: 'lastSeen', header: 'Last Seen' },
  { key: 'payload', header: 'Payload' },
  { key: 'garbled', header: 'Garbled' },
]

function makeJsReconData(): JsReconData {
  return {
    scan_metadata: { js_files_analyzed: 3 },
    secrets: [
      {
        severity: 'critical',
        name: 'AWS Access Key',
        redacted_value: 'AKIA…X',
        matched_text: 'AKIAFAKE\u0001binary',
        category: 'cloud',
        source_url: 'https://example.com/app.js',
        line_number: 42,
        context: 'var k = "AKIA…X"',
        detection_method: 'regex',
        validation: { status: 'validated' },
        confidence: 'high',
        validator_ref: 'aws',
      },
    ],
    endpoints: [
      {
        severity: 'info',
        method: 'POST',
        path: '/api/v1/users',
        full_url: 'https://api.example.com/api/v1/users',
        type: 'rest',
        category: 'user',
        base_url: 'https://api.example.com',
        source_js: 'https://example.com/app.js',
        parameters: ['id', 'name'],
        line_number: 156,
      },
    ],
    discovered_subdomains: ['admin.example.com', 'api.example.com'],
    external_domains: [{ domain: 'cdn.example.net', times_seen: 5 }],
  }
}

// ============================================================
// All-Nodes (page-level)
// ============================================================

describe('All-Nodes table exports', () => {
  test('XLSX: produces a workbook with a Nodes sheet, sanitizes binary chars, truncates long cells', async () => {
    const rows = makeTableRows()
    await exportToExcel(rows)
    await flush()
    expect(downloads).toHaveLength(1)
    const dl = downloads[0]
    expect(dl.filename).toMatch(/^redamon-data-/)
    expect(dl.filename).toMatch(TS_SUFFIX_RE)
    expect(dl.workbook).toBeDefined()
    const wb = dl.workbook!
    expect(wb.SheetNames).toContain('Nodes')
    const sheet = wb.Sheets['Nodes']
    const json = XLSX.utils.sheet_to_json<Record<string, unknown>>(sheet)
    expect(json).toHaveLength(2)
    expect(json[0]['Type']).toBe('Subdomain')
    expect(json[0]['Name']).toBe('admin.example.com')
    // banner had \u0000 and \u0007 -- must be stripped
    expect(String(json[0]['banner'])).not.toMatch(/[\u0000\u0007]/)
    // long_text truncated to <= 32767 chars (with ellipsis)
    expect(String(json[0]['long_text']).length).toBeLessThanOrEqual(32767)
    // Excluded fields
    expect(json[0]['project_id']).toBeUndefined()
    expect(json[0]['user_id']).toBeUndefined()
    // Numeric primitives preserved
    expect(typeof json[0]['response_size']).toBe('number')
    // Boolean primitive preserved (xlsx parses booleans back as boolean)
    expect(typeof json[0]['is_alive']).toBe('boolean')
  })

  test('JSON: produces parseable JSON with all expected fields', async () => {
    const rows = makeTableRows()
    exportToJson(rows)
    await flush()
    expect(downloads).toHaveLength(1)
    const dl = downloads[0]
    expect(dl.filename).toMatch(/^redamon-data-/)
    expect(dl.filename.endsWith('.json')).toBe(true)
    const data = JSON.parse(dl.text!)
    expect(Array.isArray(data)).toBe(true)
    expect(data).toHaveLength(2)
    expect(data[0].Type).toBe('Subdomain')
    expect(data[0].Name).toBe('admin.example.com')
    expect(data[0]['Connections In']).toBe(1)
    // banner kept as raw string in JSON (no xlsx sanitization)
    expect(typeof data[0].banner).toBe('string')
  })

  test('Markdown: produces a valid GFM table', async () => {
    const rows = makeTableRows()
    exportToMarkdown(rows)
    await flush()
    expect(downloads).toHaveLength(1)
    const dl = downloads[0]
    expect(dl.filename).toMatch(/^redamon-data-/)
    expect(dl.filename.endsWith('.md')).toBe(true)
    const md = dl.text!
    expect(md).toContain('# Nodes Export')
    expect(md).toContain('| Type |')
    // Header separator row
    expect(md).toMatch(/\| --- \|/)
    expect(md).toContain('admin.example.com')
    expect(md).toContain('Subdomain')
    // Pipes inside a cell value should be escaped (\|) -- our banner has no pipes
    // but we should never have a raw newline inside a cell
    const lines = md.split('\n')
    const dataLines = lines.filter(l => l.startsWith('| ') && !l.includes(' --- '))
    // every data line should have the same number of pipes (header + 2 rows + 1 sep)
    const pipeCounts = dataLines.map(l => (l.match(/\|/g) || []).length)
    const uniqueCounts = new Set(pipeCounts)
    expect(uniqueCounts.size).toBe(1)
  })
})

// ============================================================
// Red Zone tables (e.g. Blast Radius / Secrets / etc.)
// ============================================================

describe('Red Zone table exports', () => {
  test('XLSX: produces a workbook, preserves primitive types, sanitizes binary chars', async () => {
    await exportRedZoneXlsx(makeRedZoneRows(), 'Blast-Radius', RED_ZONE_COLUMNS, 'redzone-blast-radius')
    await flush()
    expect(downloads).toHaveLength(1)
    const dl = downloads[0]
    expect(dl.filename).toMatch(/^redzone-blast-radius-/)
    expect(dl.filename).toMatch(TS_SUFFIX_RE)
    const wb = dl.workbook!
    expect(wb.SheetNames).toContain('Blast-Radius')
    const sheet = wb.Sheets['Blast-Radius']
    const json = XLSX.utils.sheet_to_json<Record<string, unknown>>(sheet)
    expect(json).toHaveLength(2)
    expect(json[0]['Severity']).toBe('critical')
    expect(json[0]['Hostname']).toBe('admin.example.com')
    // Native types preserved (no flattening to string for primitives)
    expect(typeof json[0]['Port']).toBe('number')
    expect(typeof json[0]['CDN']).toBe('boolean')
    expect(typeof json[0]['CVEs']).toBe('number')
    // Arrays joined into a string
    expect(json[0]['Tags']).toBe('production, auth')
    // Object stringified
    expect(String(json[0]['Payload'])).toContain('"method":"GET"')
    // Binary chars stripped
    expect(String(json[0]['Garbled'])).not.toMatch(/[\u0000\u0007]/)
  })

  test('JSON: produces parseable JSON, keeps native objects/arrays', async () => {
    exportRedZoneJson(makeRedZoneRows(), 'Blast-Radius', RED_ZONE_COLUMNS, 'redzone-blast-radius')
    await flush()
    expect(downloads).toHaveLength(1)
    const dl = downloads[0]
    expect(dl.filename).toMatch(/^redzone-blast-radius-/)
    expect(dl.filename.endsWith('.json')).toBe(true)
    const data = JSON.parse(dl.text!)
    expect(Array.isArray(data)).toBe(true)
    expect(data).toHaveLength(2)
    expect(data[0].Severity).toBe('critical')
    expect(data[0].Hostname).toBe('admin.example.com')
    // Native types preserved in JSON
    expect(typeof data[0].Port).toBe('number')
    expect(typeof data[0].CDN).toBe('boolean')
    expect(Array.isArray(data[0].Tags)).toBe(true)
    expect(typeof data[0].Payload).toBe('object')
    expect(data[0].Payload.method).toBe('GET')
    // Null normalized
    expect(data[0]['Last Seen']).toBeNull()
  })

  test('Markdown: produces a GFM table with proper escaping', async () => {
    exportRedZoneMarkdown(makeRedZoneRows(), 'Blast-Radius', RED_ZONE_COLUMNS, 'redzone-blast-radius')
    await flush()
    expect(downloads).toHaveLength(1)
    const dl = downloads[0]
    expect(dl.filename).toMatch(/^redzone-blast-radius-/)
    expect(dl.filename.endsWith('.md')).toBe(true)
    const md = dl.text!
    expect(md).toContain('# Blast-Radius')
    expect(md).toMatch(/\| Severity \| Hostname \|/)
    expect(md).toContain('admin.example.com')
    // Object/array flattened to string
    expect(md).toContain('production, auth')
    // Same column count on every line
    const lines = md.split('\n').filter(l => l.startsWith('|'))
    const pipeCounts = new Set(lines.map(l => (l.match(/\|/g) || []).length))
    expect(pipeCounts.size).toBe(1)
  })
})

// ============================================================
// JS Recon (multi-sheet, multi-section)
// ============================================================

describe('JS Recon table exports', () => {
  test('XLSX: writes one sheet per non-empty section', async () => {
    await exportJsReconXlsx(makeJsReconData())
    await flush()
    expect(downloads).toHaveLength(1)
    const dl = downloads[0]
    expect(dl.filename).toMatch(/^js-recon-/)
    expect(dl.filename).toMatch(TS_SUFFIX_RE)
    const wb = dl.workbook!
    expect(wb.SheetNames).toContain('Secrets')
    expect(wb.SheetNames).toContain('Endpoints')
    expect(wb.SheetNames).toContain('Subdomains')
    expect(wb.SheetNames).toContain('External Domains')
    // Sheets that are empty (e.g. dependencies, source maps) must be absent
    expect(wb.SheetNames).not.toContain('Dependencies')
    expect(wb.SheetNames).not.toContain('Source Maps')

    const secrets = XLSX.utils.sheet_to_json<Record<string, unknown>>(wb.Sheets['Secrets'])
    expect(secrets).toHaveLength(1)
    expect(secrets[0]['name']).toBe('AWS Access Key')
    expect(secrets[0]['validation.status']).toBe('validated')
    // \u0001 in matched_text must be stripped
    expect(String(secrets[0]['matched_text'])).not.toMatch(/[\u0000-\u0008]/)
    // Numeric line_number preserved as number
    expect(typeof secrets[0]['line_number']).toBe('number')

    const endpoints = XLSX.utils.sheet_to_json<Record<string, unknown>>(wb.Sheets['Endpoints'])
    expect(endpoints[0]['parameters']).toBe('id, name')
  })

  test('JSON: produces a parseable object keyed by section name', async () => {
    exportJsReconJson(makeJsReconData())
    await flush()
    expect(downloads).toHaveLength(1)
    const dl = downloads[0]
    expect(dl.filename).toMatch(/^js-recon-/)
    expect(dl.filename.endsWith('.json')).toBe(true)
    const data = JSON.parse(dl.text!)
    expect(Array.isArray(data['Secrets'])).toBe(true)
    expect(data['Secrets']).toHaveLength(1)
    expect(data['Secrets'][0].name).toBe('AWS Access Key')
    expect(data['Secrets'][0]['validation.status']).toBe('validated')
    // Empty sections are not included
    expect(data['Dependencies']).toBeUndefined()
    expect(data['Source Maps']).toBeUndefined()
    // Subdomains were transformed to {subdomain: <s>}
    expect(data['Subdomains']).toEqual([
      { subdomain: 'admin.example.com' },
      { subdomain: 'api.example.com' },
    ])
  })

  test('Markdown: produces a multi-section markdown doc', async () => {
    exportJsReconMarkdown(makeJsReconData())
    await flush()
    expect(downloads).toHaveLength(1)
    const dl = downloads[0]
    expect(dl.filename).toMatch(/^js-recon-/)
    expect(dl.filename.endsWith('.md')).toBe(true)
    const md = dl.text!
    expect(md).toContain('# JS Recon Findings')
    expect(md).toContain('## Secrets (1)')
    expect(md).toContain('## Endpoints (1)')
    expect(md).toContain('## Subdomains (2)')
    expect(md).toContain('## External Domains (1)')
    // Empty sections must be omitted
    expect(md).not.toContain('## Dependencies')
    expect(md).not.toContain('## Source Maps')
    // GFM table after each section heading
    expect(md).toMatch(/## Secrets[\s\S]+?\| --- \|/)
    // Header + sep + 1 row at minimum for Secrets
    expect(md).toContain('AWS Access Key')
  })
})

// ============================================================
// Bonus: filename collision / multi-call sequencing
// ============================================================

describe('Multiple sequential exports', () => {
  test('Each call produces an independent download with a unique-ish filename', async () => {
    const rows = makeTableRows()
    await exportToExcel(rows)
    await flush()
    exportToJson(rows)
    await flush()
    exportToMarkdown(rows)
    await flush()
    expect(downloads).toHaveLength(3)
    expect(downloads[0].filename).toMatch(/\.xlsx$/)
    expect(downloads[1].filename).toMatch(/\.json$/)
    expect(downloads[2].filename).toMatch(/\.md$/)
  })
})
