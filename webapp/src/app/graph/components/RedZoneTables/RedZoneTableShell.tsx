'use client'

import { memo, useCallback, type ReactNode } from 'react'
import { Loader2, AlertTriangle, Database, Search, Download, RefreshCw, SearchX } from 'lucide-react'
import styles from './RedZoneTableShell.module.css'
import {
  exportRedZoneXlsx,
  exportRedZoneJson,
  exportRedZoneMarkdown,
  type RedZoneExportConfig,
} from './exportXlsx'

interface RedZoneTableShellProps {
  title: string
  meta?: string
  search: string
  onSearchChange: (value: string) => void
  searchPlaceholder?: string
  /** Provide rows + columns to render XLSX/JSON/MD export buttons. */
  exportConfig?: RedZoneExportConfig
  /** Legacy single-button XLSX callback (kept for back-compat). */
  onExport?: () => void
  onRefresh?: () => void
  isLoading: boolean
  error: string | null
  rowCount: number
  filteredRowCount: number
  emptyLabel?: string
  noMatchLabel?: string
  children: ReactNode
}

export const RedZoneTableShell = memo(function RedZoneTableShell({
  title,
  meta,
  search,
  onSearchChange,
  searchPlaceholder = 'Search...',
  exportConfig,
  onExport,
  onRefresh,
  isLoading,
  error,
  rowCount,
  filteredRowCount,
  emptyLabel = 'No findings yet. Run a recon scan to populate this table.',
  noMatchLabel = 'No rows match your search.',
  children,
}: RedZoneTableShellProps) {
  const handleXlsx = useCallback(() => {
    if (!exportConfig) return
    exportRedZoneXlsx(exportConfig.rows, exportConfig.sheetName, exportConfig.columns, exportConfig.fileSlug)
  }, [exportConfig])
  const handleJson = useCallback(() => {
    if (!exportConfig) return
    exportRedZoneJson(exportConfig.rows, exportConfig.sheetName, exportConfig.columns, exportConfig.fileSlug)
  }, [exportConfig])
  const handleMd = useCallback(() => {
    if (!exportConfig) return
    exportRedZoneMarkdown(exportConfig.rows, exportConfig.sheetName, exportConfig.columns, exportConfig.fileSlug)
  }, [exportConfig])

  return (
    <div className={styles.container}>
      <div className={styles.header}>
        <div className={styles.headerLeft}>
          <span className={styles.title}>{title}</span>
          {meta && <span className={styles.meta}>{meta}</span>}
          <span className={styles.rowCount}>
            {filteredRowCount === rowCount ? `${rowCount}` : `${filteredRowCount}/${rowCount}`} rows
          </span>
        </div>
        <div className={styles.headerRight}>
          <div className={styles.searchWrapper}>
            <Search size={12} className={styles.searchIcon} />
            <input
              type="text"
              className={styles.searchInput}
              placeholder={searchPlaceholder}
              value={search}
              onChange={e => onSearchChange(e.target.value)}
              aria-label={`Search ${title}`}
            />
          </div>
          {onRefresh && (
            <button className={styles.iconBtn} onClick={onRefresh} aria-label="Refresh" title="Refresh">
              <RefreshCw size={12} />
            </button>
          )}
          {exportConfig ? (
            <>
              <button className={styles.exportBtn} onClick={handleXlsx} aria-label="Export to Excel" title="Export to Excel">
                <Download size={12} />
                <span>XLSX</span>
              </button>
              <button className={styles.exportBtn} onClick={handleJson} aria-label="Export to JSON" title="Export to JSON">
                <Download size={12} />
                <span>JSON</span>
              </button>
              <button className={styles.exportBtn} onClick={handleMd} aria-label="Export to Markdown" title="Export to Markdown">
                <Download size={12} />
                <span>MD</span>
              </button>
            </>
          ) : onExport ? (
            <button className={styles.exportBtn} onClick={onExport} aria-label="Export to Excel">
              <Download size={12} />
              <span>XLSX</span>
            </button>
          ) : null}
        </div>
      </div>

      <div className={styles.body}>
        {isLoading ? (
          <div className={styles.stateContainer}>
            <Loader2 size={24} className={styles.spinner} />
            <p className={styles.stateText}>Loading...</p>
          </div>
        ) : error ? (
          <div className={styles.stateContainer}>
            <AlertTriangle size={24} className={styles.errorIcon} />
            <p className={styles.stateText}>Failed to load</p>
            <p className={styles.stateSubtext}>{error}</p>
          </div>
        ) : rowCount === 0 ? (
          <div className={styles.stateContainer}>
            <Database size={24} className={styles.emptyIcon} />
            <p className={styles.stateText}>{emptyLabel}</p>
          </div>
        ) : filteredRowCount === 0 ? (
          <div className={styles.stateContainer}>
            <SearchX size={24} className={styles.emptyIcon} />
            <p className={styles.stateText}>{noMatchLabel}</p>
            <p className={styles.stateSubtext}>{rowCount} total rows — clear the search to see them.</p>
          </div>
        ) : (
          <div className={styles.tableScroll}>{children}</div>
        )}
      </div>
    </div>
  )
})
