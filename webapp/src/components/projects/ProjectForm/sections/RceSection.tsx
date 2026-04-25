'use client'

import type { Project } from '@prisma/client'
import styles from '../ProjectForm.module.css'

type FormData = Omit<Project, 'id' | 'userId' | 'createdAt' | 'updatedAt' | 'user'>

interface RceSectionProps {
  data: FormData
  updateField: <K extends keyof FormData>(field: K, value: FormData[K]) => void
}

export function RceSection({ data, updateField }: RceSectionProps) {
  return (
    <div style={{ padding: 'var(--space-3) var(--space-4)' }}>
      <p className={styles.sectionDescription}>
        Configure how the agent tests for RCE / command injection. Disable sub-workflows you don&apos;t want
        injected into the prompt and gate destructive payloads behind the explicit aggressive toggle.
      </p>

      <h3 className={styles.fieldLabel} style={{ marginTop: 'var(--space-3)' }}>
        Sub-workflow injection
      </h3>

      <div className={styles.fieldRow}>
        <div className={styles.fieldGroup}>
          <label className={styles.fieldLabel}>
            <input
              type="checkbox"
              checked={data.rceOobCallbackEnabled ?? true}
              onChange={(e) => updateField('rceOobCallbackEnabled', e.target.checked)}
              style={{ marginRight: '8px' }}
            />
            OOB callback workflow (interactsh)
          </label>
          <span className={styles.fieldHint}>
            Adds the blind-RCE / OOB sub-prompt. The agent registers an oast.fun domain and uses DNS or HTTP
            callbacks as a quiet oracle for command execution. Disable when external OOB providers are off-limits.
          </span>
        </div>
      </div>

      <div className={styles.fieldRow}>
        <div className={styles.fieldGroup}>
          <label className={styles.fieldLabel}>
            <input
              type="checkbox"
              checked={data.rceDeserializationEnabled ?? true}
              onChange={(e) => updateField('rceDeserializationEnabled', e.target.checked)}
              style={{ marginRight: '8px' }}
            />
            Deserialization gadget workflow (ysoserial)
          </label>
          <span className={styles.fieldHint}>
            Adds the Java / PHP / Python / Ruby / .NET deserialization sub-prompt with ysoserial gadget-chain
            guidance (URLDNS, CommonsCollections, Spring, etc.). Disable when the target stack does not deserialize
            untrusted input or when you want a leaner prompt.
          </span>
        </div>
      </div>

      <div className={styles.fieldRow}>
        <div className={styles.fieldGroup}>
          <label className={styles.fieldLabel}>
            <input
              type="checkbox"
              checked={data.rceAggressivePayloads ?? false}
              onChange={(e) => updateField('rceAggressivePayloads', e.target.checked)}
              style={{ marginRight: '8px' }}
            />
            Aggressive payloads (file write, web shells, container escape)
          </label>
          <span className={styles.fieldHint}>
            <strong>Default OFF.</strong> When enabled, Step 7 of the workflow permits file writes outside /tmp,
            persistent web shells / cron / systemd hooks, reverse-shell handlers, and container / Kubernetes escape
            probes. Leave OFF for read-only proofs (id, whoami, /etc/passwd) which already produce a Level 3 finding.
            Only enable for engagements where critical-impact (Level 4) demonstration is explicitly authorised.
          </span>
        </div>
      </div>
    </div>
  )
}
