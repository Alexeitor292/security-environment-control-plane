import type { ReactNode } from 'react'
import type { CapabilityStatus } from '../models/types'
import { CapabilityTag } from './CapabilityNotice'

export interface PageHeaderProps {
  title: ReactNode
  description?: ReactNode
  actions?: ReactNode
  capabilityStatus?: CapabilityStatus
  meta?: ReactNode
}

/** Replaceable slot: page header (title, description, primary actions). */
export function PageHeader({
  title,
  description,
  actions,
  capabilityStatus,
  meta,
}: PageHeaderProps) {
  return (
    <header className="c-pagehead">
      <div className="c-pagehead__text">
        <h1>
          {title}
          {capabilityStatus && <CapabilityTag status={capabilityStatus} />}
        </h1>
        {description && <p className="c-pagehead__desc">{description}</p>}
        {meta && <div className="c-pagehead__meta">{meta}</div>}
      </div>
      {actions && <div className="c-pagehead__actions">{actions}</div>}
    </header>
  )
}
