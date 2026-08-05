import { Search } from 'lucide-react'
import type { ReactNode } from 'react'

export interface FilterOption {
  value: string
  label: string
}

export interface FilterSelectProps {
  label: string
  value: string
  options: FilterOption[]
  onChange: (value: string) => void
}

export function FilterSelect({ label, value, options, onChange }: FilterSelectProps) {
  return (
    <label className="c-filter">
      <span className="c-filter__label">{label}</span>
      <select value={value} onChange={(e) => onChange(e.target.value)}>
        {options.map((opt) => (
          <option key={opt.value} value={opt.value}>
            {opt.label}
          </option>
        ))}
      </select>
    </label>
  )
}

export function SearchField({
  value,
  onChange,
  placeholder = 'Search…',
}: {
  value: string
  onChange: (value: string) => void
  placeholder?: string
}) {
  return (
    <label className="c-search">
      <Search size={13} aria-hidden />
      <input
        type="search"
        value={value}
        placeholder={placeholder}
        onChange={(e) => onChange(e.target.value)}
        aria-label={placeholder}
      />
    </label>
  )
}

/** Replaceable slot: filter bar — lays out selects + search + extras. */
export function FilterBar({ children }: { children: ReactNode }) {
  return <div className="c-filterbar">{children}</div>
}
