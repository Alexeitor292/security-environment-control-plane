import {
  ArrowUp,
  BrainCircuit,
  FolderCode,
  Globe2,
  Maximize2,
  Mic,
  Paperclip,
  StopCircle,
  X,
} from 'lucide-react'
import { useEffect, useMemo, useRef, useState } from 'react'
import type { ChangeEvent, KeyboardEvent } from 'react'
import './AiPromptBox.css'

export type AiPromptMode = 'default' | 'search' | 'think' | 'canvas'

interface AiPromptBoxProps {
  contextLabel: string
  open: boolean
  onClose: () => void
  onOpenFullAi: () => void
}

function formatDuration(seconds: number) {
  const minutes = Math.floor(seconds / 60)
  const remainder = seconds % 60

  return `${minutes.toString().padStart(2, '0')}:${remainder.toString().padStart(2, '0')}`
}

export function AiPromptBox({ contextLabel, open, onClose, onOpenFullAi }: AiPromptBoxProps) {
  const textareaRef = useRef<HTMLTextAreaElement>(null)
  const uploadRef = useRef<HTMLInputElement>(null)

  const [value, setValue] = useState('')
  const [mode, setMode] = useState<AiPromptMode>('default')
  const [attachment, setAttachment] = useState<File | null>(null)
  const [preview, setPreview] = useState<string | null>(null)
  const [recording, setRecording] = useState(false)
  const [recordingSeconds, setRecordingSeconds] = useState(0)
  const [sent, setSent] = useState(false)

  const hasContent = value.trim().length > 0 || attachment !== null

  const placeholder = useMemo(() => {
    if (mode === 'search') {
      return 'Search the environment and connected sources...'
    }

    if (mode === 'think') {
      return 'Ask SECP to reason through the active workspace...'
    }

    if (mode === 'canvas') {
      return 'Describe what SECP should create or visualize...'
    }

    return `Ask SECP about ${contextLabel}...`
  }, [contextLabel, mode])

  useEffect(() => {
    if (!open) {
      return
    }

    const frame = window.requestAnimationFrame(() => {
      textareaRef.current?.focus()
    })

    return () => window.cancelAnimationFrame(frame)
  }, [open])

  useEffect(() => {
    function handleEscape(event: globalThis.KeyboardEvent) {
      if (open && event.key === 'Escape') {
        event.preventDefault()
        onClose()
      }
    }

    window.addEventListener('keydown', handleEscape)

    return () => window.removeEventListener('keydown', handleEscape)
  }, [onClose, open])

  useEffect(() => {
    const textarea = textareaRef.current

    if (!textarea) {
      return
    }

    textarea.style.height = 'auto'
    textarea.style.height = `${Math.min(textarea.scrollHeight, 150)}px`
  }, [value])

  useEffect(() => {
    if (!recording) {
      return
    }

    const interval = window.setInterval(() => {
      setRecordingSeconds((current) => current + 1)
    }, 1000)

    return () => window.clearInterval(interval)
  }, [recording])

  useEffect(() => {
    return () => {
      if (preview) {
        URL.revokeObjectURL(preview)
      }
    }
  }, [preview])

  function clearAttachment() {
    if (preview) {
      URL.revokeObjectURL(preview)
    }

    setAttachment(null)
    setPreview(null)
  }

  function handleUpload(event: ChangeEvent<HTMLInputElement>) {
    const file = event.target.files?.[0]

    event.target.value = ''

    if (!file || !file.type.startsWith('image/') || file.size > 10 * 1024 * 1024) {
      return
    }

    clearAttachment()
    setAttachment(file)
    setPreview(URL.createObjectURL(file))
  }

  function toggleMode(next: Exclude<AiPromptMode, 'default'>) {
    setMode((current) => (current === next ? 'default' : next))
  }

  function submit() {
    const message = value.trim()

    if (!message && !attachment) {
      return
    }

    window.dispatchEvent(
      new CustomEvent('secp:ai-prompt', {
        detail: {
          context: contextLabel,
          files: attachment ? [attachment] : [],
          message,
          mode,
        },
      }),
    )

    setValue('')
    clearAttachment()
    setSent(true)

    window.setTimeout(() => {
      setSent(false)
    }, 650)
  }

  function handleKeyDown(event: KeyboardEvent<HTMLTextAreaElement>) {
    if (event.key === 'Enter' && !event.shiftKey) {
      event.preventDefault()
      submit()
    }
  }

  function toggleRecording() {
    if (recording) {
      const duration = recordingSeconds

      setRecording(false)
      setRecordingSeconds(0)

      window.dispatchEvent(
        new CustomEvent('secp:ai-prompt', {
          detail: {
            context: contextLabel,
            files: [],
            message: `[Voice message - ${duration} seconds]`,
            mode,
          },
        }),
      )

      return
    }

    setRecordingSeconds(0)
    setRecording(true)
  }

  return (
    <section
      className={[
        'ai-prompt-box',
        open ? 'ai-prompt-box--open' : '',
        sent ? 'ai-prompt-box--sent' : '',
      ]
        .filter(Boolean)
        .join(' ')}
      aria-hidden={!open}
    >
      <span className="ai-prompt-box__bridge" aria-hidden="true" />

      <header className="ai-prompt-box__header">
        <div>
          <span />
          <strong>SECP Core</strong>
          <small>{contextLabel} context</small>
        </div>

        <nav aria-label="AI prompt controls">
          <button
            type="button"
            title="Open full AI workspace"
            aria-label="Open full AI workspace"
            onClick={onOpenFullAi}
          >
            <Maximize2 size={14} />
          </button>

          <button type="button" title="Close" aria-label="Close AI prompt" onClick={onClose}>
            <X size={14} />
          </button>
        </nav>
      </header>

      {preview && attachment ? (
        <div className="ai-prompt-box__attachment">
          <img src={preview} alt={attachment.name} />

          <span>
            <strong>{attachment.name}</strong>
            <small>Image attachment</small>
          </span>

          <button type="button" aria-label="Remove attachment" onClick={clearAttachment}>
            <X size={12} />
          </button>
        </div>
      ) : null}

      {recording ? (
        <div className="ai-prompt-box__recording">
          <div>
            <span />
            <strong>{formatDuration(recordingSeconds)}</strong>
          </div>

          <div className="ai-prompt-box__waveform">
            {Array.from({ length: 28 }).map((_, index) => (
              <i
                key={index}
                style={{
                  animationDelay: `${index * 38}ms`,
                }}
              />
            ))}
          </div>
        </div>
      ) : (
        <textarea
          ref={textareaRef}
          className="ai-prompt-box__textarea"
          placeholder={placeholder}
          rows={1}
          value={value}
          onChange={(event) => setValue(event.target.value)}
          onKeyDown={handleKeyDown}
        />
      )}

      <footer className="ai-prompt-box__footer">
        <div className="ai-prompt-box__tools">
          <button
            className="ai-prompt-tool ai-prompt-tool--attach"
            type="button"
            title="Attach image"
            aria-label="Attach image"
            onClick={() => uploadRef.current?.click()}
          >
            <Paperclip size={16} />

            <input ref={uploadRef} hidden accept="image/*" type="file" onChange={handleUpload} />
          </button>

          <button
            className={
              mode === 'search'
                ? 'ai-prompt-tool ai-prompt-tool--active ai-prompt-tool--search'
                : 'ai-prompt-tool'
            }
            type="button"
            onClick={() => toggleMode('search')}
          >
            <Globe2 size={15} />
            <span>Search</span>
          </button>

          <i />

          <button
            className={
              mode === 'think'
                ? 'ai-prompt-tool ai-prompt-tool--active ai-prompt-tool--think'
                : 'ai-prompt-tool'
            }
            type="button"
            onClick={() => toggleMode('think')}
          >
            <BrainCircuit size={15} />
            <span>Think</span>
          </button>

          <i />

          <button
            className={
              mode === 'canvas'
                ? 'ai-prompt-tool ai-prompt-tool--active ai-prompt-tool--canvas'
                : 'ai-prompt-tool'
            }
            type="button"
            onClick={() => toggleMode('canvas')}
          >
            <FolderCode size={15} />
            <span>Canvas</span>
          </button>
        </div>

        <button
          className={[
            'ai-prompt-box__submit',
            hasContent ? 'ai-prompt-box__submit--ready' : '',
            recording ? 'ai-prompt-box__submit--recording' : '',
          ]
            .filter(Boolean)
            .join(' ')}
          type="button"
          aria-label={
            recording ? 'Stop recording' : hasContent ? 'Send prompt' : 'Start voice message'
          }
          onClick={() => {
            if (recording) {
              toggleRecording()
            } else if (hasContent) {
              submit()
            } else {
              toggleRecording()
            }
          }}
        >
          {recording ? (
            <StopCircle size={18} />
          ) : hasContent ? (
            <ArrowUp size={16} />
          ) : (
            <Mic size={18} />
          )}
        </button>
      </footer>
    </section>
  )
}
