import { streamUrl } from './client'
import type { EventView } from './types'

export type StreamStatus = 'connecting' | 'connected' | 'reconnecting' | 'closed'

interface EventSourceLike {
  onopen: ((event: Event) => void) | null
  onerror: ((event: Event) => void) | null
  addEventListener(type: string, listener: EventListener): void
  close(): void
}

type EventSourceFactory = (url: string) => EventSourceLike

export interface ProcessStreamCallbacks {
  onEvent(event: EventView): void
  onReset(): void
  onStatus(status: StreamStatus): void
}

const EVENT_TYPES = [
  'run.queued',
  'run.initialized',
  'run.status_changed',
  'task.status_changed',
  'skill.progress',
]
const RETRY_DELAYS = [1000, 2000, 5000, 10_000, 15_000]

export class ProcessEventStream {
  private source: EventSourceLike | null = null
  private retryTimer: ReturnType<typeof setTimeout> | null = null
  private retryIndex = 0
  private closed = false
  private baseUrl: string
  private runId: string
  private cursor: string
  private callbacks: ProcessStreamCallbacks
  private sourceFactory: EventSourceFactory

  constructor(
    baseUrl: string,
    runId: string,
    cursor: string,
    callbacks: ProcessStreamCallbacks,
    sourceFactory: EventSourceFactory = (url) => new EventSource(url),
  ) {
    this.baseUrl = baseUrl
    this.runId = runId
    this.cursor = cursor
    this.callbacks = callbacks
    this.sourceFactory = sourceFactory
  }

  start(): void {
    this.closed = false
    this.connect('connecting')
  }

  close(): void {
    this.closed = true
    if (this.retryTimer) clearTimeout(this.retryTimer)
    this.retryTimer = null
    this.source?.close()
    this.source = null
    this.callbacks.onStatus('closed')
  }

  private connect(status: StreamStatus): void {
    if (this.closed) return
    this.callbacks.onStatus(status)
    const source = this.sourceFactory(streamUrl(this.baseUrl, this.runId, this.cursor))
    this.source = source
    source.onopen = () => this.handleOpen()
    source.onerror = () => this.handleError(source)
    EVENT_TYPES.forEach((type) => source.addEventListener(type, this.handleMessage))
    source.addEventListener('reset', this.handleReset)
  }

  private handleOpen = (): void => {
    this.retryIndex = 0
    this.callbacks.onStatus('connected')
  }

  private handleMessage = (raw: Event): void => {
    try {
      const message = raw as MessageEvent<string>
      const event = JSON.parse(message.data) as EventView
      this.cursor = message.lastEventId || event.id || this.cursor
      this.callbacks.onEvent(event)
    } catch {
      this.handleError(this.source)
    }
  }

  private handleReset = (): void => {
    this.source?.close()
    this.source = null
    this.callbacks.onReset()
  }

  private handleError(source: EventSourceLike | null): void {
    if (this.closed || source !== this.source) return
    source?.close()
    this.source = null
    const delay = RETRY_DELAYS[Math.min(this.retryIndex, RETRY_DELAYS.length - 1)]
    this.retryIndex += 1
    this.callbacks.onStatus('reconnecting')
    this.retryTimer = setTimeout(() => this.connect('reconnecting'), delay)
  }
}
