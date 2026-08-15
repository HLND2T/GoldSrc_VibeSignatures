import { afterEach, describe, expect, it, vi } from 'vitest'
import { ProcessEventStream } from './sse'

class FakeEventSource {
  onopen: ((event: Event) => void) | null = null
  onerror: ((event: Event) => void) | null = null
  listeners = new Map<string, EventListener>()
  closed = false

  addEventListener(type: string, listener: EventListener) {
    this.listeners.set(type, listener)
  }

  close() {
    this.closed = true
  }

  emit(type: string, data: unknown, id = '') {
    this.listeners.get(type)?.(new MessageEvent(type, { data: JSON.stringify(data), lastEventId: id }))
  }
}

describe('ProcessEventStream', () => {
  afterEach(() => vi.useRealTimers())

  it('reconnects manually from the newest event cursor', () => {
    vi.useFakeTimers()
    const sources: FakeEventSource[] = []
    const urls: string[] = []
    const stream = new ProcessEventStream(
      'http://127.0.0.1:8000',
      'run-1',
      '1-0',
      { onEvent: vi.fn(), onReset: vi.fn(), onStatus: vi.fn() },
      (url) => {
        urls.push(url)
        const source = new FakeEventSource()
        sources.push(source)
        return source
      },
    )
    stream.start()
    sources[0].onopen?.(new Event('open'))
    sources[0].emit('task.status_changed', { id: '2-0', type: 'task.status_changed' }, '2-0')
    sources[0].onerror?.(new Event('error'))
    vi.advanceTimersByTime(1000)
    expect(urls[0]).toContain('after=1-0')
    expect(urls[1]).toContain('after=2-0')
    expect(sources[0].closed).toBe(true)
    stream.close()
  })

  it('delegates reset events without automatic replay', () => {
    const source = new FakeEventSource()
    const onReset = vi.fn()
    const stream = new ProcessEventStream(
      'http://127.0.0.1:8000',
      'run-1',
      '1-0',
      { onEvent: vi.fn(), onReset, onStatus: vi.fn() },
      () => source,
    )
    stream.start()
    source.emit('reset', { code: 'cursor_expired' })
    expect(onReset).toHaveBeenCalledOnce()
    expect(source.closed).toBe(true)
  })
})
