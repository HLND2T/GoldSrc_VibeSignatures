import { useQuery } from '@tanstack/react-query'
import { useEffect, useRef } from 'react'
import { getRun, getSnapshot } from '../../api/client'
import { ProcessEventStream } from '../../api/sse'
import { isTerminalRun } from '../../api/types'
import { useApiConfig } from '../../app/apiContext'
import { useRunLiveStore } from './liveStore'

interface StreamOptions {
  baseUrl: string
  runId: string
  snapshotVersion: number
  liveRun: ReturnType<typeof useRunLiveStore.getState>['run']
  refetchSnapshot(): Promise<unknown>
  refetchRun(): Promise<unknown>
}

function useLiveStream({ baseUrl, runId, snapshotVersion, liveRun, refetchSnapshot, refetchRun }: StreamOptions) {
  const streamRef = useRef<ProcessEventStream | null>(null)
  const refreshTimer = useRef<ReturnType<typeof setTimeout> | null>(null)

  useEffect(() => {
    const state = useRunLiveStore.getState()
    if (!snapshotVersion || state.runId !== runId) return
    const stream = new ProcessEventStream(baseUrl, runId, state.snapshotCursor, {
      onEvent: (event) => {
        const result = useRunLiveStore.getState().applyEvent(event)
        if (event.type === 'run.initialized' || result === 'unknown') void refetchSnapshot()
        if (refreshTimer.current) clearTimeout(refreshTimer.current)
        refreshTimer.current = setTimeout(() => void refetchRun(), 500)
      },
      onReset: () => void refetchSnapshot(),
      onStatus: (status) => useRunLiveStore.getState().setStreamStatus(status),
    })
    streamRef.current?.close()
    streamRef.current = stream
    stream.start()
    return () => stream.close()
  }, [baseUrl, refetchRun, refetchSnapshot, runId, snapshotVersion])

  useEffect(() => {
    if (liveRun && isTerminalRun(liveRun.effective_status)) streamRef.current?.close()
  }, [liveRun])

  useEffect(() => () => {
    if (refreshTimer.current) clearTimeout(refreshTimer.current)
    streamRef.current?.close()
    useRunLiveStore.getState().clear()
  }, [])
}

export function useRunLive(runId: string) {
  const { baseUrl } = useApiConfig()
  const snapshotVersion = useRunLiveStore((state) => state.snapshotVersion)
  const liveRun = useRunLiveStore((state) => state.run)

  const snapshotQuery = useQuery({
    queryKey: ['snapshot', baseUrl, runId],
    queryFn: ({ signal }) => getSnapshot(baseUrl, runId, signal),
  })
  const runQuery = useQuery({
    queryKey: ['run', baseUrl, runId],
    queryFn: ({ signal }) => getRun(baseUrl, runId, signal),
    refetchInterval: () => (liveRun && !isTerminalRun(liveRun.effective_status) ? 5000 : false),
  })

  useEffect(() => {
    if (snapshotQuery.data) useRunLiveStore.getState().replaceSnapshot(snapshotQuery.data)
  }, [snapshotQuery.data])

  useEffect(() => {
    if (runQuery.data) useRunLiveStore.getState().updateRun(runQuery.data)
  }, [runQuery.data])

  useLiveStream({
    baseUrl,
    runId,
    snapshotVersion,
    liveRun,
    refetchSnapshot: snapshotQuery.refetch,
    refetchRun: runQuery.refetch,
  })

  return { snapshotQuery, runQuery }
}
