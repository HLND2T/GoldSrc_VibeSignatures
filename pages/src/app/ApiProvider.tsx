import { useQueryClient } from '@tanstack/react-query'
import { useState, type ReactNode } from 'react'
import { checkApiConnection } from '../api/client'
import {
  getConfiguredApiBaseUrl,
  isApiConnected,
  saveApiBaseUrl,
  setApiConnected,
} from '../api/config'
import { useRunLiveStore } from '../features/run-detail/liveStore'
import i18n from '../i18n'
import { ApiContext } from './apiContext'

export function ApiProvider({ children }: { children: ReactNode }) {
  const queryClient = useQueryClient()
  const [baseUrl, setBaseUrl] = useState(getConfiguredApiBaseUrl)
  const [connected, setConnected] = useState(() => isApiConnected(baseUrl))
  const [connecting, setConnecting] = useState(false)
  const [connectionError, setConnectionError] = useState<Error | null>(null)

  async function connect() {
    setConnecting(true)
    setConnectionError(null)
    try {
      await checkApiConnection(baseUrl)
      setApiConnected(baseUrl, true)
      setConnected(true)
    } catch (error) {
      setConnectionError(error instanceof Error ? error : new Error(i18n.t('errors.connectionFailed')))
      setConnected(false)
      throw error
    } finally {
      setConnecting(false)
    }
  }

  function changeBaseUrl(value: string) {
    const next = saveApiBaseUrl(value)
    queryClient.clear()
    useRunLiveStore.getState().clear()
    setBaseUrl(next)
    setConnected(false)
    setConnectionError(null)
  }

  function disconnect() {
    setApiConnected(baseUrl, false)
    queryClient.clear()
    useRunLiveStore.getState().clear()
    setConnected(false)
  }

  const value = { baseUrl, connected, connecting, connectionError, connect, changeBaseUrl, disconnect }
  return <ApiContext.Provider value={value}>{children}</ApiContext.Provider>
}
