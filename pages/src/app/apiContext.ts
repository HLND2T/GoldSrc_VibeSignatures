import { createContext, useContext } from 'react'

export interface ApiContextValue {
  baseUrl: string
  connected: boolean
  connecting: boolean
  connectionError: Error | null
  connect(): Promise<void>
  changeBaseUrl(value: string): void
  disconnect(): void
}

export const ApiContext = createContext<ApiContextValue | null>(null)

export function useApiConfig(): ApiContextValue {
  const value = useContext(ApiContext)
  if (!value) throw new Error('useApiConfig must be used inside ApiProvider')
  return value
}
