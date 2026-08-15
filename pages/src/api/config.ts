const API_STORAGE_KEY = 'gsvibe.apiBaseUrl'
const CONNECTED_STORAGE_PREFIX = 'gsvibe.apiConnected:'
export const DEFAULT_API_BASE_URL = 'http://127.0.0.1:8000'

function buildTimeApiBase(): string | undefined {
  return import.meta.env.VITE_API_BASE_URL
}

export function normalizeApiBaseUrl(value: string): string {
  const url = new URL(value.trim())
  if (!['http:', 'https:'].includes(url.protocol)) {
    throw new Error(i18n.t('errors.apiHttpOnly'))
  }
  if (url.username || url.password || url.search || url.hash) {
    throw new Error(i18n.t('errors.apiAddressParts'))
  }
  const pathname = url.pathname.replace(/\/+$/, '')
  return `${url.origin}${pathname}`
}

export function getConfiguredApiBaseUrl(): string {
  const saved = localStorage.getItem(API_STORAGE_KEY)
  const candidate = saved || buildTimeApiBase() || DEFAULT_API_BASE_URL
  try {
    return normalizeApiBaseUrl(candidate)
  } catch {
    return DEFAULT_API_BASE_URL
  }
}

export function saveApiBaseUrl(value: string): string {
  const normalized = normalizeApiBaseUrl(value)
  localStorage.setItem(API_STORAGE_KEY, normalized)
  return normalized
}

export function isApiConnected(baseUrl: string): boolean {
  return localStorage.getItem(`${CONNECTED_STORAGE_PREFIX}${baseUrl}`) === 'true'
}

export function setApiConnected(baseUrl: string, connected: boolean): void {
  const key = `${CONNECTED_STORAGE_PREFIX}${baseUrl}`
  if (connected) localStorage.setItem(key, 'true')
  else localStorage.removeItem(key)
}
import i18n from '../i18n'
