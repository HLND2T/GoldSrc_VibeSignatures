import { beforeEach, describe, expect, it } from 'vitest'
import {
  DEFAULT_API_BASE_URL,
  getConfiguredApiBaseUrl,
  normalizeApiBaseUrl,
  saveApiBaseUrl,
} from './config'

describe('API base URL configuration', () => {
  beforeEach(() => localStorage.clear())

  it('normalizes a valid URL and removes trailing slashes', () => {
    expect(normalizeApiBaseUrl(' http://127.0.0.1:8000/api/ ')).toBe('http://127.0.0.1:8000/api')
  })

  it('rejects credentials, queries and unsupported protocols', () => {
    expect(() => normalizeApiBaseUrl('ftp://localhost')).toThrow()
    expect(() => normalizeApiBaseUrl('http://user@localhost')).toThrow()
    expect(() => normalizeApiBaseUrl('http://localhost?x=1')).toThrow()
  })

  it('persists a user value ahead of the default', () => {
    saveApiBaseUrl('https://status.example.com/')
    expect(getConfiguredApiBaseUrl()).toBe('https://status.example.com')
    localStorage.clear()
    expect(getConfiguredApiBaseUrl()).toBe(DEFAULT_API_BASE_URL)
  })
})
