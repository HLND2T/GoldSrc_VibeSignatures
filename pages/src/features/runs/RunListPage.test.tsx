import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { render, screen } from '@testing-library/react'
import { http, HttpResponse } from 'msw'
import { MemoryRouter } from 'react-router-dom'
import { describe, expect, it, vi } from 'vitest'
import { ApiContext, type ApiContextValue } from '../../app/apiContext'
import { makeRun } from '../../test/fixtures'
import { server } from '../../test/server'
import { RunListPage } from './RunListPage'

const apiValue: ApiContextValue = {
  baseUrl: 'http://127.0.0.1:8000',
  connected: true,
  connecting: false,
  connectionError: null,
  connect: vi.fn(),
  changeBaseUrl: vi.fn(),
  disconnect: vi.fn(),
}

describe('RunListPage', () => {
  it('renders a paged run returned by the API', async () => {
    server.use(http.get('http://127.0.0.1:8000/api/v1/runs', () => HttpResponse.json({ items: [makeRun()], offset: 0, next_offset: null, has_more: false })))
    const client = new QueryClient({ defaultOptions: { queries: { retry: false } } })
    render(
      <QueryClientProvider client={client}>
        <ApiContext.Provider value={apiValue}>
          <MemoryRouter><RunListPage /></MemoryRouter>
        </ApiContext.Provider>
      </QueryClientProvider>,
    )
    expect(await screen.findByText('run-1')).toBeInTheDocument()
    expect(screen.getByText('运行中')).toBeInTheDocument()
  })
})
