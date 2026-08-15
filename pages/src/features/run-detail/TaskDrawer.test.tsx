import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { cleanup, render, screen } from '@testing-library/react'
import { http, HttpResponse } from 'msw'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { ApiContext, type ApiContextValue } from '../../app/apiContext'
import { makeSnapshot } from '../../test/fixtures'
import { server } from '../../test/server'
import { TaskDrawer } from './TaskDrawer'

const apiValue: ApiContextValue = {
  baseUrl: 'http://127.0.0.1:8000',
  connected: true,
  connecting: false,
  connectionError: null,
  connect: vi.fn(),
  changeBaseUrl: vi.fn(),
  disconnect: vi.fn(),
}

describe('TaskDrawer', () => {
  afterEach(cleanup)

  it('shows the complete multiline task description', async () => {
    const snapshot = makeSnapshot()
    const task = snapshot.tasks[0]
    const description = 'First diagnostic line\nSecond diagnostic line'
    server.use(
      http.get(`http://127.0.0.1:8000/api/v1/runs/run-1/tasks/${task.task_id}`, () =>
        HttpResponse.json({ ...task, description, dependencies: [], dependents: [] }),
      ),
    )
    const client = new QueryClient({ defaultOptions: { queries: { retry: false } } })

    render(
      <QueryClientProvider client={client}>
        <ApiContext.Provider value={apiValue}>
          <TaskDrawer
            runId="run-1"
            taskId={task.task_id}
            graph={snapshot.graph!}
            onClose={vi.fn()}
            onNavigate={vi.fn()}
          />
        </ApiContext.Provider>
      </QueryClientProvider>,
    )

    expect(await screen.findByText(/First diagnostic line\s+Second diagnostic line/)).toBeInTheDocument()
  })
})
