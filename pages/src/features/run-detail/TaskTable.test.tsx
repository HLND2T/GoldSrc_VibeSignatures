import { cleanup, render, screen } from '@testing-library/react'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { makeTask } from '../../test/fixtures'
import { TaskTable } from './TaskTable'

describe('TaskTable', () => {
  afterEach(cleanup)

  it('renders descriptions and includes them in task search', () => {
    const described = makeTask({ description: 'Finds the target through a unique diagnostic string' })
    const unrelated = makeTask({ task_id: `${described.job_id}/other`, name: 'other', description: null })

    render(
      <TaskTable
        tasks={[described, unrelated]}
        filters={{ query: 'diagnostic string' }}
        onSelect={vi.fn()}
      />,
    )

    expect(screen.getByText(described.description!)).toBeInTheDocument()
    expect(screen.getByRole('button', { name: described.name })).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: unrelated.name })).not.toBeInTheDocument()
  })
})
