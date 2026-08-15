import { describe, expect, it } from 'vitest'
import { encodeTaskIdPath } from './client'

describe('task API paths', () => {
  it('preserves task hierarchy while encoding individual segments', () => {
    expect(encodeTaskIdPath('stage job/skill/name?#')).toBe('stage%20job/skill/name%3F%23')
  })
})
