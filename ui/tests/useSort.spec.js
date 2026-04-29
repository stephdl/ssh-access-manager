import { describe, it, expect } from 'vitest'
import { useSort } from '../src/composables/useSort.js'

describe('useSort', () => {
  it('initializes with unsorted state', () => {
    const { sortKey, sortDir } = useSort()
    expect(sortKey.value).toBe('')
    expect(sortDir.value).toBe(0)
  })

  it('toggleSort cycles: unsorted → asc → desc → unsorted', () => {
    const { sortKey, sortDir, toggleSort } = useSort()

    toggleSort('name')
    expect(sortKey.value).toBe('name')
    expect(sortDir.value).toBe(1) // asc

    toggleSort('name')
    expect(sortKey.value).toBe('name')
    expect(sortDir.value).toBe(-1) // desc

    toggleSort('name')
    expect(sortKey.value).toBe('')
    expect(sortDir.value).toBe(0) // unsorted
  })

  it('toggleSort resets to asc when changing column', () => {
    const { sortKey, sortDir, toggleSort } = useSort()

    toggleSort('name')
    expect(sortKey.value).toBe('name')
    expect(sortDir.value).toBe(1)

    toggleSort('age')
    expect(sortKey.value).toBe('age')
    expect(sortDir.value).toBe(1) // reset to asc
  })

  it('sorted() returns original array when unsorted', () => {
    const { sorted } = useSort()
    const items = [{ id: 3 }, { id: 1 }, { id: 2 }]
    const result = sorted(items)
    expect(result).toEqual(items)
    expect(result).toBe(items) // same reference
  })

  it('sorted() returns a new array (no mutation)', () => {
    const { sorted, toggleSort } = useSort()
    toggleSort('id')
    const items = [{ id: 3 }, { id: 1 }, { id: 2 }]
    const result = sorted(items)
    expect(result).not.toBe(items) // different reference
    expect(items).toEqual([{ id: 3 }, { id: 1 }, { id: 2 }]) // original unchanged
  })

  it('sorted() handles numbers ascending', () => {
    const { sorted, toggleSort } = useSort()
    toggleSort('age')
    const items = [{ age: 30 }, { age: 10 }, { age: 20 }]
    const result = sorted(items)
    expect(result.map((x) => x.age)).toEqual([10, 20, 30])
  })

  it('sorted() handles numbers descending', () => {
    const { sorted, toggleSort } = useSort()
    toggleSort('age')
    toggleSort('age') // desc
    const items = [{ age: 30 }, { age: 10 }, { age: 20 }]
    const result = sorted(items)
    expect(result.map((x) => x.age)).toEqual([30, 20, 10])
  })

  it('sorted() handles strings ascending', () => {
    const { sorted, toggleSort } = useSort()
    toggleSort('name')
    const items = [{ name: 'Charlie' }, { name: 'Alice' }, { name: 'Bob' }]
    const result = sorted(items)
    expect(result.map((x) => x.name)).toEqual(['Alice', 'Bob', 'Charlie'])
  })

  it('sorted() handles strings descending', () => {
    const { sorted, toggleSort } = useSort()
    toggleSort('name')
    toggleSort('name') // desc
    const items = [{ name: 'Charlie' }, { name: 'Alice' }, { name: 'Bob' }]
    const result = sorted(items)
    expect(result.map((x) => x.name)).toEqual(['Charlie', 'Bob', 'Alice'])
  })

  it('sorted() handles ISO date strings ascending', () => {
    const { sorted, toggleSort } = useSort()
    toggleSort('date')
    const items = [
      { date: '2024-03-15T10:00:00Z' },
      { date: '2024-01-10T10:00:00Z' },
      { date: '2024-02-20T10:00:00Z' },
    ]
    const result = sorted(items)
    expect(result.map((x) => x.date)).toEqual([
      '2024-01-10T10:00:00Z',
      '2024-02-20T10:00:00Z',
      '2024-03-15T10:00:00Z',
    ])
  })

  it('sorted() handles ISO date strings descending', () => {
    const { sorted, toggleSort } = useSort()
    toggleSort('date')
    toggleSort('date') // desc
    const items = [
      { date: '2024-03-15T10:00:00Z' },
      { date: '2024-01-10T10:00:00Z' },
      { date: '2024-02-20T10:00:00Z' },
    ]
    const result = sorted(items)
    expect(result.map((x) => x.date)).toEqual([
      '2024-03-15T10:00:00Z',
      '2024-02-20T10:00:00Z',
      '2024-01-10T10:00:00Z',
    ])
  })

  it('sorted() handles booleans ascending (false < true)', () => {
    const { sorted, toggleSort } = useSort()
    toggleSort('active')
    const items = [{ active: true }, { active: false }, { active: true }]
    const result = sorted(items)
    expect(result.map((x) => x.active)).toEqual([false, true, true])
  })

  it('sorted() handles booleans descending', () => {
    const { sorted, toggleSort } = useSort()
    toggleSort('active')
    toggleSort('active') // desc
    const items = [{ active: false }, { active: true }, { active: false }]
    const result = sorted(items)
    expect(result.map((x) => x.active)).toEqual([true, false, false])
  })

  it('sorted() places nulls last ascending', () => {
    const { sorted, toggleSort } = useSort()
    toggleSort('value')
    const items = [{ value: 3 }, { value: null }, { value: 1 }]
    const result = sorted(items)
    expect(result.map((x) => x.value)).toEqual([1, 3, null])
  })

  it('sorted() places nulls last descending', () => {
    const { sorted, toggleSort } = useSort()
    toggleSort('value')
    toggleSort('value') // desc
    const items = [{ value: 3 }, { value: null }, { value: 1 }]
    const result = sorted(items)
    expect(result.map((x) => x.value)).toEqual([3, 1, null])
  })

  it('sorted() places undefined last ascending', () => {
    const { sorted, toggleSort } = useSort()
    toggleSort('value')
    const items = [{ value: 3 }, { value: undefined }, { value: 1 }]
    const result = sorted(items)
    expect(result.map((x) => x.value)).toEqual([1, 3, undefined])
  })

  it('sorted() handles multiple nulls', () => {
    const { sorted, toggleSort } = useSort()
    toggleSort('value')
    const items = [{ value: null }, { value: 2 }, { value: null }]
    const result = sorted(items)
    expect(result.map((x) => x.value)).toEqual([2, null, null])
  })

  it('sortIndicator returns ↕ for inactive column', () => {
    const { sortIndicator } = useSort()
    expect(sortIndicator.value('name')).toBe('↕')
  })

  it('sortIndicator returns ▲ for ascending', () => {
    const { sortIndicator, toggleSort } = useSort()
    toggleSort('name')
    expect(sortIndicator.value('name')).toBe('▲')
  })

  it('sortIndicator returns ▼ for descending', () => {
    const { sortIndicator, toggleSort } = useSort()
    toggleSort('name')
    toggleSort('name') // desc
    expect(sortIndicator.value('name')).toBe('▼')
  })

  it('sortIndicator returns ↕ after cycling back to unsorted', () => {
    const { sortIndicator, toggleSort } = useSort()
    toggleSort('name')
    toggleSort('name')
    toggleSort('name') // back to unsorted
    expect(sortIndicator.value('name')).toBe('↕')
  })
})
