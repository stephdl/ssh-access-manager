import { ref, computed } from 'vue'

/**
 * Composable for client-side column sorting.
 * @returns {Object} - Sort state and methods
 */
export function useSort() {
  const sortKey = ref('')
  const sortDir = ref(0) // 0=unsorted, 1=asc, -1=desc

  /**
   * Toggle sort direction for a given column key.
   * Cycles through: unsorted → asc → desc → unsorted
   */
  function toggleSort(key) {
    if (sortKey.value !== key) {
      sortKey.value = key
      sortDir.value = 1
    } else if (sortDir.value === 1) {
      sortDir.value = -1
    } else {
      sortKey.value = ''
      sortDir.value = 0
    }
  }

  /**
   * Returns a sorted copy of the items array.
   * @param {Array} items - Items to sort
   * @returns {Array} - Sorted copy
   */
  function sorted(items) {
    if (!sortKey.value || sortDir.value === 0) return items
    return [...items].sort((a, b) => {
      const av = a[sortKey.value]
      const bv = b[sortKey.value]
      // nulls last
      if (av == null && bv == null) return 0
      if (av == null) return 1
      if (bv == null) return -1
      // date strings (ISO 8601 or null)
      if (typeof av === 'string' && /^\d{4}-\d{2}-\d{2}/.test(av)) {
        return sortDir.value * (new Date(av) - new Date(bv))
      }
      // numbers
      if (typeof av === 'number') return sortDir.value * (av - bv)
      // booleans (false < true in ascending order)
      if (typeof av === 'boolean') return sortDir.value * (av === bv ? 0 : av ? 1 : -1)
      // strings
      return sortDir.value * String(av).localeCompare(String(bv))
    })
  }

  /**
   * Returns the appropriate sort indicator for a column.
   */
  const sortIndicator = computed(() => (key) => {
    if (sortKey.value !== key) return '↕'
    return sortDir.value === 1 ? '▲' : '▼'
  })

  return { sortKey, sortDir, toggleSort, sorted, sortIndicator }
}
