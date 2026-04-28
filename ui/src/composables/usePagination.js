import { ref, computed, watch } from 'vue'

export const PAGE_SIZES = [10, 20, 40, 50, 100]

/**
 * Composable pour la pagination côté client.
 * @param {Ref} filteredItems - Ref/Computed contenant les items filtrés
 * @returns {Object} - Objet avec les propriétés et méthodes de pagination
 */
export function usePagination(filteredItems) {
  const pageSize = ref(10)
  const currentPage = ref(1)

  // Reset currentPage à 1 quand la liste filtrée change
  watch(
    () => filteredItems.value?.length,
    () => {
      currentPage.value = 1
    }
  )

  const totalItems = computed(() => filteredItems.value?.length || 0)

  const totalPages = computed(() => Math.ceil(totalItems.value / pageSize.value) || 1)

  const paginatedItems = computed(() => {
    const items = filteredItems.value || []
    const start = (currentPage.value - 1) * pageSize.value
    const end = start + pageSize.value
    return items.slice(start, end)
  })

  function nextPage() {
    if (currentPage.value < totalPages.value) {
      currentPage.value++
    }
  }

  function prevPage() {
    if (currentPage.value > 1) {
      currentPage.value--
    }
  }

  function setPageSize(size) {
    pageSize.value = size
    currentPage.value = 1
  }

  return {
    pageSize,
    currentPage,
    totalItems,
    totalPages,
    paginatedItems,
    nextPage,
    prevPage,
    setPageSize,
    PAGE_SIZES,
  }
}
