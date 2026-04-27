export function useFormatDate() {
  function formatDate(iso) {
    if (!iso) return '—'
    return new Date(iso).toLocaleString(undefined, { dateStyle: 'short', timeStyle: 'short' })
  }

  function formatDateOnly(iso) {
    if (!iso) return '—'
    return new Date(iso).toLocaleDateString(undefined)
  }

  return { formatDate, formatDateOnly }
}
