import { ref, watch } from 'vue'

// Default to dark theme unless explicitly set to light
const isDark = ref(localStorage.getItem('theme') !== 'light')

/**
 * Initialize theme on app load
 */
export function initializeTheme() {
  applyTheme(isDark.value)
}

/**
 * Apply theme to document
 */
function applyTheme(dark) {
  if (dark) {
    document.documentElement.setAttribute('data-theme', 'dark')
  } else {
    document.documentElement.removeAttribute('data-theme')
  }
}

/**
 * Toggle between light and dark theme
 */
export function toggleTheme() {
  isDark.value = !isDark.value
  applyTheme(isDark.value)
  localStorage.setItem('theme', isDark.value ? 'dark' : 'light')
}

/**
 * Get current theme state
 */
export function useTheme() {
  return {
    isDark,
    toggleTheme,
  }
}
