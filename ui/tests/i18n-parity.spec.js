import { describe, it, expect } from 'vitest'
import en from '../src/locales/en.json'
import fr from '../src/locales/fr.json'
import es from '../src/locales/es.json'
import itLocale from '../src/locales/it.json'
import de from '../src/locales/de.json'

function flatten(obj, prefix = '') {
  const keys = new Set()
  for (const [k, v] of Object.entries(obj)) {
    const key = prefix ? `${prefix}.${k}` : k
    if (v && typeof v === 'object' && !Array.isArray(v)) {
      for (const sub of flatten(v, key)) keys.add(sub)
    } else {
      keys.add(key)
    }
  }
  return keys
}

const LOCALES = { en, fr, es, it: itLocale, de }
const FLAT = Object.fromEntries(Object.entries(LOCALES).map(([l, d]) => [l, flatten(d)]))
const REFERENCE = FLAT.en

describe('i18n — key parity across the 5 locales', () => {
  for (const lang of ['fr', 'es', 'it', 'de']) {
    it(`${lang}.json has the same set of leaf keys as en.json`, () => {
      const other = FLAT[lang]
      const missing = [...REFERENCE].filter((k) => !other.has(k)).sort()
      const extra = [...other].filter((k) => !REFERENCE.has(k)).sort()
      expect({ missing, extra }).toEqual({ missing: [], extra: [] })
    })
  }

  it('all locales report the same total leaf-key count', () => {
    const counts = Object.fromEntries(Object.entries(FLAT).map(([l, s]) => [l, s.size]))
    const unique = new Set(Object.values(counts))
    expect(unique.size, JSON.stringify(counts)).toBe(1)
  })
})
