/* Author: PTK Team
 *
 * Normalizes the CSS rules from technologies.json into a compact plan
 * that can be executed quickly inside the page context.
 */

const isPlainObject = (value) =>
    Object.prototype.toString.call(value) === '[object Object]'

const toArray = (value) => {
    if (Array.isArray(value)) {
        return value
    }

    if (typeof value === 'undefined' || value === null) {
        return []
    }

    return [value]
}

const MAX_EXPANSIONS = 64

function stripPatternMeta(rawPattern) {
    const value = String(rawPattern || '')
    const [pattern, ...metaParts] = value.split('\\;')
    const meta = {}

    metaParts.forEach((part) => {
        const [key, ...rest] = part.split(':')
        if (!key) {
            return
        }

        meta[key] = rest.join(':')
    })

    return { pattern, meta }
}

function sanitizePattern(pattern) {
    if (!pattern) {
        return ''
    }

    return pattern
        .replace(/\\\\/g, '\\')
        .replace(/\\s\*/g, ' ')
        .replace(/\\s\+/g, ' ')
        .replace(/\\s/g, ' ')
        .replace(/\\n/g, ' ')
        .replace(/\\t/g, ' ')
        .replace(/\\{/g, '{')
        .replace(/\\}/g, '}')
        .replace(/\\\[/g, '[')
        .replace(/\\]/g, ']')
        .replace(/\\\(/g, '(')
        .replace(/\\\)/g, ')')
        .replace(/\\#/g, '#')
        .replace(/\\\./g, '.')
        .replace(/\\\+/g, '+')
        .replace(/\\\-/g, '-')
        .replace(/\\,/g, ',')
        .replace(/\\\^/g, '^')
        .replace(/\\\$/g, '$')
        .replace(/\\>/g, '>')
        .replace(/\\</g, '<')
        .replace(/\\:/g, ':')
        .replace(/\\;/g, ';')
        .replace(/\\_/g, '_')
        .replace(/\\\*/g, '*')
        .replace(/\\\|/g, '|')
        .replace(/\\ /g, ' ')
}

function tokenizePattern(pattern) {
    const tokens = []
    let buffer = ''

    const pushBuffer = () => {
        if (buffer) {
            tokens.push({ type: 'literal', value: buffer })
            buffer = ''
        }
    }

    let i = 0

    while (i < pattern.length) {
        const char = pattern[i]

        if (char === '(' && pattern[i + 1] === '?' && pattern[i + 2] === ':') {
            pushBuffer()

            let depth = 1
            let j = i + 3
            let content = ''

            while (j < pattern.length && depth > 0) {
                const nextChar = pattern[j]

                if (nextChar === '(') {
                    depth += 1
                } else if (nextChar === ')') {
                    depth -= 1
                    if (depth === 0) {
                        break
                    }
                }

                if (depth > 0) {
                    content += nextChar
                }

                j += 1
            }

            const optional = pattern[j + 1] === '?'

            tokens.push({
                type: 'group',
                options: content.split('|'),
                optional,
            })

            i = j + (optional ? 1 : 0)
        } else if (char === '\\') {
            if (i + 1 < pattern.length) {
                buffer += pattern[i + 1]
                i += 1
            }
        } else {
            buffer += char
        }

        i += 1
    }

    pushBuffer()

    return tokens
}

function expandPattern(pattern) {
    const tokens = tokenizePattern(pattern)

    return tokens.reduce(
        (results, token) => {
            if (token.type === 'literal') {
                return results.map((result) => result + token.value)
            }

            if (token.type === 'group') {
                const withGroup = []

                token.options.forEach((option) => {
                    results.forEach((result) => {
                        withGroup.push(result + option)
                    })
                })

                if (token.optional) {
                    return results.concat(withGroup)
                }

                return withGroup
            }

            return results
        },
        ['']
    )
}

function expandSelectors(rawPattern) {
    const { pattern } = stripPatternMeta(rawPattern)
    if (!pattern) {
        return []
    }

    const sanitized = sanitizePattern(pattern)
    const expanded = expandPattern(sanitized)
        .map((selector) =>
            selector
                .replace(/\{/g, '')
                .replace(/\s+/g, ' ')
                .trim()
        )
        .filter(Boolean)

    const unique = Array.from(new Set(expanded))

    if (unique.length > MAX_EXPANSIONS) {
        return unique.slice(0, MAX_EXPANSIONS)
    }

    return unique
}

function expandPropertyNames(rawPattern) {
    const names = expandSelectors(rawPattern)

    return names.filter(Boolean)
}

function normalizeDescriptor(selector, descriptor) {
    if (typeof descriptor === 'boolean') {
        return [{ selector, exists: descriptor }]
    }

    if (typeof descriptor === 'string' || typeof descriptor === 'number') {
        return [
            {
                selector,
                textPatterns: [String(descriptor)],
            },
        ]
    }

    if (Array.isArray(descriptor)) {
        const patterns = descriptor
            .map((item) => String(item).trim())
            .filter(Boolean)

        if (!patterns.length) {
            return []
        }

        return [
            {
                selector,
                textPatterns: patterns,
            },
        ]
    }

    if (isPlainObject(descriptor)) {
        const props = Object.entries(descriptor)
            .map(([name, value]) => {
                const patterns = toArray(value)
                    .map((pattern) => String(pattern).trim())
                    .filter(Boolean)

                if (!patterns.length) {
                    return null
                }

                return {
                    name: name.trim(),
                    patterns,
                }
            })
            .filter(Boolean)

        if (!props.length) {
            return []
        }

        return [
            {
                selector,
                props,
            },
        ]
    }

    return []
}

function buildLegacyRule(tech, rawPattern) {
    if (!rawPattern) {
        return []
    }

    const trimmed = String(rawPattern).trim()

    if (!trimmed) {
        return []
    }

    if (trimmed.startsWith('--')) {
        const names = expandPropertyNames(trimmed)

        if (!names.length) {
            return []
        }

        return [
            {
                tech,
                selector: ':root',
                props: names.map((name) => ({
                    name,
                    patterns: ['/.+/'],
                })),
            },
        ]
    }

    const selectors = expandSelectors(trimmed)

    return selectors.map((selector) => ({
        tech,
        selector,
        exists: true,
    }))
}

export function buildCssPlan(technologies = {}, allowList = null) {
    if (!technologies || typeof technologies !== 'object') {
        return []
    }

    const plan = []

    Object.entries(technologies).forEach(([name, definition]) => {
        if (allowList && !allowList.has(name)) {
            return
        }

        const { css } = definition || {}

        if (!css) {
            return
        }

        if (isPlainObject(css)) {
            Object.entries(css).forEach(([selector, descriptor]) => {
                normalizeDescriptor(selector, descriptor).forEach((rule) => {
                    plan.push({
                        tech: name,
                        ...rule,
                    })
                })
            })

            return
        }

        const entries = toArray(css)

        entries.forEach((rawPattern) => {
            buildLegacyRule(name, rawPattern).forEach((rule) => plan.push(rule))
        })
    })

    return plan
}
export default buildCssPlan
