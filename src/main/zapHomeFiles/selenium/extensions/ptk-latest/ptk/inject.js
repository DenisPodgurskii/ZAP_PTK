;(function () {
    try {
        if (window.__PTK_INJECT_BRIDGE_READY__) {
            return
        }

        window.__PTK_INJECT_BRIDGE_READY__ = true

        const MAX_ELEMENTS_PER_SELECTOR = 3
        const MAX_SELECTOR_CHECKS = 500
        const MAX_PROPERTY_CHECKS = 1500
        const MAX_HTML_PATTERNS = 1500

        const toArray = (value) => {
            if (Array.isArray(value)) {
                return value
            }
            if (typeof value === 'undefined' || value === null) {
                return []
            }

            return [value]
        }

        const getPropertyValue = (style, name) => {
            if (!style || !name) {
                return ''
            }

            const direct = style.getPropertyValue(name)

            if (direct) {
                return direct.trim()
            }

            if (name.indexOf('-') > -1) {
                const camel = name.replace(/-([a-z])/g, (_, char) => char.toUpperCase())

                return (style[camel] || '').toString().trim()
            }

            return (style[name] || '').toString().trim()
        }

        const parseRegexPattern = (pattern) => {
            if (typeof pattern !== 'string') {
                pattern = String(pattern || '')
            }

            if (!pattern.startsWith('/')) {
                return null
            }

            const lastSlash = pattern.lastIndexOf('/')

            if (lastSlash <= 0) {
                return null
            }

            const body = pattern.slice(1, lastSlash)
            const flags = pattern.slice(lastSlash + 1) || 'i'

            try {
                return new RegExp(body, flags)
            } catch (_) {
                return null
            }
        }

        const matchPattern = (value, pattern) => {
            if (typeof pattern === 'object' && pattern) {
                pattern = pattern.pattern || pattern.value || ''
            }

            const source = String(pattern || '').trim()

            if (!source) {
                return false
            }

            const target = String(value || '').trim()

            if (!target) {
                return false
            }

            const regex = parseRegexPattern(source)

            if (regex) {
                return regex.test(target)
            }

            return target.toLowerCase().includes(source.toLowerCase())
        }

        const runJs = (technologies = []) => {
            return toArray(technologies)
                .filter(({ js }) => js)
                .map(({ name, js }) => ({ name, chains: Object.keys(js) }))
                .reduce((acc, { name, chains }) => {
                    chains.forEach((chain) => {
                        const value = chain
                            .split('.')
                            .reduce(
                                (current, method) =>
                                    current &&
                                        current instanceof Object &&
                                        Object.prototype.hasOwnProperty.call(current, method)
                                        ? current[method]
                                        : undefined,
                                window
                            )

                        if (typeof value !== 'undefined') {
                            acc.push({
                                name,
                                chain,
                                value:
                                    typeof value === 'string' || typeof value === 'number'
                                        ? value
                                        : !!value,
                            })
                        }
                    })

                    return acc
                }, [])
        }

        const runDom = (technologies = []) => {
            const toScalar = (value) =>
                typeof value === 'string' || typeof value === 'number' ? value : !!value

            return toArray(technologies)
                .filter(({ dom }) => dom)
                .map(({ name, dom }) => ({ name, dom }))
                .reduce((results, { name, dom }) => {
                    Object.keys(dom || {}).forEach((selector) => {
                        let nodes = []

                        try {
                            nodes = document.querySelectorAll(selector)
                        } catch (_) {
                            nodes = []
                        }

                        if (!nodes.length) {
                            return
                        }

                        nodes.forEach((node) => {
                            dom[selector].forEach(({ properties }) => {
                                if (!properties) {
                                    return
                                }

                                Object.keys(properties).forEach((property) => {
                                    if (!Object.prototype.hasOwnProperty.call(node, property)) {
                                        return
                                    }

                                    const value = node[property]

                                    if (typeof value === 'undefined') {
                                        return
                                    }

                                    results.push({
                                        name,
                                        selector,
                                        property,
                                        value: toScalar(value),
                                    })
                                })
                            })
                        })
                    })

                    return results
                }, [])
        }

        const htmlRegexCache = new Map()

        // cssPlan entries:
        // { tech, selector, exists?, textPatterns?, props?: [{ name, patterns }] }
        const runCss = (plan = []) => {
            if (!Array.isArray(plan) || !plan.length) {
                return { matched: [], truncated: false, evidence: { selectors: 0, propertyChecks: 0 } }
            }

            const grouped = plan.reduce((map, rule) => {
                if (!rule || !rule.selector) {
                    return map
                }

                const selector = rule.selector
                const bucket = map.get(selector) || []
                bucket.push(rule)
                map.set(selector, bucket)

                return map
            }, new Map())

            const matched = []
            const evidence = {
                selectors: 0,
                propertyChecks: 0,
            }

            let truncated = false

            const collectNodes = (selector) => {
                try {
                    const first = document.querySelector(selector)

                    if (!first) {
                        return []
                    }

                    const nodes = [first]
                    const list = document.querySelectorAll(selector)

                    for (const node of list) {
                        if (nodes.length >= MAX_ELEMENTS_PER_SELECTOR) {
                            break
                        }

                        if (node !== first) {
                            nodes.push(node)
                        }
                    }

                    return nodes
                } catch (_) {
                    return []
                }
            }

            for (const [selector, rules] of grouped.entries()) {
                if (evidence.selectors >= MAX_SELECTOR_CHECKS) {
                    truncated = true
                    break
                }

                const nodes = collectNodes(selector)

                if (!nodes.length) {
                    continue
                }

                evidence.selectors += 1

                for (const rule of rules) {
                    if (rule.exists) {
                        matched.push({
                            tech: rule.tech,
                            selector,
                            kind: 'exists',
                        })
                    }

                    if (truncated) {
                        break
                    }

                    if (Array.isArray(rule.textPatterns) && rule.textPatterns.length) {
                        for (const node of nodes) {
                            const textValue = (node.textContent || '').trim()

                            if (!textValue) {
                                continue
                            }

                            for (const pattern of rule.textPatterns) {
                                if (matchPattern(textValue, pattern)) {
                                    matched.push({
                                        tech: rule.tech,
                                        selector,
                                        prop: 'text',
                                        value: textValue,
                                        pattern,
                                        kind: 'text',
                                    })
                                }
                            }
                        }
                    }

                    if (truncated) {
                        break
                    }

                    if (Array.isArray(rule.props) && rule.props.length) {
                        for (const node of nodes) {
                            let styleDeclaration

                            try {
                                styleDeclaration = window.getComputedStyle(node)
                            } catch (_) {
                                styleDeclaration = null
                            }

                            if (!styleDeclaration) {
                                continue
                            }

                            for (const prop of rule.props) {
                                if (evidence.propertyChecks >= MAX_PROPERTY_CHECKS) {
                                    truncated = true
                                    break
                                }

                                evidence.propertyChecks += 1

                                const value = getPropertyValue(styleDeclaration, prop.name)

                                if (!value) {
                                    continue
                                }

                                const patterns = toArray(prop.patterns)

                                for (const pattern of patterns) {
                                    if (matchPattern(value, pattern)) {
                                        matched.push({
                                            tech: rule.tech,
                                            selector,
                                            prop: prop.name,
                                            value,
                                            pattern,
                                            kind: 'property',
                                        })

                                        break
                                    }
                                }

                                if (truncated) {
                                    break
                                }
                            }

                            if (truncated) {
                                break
                            }
                        }
                    }

                    if (truncated) {
                        break
                    }
                }

                if (truncated) {
                    break
                }
            }

            return {
                matched,
                truncated,
                evidence,
            }
        }

        const runHtmlPlans = (plans = {}) => {
            if (!plans || typeof plans !== 'object') {
                return {}
            }

            const htmlRoot = document.documentElement
            const htmlContent = htmlRoot ? htmlRoot.outerHTML || '' : ''
            const results = {}

            Object.entries(plans).forEach(([key, entries]) => {
                if (!Array.isArray(entries) || !entries.length) {
                    results[key] = { matched: [], truncated: false }
                    return
                }

                const matched = []
                let truncated = false
                let processed = 0

                for (const entry of entries) {
                    if (processed >= MAX_HTML_PATTERNS) {
                        truncated = true
                        break
                    }

                    processed += 1

                    if (!entry?.id || !entry?.source) {
                        continue
                    }

                    let regex = htmlRegexCache.get(entry.id)

                    if (!regex) {
                        try {
                            regex = new RegExp(entry.source, entry.flags || 'i')
                            htmlRegexCache.set(entry.id, regex)
                        } catch (_) {
                            continue
                        }
                    }

                    const match = regex.exec(htmlContent)

                    if (match) {
                        matched.push({
                            id: entry.id,
                            match: (match[0] || '').slice(0, 256),
                        })
                    }
                }

                results[key] = {
                    matched,
                    truncated,
                }
            })

            return results
        }

        const onMessage = ({ data }) => {
            if (!data || data.channel !== 'ptk_content2inject') {
                return
            }

            const response = {
                channel: 'ptk_inject2content',
                requestId: data.requestId,
                js: [],
                dom: [],
                css: { matched: [], truncated: false },
                html: createEmptyHtmlPlanResult(data.html)
            }

            try {
                response.js = runJs(data.js || [])
            } catch (_) {
                response.js = []
            }

            try {
                response.dom = runDom(data.dom || [])
            } catch (_) {
                response.dom = []
            }

            try {
                response.css = runCss(data.css || [])
            } catch (_) {
                response.css = { matched: [], truncated: false }
            }

            try {
                response.html = runHtmlPlans(data.html || {})
            } catch (_) {
                response.html = createEmptyHtmlPlanResult(data.html)
            }

            postMessage(response)
        }

        function createEmptyHtmlPlanResult(htmlData) {
            if (!htmlData || typeof htmlData !== 'object') {
                return {}
            }

            return Object.keys(htmlData).reduce((acc, key) => {
                acc[key] = { matched: [], truncated: false }
                return acc
            }, {})
        }

        addEventListener('message', onMessage)
    } catch (error) {
        try {
            console.warn('[PTK][inject] css evaluation failed', error)
        } catch (_) { }
    }
})()
