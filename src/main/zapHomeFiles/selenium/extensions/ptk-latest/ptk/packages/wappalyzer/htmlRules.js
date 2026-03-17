/* Author: PTK Team
 *
 * Builds HTML rule execution plans for both the main technologies
 * and the WAF detector. Each plan entry includes a lightweight
 * regex description that can be evaluated inside the page context.
 */

import { Wappalyzer } from './wappalyzer.js'

const DEFAULT_DATASET = 'technologies'

export function buildHtmlPlan(definitions = {}, dataset = DEFAULT_DATASET) {
    const plan = []
    const patternIndex = new Map()

    if (!definitions || typeof definitions !== 'object') {
        return { plan, patternIndex }
    }

    Object.entries(definitions).forEach(([name, definition]) => {
        if (!definition?.html) {
            return
        }

        const patterns = Wappalyzer.transformPatterns(definition.html)

        if (!patterns || !patterns.length) {
            return
        }

        patterns.forEach((pattern, index) => {
            if (!pattern?.regex) {
                return
            }

            const id = `${dataset}:${name}:${index}`

            plan.push({
                dataset,
                tech: name,
                id,
                source: pattern.regex.source,
                flags: pattern.regex.flags || 'i',
            })

            patternIndex.set(id, {
                tech: name,
                pattern: {
                    ...pattern,
                    regex: new RegExp(pattern.regex.source, pattern.regex.flags || 'i'),
                },
            })
        })
    })

    return { plan, patternIndex }
}
export default buildHtmlPlan
