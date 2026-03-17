import { selectRepresentativeResponses } from "./representativeResponseSelector.js"
import { evaluatePassiveHeaders } from "./dastPassiveHeadersEvaluator.js"
import { evaluateWappalyzerHeaders } from "./wappalyzerHeadersEvaluator.js"
import { evaluateCveHeaders } from "./cveHeadersEvaluator.js"

export async function analyzeHeadersForTab(tabContext = {}) {
    const requests = Array.isArray(tabContext.requests) ? tabContext.requests : []
    const tabUrl = tabContext.url || ""

    const responses = selectRepresentativeResponses(requests, tabUrl)
    if (!responses.length) {
        return {
            securityFindings: [],
            techHeaderMatches: [],
            evidence: {
                evaluatedResponses: 0,
            },
        }
    }

    const passiveResult = await evaluatePassiveHeaders(responses)
    const wappalyzerResult = evaluateWappalyzerHeaders(responses)
    const cveResult = evaluateCveHeaders(responses)

    return {
        securityFindings: passiveResult.tableRows || [],
        techHeaderMatches: wappalyzerResult.matches || [],
        cveHeaderMatches: cveResult.matches || [],
        evidence: {
            evaluatedResponses: responses.length,
            passiveFindings: passiveResult.rawFindings || [],
            wappalyzerMatches: wappalyzerResult.matches || [],
            cveMatches: cveResult.matches || [],
        },
    }
}
