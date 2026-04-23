function escapeRegExp(value = "") {
    return String(value).replace(/[.*+?^${}()|[\]\\]/g, "\\$&")
}

function cloneValue(value) {
    if (typeof globalThis.structuredClone === "function") {
        try {
            return globalThis.structuredClone(value)
        } catch (_) {
            // fall through
        }
    }
    return JSON.parse(JSON.stringify(value))
}

export class DastConfirmationService {
    constructor({
        getConfirmConfig = () => ({}),
        activeAttack = async () => null,
        hasRealHttpResponse = () => false,
        appendTaskRuntimeEvent = () => {},
        attackRuntimeConfirmation = () => null,
        getOastCallbackEvents = () => [],
        setOastConfirmationMetadata = () => {}
    } = {}) {
        this.getConfirmConfig = getConfirmConfig
        this.activeAttack = activeAttack
        this.hasRealHttpResponse = hasRealHttpResponse
        this.appendTaskRuntimeEvent = appendTaskRuntimeEvent
        this.attackRuntimeConfirmation = attackRuntimeConfirmation
        this.getOastCallbackEvents = getOastCallbackEvents
        this.setOastConfirmationMetadata = setOastConfirmationMetadata
    }

    evaluateGenericConfirmBorderline(result, original) {
        const confirm = this.getConfirmConfig()
        const attackLength = Number(result?.response?.length ?? result?.length ?? 0)
        const originalLength = Number(original?.response?.length ?? 0)
        const lenDeltaAbs = Math.abs(attackLength - originalLength)
        const minLenDelta = Number(confirm.minLenDelta || 0)
        const windowSize = Number(confirm.borderlineWindow || 0)
        const lower = Math.max(0, minLenDelta - windowSize)
        const upper = minLenDelta + windowSize
        const borderline = lenDeltaAbs >= lower && lenDeltaAbs < upper
        return { lenDeltaAbs, borderline, lower, upper }
    }

    async runGenericConfirm(task, combined, context) {
        const confirm = this.getConfirmConfig()
        const supports = task?.module?.metadata?.supportsGenericConfirm === true
        if (!supports) {
            this.appendTaskRuntimeEvent(task, context, {
                type: "dast_confirm_skipped",
                phase: "confirm_eval",
                reason: "module_not_opted_in_generic_confirm"
            })
            return combined
        }

        const baseline = this.evaluateGenericConfirmBorderline(combined, context?.original)
        if (confirm.confirmOnlyWhenBorderline && !baseline.borderline) {
            this.appendTaskRuntimeEvent(task, context, {
                type: "dast_confirm_skipped",
                phase: "confirm_eval",
                reason: "not_borderline",
                lenDelta: baseline.lenDeltaAbs
            })
            return combined
        }

        const maxExtra = Number(confirm.confirmMaxExtraRequests || 0)
        if (maxExtra <= 0) {
            this.appendTaskRuntimeEvent(task, context, {
                type: "dast_confirm_skipped",
                phase: "confirm_eval",
                reason: "confirm_budget_disabled"
            })
            return combined
        }

        this.appendTaskRuntimeEvent(task, context, {
            type: "dast_confirm_started",
            phase: "confirm_eval",
            mode: "generic"
        })
        const replay = await this.activeAttack(cloneValue(task?.payload))
        if (!this.hasRealHttpResponse(replay?.response)) {
            this.appendTaskRuntimeEvent(task, context, {
                type: "dast_confirm_inconclusive",
                phase: "confirm_eval",
                reason: "no_response"
            })
            return combined
        }

        const replayLength = Number(replay?.response?.length || 0)
        const originalLength = Number(context?.original?.response?.length || 0)
        const replayDeltaAbs = Math.abs(replayLength - originalLength)
        const consistent = Math.abs(replayDeltaAbs - baseline.lenDeltaAbs) <= Number(confirm.borderlineWindow || 0)

        if (!consistent) {
            combined.success = false
            combined.proof = (combined.proof ? `${combined.proof} ` : "") + "[generic confirm failed]"
            this.appendTaskRuntimeEvent(task, context, {
                type: "dast_confirm_failed",
                phase: "confirm_eval",
                mode: "generic",
                baselineDelta: baseline.lenDeltaAbs,
                replayDelta: replayDeltaAbs
            })
            return combined
        }

        this.appendTaskRuntimeEvent(task, context, {
            type: "dast_confirm_passed",
            phase: "confirm_eval",
            mode: "generic",
            baselineDelta: baseline.lenDeltaAbs,
            replayDelta: replayDeltaAbs
        })
        return combined
    }

    async maybeApplyConfirmPolicy(task, combined, context) {
        if (!combined?.success) return combined
        const confirm = this.getConfirmConfig()
        if (!confirm.confirmFindings) return combined
        const mode = String(confirm.mode || "module").toLowerCase()
        if (mode === "none" || mode === "module") return combined
        if (mode !== "generic") return combined
        return this.runGenericConfirm(task, combined, context)
    }

    _collectOastTokens(text, domains = []) {
        const tokens = new Set()
        const source = typeof text === "string" ? text : ""
        if (!source) return tokens
        domains.forEach((domain) => {
            const domainPattern = escapeRegExp(domain)
            const regex = new RegExp(`${domainPattern}\\/([A-Za-z0-9._-]+)`, "gmi")
            let match = null
            while ((match = regex.exec(source)) !== null) {
                if (match?.[1]) {
                    tokens.add(String(match[1]).toLowerCase())
                }
            }
        })
        return tokens
    }

    extractAttackOastMarkers(task, executed) {
        const oastCfg = this.attackRuntimeConfirmation(task?.attack, "oast")
        if (!oastCfg || oastCfg.enabled !== true) return null
        const domains = []
        if (typeof oastCfg.domain === "string" && oastCfg.domain.trim()) {
            domains.push(oastCfg.domain.trim().toLowerCase())
        }
        if (Array.isArray(oastCfg.domains)) {
            oastCfg.domains.forEach((domain) => {
                if (typeof domain === "string" && domain.trim()) {
                    domains.push(domain.trim().toLowerCase())
                }
            })
        }
        const uniqueDomains = Array.from(new Set(domains))
        if (!uniqueDomains.length) return null
        const haystacks = [
            executed?.request?.url || "",
            executed?.request?.raw || "",
            executed?.request?.body?.text || "",
            JSON.stringify(executed?.request?.headers || [])
        ]
        const tokens = new Set()
        haystacks.forEach((value) => {
            const found = this._collectOastTokens(value, uniqueDomains)
            found.forEach((token) => tokens.add(token))
        })
        return {
            domains: uniqueDomains,
            tokens: Array.from(tokens)
        }
    }

    findOastCallbackMatch(markers) {
        if (!markers) return null
        const events = Array.isArray(this.getOastCallbackEvents()) ? this.getOastCallbackEvents() : []
        if (!events.length) return null
        const domains = Array.isArray(markers.domains) ? markers.domains.map((d) => String(d).toLowerCase()) : []
        const tokens = Array.isArray(markers.tokens) ? markers.tokens.map((t) => String(t).toLowerCase()) : []
        for (let i = events.length - 1; i >= 0; i -= 1) {
            const event = events[i] || {}
            const url = String(event.url || "").toLowerCase()
            if (!url) continue
            const domainMatch = domains.find((domain) => url.includes(domain)) || null
            if (!domainMatch) continue
            const tokenMatch = tokens.find((token) => token && url.includes(token)) || null
            if (tokens.length && !tokenMatch) continue
            return {
                event,
                domain: domainMatch,
                token: tokenMatch
            }
        }
        return null
    }

    runOastCallbackCorrelation(task, executed, combined, context) {
        if (!task || !executed || !combined) return combined
        const markers = this.extractAttackOastMarkers(task, executed)
        if (!markers) return combined
        const oastCfg = this.attackRuntimeConfirmation(task?.attack, "oast") || {}
        const match = this.findOastCallbackMatch(markers)
        combined.metadata = Object.assign({}, combined.metadata || {})
        if (match) {
            const matchLabel = match?.token || match?.domain || "callback"
            combined.success = true
            combined.oastConfirmed = true
            combined.metadata.confirmation = {
                type: "oast_callback",
                confirmed: true,
                source: match?.event?.source || "runtime_event",
                domain: match?.domain || null,
                token: match?.token || null,
                url: match?.event?.url || null
            }
            combined.proof = combined.proof
                ? `${combined.proof} [oast callback confirmed: ${matchLabel}]`
                : `OAST callback confirmed: ${matchLabel}`
            this.appendTaskRuntimeEvent(task, context, {
                type: "dast_oast_confirmed",
                phase: "validation",
                domain: match?.domain || null,
                token: match?.token || null,
                callbackUrl: match?.event?.url || null
            })
            return combined
        }
        combined.metadata.confirmation = {
            type: "oast_callback",
            confirmed: false,
            domains: markers.domains,
            expectedTokens: markers.tokens
        }
        if (oastCfg.requireConfirmation === true) {
            combined.success = false
            combined.proof = combined.proof
                ? `${combined.proof} [oast callback not observed]`
                : "OAST callback not observed"
        }
        this.appendTaskRuntimeEvent(task, context, {
            type: "dast_oast_unconfirmed",
            phase: "validation",
            domains: markers.domains,
            expectedTokens: markers.tokens
        })
        return combined
    }
}

export default DastConfirmationService
