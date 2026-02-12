/* Author: Denis Podgurskii */
'use strict'

import { zapBridge } from './integration/zap/index.js'
import { resultsRegistry } from './resultsRegistry.js'

/**
 * Deprecated compatibility wrapper.
 * New implementation lives under background/integration/zap.
 */
export class ptk_zap {
    init(automationOrApp) {
        const app = automationOrApp?.app || automationOrApp || null
        zapBridge.init(app, resultsRegistry)
    }

    isActive() {
        return zapBridge.isActive()
    }

    async notifyScanStatus() {
        // Phase 1 streams alerts_batch via zapBridge publisher.
    }

    async pushFindings() {
        // Deprecated legacy call-path.
    }

    async notifySessionSummary() {
        // Deprecated legacy call-path.
    }

    reset() {
        // Intentionally empty in compatibility mode.
    }
}

export default zapBridge
