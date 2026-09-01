const STATUS_COPY = Object.freeze({
    ready: {
        label: 'Ready',
        detail: 'Waiting for an authorised automation client.'
    },
    starting: {
        label: 'Starting',
        detail: 'Preparing the active PTK Agent automation session.'
    },
    scanning: {
        label: 'Scanning',
        detail: 'Security checks are controlled by the active PTK Agent automation session.'
    },
    finishing: {
        label: 'Finishing',
        detail: 'Finalising security checks and preparing the session results.'
    },
    error: {
        label: 'Error',
        detail: 'The runtime reported an error. Review the automation client logs.'
    }
})

const REFRESH_INTERVAL_MS = 1000
const versionElement = document.getElementById('version')
const statusDot = document.getElementById('status-dot')
const statusLabel = document.getElementById('status-label')
const statusDetail = document.getElementById('status-detail')

function renderStatus(status) {
    const normalized = Object.prototype.hasOwnProperty.call(STATUS_COPY, status) ? status : 'error'
    const copy = STATUS_COPY[normalized]
    statusDot.dataset.status = normalized
    statusLabel.textContent = copy.label
    statusDetail.textContent = copy.detail
}

function renderVersion(version) {
    const normalized = typeof version === 'string' && version.trim() ? version.trim() : 'unknown'
    versionElement.textContent = `v${normalized}`
}

async function refreshRuntimeStatus() {
    renderVersion(browser.runtime.getManifest()?.version)
    try {
        const response = await browser.runtime.sendMessage({
            channel: 'ptk_extension_automation_popup',
            type: 'get_runtime_status'
        })
        if (response?.ok !== true) {
            renderStatus('error')
            return
        }
        renderVersion(response.version)
        renderStatus(response.status)
    } catch (_) {
        renderStatus('error')
    }
}

refreshRuntimeStatus()
const refreshTimer = setInterval(refreshRuntimeStatus, REFRESH_INTERVAL_MS)
window.addEventListener('unload', () => clearInterval(refreshTimer), { once: true })
