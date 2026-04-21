const FLAG_NAME = "scan_analysis_v1"

function isBoolean(value) {
    return typeof value === "boolean"
}

function readFlagFromObject(source, key) {
    if (!source || typeof source !== "object") return undefined
    const value = source[key]
    return isBoolean(value) ? value : undefined
}

function resolveFromSettings(settings) {
    if (!settings || typeof settings !== "object") return undefined
    const direct = readFlagFromObject(settings, FLAG_NAME)
    if (isBoolean(direct)) return direct
    const camel = readFlagFromObject(settings, "scanAnalysisV1")
    if (isBoolean(camel)) return camel
    const featureFlags = settings.featureFlags
    const featureFlagsSnake = settings.feature_flags
    const nested =
        readFlagFromObject(featureFlags, FLAG_NAME) ??
        readFlagFromObject(featureFlagsSnake, FLAG_NAME)
    if (isBoolean(nested)) return nested
    return undefined
}

function resolveFromGlobalProfile() {
    try {
        const profile = globalThis?.ptk_app?.settings?.profile
        return resolveFromSettings(profile)
    } catch (_) {
        return undefined
    }
}

export function isScanAnalysisV1Enabled(scanOrSettings = null, defaultValue = true) {
    const fromScan = resolveFromSettings(scanOrSettings?.settings || null)
    if (isBoolean(fromScan)) return fromScan
    const fromSettings = resolveFromSettings(scanOrSettings)
    if (isBoolean(fromSettings)) return fromSettings
    const fromGlobal = resolveFromGlobalProfile()
    if (isBoolean(fromGlobal)) return fromGlobal
    return defaultValue
}

export function shouldShowScanAnalysisUI(scanOrSettings = null) {
    return isScanAnalysisV1Enabled(scanOrSettings, true)
}

export function shouldIncludeScanAnalysisInExport(scanOrSettings = null) {
    return isScanAnalysisV1Enabled(scanOrSettings, true)
}

export default isScanAnalysisV1Enabled
