const MINIFIED_LINE_THRESHOLD = 800

function isMinified(text) {
    if (!text) return false
    const lines = String(text).split(/\r?\n/)
    return lines.length <= 2 && lines[0].length > MINIFIED_LINE_THRESHOLD
}

function truncateEvidenceText(text, { maxChars = 3000, maxLines = 30 } = {}) {
    if (!text) return { text: "", truncated: false }
    const raw = String(text)
    const lines = raw.split(/\r?\n/)
    let truncated = false
    let output = raw

    if (lines.length > maxLines) {
        output = lines.slice(0, maxLines).join("\n")
        truncated = true
    }
    if (output.length > maxChars) {
        output = output.slice(0, Math.max(0, maxChars - 24))
        truncated = true
    }

    if (isMinified(raw) && raw.length > maxChars) {
        const head = raw.slice(0, Math.min(1200, raw.length))
        const tail = raw.slice(-400)
        output = `${head}\n...[truncated]...\n${tail}`
        truncated = true
    }

    if (truncated && !output.includes("...[truncated]...")) {
        output = `${output}\n...[truncated]...`
    }

    return { text: output, truncated }
}

export function buildEvidenceRows(evidence = {}) {
    const rows = []
    let truncated = false
    const blocks = [
        { label: "Request", value: evidence.requestSnippet },
        { label: "Response", value: evidence.responseSnippet },
        { label: "Source Context", value: evidence.codeSnippet },
        { label: "Notes", value: evidence.notes }
    ]
    blocks.forEach(block => {
        if (!block.value) return
        const result = truncateEvidenceText(block.value, { maxChars: 3000, maxLines: 30 })
        if (result.truncated) truncated = true
        rows.push([block.label, result.text])
    })
    return { rows, truncated }
}
