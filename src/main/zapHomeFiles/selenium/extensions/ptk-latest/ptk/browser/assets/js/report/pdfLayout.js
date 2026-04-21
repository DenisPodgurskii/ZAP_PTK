import { pdfTheme, setBody, setH1, setH2, setSmall } from "./pdfTheme.js"

export function clampCellText(text, { maxChars = 120, maxLines = 2 } = {}) {
    if (!text) return ""
    const raw = String(text)
    const lines = raw.split(/\r?\n/)
    let trimmed = lines.slice(0, maxLines).join("\n")
    let truncated = false
    if (lines.length > maxLines) truncated = true
    if (trimmed.length > maxChars) {
        trimmed = trimmed.slice(0, Math.max(0, maxChars - 3))
        truncated = true
    }
    if (truncated) trimmed = `${trimmed}...`
    return trimmed
}

export function formatUrlForTable(url, mode = "overview") {
    if (!url) return ""
    try {
        const parsed = new URL(String(url))
        if (mode === "overview") {
            return `${parsed.origin}${parsed.pathname}${parsed.search || ""}${parsed.hash || ""}`
        }
        const params = parsed.searchParams
        const keys = []
        params.forEach((_, key) => keys.push(key))
        const query = keys.length ? `?${keys.map(key => `${key}=`).join("&")}` : ""
        return `${parsed.origin}${parsed.pathname}${query}${parsed.hash || ""}`
    } catch (_) {
        return String(url)
    }
}

export function createPdfLayout(doc, meta = {}, theme = pdfTheme) {
    const margin = theme.page.margin
    const pageWidth = doc.internal.pageSize.getWidth()
    const pageHeight = doc.internal.pageSize.getHeight()

    const contentTop = margin + theme.page.headerHeight
    const contentBottom = pageHeight - margin - theme.page.footerHeight

    const drawHeader = (pageNumber, totalPages) => {
        return
    }

    const drawFooter = (pageNumber, totalPages) => {
        setBody(doc, theme)
        doc.setTextColor(...theme.colors.footerText)
        const label = `OWASP PTK - ${meta.host || "unknown"} - ${meta.generatedAt || ""} - Page ${pageNumber}/${totalPages}`
        doc.text(label, margin, pageHeight - 12)
        doc.setTextColor(0)
    }

    const drawDivider = (y) => {
        doc.setDrawColor(...theme.colors.divider)
        doc.setLineWidth(0.5)
        doc.line(margin, y, pageWidth - margin, y)
    }

    const drawHeaderBlock = ({ title, subtitle, logoDataUrl } = {}) => {
        let cursor = margin
        if (logoDataUrl) {
            try {
                doc.addImage(logoDataUrl, "PNG", margin, cursor, 42, 42)
            } catch (_) { }
        }
        const textX = logoDataUrl ? margin + 56 : margin
        setH1(doc, theme)
        doc.setTextColor(...theme.colors.headerText)
        doc.text(title || "OWASP PTK Security Report", textX, cursor + 24)
        setBody(doc, theme)
        if (subtitle) {
            doc.setTextColor(...theme.colors.mutedText)
            doc.text(subtitle, textX, cursor + 42)
            cursor += 56
        } else {
            cursor += 48
        }
        doc.setTextColor(0)
        drawDivider(cursor)
        return cursor + theme.spacing.sm
    }

    const drawSectionTitle = (text, cursor) => {
        setH2(doc, theme)
        doc.setTextColor(...theme.colors.headerText)
        doc.text(text, margin, cursor)
        doc.setTextColor(0)
        drawDivider(cursor + 6)
        return cursor + theme.spacing.sm + 6
    }

    const drawMutedLabel = (text, x, y) => {
        setSmall(doc, theme)
        doc.setTextColor(...theme.colors.mutedText)
        doc.text(text, x, y)
        doc.setTextColor(0)
        return y + theme.spacing.xs
    }

    return {
        margin,
        pageWidth,
        pageHeight,
        contentTop,
        contentBottom,
        drawHeader,
        drawFooter,
        drawDivider,
        drawHeaderBlock,
        drawSectionTitle,
        drawMutedLabel
    }
}
