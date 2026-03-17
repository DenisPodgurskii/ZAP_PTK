import { pdfTheme, setBody, setCode, setSmall } from "./pdfTheme.js"
import { clampCellText } from "./pdfLayout.js"

export function drawFlagIcon(doc, { x, y, severity = "info", size = 12 } = {}) {
    const severityKey = String(severity).toLowerCase()
    const color = pdfTheme.severityColors[severityKey] || pdfTheme.severityColors.info
    doc.setFillColor(...color)
    // Draw flag pole
    doc.setLineWidth(1.5)
    doc.setDrawColor(...color)
    doc.line(x, y, x, y + size)
    // Draw flag (triangle/pennant shape)
    const flagWidth = size * 0.8
    const flagHeight = size * 0.5
    doc.triangle(x, y, x + flagWidth, y + flagHeight / 2, x, y + flagHeight, "F")
    return x + flagWidth + 4
}

export function drawReplayIcon(doc, { x, y, size = 10, available = true } = {}) {
    if (!available) return
    // Draw a small rocket/arrow icon for replay
    const color = available ? [66, 165, 245] : [180, 180, 180] // Blue or gray
    doc.setFillColor(...color)
    // Simple arrow/chevron shape
    doc.triangle(x, y + size / 2, x + size * 0.7, y, x + size * 0.7, y + size, "F")
    doc.rect(x + size * 0.5, y + size * 0.3, size * 0.4, size * 0.4, "F")
}

export function drawCheckIcon(doc, { x, y, size = 8, checked = true } = {}) {
    if (checked) {
        doc.setFillColor(76, 175, 80) // Green
        doc.circle(x + size / 2, y + size / 2, size / 2, "F")
        doc.setDrawColor(255, 255, 255)
        doc.setLineWidth(1)
        // Checkmark
        doc.line(x + size * 0.25, y + size * 0.5, x + size * 0.45, y + size * 0.7)
        doc.line(x + size * 0.45, y + size * 0.7, x + size * 0.75, y + size * 0.3)
    } else {
        doc.setDrawColor(200, 200, 200)
        doc.setLineWidth(0.5)
        doc.circle(x + size / 2, y + size / 2, size / 2)
    }
    doc.setDrawColor(0)
}

export function drawBadge(doc, text, { x, y, fill = [46, 125, 50], textColor = [255, 255, 255] } = {}) {
    const paddingX = 6
    const height = 16
    setBody(doc, pdfTheme)
    doc.setFont("helvetica", "bold")
    const width = doc.getTextWidth(text) + paddingX * 2
    doc.setFillColor(...fill)
    doc.roundedRect(x, y, width, height, 2, 2, "F")
    doc.setTextColor(...textColor)
    doc.text(text, x + paddingX, y + 12)
    doc.setTextColor(0)
    return width
}

export function drawHostBanner(doc, { x, y, width, text } = {}) {
    const bannerHeight = 28
    doc.setFillColor(...pdfTheme.colors.cardBg)
    doc.roundedRect(x, y, width, bannerHeight, 4, 4, "F")
    setBody(doc, pdfTheme)
    doc.setFont("helvetica", "bold")
    doc.text(text || "unknown", x + width / 2, y + 18, { align: "center" })
    return y + bannerHeight + pdfTheme.spacing.sm
}

export function drawRiskBarList(doc, { x, y, counts, barMaxWidth = 140, labelWidth = 60 } = {}) {
    const items = [
        ["Critical", counts.critical || 0, pdfTheme.severityColors.critical],
        ["High", counts.high || 0, pdfTheme.severityColors.high],
        ["Medium", counts.medium || 0, pdfTheme.severityColors.medium],
        ["Low", counts.low || 0, pdfTheme.severityColors.low],
        ["Info", counts.info || 0, pdfTheme.severityColors.info]
    ]
    const max = Math.max(...items.map(item => item[1]), 1)
    let lineY = y
    setBody(doc, pdfTheme)
    doc.setFont("helvetica", "bold")
    doc.text("Risk ratings:", x, lineY)
    lineY += 8
    doc.setFont("helvetica", "normal")
    items.forEach(([label, count, color]) => {
        doc.text(`${label}:`, x, lineY + 10)
        const barX = x + labelWidth
        const barWidth = barMaxWidth * (count / max)
        doc.setFillColor(...color)
        doc.roundedRect(barX, lineY + 2, Math.max(2, barWidth), 10, 2, 2, "F")
        doc.setTextColor(0)
        doc.text(String(count), barX + Math.max(2, barWidth) + 6, lineY + 10)
        lineY += 16
    })
    return lineY
}

export function drawKeyValueBlock(doc, { x, y, rows, labelWidth = 80 } = {}) {
    setBody(doc, pdfTheme)
    doc.setFont("helvetica", "bold")
    doc.text("Scan information:", x, y)
    doc.setFont("helvetica", "normal")
    let lineY = y + 12
    rows.forEach(([label, value]) => {
        doc.text(label, x, lineY)
        doc.text(String(value || ""), x + labelWidth, lineY)
        lineY += 12
    })
    return lineY
}

export function normalizeEvidenceSummary(text) {
    if (!text) return ""
    const clean = String(text).replace(/\s+/g, " ").trim()
    return clampCellText(clean, { maxChars: 140, maxLines: 2 })
}

export function drawCodeBlock(doc, { x, y, label, text, width = 520 } = {}) {
    const padding = 6
    setCode(doc, pdfTheme)
    const lines = doc.splitTextToSize(text || "", width - padding * 2)
    const height = lines.length * 10 + padding * 2
    doc.setFillColor(...pdfTheme.colors.codeBg)
    doc.rect(x, y, width, height, "F")
    doc.setTextColor(60)
    if (label) {
        setBody(doc, pdfTheme)
        doc.setFont("helvetica", "bold")
        doc.text(label, x, y - 6)
    }
    setCode(doc, pdfTheme)
    doc.setTextColor(40)
    doc.text(lines, x + padding, y + 10)
    doc.setTextColor(0)
    return y + height + 8
}

export function drawSummaryCard(doc, { x, y, width, height } = {}) {
    doc.setFillColor(...pdfTheme.colors.cardBg)
    doc.roundedRect(x, y, width, height, 4, 4, "F")
    doc.setDrawColor(...pdfTheme.colors.border)
    doc.setLineWidth(0.4)
    doc.roundedRect(x, y, width, height, 4, 4)
    return y + height + pdfTheme.spacing.sm
}

export function drawMutedText(doc, { x, y, text } = {}) {
    setSmall(doc, pdfTheme)
    doc.setTextColor(...pdfTheme.colors.mutedText)
    doc.text(text || "", x, y)
    doc.setTextColor(0)
    return y + pdfTheme.spacing.xs
}
