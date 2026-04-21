export const pdfTheme = {
    page: {
        margin: 40,
        headerHeight: 22,
        footerHeight: 24
    },
    typography: {
        h1: 20,
        h2: 14,
        h3: 12,
        body: 10,
        small: 9,
        table: 9,
        code: 8
    },
    colors: {
        headerText: [40, 40, 40],
        footerText: [120, 120, 120],
        tableHeaderText: [30, 30, 30],
        executiveHeaderBg: [245, 247, 250],
        technicalHeaderBg: [242, 245, 248],
        stripeBg: [249, 250, 252],
        border: [220, 224, 230],
        divider: [220, 224, 230],
        cardBg: [248, 249, 252],
        codeBg: [245, 245, 245],
        mutedText: [110, 110, 110],
        brandBlue: [23, 92, 166]
    },
    severityColors: {
        critical: [176, 35, 24],
        high: [224, 45, 45],
        medium: [247, 144, 9],
        low: [250, 204, 21],
        info: [37, 99, 235]
    },
    spacing: {
        xs: 6,
        sm: 10,
        md: 16,
        lg: 24
    },
    tables: {
        executive: {
            theme: "striped",
            styles: {
                fontSize: 9,
                cellPadding: 2,
                overflow: "linebreak",
                lineColor: [220, 224, 230],
                lineWidth: 0.1
            },
            headStyles: {
                fillColor: [245, 247, 250],
                textColor: [30, 30, 30],
                fontStyle: "bold"
            },
            alternateRowStyles: {
                fillColor: [249, 250, 252]
            }
        },
        technical: {
            theme: "striped",
            styles: {
                fontSize: 9,
                cellPadding: 2,
                overflow: "linebreak",
                lineColor: [220, 224, 230],
                lineWidth: 0.1
            },
            headStyles: {
                fillColor: [242, 245, 248],
                textColor: [30, 30, 30],
                fontStyle: "bold"
            },
            alternateRowStyles: {
                fillColor: [249, 250, 252]
            }
        }
    }
}

export function setH1(doc, theme = pdfTheme) {
    doc.setFont("helvetica", "bold")
    doc.setFontSize(theme.typography.h1)
}

export function setH2(doc, theme = pdfTheme) {
    doc.setFont("helvetica", "bold")
    doc.setFontSize(theme.typography.h2)
}

export function setH3(doc, theme = pdfTheme) {
    doc.setFont("helvetica", "bold")
    doc.setFontSize(theme.typography.h3)
}

export function setBody(doc, theme = pdfTheme) {
    doc.setFont("helvetica", "normal")
    doc.setFontSize(theme.typography.body)
}

export function setSmall(doc, theme = pdfTheme) {
    doc.setFont("helvetica", "normal")
    doc.setFontSize(theme.typography.small)
}

export function setCode(doc, theme = pdfTheme) {
    doc.setFont("courier", "normal")
    doc.setFontSize(theme.typography.code)
}
