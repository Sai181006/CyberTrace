"""Render the checked-in final report as a print-ready PDF."""

from __future__ import annotations

import html
import re
from pathlib import Path

from reportlab.lib import colors
from reportlab.lib.enums import TA_LEFT
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.platypus import (
    KeepTogether,
    PageBreak,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
)

ROOT = Path(__file__).resolve().parent.parent
SOURCE = ROOT / "docs" / "final-report.md"
OUTPUT = ROOT / "output" / "pdf" / "CyberTrace_Final_Report.pdf"


def inline(value: str) -> str:
    value = html.escape(value)
    value = re.sub(r"\[([^]]+)\]\(([^)]+)\)", r"\1 (\2)", value)
    value = re.sub(r"`([^`]+)`", r"<font name='Courier' size='9'>\1</font>", value)
    return value


def footer(canvas, document) -> None:
    canvas.saveState()
    canvas.setFont("Helvetica", 8)
    canvas.setFillColor(colors.HexColor("#5C6F79"))
    canvas.drawString(0.82 * inch, 0.48 * inch, "CyberTrace | BCSE302P")
    canvas.drawRightString(7.68 * inch, 0.48 * inch, str(document.page))
    canvas.restoreState()


def main() -> None:
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    styles = getSampleStyleSheet()
    title = ParagraphStyle(
        "ReportTitle",
        parent=styles["Title"],
        fontName="Helvetica-Bold",
        fontSize=21,
        leading=25,
        textColor=colors.black,
        alignment=TA_LEFT,
        spaceAfter=14,
    )
    heading = ParagraphStyle(
        "ReportHeading",
        parent=styles["Heading1"],
        fontName="Helvetica-Bold",
        fontSize=13,
        leading=17,
        textColor=colors.black,
        spaceBefore=12,
        spaceAfter=5,
        keepWithNext=True,
    )
    body = ParagraphStyle(
        "ReportBody",
        parent=styles["BodyText"],
        fontName="Helvetica",
        fontSize=9.7,
        leading=13.4,
        textColor=colors.black,
        alignment=TA_LEFT,
        spaceAfter=5,
        splitLongWords=True,
    )
    small = ParagraphStyle(
        "ReportSmall",
        parent=body,
        fontSize=8.5,
        leading=12,
        alignment=TA_LEFT,
        spaceAfter=6,
    )
    story = []
    for raw in SOURCE.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line:
            continue
        if line.startswith("# "):
            story.append(Paragraph(inline(line[2:]), title))
            story.append(
                Paragraph("BCSE302P Database Systems Lab | 11 October 2026", small)
            )
            story.append(Spacer(1, 9))
        elif line.startswith("## "):
            if line == "## Reproducibility and submitted artifacts":
                story.append(PageBreak())
            story.append(Paragraph(inline(line[3:]), heading))
        elif re.match(r"^\d+\. ", line):
            story.append(KeepTogether([Paragraph(inline(line), small)]))
        else:
            story.append(KeepTogether([Paragraph(inline(line), body)]))

    pdf = SimpleDocTemplate(
        str(OUTPUT),
        pagesize=letter,
        leftMargin=0.82 * inch,
        rightMargin=0.82 * inch,
        topMargin=0.65 * inch,
        bottomMargin=0.65 * inch,
        title="CyberTrace Final Project Report",
        author="CyberTrace Project",
    )
    pdf.build(story, onFirstPage=footer, onLaterPages=footer)
    print(OUTPUT)


if __name__ == "__main__":
    main()
