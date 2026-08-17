#!/usr/bin/env python3
"""
Build CyberSnare-Phase0-Design-Record.pdf from the Markdown sources in src/.

Renders a restricted Markdown subset with ReportLab. Figures are hand-authored SVG,
converted to PNG by Inkscape and cached in build/.

Usage:  python3 build_pdf.py
"""

import os
import re
import subprocess
import sys

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_JUSTIFY
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.lib.utils import ImageReader
from reportlab.pdfbase import pdfmetrics
from reportlab.platypus import (
    BaseDocTemplate, Frame, Image, KeepTogether, NextPageTemplate, PageBreak,
    PageTemplate, Paragraph, Spacer, Table, TableStyle,
)
from reportlab.platypus.tableofcontents import TableOfContents

HERE = os.path.dirname(os.path.abspath(__file__))
SRC = os.path.join(HERE, "src")
FIGS = os.path.join(HERE, "figures")
BUILD = os.path.join(HERE, "build")
OUT = os.path.join(HERE, "CyberSnare-Phase0-Design-Record.pdf")

SOURCES = [
    "00-summary.md",
    "01-part1-design-record.md",
    "02-part2-execution-plan.md",
    "03-appendices.md",
]

DOC_TITLE = "CyberSnare — Phase 0 Design Record"

# ---------------------------------------------------------------- palette

INK = colors.HexColor("#1c2430")
MUTED = colors.HexColor("#5a6675")
RULE = colors.HexColor("#c8d0da")
ACCENT = colors.HexColor("#2b4a63")
BLUE = colors.HexColor("#2b6ca3")
PURPLE = colors.HexColor("#6a4b9c")
GREEN = colors.HexColor("#2b7d5c")
RED = colors.HexColor("#a83232")
TBLHEAD = colors.HexColor("#eef2f6")
TBLALT = colors.HexColor("#f8fafb")
CALLOUT = colors.HexColor("#f4f7fa")

PAGE_W, PAGE_H = A4
LM = RM = 18 * mm
TM = 22 * mm
BM = 18 * mm
AVAIL_W = PAGE_W - LM - RM

# ---------------------------------------------------------------- styles


def build_styles():
    ss = getSampleStyleSheet()
    s = {}
    s["body"] = ParagraphStyle(
        "body", parent=ss["Normal"], fontName="Times-Roman", fontSize=10.2,
        leading=14.6, textColor=INK, spaceAfter=7, alignment=TA_JUSTIFY,
    )
    s["h1"] = ParagraphStyle(
        "h1", parent=ss["Normal"], fontName="Helvetica-Bold", fontSize=16,
        leading=20, textColor=INK, spaceBefore=16, spaceAfter=3,
    )
    s["h2"] = ParagraphStyle(
        "h2", parent=ss["Normal"], fontName="Helvetica-Bold", fontSize=12.2,
        leading=16, textColor=ACCENT, spaceBefore=13, spaceAfter=5,
    )
    s["h3"] = ParagraphStyle(
        "h3", parent=ss["Normal"], fontName="Helvetica-Bold", fontSize=10.6,
        leading=14, textColor=INK, spaceBefore=10, spaceAfter=4,
    )
    s["h4"] = ParagraphStyle(
        "h4", parent=ss["Normal"], fontName="Helvetica-BoldOblique", fontSize=10,
        leading=13, textColor=MUTED, spaceBefore=8, spaceAfter=3,
    )
    s["bullet"] = ParagraphStyle(
        "bullet", parent=s["body"], leftIndent=13, bulletIndent=3,
        spaceAfter=3.5, alignment=TA_JUSTIFY,
    )
    s["quote"] = ParagraphStyle(
        "quote", parent=ss["Normal"], fontName="Times-Italic", fontSize=10.6,
        leading=15, textColor=INK, alignment=TA_JUSTIFY,
    )
    s["code"] = ParagraphStyle(
        "code", parent=ss["Normal"], fontName="Courier", fontSize=8.1,
        leading=10.4, textColor=INK,
    )
    s["cell"] = ParagraphStyle(
        "cell", parent=ss["Normal"], fontName="Helvetica", fontSize=8.2,
        leading=11, textColor=INK,
    )
    s["cellh"] = ParagraphStyle(
        "cellh", parent=s["cell"], fontName="Helvetica-Bold", textColor=ACCENT,
    )
    s["caption"] = ParagraphStyle(
        "caption", parent=ss["Normal"], fontName="Helvetica-Oblique", fontSize=8.6,
        leading=11.5, textColor=MUTED, alignment=TA_CENTER, spaceBefore=5,
    )
    s["toc1"] = ParagraphStyle(
        "toc1", fontName="Helvetica-Bold", fontSize=10, leading=17, textColor=INK,
    )
    s["toc2"] = ParagraphStyle(
        "toc2", fontName="Helvetica", fontSize=9.2, leading=14,
        leftIndent=16, textColor=colors.HexColor("#3a4757"),
    )
    s["title"] = ParagraphStyle(
        "title", fontName="Helvetica-Bold", fontSize=27, leading=33,
        textColor=INK, alignment=TA_CENTER,
    )
    s["subtitle"] = ParagraphStyle(
        "subtitle", fontName="Helvetica", fontSize=13.5, leading=19,
        textColor=ACCENT, alignment=TA_CENTER,
    )
    s["tp"] = ParagraphStyle(
        "tp", fontName="Helvetica", fontSize=10, leading=15,
        textColor=MUTED, alignment=TA_CENTER,
    )
    s["partnum"] = ParagraphStyle(
        "partnum", fontName="Helvetica-Bold", fontSize=22, leading=28,
        textColor=INK, alignment=TA_CENTER,
    )
    return s


# ---------------------------------------------------------------- inline markup

_CODE_RE = re.compile(r"`([^`]+)`")
_BOLD_RE = re.compile(r"\*\*([^*]+)\*\*")
_ITAL_RE = re.compile(r"(?<!\*)\*([^*]+)\*(?!\*)")


def inline(text):
    """Escape XML, then apply code / bold / italic. Code spans are protected first."""
    spans = []

    def stash(m):
        spans.append(m.group(1))
        return "\x00%d\x00" % (len(spans) - 1)

    text = _CODE_RE.sub(stash, text)
    text = text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    text = _BOLD_RE.sub(r"<b>\1</b>", text)
    text = _ITAL_RE.sub(r"<i>\1</i>", text)

    def restore(m):
        raw = spans[int(m.group(1))]
        raw = raw.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
        return ('<font face="Courier" size="8.6" color="#8a3a2a">%s</font>' % raw)

    return re.sub(r"\x00(\d+)\x00", restore, text)


def split_row(line):
    """Split a Markdown table row on unescaped pipes."""
    line = line.strip()
    if line.startswith("|"):
        line = line[1:]
    if line.endswith("|"):
        line = line[:-1]
    parts, cur, i = [], "", 0
    while i < len(line):
        if line[i] == "\\" and i + 1 < len(line) and line[i + 1] == "|":
            cur += "|"
            i += 2
            continue
        if line[i] == "|":
            parts.append(cur)
            cur = ""
            i += 1
            continue
        cur += line[i]
        i += 1
    parts.append(cur)
    return [p.strip() for p in parts]


# ---------------------------------------------------------------- figures


def svg_to_png(svg_path, dpi=300):
    os.makedirs(BUILD, exist_ok=True)
    name = os.path.splitext(os.path.basename(svg_path))[0] + ".png"
    png = os.path.join(BUILD, name)
    if os.path.exists(png) and os.path.getmtime(png) >= os.path.getmtime(svg_path):
        return png
    subprocess.run(
        ["inkscape", "--export-type=png", "--export-dpi=%d" % dpi, "-o", png, svg_path],
        check=True, capture_output=True,
    )
    return png


def figure_flowable(number, caption, relpath, styles):
    """Figures are numbered by order of appearance, never by filename.

    Numbering them in the Markdown invites them to drift out of order the moment a
    figure moves between sections — which is exactly what happened before this.
    """
    caption = "Figure %d — %s" % (number, caption)
    svg = os.path.join(HERE, relpath)
    if not os.path.exists(svg):
        return [Paragraph("[missing figure: %s]" % relpath, styles["caption"])]
    png = svg_to_png(svg)
    iw, ih = ImageReader(png).getSize()
    w = min(AVAIL_W, AVAIL_W)
    h = w * ih / iw
    max_h = PAGE_H - TM - BM - 60
    if h > max_h:
        h = max_h
        w = h * iw / ih
    img = Image(png, width=w, height=h)
    img.hAlign = "CENTER"
    return [Spacer(1, 7), KeepTogether([img, Paragraph(inline(caption), styles["caption"])]), Spacer(1, 9)]


# ---------------------------------------------------------------- tables


def make_table(rows, styles):
    header, body = rows[0], rows[1:]
    ncol = len(header)

    def plain(s):
        return re.sub(r"[*`~]", "", s)

    # A column must be at least as wide as its longest unbreakable word, or the
    # word gets hyphen-less split mid-token ("Prefer / red"). Measure it rather
    # than guessing from character counts.
    minw, weight = [], []
    for c in range(ncol):
        widest_word = 0.0
        chars = 0
        cells = [header[c]] + [r[c] for r in body if c < len(r)]
        for cell in cells:
            txt = plain(cell)
            chars += min(len(txt), 140)
            for word in txt.split():
                widest_word = max(
                    widest_word, pdfmetrics.stringWidth(word, "Helvetica-Bold", 8.2))
        minw.append(min(widest_word + 12.0, AVAIL_W * 0.42))
        weight.append(max(chars, 8))

    if sum(minw) > AVAIL_W:
        scale = AVAIL_W / sum(minw)
        minw = [m * scale for m in minw]
    extra = AVAIL_W - sum(minw)
    tw = float(sum(weight))
    widths = [minw[c] + extra * weight[c] / tw for c in range(ncol)]

    data = [[Paragraph(inline(c), styles["cellh"]) for c in header]]
    for r in body:
        r = list(r) + [""] * (ncol - len(r))
        data.append([Paragraph(inline(c), styles["cell"]) for c in r[:ncol]])

    t = Table(data, colWidths=widths, repeatRows=1, hAlign="LEFT")
    st = [
        ("BACKGROUND", (0, 0), (-1, 0), TBLHEAD),
        ("LINEBELOW", (0, 0), (-1, 0), 0.9, ACCENT),
        ("LINEBELOW", (0, 1), (-1, -2), 0.35, RULE),
        ("LINEBELOW", (0, -1), (-1, -1), 0.7, RULE),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("TOPPADDING", (0, 0), (-1, -1), 4.5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4.5),
        ("LEFTPADDING", (0, 0), (-1, -1), 5),
        ("RIGHTPADDING", (0, 0), (-1, -1), 5),
    ]
    for i in range(2, len(data), 2):
        st.append(("BACKGROUND", (0, i), (-1, i), TBLALT))
    t.setStyle(TableStyle(st))
    return [Spacer(1, 4), t, Spacer(1, 9)]


def make_callout(lines, styles):
    body = " ".join(lines)
    p = Paragraph(inline(body), styles["quote"])
    t = Table([[p]], colWidths=[AVAIL_W], hAlign="LEFT")
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), CALLOUT),
        ("LINEBEFORE", (0, 0), (0, -1), 2.6, PURPLE),
        ("LEFTPADDING", (0, 0), (-1, -1), 11),
        ("RIGHTPADDING", (0, 0), (-1, -1), 10),
        ("TOPPADDING", (0, 0), (-1, -1), 8),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
    ]))
    return [Spacer(1, 5), t, Spacer(1, 9)]


def make_code(lines, styles):
    safe = []
    for ln in lines:
        ln = ln.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
        ln = ln.replace(" ", "&nbsp;")
        safe.append(ln if ln else "&nbsp;")
    p = Paragraph("<br/>".join(safe), styles["code"])
    t = Table([[p]], colWidths=[AVAIL_W], hAlign="LEFT")
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#f6f7f9")),
        ("BOX", (0, 0), (-1, -1), 0.5, RULE),
        ("LEFTPADDING", (0, 0), (-1, -1), 9),
        ("RIGHTPADDING", (0, 0), (-1, -1), 7),
        ("TOPPADDING", (0, 0), (-1, -1), 7),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 7),
    ]))
    return [Spacer(1, 4), t, Spacer(1, 9)]


# ---------------------------------------------------------------- parser


class Rule(Spacer):
    """A thin horizontal rule."""

    def __init__(self):
        Spacer.__init__(self, AVAIL_W, 11)

    def draw(self):
        self.canv.setStrokeColor(RULE)
        self.canv.setLineWidth(0.6)
        self.canv.line(0, 5, AVAIL_W, 5)


class H1(Paragraph):
    """H1 that also paints an accent rule and registers a TOC entry."""

    def __init__(self, text, style, key):
        Paragraph.__init__(self, text, style)
        self._key = key
        self._raw = re.sub(r"<[^>]+>", "", text)

    def draw(self):
        Paragraph.draw(self)
        self.canv.setStrokeColor(ACCENT)
        self.canv.setLineWidth(1.4)
        self.canv.line(0, -4, AVAIL_W, -4)


def parse(md, styles, figure_index):
    flow = []
    lines = md.split("\n")
    i = 0
    para, bullets = [], []

    def flush_para():
        nonlocal para
        if para:
            flow.append(Paragraph(inline(" ".join(para)), styles["body"]))
            para = []

    def flush_bullets():
        nonlocal bullets
        for b in bullets:
            flow.append(Paragraph(inline(b), styles["bullet"], bulletText="•"))
        if bullets:
            flow.append(Spacer(1, 5))
        bullets = []

    while i < len(lines):
        ln = lines[i]
        st = ln.strip()

        if st.startswith("\\part{"):
            flush_para(); flush_bullets()
            title = st[6:st.rindex("}")]
            flow.append(PageBreak())
            flow.append(Spacer(1, 190))
            flow.append(Paragraph(title, styles["partnum"]))
            flow.append(Spacer(1, 14))
            flow.append(Rule())
            flow.append(PageBreak())
            i += 1
            continue

        if st == "\\pagebreak":
            flush_para(); flush_bullets()
            flow.append(PageBreak())
            i += 1
            continue

        if not st:
            flush_para(); flush_bullets()
            i += 1
            continue

        if st.startswith("```"):
            flush_para(); flush_bullets()
            i += 1
            buf = []
            while i < len(lines) and not lines[i].strip().startswith("```"):
                buf.append(lines[i])
                i += 1
            i += 1
            flow.extend(make_code(buf, styles))
            continue

        m = re.match(r"^!\[(.*?)\]\((.*?)\)$", st)
        if m:
            flush_para(); flush_bullets()
            cap, path = m.group(1), m.group(2)
            figure_index.append(cap)
            flow.extend(figure_flowable(len(figure_index), cap, path, styles))
            i += 1
            continue

        if st.startswith("|"):
            flush_para(); flush_bullets()
            rows = []
            while i < len(lines) and lines[i].strip().startswith("|"):
                cells = split_row(lines[i])
                if not all(re.fullmatch(r":?-{2,}:?", c) for c in cells if c):
                    rows.append(cells)
                i += 1
            if rows:
                flow.extend(make_table(rows, styles))
            continue

        if st.startswith(">"):
            flush_para(); flush_bullets()
            buf = []
            while i < len(lines) and lines[i].strip().startswith(">"):
                buf.append(lines[i].strip().lstrip(">").strip())
                i += 1
            buf = [b for b in buf if b]
            flow.extend(make_callout(buf, styles))
            continue

        if re.fullmatch(r"-{3,}", st):
            flush_para(); flush_bullets()
            flow.append(Rule())
            i += 1
            continue

        m = re.match(r"^(#{1,4})\s+(.*)$", st)
        if m:
            flush_para(); flush_bullets()
            level, text = len(m.group(1)), m.group(2)
            if level == 1:
                flow.append(Spacer(1, 6))
                flow.append(H1(inline(text), styles["h1"], text))
                flow.append(Spacer(1, 7))
            else:
                flow.append(Paragraph(inline(text), styles["h%d" % level]))
            i += 1
            continue

        m = re.match(r"^[-*]\s+(.*)$", st)
        if m:
            flush_para()
            bullets.append(m.group(1))
            i += 1
            continue

        m = re.match(r"^(\d+)\.\s+(.*)$", st)
        if m:
            flush_para()
            flush_bullets()
            flow.append(Paragraph(inline(m.group(2)), styles["bullet"],
                                  bulletText="%s." % m.group(1)))
            i += 1
            continue

        para.append(st)
        i += 1

    flush_para()
    flush_bullets()
    return flow


# ---------------------------------------------------------------- document


class Doc(BaseDocTemplate):
    def __init__(self, path, styles):
        BaseDocTemplate.__init__(
            self, path, pagesize=A4,
            leftMargin=LM, rightMargin=RM, topMargin=TM, bottomMargin=BM,
            title=DOC_TITLE, author="Eman Azam · Sara Sultan · Uliya Fatima",
            subject="CyberSnare — adaptive deception control plane",
        )
        self.styles = styles
        self.section = ""
        frame = Frame(LM, BM, AVAIL_W, PAGE_H - TM - BM, id="body",
                      leftPadding=0, rightPadding=0, topPadding=0, bottomPadding=0)
        self.addPageTemplates([
            PageTemplate(id="plain", frames=[frame]),
            # onPageEnd, not onPage: the running header must reflect the section
            # that appears ON this page, and afterFlowable only updates it as the
            # page's flowables are drawn.
            PageTemplate(id="main", frames=[frame], onPageEnd=self.decorate),
        ])

    def afterFlowable(self, flowable):
        if isinstance(flowable, H1):
            self.section = flowable._raw
            self.notify("TOCEntry", (0, flowable._raw, self.page))
        elif isinstance(flowable, Paragraph) and flowable.style.name == "h2":
            txt = re.sub(r"<[^>]+>", "", flowable.getPlainText())
            self.notify("TOCEntry", (1, txt, self.page))

    def decorate(self, canv, doc):
        canv.saveState()
        canv.setFont("Helvetica", 7.4)
        canv.setFillColor(MUTED)
        canv.drawString(LM, PAGE_H - TM + 12, DOC_TITLE)
        sec = self.section
        if len(sec) > 58:
            sec = sec[:56] + "…"
        canv.drawRightString(PAGE_W - RM, PAGE_H - TM + 12, sec)
        canv.setStrokeColor(RULE)
        canv.setLineWidth(0.5)
        canv.line(LM, PAGE_H - TM + 7, PAGE_W - RM, PAGE_H - TM + 7)
        canv.line(LM, BM - 12, PAGE_W - RM, BM - 12)
        canv.setFont("Helvetica", 7.8)
        canv.drawCentredString(PAGE_W / 2.0, BM - 23, str(doc.page))
        canv.drawString(LM, BM - 23, "v1.0 · for review")
        canv.drawRightString(PAGE_W - RM, BM - 23, "FYP-2 · Air University")
        canv.restoreState()


def title_page(styles):
    f = [Spacer(1, 96)]
    f.append(Paragraph("CyberSnare", styles["title"]))
    f.append(Spacer(1, 10))
    f.append(Paragraph("Phase 0 Design Record", styles["subtitle"]))
    f.append(Spacer(1, 6))
    f.append(Paragraph("An adaptive deception control plane", styles["tp"]))
    f.append(Spacer(1, 30))
    f.append(Rule())
    f.append(Spacer(1, 26))

    rows = [
        ["Project", "CyberSnare — Multi-Tier Adaptive Deception Platform"],
        ["Programme", "BS Cyber Security, FYP-2 — Air University NCSA"],
        ["Team", "Eman Azam · Sara Sultan · Uliya Fatima"],
        ["Supervisor", "Mr. Hilmand Khan"],
        ["Co-supervisor", "Mr. Jalal Shah"],
        ["Version", "1.0 — for review"],
        ["Supersedes", "Nothing. First issue"],
        ["Next artefact", "Architecture document set, only after this record is agreed"],
    ]
    data = [[Paragraph("<b>%s</b>" % a, styles["cell"]), Paragraph(b, styles["cell"])]
            for a, b in rows]
    t = Table(data, colWidths=[AVAIL_W * 0.26, AVAIL_W * 0.74], hAlign="CENTER")
    t.setStyle(TableStyle([
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("TOPPADDING", (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ("LINEBELOW", (0, 0), (-1, -2), 0.3, RULE),
        ("LEFTPADDING", (0, 0), (-1, -1), 0),
    ]))
    f.append(t)
    f.append(Spacer(1, 40))
    f.append(Paragraph(
        "This record supersedes the internal mechanisms of the approved FYP-1 proposal while "
        "preserving its research identity and every approved objective. Section 9 records each "
        "change with its justification.", styles["tp"]))
    f.append(PageBreak())
    return f


def figure_list(captions, styles):
    f = [Paragraph("Figures", styles["h1"]), Spacer(1, 8)]
    rows = [["Figure %d" % (i + 1), c] for i, c in enumerate(captions)]
    data = [[Paragraph("<b>%s</b>" % a, styles["cell"]), Paragraph(b, styles["cell"])]
            for a, b in rows]
    t = Table(data, colWidths=[AVAIL_W * 0.14, AVAIL_W * 0.86], hAlign="LEFT")
    t.setStyle(TableStyle([
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("TOPPADDING", (0, 0), (-1, -1), 3.5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 3.5),
        ("LEFTPADDING", (0, 0), (-1, -1), 0),
        ("LINEBELOW", (0, 0), (-1, -2), 0.3, RULE),
    ]))
    f.append(t)
    f.append(PageBreak())
    return f


def main():
    styles = build_styles()

    # pre-scan for the figure list
    captions = []
    bodies = []
    for name in SOURCES:
        with open(os.path.join(SRC, name), encoding="utf-8") as fh:
            md = fh.read()
        bodies.append(md)
        captions += re.findall(r"^!\[(.*?)\]\(.*?\)$", md, flags=re.M)

    story = []
    story += title_page(styles)
    story.append(NextPageTemplate("main"))

    toc = TableOfContents()
    toc.levelStyles = [styles["toc1"], styles["toc2"]]
    story.append(Paragraph("Contents", styles["h1"]))
    story.append(Spacer(1, 10))
    story.append(toc)
    story.append(PageBreak())

    story += figure_list(captions, styles)

    figure_index = []
    for md in bodies:
        story += parse(md, styles, figure_index)

    doc = Doc(OUT, styles)
    doc.multiBuild(story)

    size = os.path.getsize(OUT)
    print("built %s  (%.1f KB)" % (OUT, size / 1024.0))
    print("figures embedded: %d" % len(captions))


if __name__ == "__main__":
    sys.exit(main())
