"""security-report.pdf -- executive/auditor rendering of final-report.json.

Layout rule, enforced structurally: the DEPLOYMENT RESULT block and the SECURITY
RESULT block are separate, individually framed panels with an explicit statement
between them that one does not imply the other. There is no combined "overall"
banner anywhere in this document.
"""

from __future__ import annotations

import os
from typing import Any, Dict, List, Optional
from xml.sax.saxutils import escape

try:  # pragma: no cover - import guard
    from reportlab.lib import colors
    from reportlab.lib.enums import TA_CENTER
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
    from reportlab.lib.units import mm
    from reportlab.platypus import (
        HRFlowable,
        KeepTogether,
        PageBreak,
        Paragraph,
        SimpleDocTemplate,
        Spacer,
        Table,
        TableStyle,
    )

    REPORTLAB_AVAILABLE = True
    REPORTLAB_IMPORT_ERROR = ""
except ImportError as exc:  # pragma: no cover - environment specific
    REPORTLAB_AVAILABLE = False
    REPORTLAB_IMPORT_ERROR = str(exc)


class PdfGenerationError(RuntimeError):
    """Raised when the PDF cannot be produced. Never swallowed silently."""


MAX_TABLE_ROWS = 250
MAX_DETAILED_FINDINGS = 40

STATUS_COLOURS = {
    "PASS": ("#1B5E20", "#E8F5E9"),
    "FAIL": ("#B71C1C", "#FFEBEE"),
    "FAILED": ("#B71C1C", "#FFEBEE"),
    "NOT_VERIFIED": ("#E65100", "#FFF3E0"),
    "NOT_TESTED": ("#37474F", "#ECEFF1"),
    "NOT_IMPLEMENTED": ("#37474F", "#ECEFF1"),
    "NOT_APPLICABLE": ("#455A64", "#F5F5F5"),
    "DEPLOYED": ("#0D47A1", "#E3F2FD"),
    "SKIPPED": ("#37474F", "#ECEFF1"),
    "UNKNOWN": ("#37474F", "#ECEFF1"),
    "ERROR": ("#B71C1C", "#FFEBEE"),
    "OK": ("#1B5E20", "#E8F5E9"),
    "PARTIAL": ("#E65100", "#FFF3E0"),
}

SEVERITY_COLOURS = {
    "CRITICAL": "#B71C1C",
    "HIGH": "#D84315",
    "UNKNOWN": "#6A1B9A",
    "MEDIUM": "#EF6C00",
    "LOW": "#1565C0",
    "INFO": "#455A64",
}


def _hex(colour) -> str:
    """reportlab inline <font color=...> requires a leading '#'."""
    return "#" + colour.hexval()[2:]


def _colour_for(status: str) -> tuple:
    key = str(status or "").upper()
    fg, bg = STATUS_COLOURS.get(key, ("#212121", "#FAFAFA"))
    return colors.HexColor(fg), colors.HexColor(bg)


def _text(value: Any, limit: Optional[int] = None) -> str:
    raw = str(value if value is not None else "")
    raw = raw.replace("\r", " ").replace("\n", " ").strip()
    if limit and len(raw) > limit:
        raw = raw[: limit - 1] + "…"
    return escape(raw)


class _Styles:
    def __init__(self) -> None:
        base = getSampleStyleSheet()
        self.title = ParagraphStyle(
            "DocTitle", parent=base["Title"], fontSize=20, leading=24, spaceAfter=2, textColor=colors.HexColor("#0D1B2A")
        )
        self.subtitle = ParagraphStyle(
            "DocSubtitle", parent=base["Normal"], fontSize=9.5, leading=13, textColor=colors.HexColor("#455A64")
        )
        self.h1 = ParagraphStyle(
            "H1", parent=base["Heading1"], fontSize=14, leading=17, spaceBefore=14, spaceAfter=6,
            textColor=colors.HexColor("#0D1B2A"),
        )
        self.h2 = ParagraphStyle(
            "H2", parent=base["Heading2"], fontSize=11.5, leading=14, spaceBefore=10, spaceAfter=4,
            textColor=colors.HexColor("#1B263B"),
        )
        self.body = ParagraphStyle("Body", parent=base["Normal"], fontSize=9, leading=12.5)
        self.small = ParagraphStyle("Small", parent=base["Normal"], fontSize=7.6, leading=9.8)
        self.cell = ParagraphStyle("Cell", parent=base["Normal"], fontSize=8, leading=10.5)
        self.cell_bold = ParagraphStyle("CellBold", parent=self.cell, fontName="Helvetica-Bold")
        self.mono = ParagraphStyle("Mono", parent=base["Normal"], fontName="Courier", fontSize=7.5, leading=9.5)
        self.panel_label = ParagraphStyle(
            "PanelLabel", parent=base["Normal"], fontSize=9, leading=12, alignment=TA_CENTER,
            textColor=colors.HexColor("#37474F"),
        )
        self.panel_value = ParagraphStyle(
            "PanelValue", parent=base["Normal"], fontSize=17, leading=21, alignment=TA_CENTER,
            fontName="Helvetica-Bold",
        )
        self.warn = ParagraphStyle(
            "Warn", parent=base["Normal"], fontSize=8.5, leading=11.5, textColor=colors.HexColor("#B71C1C"),
        )
        self.note = ParagraphStyle(
            "Note", parent=base["Normal"], fontSize=8, leading=11, textColor=colors.HexColor("#455A64"),
        )


def _kv_table(rows: List[tuple], styles: _Styles, widths: tuple = (52 * mm, 118 * mm)) -> Table:
    data = []
    for label, value in rows:
        data.append([Paragraph(_text(label), styles.cell_bold), Paragraph(_text(value), styles.cell)])
    table = Table(data, colWidths=widths, hAlign="LEFT")
    table.setStyle(
        TableStyle(
            [
                ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#CFD8DC")),
                ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#F5F7F9")),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("LEFTPADDING", (0, 0), (-1, -1), 5),
                ("RIGHTPADDING", (0, 0), (-1, -1), 5),
                ("TOPPADDING", (0, 0), (-1, -1), 3.5),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 3.5),
            ]
        )
    )
    return table


def _status_panel(title: str, entries: List[tuple], styles: _Styles) -> Table:
    """One framed result panel with large status values."""
    header = [Paragraph("<b>%s</b>" % _text(title), styles.panel_label)]
    label_row = []
    value_row = []
    for label, value in entries:
        fg, _bg = _colour_for(value)
        label_row.append(Paragraph(_text(label), styles.panel_label))
        value_row.append(
            Paragraph('<font color="%s">%s</font>' % (_hex(fg), _text(value)), styles.panel_value)
        )

    columns = len(entries)
    width = 170 * mm
    inner = Table(
        [label_row, value_row],
        colWidths=[width / columns] * columns,
        hAlign="LEFT",
    )
    inner.setStyle(
        TableStyle(
            [
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                ("TOPPADDING", (0, 0), (-1, 0), 6),
                ("BOTTOMPADDING", (0, 1), (-1, 1), 8),
                ("LINEAFTER", (0, 0), (-2, -1), 0.4, colors.HexColor("#CFD8DC")),
            ]
        )
    )

    outer = Table([header, [inner]], colWidths=[width], hAlign="LEFT")
    outer.setStyle(
        TableStyle(
            [
                ("BOX", (0, 0), (-1, -1), 1.0, colors.HexColor("#90A4AE")),
                ("BACKGROUND", (0, 0), (0, 0), colors.HexColor("#ECEFF1")),
                ("LINEBELOW", (0, 0), (0, 0), 0.6, colors.HexColor("#90A4AE")),
                ("TOPPADDING", (0, 0), (-1, 0), 5),
                ("BOTTOMPADDING", (0, 0), (-1, 0), 5),
                ("LEFTPADDING", (0, 0), (-1, -1), 0),
                ("RIGHTPADDING", (0, 0), (-1, -1), 0),
            ]
        )
    )
    return outer


def _data_table(header: List[str], rows: List[List[Any]], widths: List[float], styles: _Styles) -> Table:
    data = [[Paragraph("<b>%s</b>" % _text(column), styles.cell) for column in header]]
    for row in rows:
        data.append([cell if isinstance(cell, Paragraph) else Paragraph(_text(cell), styles.small) for cell in row])
    table = Table(data, colWidths=widths, repeatRows=1, hAlign="LEFT")
    table.setStyle(
        TableStyle(
            [
                ("GRID", (0, 0), (-1, -1), 0.35, colors.HexColor("#CFD8DC")),
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1B263B")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#F7F9FA")]),
                ("LEFTPADDING", (0, 0), (-1, -1), 4),
                ("RIGHTPADDING", (0, 0), (-1, -1), 4),
                ("TOPPADDING", (0, 0), (-1, -1), 3),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
            ]
        )
    )
    return table


def _page_furniture(canvas, doc) -> None:
    canvas.saveState()
    canvas.setFont("Helvetica", 7.5)
    canvas.setFillColor(colors.HexColor("#607D8B"))
    canvas.drawString(20 * mm, 12 * mm, doc._framework_footer)  # noqa: SLF001 - set by build_pdf
    canvas.drawRightString(A4[0] - 20 * mm, 12 * mm, "Page %d" % doc.page)
    canvas.setStrokeColor(colors.HexColor("#CFD8DC"))
    canvas.line(20 * mm, 15 * mm, A4[0] - 20 * mm, 15 * mm)
    canvas.restoreState()


def build_pdf(
    report: Dict[str, Any],
    output_path: str,
    max_table_rows: Optional[int] = None,
    max_detailed: Optional[int] = None,
) -> str:  # noqa: C901 - linear document assembly
    # Limits are arguments, not constants: the defaults show a fraction of the
    # findings on a legacy codebase, and a reader with no way to raise them
    # cannot tell a short report from a short list of problems.
    table_limit = MAX_TABLE_ROWS if max_table_rows is None else max(0, int(max_table_rows))
    detail_limit = MAX_DETAILED_FINDINGS if max_detailed is None else max(0, int(max_detailed))
    if not REPORTLAB_AVAILABLE:
        raise PdfGenerationError(
            "reportlab is not installed, so the PDF report could not be generated (%s). "
            "The PDF is a required deliverable; install reportlab and re-run." % REPORTLAB_IMPORT_ERROR
        )

    styles = _Styles()
    project = report["project"]
    status = report["status"]
    verdict = report["verdict"]
    findings = report["findings"]
    gate = report.get("quality_gate") or {}

    os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)
    doc = SimpleDocTemplate(
        output_path,
        pagesize=A4,
        leftMargin=20 * mm,
        rightMargin=20 * mm,
        topMargin=16 * mm,
        bottomMargin=20 * mm,
        title="Application Security Report",
        author=report["framework"]["name"],
        subject="Security validation report",
    )
    doc._framework_footer = "%s v%s | Phase %s | %s" % (  # noqa: SLF001
        report["framework"]["name"],
        report["framework"]["version"],
        report["framework"]["active_phase"],
        report["generated_at"],
    )

    story: List[Any] = []

    # --- Cover ---------------------------------------------------------------
    story.append(Paragraph("Application Security Report", styles.title))
    story.append(
        Paragraph(
            "%s &mdash; version %s &mdash; Phase %s &mdash; generated %s"
            % (
                _text(report["framework"]["name"]),
                _text(report["framework"]["version"]),
                _text(report["framework"]["active_phase"]),
                _text(report["generated_at"]),
            ),
            styles.subtitle,
        )
    )
    story.append(Spacer(1, 5 * mm))
    story.append(HRFlowable(width="100%", thickness=1.2, color=colors.HexColor("#1B263B")))
    story.append(Spacer(1, 6 * mm))

    # --- Panel 1: deployment result ------------------------------------------
    story.append(
        _status_panel(
            "SECTION A &nbsp;&mdash;&nbsp; APPLICATION DEPLOYMENT RESULT",
            [("BUILD", status["build"]), ("DEPLOYMENT", status["deployment"])],
            styles,
        )
    )
    story.append(Spacer(1, 4 * mm))
    story.append(
        Paragraph(
            "<b>These two results describe delivery only.</b> They say nothing about the security of "
            "the application. A successful deployment is not a security pass.",
            styles.warn,
        )
    )
    story.append(Spacer(1, 5 * mm))
    story.append(HRFlowable(width="100%", thickness=2.0, color=colors.HexColor("#B0BEC5"), dash=(3, 3)))
    story.append(Spacer(1, 5 * mm))

    # --- Panel 2: security result --------------------------------------------
    story.append(
        _status_panel(
            "SECTION B &nbsp;&mdash;&nbsp; APPLICATION SECURITY RESULT",
            [("SECURITY", status["security"]), ("RUNTIME SECURITY", status["runtime_security"])],
            styles,
        )
    )
    story.append(Spacer(1, 4 * mm))
    story.append(
        _kv_table(
            [
                ("Verdict scope", status["verdict_scope"]),
                ("Security coverage complete", "YES" if status["coverage_complete"] else "NO"),
                ("Status independence", status["independence_note"]),
            ],
            styles,
        )
    )
    if not status["coverage_complete"]:
        story.append(Spacer(1, 3 * mm))
        story.append(
            Paragraph(
                "<b>This is not a full security assessment.</b> Security categories listed later in this "
                "report as NOT_VERIFIED or NOT_IMPLEMENTED were not tested. Their absence from the "
                "findings list is not evidence that no such issue exists.",
                styles.warn,
            )
        )

    story.append(PageBreak())

    # --- Project -------------------------------------------------------------
    story.append(Paragraph("1. Project", styles.h1))
    story.append(
        _kv_table(
            [
                ("Project name", project["project_name"]),
                ("Repository", project["repository"]),
                ("Commit", project["commit"]),
                ("Branch", project["branch"]),
                ("Environment", project["environment"]),
                ("Deployment target", project["deployment_target"]),
                ("Deployed URL", project["deployed_url"]),
                ("Pipeline run", project["run_url"]),
            ],
            styles,
        )
    )

    capabilities = report.get("capabilities") or {}
    story.append(Paragraph("2. Detected capabilities", styles.h1))
    story.append(
        _kv_table(
            [
                ("Languages", ", ".join(capabilities.get("languages") or []) or "none detected"),
                ("Frameworks", ", ".join(capabilities.get("frameworks") or []) or "none detected"),
                ("Package managers", ", ".join(capabilities.get("package_manager") or []) or "none detected"),
                ("Docker", capabilities.get("docker")),
                ("Infrastructure as code", capabilities.get("iac")),
                ("Kubernetes", capabilities.get("kubernetes")),
                ("OpenAPI", capabilities.get("openapi")),
                ("Frontend / Backend", "%s / %s" % (capabilities.get("frontend"), capabilities.get("backend"))),
                ("Cloud", capabilities.get("cloud") or "NOT_ESTABLISHED"),
            ],
            styles,
        )
    )

    # --- Verdict -------------------------------------------------------------
    story.append(Paragraph("3. Security verdict", styles.h1))
    fg, bg = _colour_for(status["security"])
    verdict_table = Table(
        [[Paragraph('<font color="%s"><b>SECURITY = %s</b></font>' % (_hex(fg), _text(status["security"])),
                    styles.panel_value)]],
        colWidths=[170 * mm],
        hAlign="LEFT",
    )
    verdict_table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, -1), bg),
                ("BOX", (0, 0), (-1, -1), 1.0, fg),
                ("TOPPADDING", (0, 0), (-1, -1), 7),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 7),
            ]
        )
    )
    story.append(verdict_table)
    story.append(Spacer(1, 3 * mm))
    for reason in verdict["rationale"]:
        story.append(Paragraph("&bull; %s" % _text(reason), styles.body))
    story.append(Spacer(1, 2 * mm))

    if verdict["threshold_breaches"]:
        story.append(Paragraph("Policy threshold breaches", styles.h2))
        story.append(
            _data_table(
                ["Severity", "Open findings", "Permitted"],
                [[b["severity"], b["count"], b["threshold"]] for b in verdict["threshold_breaches"]],
                [50 * mm, 60 * mm, 60 * mm],
                styles,
            )
        )

    # --- Quality gate --------------------------------------------------------
    story.append(Paragraph("4. SonarQube status", styles.h1))
    story.append(
        _kv_table(
            [
                ("Quality gate status", gate.get("status", "UNKNOWN")),
                ("Conditions evaluated", len(gate.get("conditions") or [])),
                ("Failing conditions", len(gate.get("failing_conditions") or [])),
            ],
            styles,
        )
    )
    if gate.get("conditions"):
        story.append(Spacer(1, 3 * mm))
        story.append(
            _data_table(
                ["Metric", "Comparator", "Threshold", "Actual", "Status"],
                [
                    [c.get("metric"), c.get("comparator"), c.get("threshold"), c.get("actual"), c.get("status")]
                    for c in gate["conditions"]
                ],
                [58 * mm, 28 * mm, 26 * mm, 28 * mm, 30 * mm],
                styles,
            )
        )
    if gate.get("status") == "UNKNOWN":
        story.append(Spacer(1, 2 * mm))
        story.append(
            Paragraph(
                "The quality gate status could not be retrieved. It is recorded as UNKNOWN and is "
                "never interpreted as passing.",
                styles.warn,
            )
        )

    # --- Counts --------------------------------------------------------------
    story.append(Paragraph("5. Finding counts", styles.h1))
    story.append(
        _kv_table(
            [("Total findings collected", findings["total"]), ("Open findings", findings["open"])],
            styles,
        )
    )
    story.append(Spacer(1, 3 * mm))
    story.append(Paragraph("Severity breakdown", styles.h2))
    severity_rows = []
    for severity, count in findings["severity_breakdown"].items():
        security_count = findings["security_severity_breakdown"].get(severity, 0)
        severity_rows.append(
            [
                Paragraph(
                    '<font color="%s"><b>%s</b></font>'
                    % (SEVERITY_COLOURS.get(severity, "#212121"), _text(severity)),
                    styles.small,
                ),
                count,
                security_count,
            ]
        )
    story.append(
        _data_table(
            ["Severity", "All open findings", "Security-relevant open findings"],
            severity_rows,
            [45 * mm, 60 * mm, 65 * mm],
            styles,
        )
    )

    # --- Finding aggregation (lifecycle) --------------------------------------
    lifecycle = report.get("lifecycle") or {}
    counts = lifecycle.get("counts") or {}
    story.append(Paragraph("5.1 Finding aggregation (new / existing / fixed)", styles.h1))
    story.append(
        _data_table(
            ["State", "Count"],
            [
                ["New", counts.get("new", 0)],
                ["Existing / still open", counts.get("existing", 0)],
                ["Fixed since baseline", counts.get("fixed", 0)],
                ["False positive (suppressed)", counts.get("false_positive", 0)],
                ["Accepted risk (suppressed)", counts.get("accepted_risk", 0)],
                ["EXPIRED suppression (NOT suppressed)", counts.get("expired_exceptions", 0)],
                ["Unknown (scanner did not run)", counts.get("unknown", 0)],
            ],
            [95 * mm, 75 * mm],
            styles,
        )
    )
    story.append(Spacer(1, 3 * mm))
    story.append(
        _kv_table(
            [
                ("Baseline available", "YES" if lifecycle.get("baseline_available") else "NO"),
                ("Baseline source", lifecycle.get("baseline_source") or "none"),
                ("Baseline findings", lifecycle.get("baseline_finding_count", 0)),
                ("Exceptions loaded", lifecycle.get("exceptions_loaded", 0)),
            ],
            styles,
        )
    )
    for note in lifecycle.get("notes") or []:
        story.append(Spacer(1, 2 * mm))
        story.append(Paragraph("&bull; %s" % _text(note), styles.note))
    if lifecycle.get("expired_exception_details"):
        story.append(Spacer(1, 3 * mm))
        story.append(Paragraph(
            "<b>Expired suppressions — these findings are NOT suppressed and count against policy.</b>",
            styles.warn))
        story.append(Spacer(1, 2 * mm))
        story.append(
            _data_table(
                ["Fingerprint", "Kind", "Owner", "Expiry", "Why"],
                [
                    [str(i.get("fingerprint", ""))[:14], i.get("kind"), i.get("owner") or "-",
                     i.get("expires") or "none", i.get("why")]
                    for i in lifecycle["expired_exception_details"]
                ],
                [30 * mm, 26 * mm, 26 * mm, 26 * mm, 62 * mm],
                styles,
            )
        )

    # --- Findings ------------------------------------------------------------
    story.append(PageBreak())
    story.append(Paragraph("6. Findings", styles.h1))
    items = findings["items"]
    if not items:
        story.append(
            Paragraph(
                "No findings were returned by the scanners that executed in this run. This is not a "
                "statement that the application is secure &mdash; see sections 8 to 10 for the controls "
                "that did not execute.",
                styles.body,
            )
        )
    else:
        rows = []
        for index, finding in enumerate(items[:table_limit], 1):
            rows.append(
                [
                    index,
                    Paragraph(
                        '<font color="%s"><b>%s</b></font>'
                        % (SEVERITY_COLOURS.get(finding["severity"], "#212121"), _text(finding["severity"])),
                        styles.small,
                    ),
                    Paragraph(_text(finding.get("lifecycle", "-")), styles.small),
                    Paragraph(_text(finding.get("tool")), styles.small),
                    Paragraph(_text(finding["file"], 60) or "-", styles.small),
                    finding["line"] or "-",
                    Paragraph(_text(finding["description"], 110), styles.small),
                ]
            )
        story.append(
            _data_table(
                ["#", "Severity", "State", "Tool", "File", "Line", "Description"],
                rows,
                [8 * mm, 18 * mm, 18 * mm, 22 * mm, 40 * mm, 10 * mm, 54 * mm],
                styles,
            )
        )
        if len(items) > table_limit:
            story.append(Spacer(1, 2 * mm))
            story.append(
                Paragraph(
                    "Table truncated to %d of %d findings. The complete, untruncated list is in "
                    "findings.csv (one row per finding, with an owner column to fill in) and in "
                    "final-report.json."
                    % (table_limit, len(items)),
                    styles.note,
                )
            )

        story.append(Paragraph("6.1 Finding detail", styles.h1))
        for index, finding in enumerate(items[:detail_limit], 1):
            block = [
                Paragraph(
                    "%d. <b>[%s]</b> %s" % (index, _text(finding["severity"]), _text(finding["description"], 130)),
                    styles.h2,
                ),
                _kv_table(
                    [
                        ("Fingerprint", finding["fingerprint"]),
                        ("Lifecycle state", finding.get("lifecycle", "")),
                        ("Tool / rule", "%s / %s" % (finding["tool"], finding.get("rule") or "n/a")),
                        ("Category", finding["category"]),
                        ("Severity", finding["severity"]),
                        ("CWE", finding["cwe"] or "not mapped"),
                        ("OWASP", finding["owasp"] or "not mapped"),
                        ("File", finding["file"] or "n/a"),
                        ("Line", finding["line"] or "n/a"),
                        ("Endpoint", finding["endpoint"] or "n/a"),
                        ("Status", finding["status"]),
                        ("Evidence", finding["evidence"]),
                        ("Impact", finding["impact"]),
                        ("Remediation", finding["remediation"]),
                        ("First / last seen", "%s / %s" % (finding["first_seen"], finding["last_seen"])),
                        ("Commit / branch", "%s / %s" % (finding["commit"], finding["branch"])),
                    ],
                    styles,
                ),
                Spacer(1, 3 * mm),
            ]
            story.append(KeepTogether(block))
        if len(items) > detail_limit:
            story.append(
                Paragraph(
                    "Detailed entries truncated to the %d most severe of %d findings. Every "
                    "finding, with the same fields, is in findings.csv."
                    % (detail_limit, len(items)),
                    styles.note,
                )
            )

    # --- Scanners ------------------------------------------------------------
    story.append(PageBreak())
    story.append(Paragraph("7. Scanner execution", styles.h1))
    scanner_rows = []
    for scanner in report["scanners"]:
        fg, _bg = _colour_for(scanner["status"])
        scanner_rows.append(
            [
                scanner["tool"],
                scanner["category_key"],
                Paragraph('<font color="%s"><b>%s</b></font>' % (_hex(fg), _text(scanner["status"])), styles.small),
                len(scanner["errors"]),
                len(scanner["warnings"]),
            ]
        )
    story.append(
        _data_table(
            ["Tool", "Category", "Status", "Errors", "Warnings"],
            scanner_rows or [["none", "-", "-", 0, 0]],
            [36 * mm, 52 * mm, 32 * mm, 25 * mm, 25 * mm],
            styles,
        )
    )

    failures = [(s["tool"], e) for s in report["scanners"] for e in s["errors"]]
    story.append(Paragraph("7.1 Scanner failures", styles.h2))
    if failures:
        for tool, error in failures:
            story.append(Paragraph("&bull; <b>%s</b>: %s" % (_text(tool), _text(error)), styles.body))
    else:
        story.append(Paragraph("No scanner reported an error in this run.", styles.body))

    warnings = [(s["tool"], w) for s in report["scanners"] for w in s["warnings"]]
    if warnings:
        story.append(Paragraph("7.2 Scanner warnings", styles.h2))
        for tool, warning in warnings:
            story.append(Paragraph("&bull; <b>%s</b>: %s" % (_text(tool), _text(warning)), styles.body))

    # --- File coverage -------------------------------------------------------
    # Section 7 says which CONTROLS ran. This says which FILES they read. A
    # scanner that completed over half a repository reports identically to one
    # that read all of it, so without this the reader cannot tell the difference
    # between "nothing was found" and "most of it was never opened".
    story.append(Paragraph("7.3 File coverage", styles.h2))
    coverage = report.get("file_coverage") or {}
    if not coverage.get("available"):
        story.append(Paragraph(
            "<b>File-level coverage is NOT ESTABLISHED for this run.</b> %s This is not a "
            "statement that every file was analysed."
            % _text(coverage.get("reason", "the census did not run")),
            styles.warn,
        ))
    else:
        story.append(
            _data_table(
                ["Measure", "Value"],
                [
                    ["Code files in workspace", coverage.get("code_files", 0)],
                    ["Read by a completed scanner", coverage.get("code_files_analysed", 0)],
                    ["NOT read by any scanner", coverage.get("code_files_not_analysed", 0)],
                    ["Coverage", "%.1f%%" % coverage.get("coverage_percent", 0.0)],
                ],
                [90 * mm, 80 * mm],
                styles,
            )
        )
        statement = _text(coverage.get("statement", ""))
        story.append(Paragraph(statement, styles.warn if not coverage.get("complete") else styles.body))
        not_analysed = coverage.get("not_analysed") or {}
        if not_analysed:
            rows = [[bucket, detail.get("count", 0)] for bucket, detail in not_analysed.items()]
            story.append(Paragraph("Why files were not analysed", styles.h2))
            story.append(_data_table(["Reason", "Files"], rows, [120 * mm, 50 * mm], styles))
            story.append(Paragraph(
                "The individual files are listed in report.md and in final-report.json.",
                styles.small,
            ))
        for note in (coverage.get("notes") or [])[:6]:
            story.append(Paragraph("&bull; %s" % _text(note), styles.small))

    # --- Category matrix -----------------------------------------------------
    story.append(Paragraph("8. Security category matrix", styles.h1))
    story.append(
        Paragraph(
            "Every category resolves to exactly one status. Nothing is skipped silently.", styles.note
        )
    )
    story.append(Spacer(1, 2 * mm))
    category_rows = []
    for category in report["categories"]:
        fg, _bg = _colour_for(category["status"])
        category_rows.append(
            [
                Paragraph(_text(category["title"]), styles.small),
                category["phase"],
                Paragraph('<font color="%s"><b>%s</b></font>' % (_hex(fg), _text(category["status"])), styles.small),
                category["finding_count"],
                Paragraph(_text(category["reason"], 150), styles.small),
            ]
        )
    story.append(
        _data_table(
            ["Category", "Phase", "Status", "Findings", "Reason"],
            category_rows,
            [40 * mm, 13 * mm, 27 * mm, 17 * mm, 73 * mm],
            styles,
        )
    )

    summary = report["category_summary"]

    story.append(Paragraph("9. Categories NOT TESTED in this run", styles.h1))
    not_verified = summary.get("not_verified") or []
    if not_verified:
        for entry in not_verified:
            story.append(Paragraph("&bull; <b>%s</b> &mdash; %s" % (_text(entry["title"]), _text(entry["reason"])), styles.body))
            for note in entry.get("notes") or []:
                story.append(Paragraph("&nbsp;&nbsp;&ndash; %s" % _text(note), styles.note))
    else:
        story.append(Paragraph("None.", styles.body))

    story.append(Paragraph("10. Categories NOT IMPLEMENTED yet", styles.h1))
    not_implemented = summary.get("not_implemented") or []
    if not_implemented:
        story.append(
            _data_table(
                ["Category", "Planned phase", "Tools", "Status"],
                [
                    [entry["title"], entry["phase"], ", ".join(entry.get("tools") or []), entry["status"]]
                    for entry in not_implemented
                ],
                [58 * mm, 24 * mm, 48 * mm, 40 * mm],
                styles,
            )
        )
    else:
        story.append(Paragraph("None.", styles.body))

    not_applicable = summary.get("not_applicable") or []
    story.append(Paragraph("11. Categories NOT APPLICABLE to this project", styles.h1))
    if not_applicable:
        for entry in not_applicable:
            story.append(Paragraph("&bull; <b>%s</b> &mdash; %s" % (_text(entry["title"]), _text(entry["reason"])), styles.body))
    else:
        story.append(Paragraph("None.", styles.body))

    # --- Limitations ---------------------------------------------------------
    story.append(PageBreak())
    story.append(Paragraph("12. Automation limitations", styles.h1))
    for limitation in report["limitations"]:
        story.append(
            Paragraph("&bull; <b>%s</b>: %s" % (_text(limitation["code"]), _text(limitation["detail"])), styles.body)
        )

    story.append(Paragraph("13. Manual security controls &mdash; NOT tested by any scanner", styles.h1))
    story.append(
        _data_table(
            ["Control", "Status", "Why automation cannot cover it"],
            [
                [
                    Paragraph(_text(control["title"]), styles.small),
                    Paragraph(_text(control["status"]), styles.small),
                    Paragraph(_text(control["why_not_automatable"]), styles.small),
                ]
                for control in report["manual_controls"]
            ],
            [45 * mm, 32 * mm, 93 * mm],
            styles,
        )
    )

    # --- Final verdict -------------------------------------------------------
    story.append(Paragraph("14. Final security verdict", styles.h1))
    story.append(
        _status_panel(
            "FINAL STATUS &nbsp;&mdash;&nbsp; FOUR INDEPENDENT RESULTS",
            [
                ("BUILD", status["build"]),
                ("DEPLOYMENT", status["deployment"]),
                ("SECURITY", status["security"]),
                ("RUNTIME", status["runtime_security"]),
            ],
            styles,
        )
    )
    story.append(Spacer(1, 4 * mm))
    story.append(Paragraph("Scope of this verdict: <b>%s</b>" % _text(status["verdict_scope"]), styles.body))
    story.append(Spacer(1, 2 * mm))
    story.append(
        Paragraph(
            "A deployment result never implies a security result. This report asserts security only for "
            "the controls listed as PASS or FAILED in the category matrix.",
            styles.warn,
        )
    )

    doc.build(story, onFirstPage=_page_furniture, onLaterPages=_page_furniture)
    return output_path


def write_pdf(
    report: Dict[str, Any],
    output_dir: str,
    filename: str = "security-report.pdf",
    max_table_rows: Optional[int] = None,
    max_detailed: Optional[int] = None,
) -> str:
    os.makedirs(output_dir, exist_ok=True)
    return build_pdf(
        report, os.path.join(output_dir, filename),
        max_table_rows=max_table_rows, max_detailed=max_detailed,
    )
