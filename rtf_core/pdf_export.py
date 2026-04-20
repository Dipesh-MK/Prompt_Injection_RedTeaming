"""
rtf_core/pdf_export.py
----------------------
Generates a professional PDF security report using fpdf2.
No external binaries required — pure Python.

Usage:
    from rtf_core.pdf_export import generate_pdf
    pdf_bytes = generate_pdf(report_dict)
    st.download_button("Download PDF", pdf_bytes, "report.pdf", "application/pdf")
"""

import io
import datetime
from fpdf import FPDF, XPos, YPos

def sanitize(text: str) -> str:
    if not isinstance(text, str):
        text = str(text)
    return text.encode("latin-1", "ignore").decode("latin-1")


# ── Colour palette ─────────────────────────────────────────────────────────────
RED    = (230, 57,  70)
DARK   = (13,  17,  23)
GRAY   = (100, 110, 120)
WHITE  = (230, 237, 243)
GREEN  = (46,  160, 67)
ORANGE = (253, 126, 20)
YELLOW = (255, 193, 7)

SEV_COLORS = {
    "Info":     (108, 117, 125),
    "Low":      (23,  162, 184),
    "Medium":   (255, 193, 7),
    "High":     (253, 126, 20),
    "Critical": (220, 53,  69),
}


class RTFReport(FPDF):
    def header(self):
        # Red banner bar
        self.set_fill_color(*RED)
        self.rect(0, 0, 210, 12, "F")
        self.set_font("Helvetica", "B", 9)
        self.set_text_color(*WHITE)
        self.set_xy(10, 2)
        self.cell(0, 8, "REDTEAMFORGE - CONFIDENTIAL SECURITY REPORT", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        self.ln(6)

    def footer(self):
        self.set_y(-15)
        self.set_font("Helvetica", "", 7)
        self.set_text_color(*GRAY)
        ts = datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")
        self.cell(0, 10, f"Generated {ts}  |  Page {self.page_no()}", align="C")


def _risk_color(score: int) -> tuple:
    if score >= 75:  return RED
    if score >= 50:  return ORANGE
    if score >= 25:  return YELLOW
    return GREEN


def generate_pdf(report: dict) -> bytes:
    """
    Generate a styled PDF from a report dict (from report_builder.build_report).
    Returns raw bytes suitable for st.download_button.
    """
    pdf = RTFReport(orientation="P", unit="mm", format="A4")
    pdf.set_auto_page_break(auto=True, margin=20)
    pdf.add_page()

    risk_score = report.get("risk_score", 0)
    vuln_count = report.get("vuln_count", 0)
    total      = report.get("total_probes", 0)

    # ── Title ─────────────────────────────────────────────────────────────────
    pdf.set_font("Helvetica", "B", 22)
    pdf.set_text_color(*DARK)
    pdf.cell(0, 12, "LLM Security Assessment Report", align="C", new_x=XPos.LMARGIN, new_y=YPos.NEXT)

    pdf.set_font("Helvetica", "", 10)
    pdf.set_text_color(*GRAY)
    pdf.cell(0, 6, sanitize(report.get("session_name", "")), align="C", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.ln(4)

    # ── Risk Score banner ─────────────────────────────────────────────────────
    r, g, b = _risk_color(risk_score)
    pdf.set_fill_color(r, g, b)
    pdf.set_text_color(*WHITE)
    pdf.set_font("Helvetica", "B", 36)
    pdf.rect(10, pdf.get_y(), 190, 22, "F")
    pdf.set_xy(10, pdf.get_y() + 2)
    pdf.cell(190, 18, f"Overall Risk Score: {risk_score}/100", align="C",
             new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.ln(6)

    # ── Session Metadata ──────────────────────────────────────────────────────
    pdf.set_font("Helvetica", "B", 13)
    pdf.set_text_color(*DARK)
    pdf.cell(0, 8, "Session Details", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.set_draw_color(*RED); pdf.line(10, pdf.get_y(), 200, pdf.get_y()); pdf.ln(2)

    details = [
        ("Target Webhook",  sanitize(report.get("webhook_url", "N/A"))),
        ("Total Probes",    str(total)),
        ("Vulnerabilities", f"{vuln_count} of {total} probes triggered a finding"),
        ("Session Start",   report.get("start_time", "")[:19].replace("T", "  ")),
        ("Session End",     report.get("end_time",   "")[:19].replace("T", "  ")),
    ]
    pdf.set_font("Helvetica", "", 9)
    for label, value in details:
        pdf.set_text_color(*GRAY)
        pdf.cell(45, 6, label + ":", new_x=XPos.RIGHT, new_y=YPos.LAST)
        pdf.set_text_color(*DARK)
        pdf.cell(0, 6, value, new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.ln(4)

    # ── Severity Breakdown ────────────────────────────────────────────────────
    pdf.set_font("Helvetica", "B", 13)
    pdf.set_text_color(*DARK)
    pdf.cell(0, 8, "Severity Distribution", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.set_draw_color(*RED); pdf.line(10, pdf.get_y(), 200, pdf.get_y()); pdf.ln(2)

    breakdown = report.get("sev_breakdown", {})
    col_w = 35
    for label, count in breakdown.items():
        color = SEV_COLORS.get(label, (100, 100, 100))
        pdf.set_fill_color(*color)
        pdf.set_text_color(*WHITE)
        pdf.set_font("Helvetica", "B", 9)
        pdf.cell(col_w, 7, f"{label}: {count}", fill=True,
                 border=0, align="C", new_x=XPos.RIGHT, new_y=YPos.LAST)
        pdf.cell(2, 7, "", new_x=XPos.RIGHT, new_y=YPos.LAST)
    pdf.ln(12)

    # ── Weak Areas ────────────────────────────────────────────────────────────
    wa_freq = report.get("weak_area_freq", {})
    if wa_freq:
        pdf.set_font("Helvetica", "B", 13)
        pdf.set_text_color(*DARK)
        pdf.cell(0, 8, "Identified Weak Areas", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        pdf.set_draw_color(*RED); pdf.line(10, pdf.get_y(), 200, pdf.get_y()); pdf.ln(2)
        pdf.set_font("Helvetica", "", 9)
        for area, cnt in wa_freq.items():
            pdf.set_text_color(*DARK)
            pdf.cell(150, 5, f"  * {sanitize(area)}", new_x=XPos.RIGHT, new_y=YPos.LAST)
            pdf.set_text_color(*RED)
            pdf.cell(0, 5, f"{cnt} finding(s)", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        pdf.ln(4)

    # ── Top Vulnerabilities ───────────────────────────────────────────────────
    top_vulns = report.get("top_vulns", [])
    if top_vulns:
        pdf.set_font("Helvetica", "B", 13)
        pdf.set_text_color(*DARK)
        pdf.cell(0, 8, f"Top {len(top_vulns)} Vulnerabilities (Evidence)", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        pdf.set_draw_color(*RED); pdf.line(10, pdf.get_y(), 200, pdf.get_y()); pdf.ln(2)

        for i, v in enumerate(top_vulns, 1):
            sev_color = SEV_COLORS.get(v.get("sev_label", "Info"), (100, 100, 100))
            # Severity badge
            pdf.set_fill_color(*sev_color)
            pdf.set_text_color(*WHITE)
            pdf.set_font("Helvetica", "B", 8)
            pdf.cell(25, 5, sanitize(v.get("sev_label", "")), fill=True, align="C",
                     new_x=XPos.RIGHT, new_y=YPos.LAST)
            pdf.set_text_color(*DARK)
            pdf.set_font("Helvetica", "B", 9)
            pdf.cell(0, 5, f"  #{i} - {sanitize(v.get('weak_area', 'Unknown'))}",
                     new_x=XPos.LMARGIN, new_y=YPos.NEXT)

            # Probe
            pdf.set_font("Helvetica", "I", 8)
            pdf.set_text_color(*GRAY)
            pdf.cell(15, 5, "Probe:", new_x=XPos.RIGHT, new_y=YPos.LAST)
            pdf.set_font("Helvetica", "", 8)
            pdf.set_text_color(*DARK)
            probe_snip = sanitize(v.get("probe", ""))[:120] + ("..." if len(v.get("probe","")) > 120 else "")
            pdf.multi_cell(0, 5, probe_snip, new_x=XPos.LMARGIN, new_y=YPos.NEXT)

            # Insight
            pdf.set_font("Helvetica", "I", 8)
            pdf.set_text_color(*GRAY)
            pdf.cell(15, 5, "Finding:", new_x=XPos.RIGHT, new_y=YPos.LAST)
            pdf.set_font("Helvetica", "", 8)
            pdf.set_text_color(*DARK)
            pdf.multi_cell(0, 5, sanitize(v.get("insight", ""))[:200], new_x=XPos.LMARGIN, new_y=YPos.NEXT)
            
            # Tools (if any)
            if v.get("type") == "tool_abuse" and v.get("tools") != "none":
                pdf.set_font("Helvetica", "I", 8)
                pdf.set_text_color(*GRAY)
                pdf.cell(15, 5, "Tools:", new_x=XPos.RIGHT, new_y=YPos.LAST)
                pdf.set_font("Helvetica", "B", 8)
                pdf.set_text_color(*ORANGE)
                pdf.multi_cell(0, 5, sanitize(v.get("tools", "")), new_x=XPos.LMARGIN, new_y=YPos.NEXT)

            pdf.ln(2)

    # ── Recommendations ───────────────────────────────────────────────────────
    pdf.add_page()
    pdf.set_font("Helvetica", "B", 13)
    pdf.set_text_color(*DARK)
    pdf.cell(0, 8, "Recommendations", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.set_draw_color(*RED); pdf.line(10, pdf.get_y(), 200, pdf.get_y()); pdf.ln(2)

    recs = [
        "Implement a layered input sanitization pipeline before system prompt exposure.",
        "Add explicit output filtering for all categories in the taxonomy taxonomy.",
        "Introduce role-based guardrails that cannot be overridden by user messages.",
        "Conduct regular red-team sessions after every major model update or prompt change.",
        "Monitor production traffic for patterns matching discovered attack strategies.",
        "Consider adding a secondary safety classifier (e.g., LlamaGuard) as a post-processor.",
    ]
    pdf.set_font("Helvetica", "", 9)
    pdf.set_text_color(*DARK)
    for r_text in recs:
        pdf.cell(0, 6, f"  *  {r_text}", new_x=XPos.LMARGIN, new_y=YPos.NEXT)

    # ── Footer note ───────────────────────────────────────────────────────────
    pdf.ln(8)
    pdf.set_font("Helvetica", "I", 8)
    pdf.set_text_color(*GRAY)
    pdf.multi_cell(0, 5,
        "This report was generated automatically by RedTeamForge. "
        "All findings should be reviewed by a qualified security professional before remediation.",
        new_x=XPos.LMARGIN, new_y=YPos.NEXT)

    # Return bytes
    return bytes(pdf.output())
