from rich import box
from rich.console import Group
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from patchday.dates import parse_date
from patchday.vulns import plain_text


def normalize_text(value):
    return plain_text(value)


def severity_text(severity):
    styles = {
        "Critical": "bold red",
        "Important": "bold yellow",
        "Moderate": "green",
        "Low": "dim green",
    }
    return Text(severity, style=styles.get(severity, "dim"))


def first_present(mapping, keys):
    for key in keys:
        value = mapping.get(key)
        if value not in (None, "", []):
            return value
    return None


def add_detail_row(table, label, value):
    if value not in (None, "", []):
        table.add_row(label, str(value))


def cvss_text(vuln, details=None):
    details = details or {}
    cvss = vuln["cvss"] if vuln["cvss"] is not None else details.get("cvss")
    return "-" if cvss is None else f"{float(cvss):.1f}"


def published_text(vuln):
    published = parse_date(vuln["published"])
    return published.isoformat() if published else "-"


def detail_renderable(vuln, *, details=None, loading=False, error=None):
    details = details or {}
    raw = vuln.get("raw", {})
    title = Text(vuln["title"], style="bold")
    summary = Text.assemble(
        (vuln["cve"], "bold cyan"),
        "  ",
        severity_text(vuln["severity"]),
        "  ",
        ("CVSS=", "bold"),
        cvss_text(vuln, details),
    )

    detail = Table(box=box.SIMPLE, show_header=False, expand=True)
    detail.add_column("Field", style="bold", no_wrap=True)
    detail.add_column("Value", overflow="fold")
    add_detail_row(detail, "Published", published_text(vuln))
    add_detail_row(detail, "Release", vuln.get("release"))
    add_detail_row(detail, "CVSS vector", details.get("cvss_vector"))
    add_detail_row(
        detail,
        "Impact",
        first_present(raw, ("impact", "impactDescription", "impactType")),
    )
    add_detail_row(
        detail,
        "Max severity",
        first_present(raw, ("maxSeverity", "severity")),
    )
    add_detail_row(
        detail,
        "Exploitability",
        details.get("exploitability")
        or first_present(raw, ("exploitability", "exploitation", "exploitStatus")),
    )
    add_detail_row(detail, "Publicly disclosed", details.get("publicly_disclosed"))
    add_detail_row(detail, "Exploited", details.get("exploited"))
    add_detail_row(
        detail,
        "Affected product",
        first_present(raw, ("productName", "product", "productFamilyName")),
    )
    add_detail_row(detail, "MSRC published", details.get("published"))
    add_detail_row(detail, "MSRC modified", details.get("last_modified"))
    add_detail_row(detail, "CWE", ", ".join(details.get("cwe", [])))

    pieces = [summary, title, detail]

    description = details.get("description")
    description_key = normalize_text(description)
    if description:
        pieces.append(Text("MSRC description", style="bold"))
        pieces.append(Text(description))
    elif loading:
        pieces.append(Text("Loading MSRC details...", style="yellow"))
    elif error:
        pieces.append(Text(f"MSRC detail error: {error}", style="red"))
    else:
        pieces.append(Text("Press Enter to load MSRC details.", style="dim"))

    articles = details.get("articles", [])
    for article in articles:
        article_text = plain_text(
            article.get("unformattedDescription") or article.get("description")
        )
        if not article_text:
            continue
        if normalize_text(article_text) == description_key:
            continue
        pieces.append(Text(""))
        pieces.append(
            Text(article.get("title") or article.get("articleType") or "Article", style="bold")
        )
        pieces.append(Text(article_text))

    references = details.get("references", [])
    if references:
        refs = Table(box=box.SIMPLE, show_header=False, expand=True)
        refs.add_column("References", style="bold", no_wrap=True)
        refs.add_column("URL", overflow="fold")
        for index, url in enumerate(references, start=1):
            refs.add_row(str(index), url)
        pieces.append(refs)

    return Panel(Group(*pieces), title="Details", border_style="cyan")
