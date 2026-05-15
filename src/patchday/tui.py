from textual import work
from textual.app import App, ComposeResult
from textual.containers import Horizontal, Vertical
from textual.widgets import DataTable, Footer, Header, Static

from rich.panel import Panel

from patchday.msrc import DEFAULT_TIMEOUT, make_session, msrc_details
from patchday.rendering import (
    cvss_text,
    detail_renderable,
    published_text,
    severity_text,
)
from patchday.theme import TOKYO_NIGHT, rich_style, themed_css
from patchday.vulns import filter_vulns


class PatchdayApp(App):
    TITLE = "Patchday"

    CSS = themed_css("""
    Screen {
        background: @bg@;
        color: @fg@;
    }

    Header {
        background: @bg_dark@;
        color: @fg@;
    }

    Footer {
        background: @bg_dark@;
        color: @fg_muted@;
    }

    #summary {
        height: 3;
        padding: 0 1;
        content-align: left middle;
        background: @bg_highlight@;
        color: @fg@;
    }

    #body {
        height: 1fr;
    }

    #list-pane {
        width: 58%;
        min-width: 60;
    }

    #detail-pane {
        width: 1fr;
        min-width: 42;
        padding: 0 1;
    }

    DataTable {
        height: 1fr;
        background: @bg@;
        color: @fg@;
        scrollbar-background: @bg_dark@;
        scrollbar-color: @border@;
        scrollbar-color-hover: @blue@;
        scrollbar-color-active: @cyan@;

        & > .datatable--header {
            background: @bg_dark@;
            color: @blue@;
            text-style: bold;
        }

        & > .datatable--even-row {
            background: @bg_dark@;
        }

        & > .datatable--cursor {
            background: @bg_highlight@;
            color: @fg@;
        }

        &:focus > .datatable--cursor {
            background: @bg_highlight@;
            text-style: bold;
        }
    }

    #details {
        height: 1fr;
    }
    """)

    BINDINGS = [
        ("enter", "load_details", "Load details"),
        ("y", "copy_cve", "Copy CVE"),
        ("r", "refresh_details", "Refresh details"),
        ("q", "quit", "Quit"),
    ]

    def __init__(
        self,
        *,
        vulns,
        release,
        start_date,
        end_date,
        generated_at,
        include_all,
    ):
        super().__init__()
        self.vulns = filter_vulns(vulns, include_all)
        self.vulns_by_cve = {vuln["cve"]: vuln for vuln in self.vulns}
        self.release = release
        self.start_date = start_date
        self.end_date = end_date
        self.generated_at = generated_at
        self.detail_cache = {}
        self.selected_cve = self.vulns[0]["cve"] if self.vulns else None

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        yield Static(self.summary_text(), id="summary")
        with Horizontal(id="body"):
            with Vertical(id="list-pane"):
                yield DataTable(id="cves", zebra_stripes=True)
            with Vertical(id="detail-pane"):
                yield Static(id="details")
        yield Footer()

    def on_mount(self):
        table = self.query_one("#cves", DataTable)
        table.cursor_type = "row"
        table.add_columns("CVE", "Severity", "CVSS", "Published", "Title")
        for vuln in self.vulns:
            table.add_row(
                vuln["cve"],
                severity_text(vuln["severity"]),
                cvss_text(vuln),
                published_text(vuln),
                vuln["title"],
                key=vuln["cve"],
            )
        table.focus()
        self.update_detail()

    def summary_text(self):
        window = (
            f"{self.start_date.isoformat()} to {self.end_date.isoformat()}"
            if self.end_date
            else self.start_date.isoformat()
        )
        return (
            f"[bold]patchday[/bold]  "
            f"[{TOKYO_NIGHT['cyan']}]{self.release}[/]  "
            f"window=[{TOKYO_NIGHT['cyan']}]{window}[/]  "
            f"shown=[bold]{len(self.vulns)}[/bold]  "
            f"generated=[{TOKYO_NIGHT['comment']}]{self.generated_at.strftime('%Y-%m-%d %H:%M UTC')}[/]"
        )

    def selected_vuln(self):
        if self.selected_cve is None:
            return None
        return self.vulns_by_cve.get(self.selected_cve)

    def update_detail(self, *, loading=False, error=None):
        detail = self.query_one("#details", Static)
        vuln = self.selected_vuln()
        if vuln is None:
            detail.update(
                Panel(
                    (
                        f"No CVEs found for {self.release}.\n\n"
                        "Microsoft's current feed did not return records for "
                        "this release."
                    ),
                    title="Details",
                    border_style=rich_style("yellow"),
                )
            )
            return
        detail.update(
            detail_renderable(
                vuln,
                details=self.detail_cache.get(vuln["cve"]),
                loading=loading,
                error=error,
            )
        )

    def on_data_table_row_highlighted(self, event):
        row_key = getattr(event.row_key, "value", str(event.row_key))
        if row_key in self.vulns_by_cve:
            self.selected_cve = row_key
            self.update_detail()

    def on_data_table_row_selected(self, event):
        row_key = getattr(event.row_key, "value", str(event.row_key))
        if row_key in self.vulns_by_cve:
            self.selected_cve = row_key
            self.action_load_details()

    def action_load_details(self):
        vuln = self.selected_vuln()
        if vuln is None:
            return
        if vuln["cve"] in self.detail_cache:
            self.update_detail()
            return
        self.update_detail(loading=True)
        self.fetch_details(vuln["cve"])

    @work(thread=True, exclusive=True)
    def fetch_details(self, cve):
        try:
            details = msrc_details(
                cve,
                session=make_session(),
                timeout=DEFAULT_TIMEOUT,
                verify_tls=True,
            )
        except RuntimeError as exc:
            self.call_from_thread(self.apply_details, cve, None, str(exc))
            return
        self.call_from_thread(self.apply_details, cve, details, None)

    def apply_details(self, cve, details, error):
        vuln = self.vulns_by_cve.get(cve)
        if vuln is None:
            return
        if error:
            if self.selected_cve == cve:
                self.update_detail(error=error)
            return
        if vuln["cvss"] is None and details.get("cvss") is not None:
            vuln["cvss"] = details["cvss"]
        self.detail_cache[cve] = details
        if self.selected_cve == cve:
            self.update_detail()

    def action_refresh_details(self):
        vuln = self.selected_vuln()
        if vuln is None:
            return
        self.detail_cache.pop(vuln["cve"], None)
        self.action_load_details()

    def action_copy_cve(self):
        vuln = self.selected_vuln()
        if vuln is None:
            self.notify("No CVE selected.", severity="warning")
            return
        self.copy_to_clipboard(vuln["cve"])
        self.notify(f"Copied {vuln['cve']} to clipboard.")


def render_tui(
    vulns,
    *,
    generated_at,
    release,
    start_date,
    end_date,
    include_all,
):
    PatchdayApp(
        vulns=vulns,
        release=release,
        start_date=start_date,
        end_date=end_date,
        generated_at=generated_at,
        include_all=include_all,
    ).run()
