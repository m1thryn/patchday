# Patchday

Patchday is a terminal UI for browsing Microsoft Patch Tuesday CVEs. It shows a
compact CVE list, opens MSRC details on demand, and emits enriched JSON for
automation.

This project was created with assistance from LLMs including Codex and Claude.

## Install

```sh
uv tool install "git+https://github.com/m1thryn/patchday.git"
```

## Help

```text
usage: patchday [-h] [--month YYYY-MM] [--all-severities] [--json]

Pull Microsoft Patch Tuesday CVEs.

options:
  -h, --help        show this help message and exit
  --month YYYY-MM   Patch Tuesday month to report, default: current UTC month
  --all-severities  show every CVE instead of only Critical and Important
                    entries
  --json            emit JSON instead of launching the TUI
```

## Data Sources

Microsoft MSRC:
`https://api.msrc.microsoft.com/sug/v2.0/en-US/vulnerability`

Microsoft MSRC CVE details:
`https://api.msrc.microsoft.com/sug/v2.0/en-US/vulnerability/{CVE-ID}`
