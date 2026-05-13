import re
from html import unescape

from patchday.dates import parse_date
from patchday.msrc import as_score

TAG_RE = re.compile(r"<[^>]+>")
WHITESPACE_RE = re.compile(r"\s+")


def plain_text(value):
    if not value:
        return ""
    return WHITESPACE_RE.sub(" ", unescape(TAG_RE.sub("", value))).strip()


def find_cvss_score(value):
    if isinstance(value, dict):
        for key, child in value.items():
            key_lower = key.lower()
            if key_lower in {"basescore", "base_score", "cvssscore", "cvss_score"}:
                score = as_score(child)
                if score is not None:
                    return score
            found = find_cvss_score(child)
            if found is not None:
                return found
    elif isinstance(value, list):
        for child in value:
            found = find_cvss_score(child)
            if found is not None:
                return found
    return None


def normalize(items, *, release, start_date=None, end_date=None):
    vulns = []
    seen = set()

    for item in items:
        cve = item.get("cveNumber")
        if not cve or cve in seen:
            continue
        if release and item.get("releaseNumber") != release:
            continue

        published = item.get("releaseDate")
        published_date = parse_date(published)
        if start_date and (not published_date or published_date < start_date):
            continue
        if end_date and (not published_date or published_date > end_date):
            continue

        seen.add(cve)
        vulns.append(
            {
                "cve": cve,
                "title": item.get("cveTitle") or "no title",
                "severity": item.get("severity") or "unknown",
                "published": published,
                "release": item.get("releaseNumber"),
                "cvss": find_cvss_score(item),
                "raw": item,
            }
        )

    return vulns


def sort_key(vuln):
    severity_rank = {"Critical": 3, "Important": 2, "Moderate": 1, "Low": 0}
    return (
        severity_rank.get(vuln["severity"], -1),
        vuln["cvss"] or 0,
        vuln["cve"],
    )


def filter_vulns(vulns, include_all):
    return [
        vuln
        for vuln in sorted(vulns, key=sort_key, reverse=True)
        if include_all or vuln["severity"] in ("Critical", "Important")
    ]


def encode_articles(articles):
    encoded = []
    for article in articles:
        text = plain_text(
            article.get("unformattedDescription") or article.get("description")
        )
        if not text:
            continue
        encoded.append(
            {
                "title": article.get("title"),
                "type": article.get("articleType"),
                "ordinal": article.get("ordinal"),
                "text": text,
            }
        )
    return encoded


def encode_details(details):
    if not details:
        return None
    if details.get("error"):
        return {"error": details["error"]}

    return {
        "description": details.get("description"),
        "cvss": details.get("cvss"),
        "cvss_vector": details.get("cvss_vector"),
        "published": details.get("published"),
        "last_modified": details.get("last_modified"),
        "exploitability": details.get("exploitability"),
        "publicly_disclosed": details.get("publicly_disclosed"),
        "exploited": details.get("exploited"),
        "cwe": details.get("cwe", []),
        "references": details.get("references", []),
        "articles": encode_articles(details.get("articles", [])),
    }


def encode_vulns(vulns, details_by_cve=None):
    details_by_cve = details_by_cve or {}
    encoded = []
    for vuln in vulns:
        item = {key: value for key, value in vuln.items() if key != "raw"}
        details = encode_details(details_by_cve.get(vuln["cve"]))
        if details is not None:
            item["msrc_details"] = details
            if item["cvss"] is None and details.get("cvss") is not None:
                item["cvss"] = details["cvss"]
        encoded.append(item)
    return encoded
