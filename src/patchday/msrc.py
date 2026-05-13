from concurrent.futures import ThreadPoolExecutor, as_completed

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

MSRC = "https://api.msrc.microsoft.com/sug/v2.0/en-US/vulnerability"

DEFAULT_TIMEOUT = 30
DEFAULT_RETRIES = 2


def make_session(retries=DEFAULT_RETRIES):
    retry_policy = Retry(
        total=retries,
        connect=retries,
        read=retries,
        status=retries,
        backoff_factor=1,
        status_forcelist=(429, 500, 502, 503, 504),
        allowed_methods=("GET",),
        raise_on_status=False,
    )
    adapter = HTTPAdapter(max_retries=retry_policy)
    session = requests.Session()
    session.headers.update(
        {
            "Accept": "application/json",
            "User-Agent": "patchday/1.0",
        }
    )
    session.mount("https://", adapter)
    session.mount("http://", adapter)
    return session


def get_json(url, *, session, timeout=DEFAULT_TIMEOUT, verify_tls=True, params=None):
    try:
        response = session.get(
            url,
            params=params,
            timeout=timeout,
            verify=verify_tls,
        )
        response.raise_for_status()
        return response.json()
    except requests.exceptions.SSLError as exc:
        raise RuntimeError(
            "TLS certificate verification failed. "
            "Fix Python's CA trust store and try again."
        ) from exc
    except requests.exceptions.HTTPError as exc:
        status = exc.response.status_code if exc.response is not None else "unknown"
        raise RuntimeError(f"GET {url} failed with HTTP {status}") from exc
    except ValueError as exc:
        raise RuntimeError(f"GET {url} returned invalid JSON: {exc}") from exc
    except requests.exceptions.RequestException as exc:
        raise RuntimeError(f"GET {url} failed: {exc}") from exc


def msrc_data(session, timeout=DEFAULT_TIMEOUT, verify_tls=True):
    data = get_json(MSRC, session=session, timeout=timeout, verify_tls=verify_tls)
    return data.get("value", [])


def msrc_details(cve, *, session, timeout=DEFAULT_TIMEOUT, verify_tls=True):
    data = get_json(
        f"{MSRC}/{cve}",
        session=session,
        timeout=timeout,
        verify_tls=verify_tls,
    )

    references = [data["mitreUrl"]] if data.get("mitreUrl") else []
    return {
        "cvss": as_score(data.get("baseScore")),
        "cvss_vector": data.get("vectorString"),
        "description": data.get("unformattedDescription"),
        "published": data.get("releaseDate"),
        "last_modified": data.get("latestRevisionDate"),
        "exploitability": data.get("latestSoftwareRelease"),
        "publicly_disclosed": data.get("publiclyDisclosed"),
        "exploited": data.get("exploited"),
        "cwe": data.get("cweList", []),
        "references": references,
        "articles": data.get("articles", []),
    }


def msrc_details_for_vulns(
    vulns,
    *,
    timeout=DEFAULT_TIMEOUT,
    verify_tls=True,
    workers=8,
):
    def fetch(cve):
        try:
            return cve, msrc_details(
                cve,
                session=make_session(),
                timeout=timeout,
                verify_tls=verify_tls,
            )
        except RuntimeError as exc:
            return cve, {"error": str(exc)}

    details = {}
    with ThreadPoolExecutor(max_workers=workers) as executor:
        futures = [executor.submit(fetch, vuln["cve"]) for vuln in vulns]
        for future in as_completed(futures):
            cve, result = future.result()
            details[cve] = result
    return details


def as_score(value):
    try:
        score = float(value)
    except (TypeError, ValueError):
        return None
    if 0 <= score <= 10:
        return score
    return None
