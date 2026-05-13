import calendar
import re
from datetime import UTC, date, datetime, timedelta

from dateutil import parser as date_parser

MICROSOFT_JSON_DATE_RE = re.compile(r"/Date\((?P<millis>-?\d+)")


def patch_tuesday(year, month):
    first = date(year, month, 1)
    days_until_tuesday = (1 - first.weekday()) % 7
    return first + timedelta(days=days_until_tuesday + 7)


def parse_date(value):
    if not value:
        return None

    match = MICROSOFT_JSON_DATE_RE.match(value)
    if match:
        millis = int(match.group("millis"))
        return datetime.fromtimestamp(millis / 1000, UTC).date()

    try:
        return date_parser.parse(value).date()
    except (TypeError, ValueError, OverflowError):
        return None


def release_label(year, month):
    return f"{year:04d}-{calendar.month_abbr[month]}"
