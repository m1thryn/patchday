TOKYO_NIGHT = {
    "bg": "#1a1b26",
    "bg_dark": "#16161e",
    "bg_highlight": "#292e42",
    "border": "#3b4261",
    "fg": "#c0caf5",
    "fg_muted": "#a9b1d6",
    "comment": "#565f89",
    "blue": "#7aa2f7",
    "cyan": "#7dcfff",
    "green": "#9ece6a",
    "yellow": "#e0af68",
    "red": "#f7768e",
}


def rich_style(color, *modifiers):
    return " ".join((*modifiers, TOKYO_NIGHT[color]))


def themed_css(template):
    for name, value in TOKYO_NIGHT.items():
        template = template.replace(f"@{name}@", value)
    return template
