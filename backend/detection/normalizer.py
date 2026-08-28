"""Defensive URL normalization that never changes the captured original value."""
import html
import unicodedata
from urllib.parse import parse_qs, unquote, urlsplit, urlunsplit


def normalize_url(url: object) -> dict:
    original = "" if url is None else str(url)
    try:
        # Decode encoded characters so obfuscated suspicious patterns can be
        # inspected consistently. Two passes catch common double-encoding.
        decoded = html.unescape(original)
        for _ in range(2):
            next_value = unquote(decoded, errors="replace")
            if next_value == decoded:
                break
            decoded = next_value
        normalized = unicodedata.normalize("NFKC", decoded).strip()

        # urlsplit treats a bare host as a path, so add // only for parsing.
        parse_target = normalized
        if "://" not in parse_target and parse_target and not parse_target.startswith(("/", "?")):
            parse_target = "//" + parse_target
        parts = urlsplit(parse_target, allow_fragments=True)
        hostname = (parts.hostname or "").lower().rstrip(".")
        path = parts.path or "/"
        query = parts.query
        parameters = parse_qs(query, keep_blank_values=True, strict_parsing=False)
        comparison = normalized.lower()
        return {
            "original": original,
            "normalized": normalized,
            "comparison": comparison,
            "path": path,
            "query": query,
            "parameters": parameters,
            "hostname": hostname,
            "scheme": parts.scheme.lower(),
            "parse_error": None,
        }
    except (TypeError, ValueError, UnicodeError) as exc:
        return {
            "original": original,
            "normalized": original,
            "comparison": original.lower(),
            "path": "",
            "query": "",
            "parameters": {},
            "hostname": "",
            "scheme": "",
            "parse_error": f"URL could not be fully parsed: {exc}",
        }
