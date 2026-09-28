#!/usr/bin/env python3
"""Summarize SARIF reports into a Markdown digest with file paths and code context.

Reads every ``*.sarif`` file under a report directory and writes ``summary.md``
next to them. Each finding is rendered with its severity, rule id, message,
``file:line`` location, a link to the source on GitHub, and a fenced snippet of
the offending source read from the checked-out workspace.

Used by ``.github/workflows/security-scan.md`` to build the deterministic input
for the security-scan issue, so the agent never has to inspect files itself.
"""

from __future__ import annotations

import json
import os
import re
import sys
from pathlib import Path

MAX_FINDINGS_PER_TOOL = 20
MAX_LOCATIONS_PER_FINDING = 3
MAX_SNIPPET_LINES = 9
MAX_SNIPPET_CHARS = 1500
MAX_REMEDIATION_CHARS = 600

LEVEL_ORDER = {"error": 0, "warning": 1, "note": 2, "none": 3}

SEVERITY_BANDS = ((9.0, "critical"), (7.0, "high"), (4.0, "medium"), (0.0, "low"))


def env(name: str, default: str = "") -> str:
    return os.environ.get(name, default).strip()


def blob_link(path: str, start: int | None) -> str | None:
    """Permalink to a finding in the GitHub web UI, if the repo is known."""
    repo = env("GITHUB_REPOSITORY")
    if not repo or not path:
        return None
    server = env("GITHUB_SERVER_URL", "https://github.com").rstrip("/")
    sha = env("GITHUB_SHA", "HEAD")
    url = f"{server}/{repo}/blob/{sha}/{path}"
    return f"{url}#L{start}" if start else url


def normalize_uri(uri: object) -> str | None:
    """Normalize a SARIF artifact URI into a workspace-relative path."""
    if not isinstance(uri, str):
        return None
    cleaned = uri.strip()
    if not cleaned:
        return None
    for prefix in ("file://", "%SRCROOT%/"):
        if cleaned.startswith(prefix):
            cleaned = cleaned[len(prefix) :]
    while cleaned.startswith(("./", "/")):
        cleaned = cleaned[2:] if cleaned.startswith("./") else cleaned[1:]
    return cleaned or None


def read_snippet(path: str | None, start: int | None, end: int | None) -> str | None:
    """Read the source lines around a finding from the checked-out workspace."""
    if not path or not start:
        return None
    candidate = Path(path)
    if not candidate.is_file():
        return None
    try:
        lines = candidate.read_text(errors="replace").splitlines()
    except OSError:
        return None
    if not lines or start > len(lines):
        return None

    start = max(1, start)
    end = min(max(end or start, start), len(lines))
    pad = (MAX_SNIPPET_LINES - (end - start + 1)) // 2
    lo, hi = max(1, start - pad), min(len(lines), end + pad)
    width = len(str(hi))
    out = [f"{'>>' if start <= n <= end else '  '} {str(n).rjust(width)} | {lines[n - 1]}" for n in range(lo, hi + 1)]

    text = "\n".join(out)
    if len(text) > MAX_SNIPPET_CHARS:
        text = text[:MAX_SNIPPET_CHARS] + "\n... (truncated)"
    return text


def rules_by_id(run: dict) -> dict[str, dict]:
    """Index a run's rules, including those contributed by tool extensions."""
    tool = run.get("tool") or {}
    sections = [tool.get("driver") or {}, *(tool.get("extensions") or [])]
    rules: dict[str, dict] = {}
    for section in sections:
        for rule in section.get("rules") or []:
            if isinstance(rule, dict) and rule.get("id"):
                rules[rule["id"]] = rule
    return rules


def severity_of(result: dict, rule: dict) -> tuple[str, float | None]:
    """Prefer the numeric ``security-severity`` score, else the SARIF level."""
    props = {**(rule.get("properties") or {}), **(result.get("properties") or {})}
    raw = props.get("security-severity")
    if raw is not None:
        try:
            score = float(raw)
        except (TypeError, ValueError):
            score = None
        if score is not None:
            band = next(name for threshold, name in SEVERITY_BANDS if score >= threshold)
            return f"{band} (security-severity {score:g})", score
    level = result.get("level") or (rule.get("defaultConfiguration") or {}).get("level") or "warning"
    return str(level), None


def locations_of(result: dict) -> list[dict]:
    out = []
    for location in result.get("locations") or []:
        physical = location.get("physicalLocation") or {}
        artifact = physical.get("artifactLocation") or {}
        region = physical.get("region") or {}
        context = ((physical.get("contextRegion") or {}).get("snippet") or {}).get("text")
        out.append(
            {
                "uri": normalize_uri(artifact.get("uri")),
                "start": region.get("startLine"),
                "end": region.get("endLine") or region.get("startLine"),
                "context": context,
            }
        )
    return out


def condense_help(text: str) -> str:
    """Keep only the actionable part of a CodeQL help page.

    CodeQL ``help`` fields carry full documentation (title, long prose, a worked
    example, references). Only the summary and the Recommendation section are
    useful in an issue body, so drop the rest and cap the length.
    """
    if not text:
        return ""

    kept: list[str] = []
    for section in re.split(r"(?m)^#{1,6}\s+", text):
        section = section.strip()
        if not section:
            continue
        title, _, body = section.partition("\n")
        body = body.strip()
        is_recommendation = title.lower().startswith("recommendation")
        if title.lower().startswith("issue") and len(kept) >= 1:
            break
        if is_recommendation:
            kept.append(f"**Recommendation:** {body}")
        elif not kept:
            kept.append(f"**{title.strip()}**" + (f"\n\n{body}" if body else ""))
        if sum(len(part) for part in kept) > MAX_REMEDIATION_CHARS:
            break

    out = "\n\n".join(kept) if kept else text.strip()
    if len(out) > MAX_REMEDIATION_CHARS:
        out = out[:MAX_REMEDIATION_CHARS].rsplit(" ", 1)[0] + " …"
    return out


def remediation_of(result: dict, rule: dict) -> str:
    sources = []
    for source in (rule.get("help"), rule.get("fullDescription")):
        text = source.get("text") or "" if isinstance(source, dict) else (source or "")
        if isinstance(text, str) and text.strip():
            sources.append(text)
    text = condense_help("\n\n".join(sources))

    if result.get("fixes"):
        suggestions = []
        for fix in result["fixes"]:
            for change in fix.get("artifactChanges") or []:
                for replacement in change.get("replacements") or []:
                    if replacement.get("deletedFile"):
                        continue
                    content = (replacement.get("insertedContent") or {}).get("text")
                    if isinstance(content, str) and content.strip():
                        suggestions.append(content.strip().splitlines()[0].strip())
        if suggestions:
            text = f"{text}\n\nSuggested fix: {'; '.join(dict.fromkeys(suggestions))}".strip()
        else:
            text = f"{text}\n\nA fix is available (see the report for the resolved version).".strip()
    return text


def sort_findings(results: list[dict], rules: dict[str, dict]) -> list[tuple[dict, dict, str]]:
    """Most severe first: numeric score, then SARIF level."""
    scored = []
    for result in results:
        rule = rules.get(result.get("ruleId"), {})
        label, score = severity_of(result, rule)
        rank = (score if score is not None else 99.0, LEVEL_ORDER.get(result.get("level", "warning"), 1))
        scored.append((rank, label, result, rule))
    scored.sort(key=lambda item: item[0])
    return [(result, rule, label) for _, label, result, rule in scored]


def render_tool(sarif: dict) -> tuple[str, int]:
    runs = sarif.get("runs") or []
    tool_name = ((runs[0].get("tool") or {}).get("driver") or {}).get("name", "unknown") if runs else "unknown"
    total = sum(len(run.get("results") or []) for run in runs)

    lines = [f"## {tool_name} — {total} finding(s)", ""]
    if total == 0:
        return "\n".join([*lines, "No findings.", ""]), 0

    emitted = 0
    for run in runs:
        rules = rules_by_id(run)
        for result, rule, label in sort_findings(run.get("results") or [], rules):
            if emitted >= MAX_FINDINGS_PER_TOOL:
                break
            emitted += 1
            lines += [f"### {emitted}. `{result.get('ruleId', 'unknown')}` — {label}", ""]

            message = (result.get("message") or {}).get("text")
            if message and message.strip():
                lines += [f"**Message:** {message.strip()}", ""]

            locations = locations_of(result)
            if not locations:
                lines += ["**Location:** not reported", ""]
            for loc in locations[:MAX_LOCATIONS_PER_FINDING]:
                uri = loc["uri"] or "unknown"
                start, end = loc["start"], loc["end"]
                if start and end and end != start:
                    where = f"`{uri}:{start}-{end}`"
                elif start:
                    where = f"`{uri}:{start}`"
                else:
                    where = f"`{uri}`"
                link = blob_link(uri, start) if loc["uri"] else None
                lines.append(f"**Location:** {where} — [open in GitHub]({link})" if link else f"**Location:** {where}")

                snippet = loc["context"] or read_snippet(uri, start, end)
                if snippet:
                    language = "python" if uri.endswith(".py") else ""
                    lines += ["", f"```{language}", snippet.rstrip(), "```"]
                lines.append("")
            if len(locations) > MAX_LOCATIONS_PER_FINDING:
                omitted = len(locations) - MAX_LOCATIONS_PER_FINDING
                lines += [f"_{omitted} further location(s) omitted._", ""]

            remediation = remediation_of(result, rule)
            if remediation:
                lines += ["**Remediation:**", "", remediation.strip(), ""]

    if total > emitted:
        lines += [f"_{total - emitted} further finding(s) omitted (limit {MAX_FINDINGS_PER_TOOL})._", ""]
    return "\n".join(lines), total


def main(argv: list[str]) -> int:
    report_dir = Path(argv[1] if len(argv) > 1 else "security-scan-reports")
    out = report_dir / "summary.md"
    sarif_files = sorted(report_dir.rglob("*.sarif")) if report_dir.is_dir() else []

    parts = ["# Security scan summary", ""]
    if not sarif_files:
        parts += ["No SARIF reports were produced. Every tool failed to run.", ""]
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text("\n".join(parts))
        print(f"wrote {out} (no reports)")
        return 0

    grand_total = 0
    for path in sarif_files:
        rel = path.relative_to(report_dir)
        try:
            sarif = json.loads(path.read_text())
            body, count = render_tool(sarif)
        except Exception as exc:  # noqa: BLE001 - one bad report must not lose the rest
            body, count = f"## {rel}\n\nCould not process `{rel}`: {exc}\n", 0
        grand_total += count
        parts += [f"<!-- source: {rel} -->", body.rstrip(), ""]

    parts += [f"**Total findings across all tools: {grand_total}**", ""]
    out.write_text("\n".join(parts))
    print(f"wrote {out} ({grand_total} findings from {len(sarif_files)} report(s))")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
