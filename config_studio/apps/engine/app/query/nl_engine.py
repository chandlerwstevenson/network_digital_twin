"""Natural language config query engine — powered by Claude API (REQ-3.12).

Answers questions about configs with exact line number references.
Uses zero-retention API calls per REQ-4.3.3.
"""

from __future__ import annotations

import re
from app.api.schemas import (
    MultiConfigQueryMatch,
    MultiConfigQueryResponse,
    NLQueryResponse,
    VendorDetection,
)
from app.config import ANTHROPIC_API_KEY


async def answer_query(
    config_text: str,
    question: str,
    vendor_info: VendorDetection,
) -> NLQueryResponse:
    """Answer a natural language question about a network config using Claude.

    Returns the answer with line number references.
    """
    if not ANTHROPIC_API_KEY:
        return _fallback_query(config_text, question)

    try:
        import anthropic

        client = anthropic.AsyncAnthropic(api_key=ANTHROPIC_API_KEY)

        # Number the lines for reference
        numbered_config = "\n".join(
            f"L{i+1}: {line}" for i, line in enumerate(config_text.splitlines())
        )

        system_prompt = (
            "You are an expert network engineer analyzing a network device configuration. "
            f"The device is running {vendor_info.vendor.value} "
            f"{'version ' + vendor_info.os_version if vendor_info.os_version else ''}. "
            "Answer the user's question about this config precisely and concisely. "
            "Always reference specific line numbers (L1, L2, etc.) from the config. "
            "If the answer involves multiple items, format as a numbered list. "
            "Do not make assumptions about config that is not present. "
            "If the answer cannot be determined from the config alone, say so."
        )

        message = await client.messages.create(
            model="claude-sonnet-4-20250514",
            max_tokens=1500,
            system=system_prompt,
            messages=[
                {
                    "role": "user",
                    "content": f"Config:\n```\n{numbered_config}\n```\n\nQuestion: {question}",
                }
            ],
        )

        answer_text = message.content[0].text if message.content else "Unable to answer."

        # Extract line references from the answer
        line_refs = sorted(set(int(m.group(1)) for m in re.finditer(r"L(\d+)", answer_text)))

        return NLQueryResponse(
            answer=answer_text,
            line_references=line_refs,
            confidence=0.9,
        )

    except Exception:
        return _fallback_query(config_text, question)


async def answer_multi_config_query(configs: list[dict], question: str) -> MultiConfigQueryResponse:
    """Answer a natural language question across multiple configs in one session."""
    prepared = _prepare_multi_config_inputs(configs)
    if not ANTHROPIC_API_KEY:
        return _fallback_multi_query(prepared, question)

    try:
        import anthropic

        client = anthropic.AsyncAnthropic(api_key=ANTHROPIC_API_KEY)
        joined_configs = "\n\n".join(
            f"[{item['hostname']} | {item['vendor_info'].vendor.value}]\n{item['numbered_config']}"
            for item in prepared
        )
        system_prompt = (
            "You are an expert network engineer analyzing multiple network device configurations in one session. "
            "Answer only from the submitted configs. Always mention the device hostname for every claim. "
            "Reference exact line numbers using the format HOSTNAME:L12. "
            "If a device does not contain evidence for the answer, omit it. "
            "If the answer cannot be determined from the configs alone, say so clearly."
        )
        message = await client.messages.create(
            model="claude-sonnet-4-20250514",
            max_tokens=1800,
            system=system_prompt,
            messages=[
                {
                    "role": "user",
                    "content": f"Configs:\n```\n{joined_configs}\n```\n\nQuestion: {question}",
                }
            ],
        )
        answer_text = message.content[0].text if message.content else "Unable to answer."
        return MultiConfigQueryResponse(
            answer=answer_text,
            matches=_build_multi_matches(prepared, question),
            confidence=0.9,
        )
    except Exception:
        return _fallback_multi_query(prepared, question)


def _prepare_multi_config_inputs(configs: list[dict]) -> list[dict]:
    prepared = []
    for index, item in enumerate(configs, start=1):
        vendor_info = item["vendor_info"]
        hostname = item.get("hostname") or vendor_info.hostname or f"device-{index}"
        config_text = item["config_text"]
        prepared.append(
            {
                "hostname": hostname,
                "vendor_info": vendor_info,
                "config_text": config_text,
                "lines": config_text.splitlines(),
                "numbered_config": "\n".join(
                    f"{hostname}:L{i+1}: {line}" for i, line in enumerate(config_text.splitlines())
                ),
            }
        )
    return prepared


def _fallback_query(config_text: str, question: str) -> NLQueryResponse:
    """Simple keyword-based fallback when Claude API is unavailable.

    This ensures deterministic checks still work per REQ-4.2.3.
    """
    lines = config_text.splitlines()
    matching_lines = []

    for i, line in enumerate(lines):
        lower_line = line.lower()
        if any(kw in lower_line for kw in _keywords_from_question(question)):
            matching_lines.append(i + 1)

    if matching_lines:
        preview = "\n".join(
            f"L{n}: {lines[n-1].strip()}" for n in matching_lines[:20]
        )
        answer = f"Found {len(matching_lines)} matching lines for keywords {_keywords_from_question(question)}:\n\n{preview}"
        if len(matching_lines) > 20:
            answer += f"\n\n... and {len(matching_lines) - 20} more matches."
    else:
        answer = f"No lines matching keywords {_keywords_from_question(question)} found in the config."

    return NLQueryResponse(
        answer=answer,
        line_references=matching_lines[:50],
        confidence=0.3,
    )


def _fallback_multi_query(configs: list[dict], question: str) -> MultiConfigQueryResponse:
    matches = _build_multi_matches(configs, question)
    if not matches:
        return MultiConfigQueryResponse(
            answer=f"No matches for keywords {_keywords_from_question(question)} were found across the submitted configs.",
            matches=[],
            confidence=0.35,
        )

    summary_lines = []
    for match in matches:
        refs = ", ".join(f"L{line}" for line in match.line_references[:10]) or "no line references"
        summary_lines.append(f"- {match.hostname} ({match.vendor}): {refs}")

    answer = (
        f"Found matches for keywords {_keywords_from_question(question)} across {len(matches)} device(s):\n"
        + "\n".join(summary_lines)
    )
    return MultiConfigQueryResponse(answer=answer, matches=matches, confidence=0.4)


def _build_multi_matches(configs: list[dict], question: str) -> list[MultiConfigQueryMatch]:
    keywords = _keywords_from_question(question)
    matches: list[MultiConfigQueryMatch] = []
    for item in configs:
        line_refs = []
        previews = []
        for idx, line in enumerate(item["lines"], start=1):
            lower_line = line.lower()
            if any(keyword in lower_line for keyword in keywords):
                line_refs.append(idx)
                previews.append(f"L{idx}: {line.strip()}")
        if line_refs:
            matches.append(
                MultiConfigQueryMatch(
                    hostname=item["hostname"],
                    vendor=item["vendor_info"].vendor.value,
                    line_references=line_refs[:50],
                    preview=previews[:10],
                )
            )
    return matches


def _keywords_from_question(question: str) -> list[str]:
    stop_words = {"what", "which", "where", "how", "is", "are", "the", "a", "an",
                  "do", "does", "have", "has", "any", "all", "show", "me", "list",
                  "find", "get", "every", "each", "no", "not", "my", "in", "on",
                  "with", "without", "that", "this", "of", "to", "and", "or"}
    return [
        w.strip("?.,!") for w in question.lower().split()
        if w.strip("?.,!") not in stop_words and len(w.strip("?.,!")) > 2
    ]
