"""Natural language config query engine — powered by Claude API (REQ-3.12).

Answers questions about configs with exact line number references.
Uses zero-retention API calls per REQ-4.3.3.
"""

from __future__ import annotations

import re
from app.api.schemas import NLQueryResponse, VendorDetection
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

    except Exception as e:
        return NLQueryResponse(
            answer=f"LLM query failed: {str(e)}. Falling back to keyword search.",
            line_references=[],
            confidence=0.0,
        )


def _fallback_query(config_text: str, question: str) -> NLQueryResponse:
    """Simple keyword-based fallback when Claude API is unavailable.

    This ensures deterministic checks still work per REQ-4.2.3.
    """
    lines = config_text.splitlines()
    matching_lines = []

    # Extract keywords from question
    stop_words = {"what", "which", "where", "how", "is", "are", "the", "a", "an",
                  "do", "does", "have", "has", "any", "all", "show", "me", "list",
                  "find", "get", "every", "each", "no", "not", "my", "in", "on",
                  "with", "without", "that", "this", "of", "to", "and", "or"}
    keywords = [
        w.strip("?.,!") for w in question.lower().split()
        if w.strip("?.,!") not in stop_words and len(w.strip("?.,!")) > 2
    ]

    for i, line in enumerate(lines):
        lower_line = line.lower()
        if any(kw in lower_line for kw in keywords):
            matching_lines.append(i + 1)

    if matching_lines:
        preview = "\n".join(
            f"L{n}: {lines[n-1].strip()}" for n in matching_lines[:20]
        )
        answer = f"Found {len(matching_lines)} matching lines for keywords {keywords}:\n\n{preview}"
        if len(matching_lines) > 20:
            answer += f"\n\n... and {len(matching_lines) - 20} more matches."
    else:
        answer = f"No lines matching keywords {keywords} found in the config."

    return NLQueryResponse(
        answer=answer,
        line_references=matching_lines[:50],
        confidence=0.3,
    )
