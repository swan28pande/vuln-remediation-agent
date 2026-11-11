"""Claude call that drafts a fix as structured JSON."""

import json

import anthropic
from pydantic import BaseModel, Field

from .config import settings

client = anthropic.Anthropic()


class FileEdit(BaseModel):
    path: str = Field(description="Repo-relative path of the file to replace")
    new_content: str = Field(description="Full new content of the file")


class Fix(BaseModel):
    fix_type: str = Field(description="'version_bump', 'code_patch', or 'none'")
    summary: str = Field(description="One-line PR title")
    rationale: str = Field(description="Markdown explanation for the PR body")
    edits: list[FileEdit]


FIX_SCHEMA = {
    "type": "object",
    "additionalProperties": False,
    "required": ["fix_type", "summary", "rationale", "edits"],
    "properties": {
        "fix_type": {"type": "string", "enum": ["version_bump", "code_patch", "none"]},
        "summary": {"type": "string"},
        "rationale": {"type": "string"},
        "edits": {
            "type": "array",
            "items": {
                "type": "object",
                "additionalProperties": False,
                "required": ["path", "new_content"],
                "properties": {"path": {"type": "string"}, "new_content": {"type": "string"}},
            },
        },
    },
}

SYSTEM = """You are a security engineer fixing one vulnerability in a repository.
You get the alert, the OSV record, and the current content of the relevant file(s).
Produce the smallest change that removes the vulnerability without changing behaviour:
- Dependency alerts: bump to the lowest fixed version in the manifest; keep formatting intact.
- Code-scanning alerts: patch the flagged code only.
Return the complete new content of every file you change. If no safe fix is possible,
return fix_type "none" with no edits and explain why in rationale."""


def draft_fix(alert: dict, osv: dict | None, files: dict[str, str]) -> Fix:
    context = {
        "alert": alert,
        "osv": osv,
        "files": files,
    }
    response = client.beta.messages.create(
        model=settings.model,
        max_tokens=16000,
        system=SYSTEM,
        messages=[{"role": "user", "content": json.dumps(context, indent=1)}],
        output_config={
            "effort": "high",
            "format": {"type": "json_schema", "schema": FIX_SCHEMA},
        },
        # Re-run on a fallback model if a safety classifier declines.
        betas=["server-side-fallback-2026-07-01"],
        fallbacks="default",
    )
    if response.stop_reason == "refusal":
        raise RuntimeError("model declined to draft a fix")
    text = next(b.text for b in response.content if b.type == "text")
    return Fix.model_validate_json(text)
