from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Protocol

from .models import Claim


class TextGenerator(Protocol):
    def generate(self, instruction: str, claims: list[Claim]) -> str: ...


@dataclass(slots=True)
class DeterministicBriefGenerator:
    """Offline fallback that turns approved claims into a factual brief.

    It is intentionally plain. Production model output must still pass the same
    deterministic claim, rights, originality, and disclosure gates.
    """

    heading: str = "Evidence brief"

    def generate(self, instruction: str, claims: list[Claim]) -> str:
        instruction_id = hashlib.sha256(instruction.encode("utf-8")).hexdigest()[:12]
        lines = [f"# {self.heading}", "", f"Instruction receipt: `{instruction_id}`", ""]
        for claim in claims:
            lines.append(f"- **{claim.state.value}:** {claim.public_wording}")
        lines.extend(["", "Independent editorial analysis. Sources are bound in the claim ledger."])
        return "\n".join(lines) + "\n"


class VertexTextGenerator:
    """Optional Google Gen AI adapter with structured evidence context."""

    def __init__(self, model: str, *, project: str | None = None, location: str = "global") -> None:
        try:
            from google.genai import Client
        except ImportError as exc:  # pragma: no cover - optional integration
            raise RuntimeError("install remedialhq[vertex]") from exc
        self._client = Client(vertexai=True, project=project, location=location)
        self._model = model

    def generate(self, instruction: str, claims: list[Claim]) -> str:
        evidence = json.dumps([claim.to_dict() for claim in claims], ensure_ascii=False)
        prompt = (
            "Use only the supplied claim objects. Preserve each claim's state language. "
            "Never upgrade OBSERVED, REPORTED, or INFERRED to CONFIRMED.\n\n"
            f"Instruction:\n{instruction}\n\nClaims:\n{evidence}"
        )
        response = self._client.models.generate_content(model=self._model, contents=prompt)
        text = getattr(response, "text", None)
        if not text:
            raise RuntimeError("model returned no text")
        return str(text)
