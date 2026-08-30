import json
import tempfile
import unittest
from pathlib import Path

from remedialhq.models import Claim, ClaimState
from remedialhq.pipeline import load_claims
from remedialhq.provenance import SourceRecord, load_sources, validate_source_bindings
from remedialhq.source_registry import SourceRegistry


class ProvenanceTests(unittest.TestCase):
    def setUp(self) -> None:
        root = Path(__file__).resolve().parents[1]
        self.registry = SourceRegistry.load(root / "config/sources.json")
        self.first_party = SourceRecord(
            "SRC-1", "Publisher", "Title", "https://www.rockstargames.com/VI", "FIRST_PARTY",
            "TEXT_FACTS_ONLY", False,
        )
        self.visual = SourceRecord(
            "SRC-V", "Publisher", "Video", "https://www.youtube.com/watch?v=tJbzMqJGH4k",
            "FIRST_PARTY_VISUAL",
            "NO_COMMERCIAL_REUPLOAD_BY_DEFAULT", False,
        )

    def _load_source_row(self, row: dict[str, object]) -> list[SourceRecord]:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "sources.jsonl"
            path.write_text(json.dumps(row) + "\n", encoding="utf-8")
            return load_sources(path)

    def test_valid_first_party_claim(self) -> None:
        claim = Claim("CLM-1", "Fact", ClaimState.CONFIRMED, 1.0, ("SRC-1",), "Fact")
        self.assertEqual(
            validate_source_bindings([claim], [self.first_party], registry=self.registry),
            [],
        )

    def test_missing_source_is_rejected(self) -> None:
        claim = Claim("CLM-1", "Fact", ClaimState.CONFIRMED, 1.0, ("SRC-X",), "Fact")
        issues = validate_source_bindings(
            [claim], [self.first_party], registry=self.registry
        )
        self.assertTrue(any(issue["type"] == "missing_sources" for issue in issues))

    def test_observation_requires_visual_source(self) -> None:
        claim = Claim("CLM-1", "Seen", ClaimState.OBSERVED, 0.8, ("SRC-1",), "It appears")
        issues = validate_source_bindings(
            [claim], [self.first_party], registry=self.registry
        )
        self.assertTrue(any(issue["type"] == "observation_without_first_party_visual" for issue in issues))
        self.assertEqual(
            validate_source_bindings(
                [
                    Claim(
                        "CLM-2",
                        "Seen",
                        ClaimState.OBSERVED,
                        0.8,
                        ("SRC-V",),
                        "It appears",
                    )
                ],
                [self.visual],
                registry=self.registry,
            ),
            [],
        )

    def test_string_false_cannot_bypass_prohibited_validation(self) -> None:
        with self.assertRaisesRegex(TypeError, "must be a JSON boolean"):
            self._load_source_row(
                {
                    "source_id": "SRC-UNSAFE",
                    "publisher": "Publisher",
                    "title": "Title",
                    "url": "https://example.com/fact",
                    "source_tier": "FIRST_PARTY",
                    "rights_status": "TEXT_FACTS_ONLY",
                    "prohibited": "false",
                }
            )

    def test_missing_prohibited_classification_is_rejected(self) -> None:
        with self.assertRaisesRegex(ValueError, "classification is required"):
            self._load_source_row(
                {
                    "source_id": "SRC-UNCLASSIFIED",
                    "publisher": "Publisher",
                    "title": "Title",
                    "url": "https://example.com/fact",
                    "source_tier": "FIRST_PARTY",
                    "rights_status": "TEXT_FACTS_ONLY",
                }
            )

    def test_invented_first_party_tier_is_rejected(self) -> None:
        with self.assertRaisesRegex(ValueError, "source tier is not supported"):
            self._load_source_row(
                {
                    "source_id": "SRC-FORGED",
                    "publisher": "Publisher",
                    "title": "Title",
                    "url": "https://example.com/fact",
                    "source_tier": "FIRST_PARTY_UNREVIEWED",
                    "rights_status": "TEXT_FACTS_ONLY",
                    "prohibited": False,
                }
            )

    def test_unsupported_rights_status_is_rejected(self) -> None:
        with self.assertRaisesRegex(ValueError, "rights status is not supported"):
            self._load_source_row(
                {
                    "source_id": "SRC-RIGHTS",
                    "publisher": "Publisher",
                    "title": "Title",
                    "url": "https://example.com/fact",
                    "source_tier": "FIRST_PARTY",
                    "rights_status": "UNRESTRICTED_REUPLOAD",
                    "prohibited": False,
                }
            )

    def test_registry_reconciliation_rejects_unknown_url_and_tier_mismatch(self) -> None:
        unknown = SourceRecord(
            "SRC-UNKNOWN",
            "Publisher",
            "Title",
            "https://example.com/fact",
            "FIRST_PARTY",
            "TEXT_FACTS_ONLY",
            False,
        )
        wrong_tier = SourceRecord(
            "SRC-WRONG-TIER",
            "Rockstar Games",
            "Grand Theft Auto VI official page",
            "https://www.rockstargames.com/VI",
            "FIRST_PARTY_POLICY",
            "TEXT_FACTS_ONLY",
            False,
        )
        wrong_rights = SourceRecord(
            "SRC-WRONG-RIGHTS",
            "Rockstar Games",
            "Grand Theft Auto VI official page",
            "https://www.rockstargames.com/VI",
            "FIRST_PARTY",
            "NO_COMMERCIAL_REUPLOAD_BY_DEFAULT",
            False,
        )
        issues = validate_source_bindings(
            [], [unknown, wrong_tier, wrong_rights], registry=self.registry
        )
        self.assertTrue(
            any(issue["type"] == "source_not_in_default_deny_registry" for issue in issues)
        )
        self.assertTrue(
            any(issue["type"] == "source_registry_tier_mismatch" for issue in issues)
        )
        self.assertTrue(
            any(issue["type"] == "source_registry_rights_mismatch" for issue in issues)
        )

    def test_seed_sources_reconcile_with_default_deny_registry(self) -> None:
        root = Path(__file__).resolve().parents[1]
        sources = load_sources(root / "data/sources/seed_sources.jsonl")
        claims = load_claims(root / "data/claims/seed_claims.jsonl")
        registry = SourceRegistry.load(root / "config/sources.json")
        self.assertEqual(
            validate_source_bindings(claims, sources, registry=registry),
            [],
        )


if __name__ == "__main__":
    unittest.main()
