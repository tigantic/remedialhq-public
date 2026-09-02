from __future__ import annotations

import math
import unittest

from remedialhq.gates import evaluate
from remedialhq.models import (
    Asset,
    Claim,
    ClaimState,
    ContentPackage,
    Decision,
    RightsStatus,
)


def claim(state: ClaimState = ClaimState.CONFIRMED) -> Claim:
    return Claim(
        claim_id="CLM-1",
        proposition="A fact",
        state=state,
        confidence=1.0,
        source_ids=("SRC-1",),
        public_wording="A fact is supported.",
    )


def package(**overrides: object) -> ContentPackage:
    values: dict[str, object] = {
        "package_id": "PKG-1",
        "title": "What the evidence shows",
        "body": "A fact is supported.",
        "platform": "youtube",
        "claim_ids": ["CLM-1"],
        "assets": [Asset("AST-1", "original.svg", RightsStatus.ORIGINAL_GENERATED)],
        "disclosures": {"independence"},
        "originality_score": 0.95,
        "recent_similarity": 0.1,
        "rights_risk": 0.02,
        "metadata": {
            "title_claim_ids": ["CLM-1"],
            "content_blocks": [
                {"block_id": "B1", "text": "A fact is supported.", "factual": True, "claim_ids": ["CLM-1"]}
            ]
        },
    }
    values.update(overrides)
    return ContentPackage(**values)  # type: ignore[arg-type]


class GateTests(unittest.TestCase):
    def test_clean_package_passes(self) -> None:
        report = evaluate(package(), [claim()])
        self.assertEqual(report.decision, Decision.PASS)

    def test_pending_claim_holds(self) -> None:
        report = evaluate(package(), [claim(ClaimState.PENDING)])
        self.assertEqual(report.decision, Decision.HOLD)

    def test_prohibited_leak_rejects(self) -> None:
        leaked = Asset("AST-L", "leak.mp4", RightsStatus.PROHIBITED_LEAK)
        report = evaluate(package(assets=[leaked]), [claim()])
        self.assertEqual(report.decision, Decision.REJECT)

    def test_missing_affiliate_disclosure_holds(self) -> None:
        report = evaluate(
            package(metadata={"affiliate": True, "content_blocks": [{"block_id": "B1", "text": "A fact is supported.", "factual": True, "claim_ids": ["CLM-1"]}]}, disclosures={"independence"}),
            [claim()],
        )
        self.assertEqual(report.decision, Decision.HOLD)

    def test_certainty_language_cannot_outrun_evidence(self) -> None:
        report = evaluate(package(title="Official mechanics confirmed"), [claim(ClaimState.OBSERVED)])
        self.assertEqual(report.decision, Decision.HOLD)



    def test_bound_claim_cannot_cover_unrelated_factual_text(self) -> None:
        bad = package(metadata={"content_blocks": [{"block_id": "B1", "text": "The moon contains 900 casinos.", "factual": True, "claim_ids": ["CLM-1"]}]})
        report = evaluate(bad, [claim()])
        self.assertEqual(report.decision, Decision.HOLD)
        alignment = next(item for item in report.findings if item.gate == "fact_alignment")
        self.assertIn("B1", alignment.details["numbers_absent_from_bound_claims"])

    def test_supported_clause_cannot_pad_an_unrelated_assertion(self) -> None:
        text = "A fact is supported and the moon has casinos."
        bad = package(
            body=text,
            metadata={
                "title_claim_ids": ["CLM-1"],
                "content_blocks": [
                    {
                        "block_id": "B1",
                        "text": text,
                        "factual": True,
                        "claim_ids": ["CLM-1"],
                    }
                ],
            },
        )
        report = evaluate(bad, [claim()])
        self.assertEqual(report.decision, Decision.HOLD)
        alignment = next(item for item in report.findings if item.gate == "fact_alignment")
        self.assertIn("B1", alignment.details["not_exact_reviewed_public_wording"])

    def test_observed_claim_requires_observation_language(self) -> None:
        observed = claim(ClaimState.OBSERVED)
        bad = package(metadata={"content_blocks": [{"block_id": "B1", "text": "A fact is supported.", "factual": True, "claim_ids": ["CLM-1"]}]})
        report = evaluate(bad, [observed])
        self.assertEqual(report.decision, Decision.HOLD)

    def test_title_certainty_requires_explicit_confirmed_title_claims(self) -> None:
        confirmed = claim(ClaimState.CONFIRMED)
        good = package(
            title="Official fact confirmed",
            metadata={
                "title_claim_ids": ["CLM-1"],
                "content_blocks": [{"block_id": "B1", "text": "A fact is supported.", "factual": True, "claim_ids": ["CLM-1"]}],
            },
        )
        self.assertEqual(evaluate(good, [confirmed]).decision, Decision.PASS)

    def test_unrelated_title_cannot_borrow_a_legitimate_claim(self) -> None:
        bad = package(title="A fact mines crypto for $999")
        report = evaluate(bad, [claim()])
        self.assertEqual(report.decision, Decision.HOLD)
        title = next(item for item in report.findings if item.gate == "title_strength")
        self.assertIn("999", title.details["unexplained_numbers"])

    def test_nonfactual_label_cannot_hide_an_arbitrary_assertion(self) -> None:
        text = "GTA VI officially costs $999 and mines crypto."
        report = evaluate(
            package(
                body=text,
                metadata={
                    "title_claim_ids": ["CLM-1"],
                    "content_blocks": [
                        {
                            "block_id": "B1",
                            "kind": "editorial_method",
                            "text": text,
                            "factual": False,
                            "claim_ids": [],
                        }
                    ],
                },
            ),
            [claim()],
        )
        self.assertEqual(report.decision, Decision.HOLD)

    def test_unbound_factual_block_holds(self) -> None:
        report = evaluate(
            package(metadata={"content_blocks": [{"block_id": "B1", "text": "Unsupported fact", "factual": True, "claim_ids": []}]}),
            [claim()],
        )
        self.assertEqual(report.decision, Decision.HOLD)

    def test_body_must_match_structured_blocks(self) -> None:
        report = evaluate(package(body="A hidden unsupported assertion."), [claim()])
        self.assertEqual(report.decision, Decision.HOLD)
        lineage = next(item for item in report.findings if item.gate == "lineage")
        self.assertFalse(lineage.details["body_matches_structured_blocks"])

    def test_unclassified_nonfactual_block_holds(self) -> None:
        report = evaluate(
            package(
                body="The moon contains casinos.",
                metadata={
                    "content_blocks": [
                        {
                            "block_id": "B1",
                            "text": "The moon contains casinos.",
                            "factual": False,
                            "claim_ids": ["CLM-1"],
                        }
                    ]
                },
            ),
            [claim()],
        )
        self.assertEqual(report.decision, Decision.HOLD)

    def test_nonfinite_risk_metrics_are_rejected_at_construction(self) -> None:
        for value in (math.nan, math.inf, -0.1, 1.1):
            with self.subTest(value=value), self.assertRaises(ValueError):
                package(rights_risk=value)

    def test_machine_identifiers_block_filename_and_markup_injection(self) -> None:
        for field_name, value in (
            ("package_id", "../escaped"),
            ("package_id", "/absolute"),
            ("platform", "youtube/../../escape"),
            ("claim_ids", ["<script>alert(1)</script>"]),
        ):
            with self.subTest(field_name=field_name, value=value), self.assertRaisesRegex(
                ValueError, "must contain"
            ):
                package(**{field_name: value})

    def test_claim_and_asset_identifiers_are_machine_safe(self) -> None:
        with self.assertRaisesRegex(ValueError, "claim_id must contain"):
            Claim("<script>", "Fact", ClaimState.CONFIRMED, 1.0, ("SRC-1",), "Fact")
        with self.assertRaisesRegex(ValueError, "source_ids must contain"):
            Claim("CLM-1", "Fact", ClaimState.CONFIRMED, 1.0, ("../source",), "Fact")
        with self.assertRaisesRegex(ValueError, "asset_id must contain"):
            Asset("../asset", "original.svg", RightsStatus.ORIGINAL_GENERATED)

    def test_duplicate_claim_and_source_identifiers_are_rejected(self) -> None:
        with self.assertRaisesRegex(ValueError, "source_ids must be unique"):
            Claim(
                "CLM-1",
                "Fact",
                ClaimState.CONFIRMED,
                1.0,
                ("SRC-1", "SRC-1"),
                "Fact",
            )
        with self.assertRaisesRegex(ValueError, "claim_ids must be unique"):
            package(claim_ids=["CLM-1", "CLM-1"])


if __name__ == "__main__":
    unittest.main()
