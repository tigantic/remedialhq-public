from __future__ import annotations

import unittest

from remedialhq.scoring import OpportunitySignals, score


class ScoringTests(unittest.TestCase):
    def test_rights_risk_reduces_score(self) -> None:
        common = {
            "demand": 0.9,
            "momentum": 0.9,
            "competition_advantage": 0.7,
            "evidence_readiness": 0.9,
            "originality_headroom": 0.8,
            "revenue_intent": 0.7,
            "shelf_life": 0.8,
        }
        safe = score(OpportunitySignals(**common, rights_risk=0.0))
        risky = score(OpportunitySignals(**common, rights_risk=1.0))
        self.assertGreater(safe, risky)
        self.assertAlmostEqual(safe - risky, 0.2)

    def test_bounds_are_enforced(self) -> None:
        with self.assertRaises(ValueError):
            OpportunitySignals(2, 0, 0, 0, 0, 0, 0, 0)


if __name__ == "__main__":
    unittest.main()
