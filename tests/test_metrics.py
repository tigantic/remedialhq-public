from __future__ import annotations

import unittest

from remedialhq.metrics import UnitEconomics, retention_auc


class MetricsTests(unittest.TestCase):
    def test_unit_economics(self) -> None:
        unit = UnitEconomics(revenue=100, variable_cost=25, fixed_cost_allocation=5)
        self.assertEqual(unit.contribution, 70)
        self.assertEqual(unit.margin, 0.7)

    def test_retention_auc(self) -> None:
        self.assertEqual(retention_auc([1.0, 0.8, 0.6]), 0.8)


if __name__ == "__main__":
    unittest.main()
