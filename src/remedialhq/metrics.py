from __future__ import annotations

from dataclasses import dataclass
from itertools import pairwise


@dataclass(frozen=True, slots=True)
class UnitEconomics:
    revenue: float
    variable_cost: float
    fixed_cost_allocation: float = 0.0

    @property
    def contribution(self) -> float:
        return round(self.revenue - self.variable_cost - self.fixed_cost_allocation, 2)

    @property
    def margin(self) -> float:
        if self.revenue <= 0:
            return 0.0
        return round(self.contribution / self.revenue, 4)


def retention_auc(retention_points: list[float]) -> float:
    """Normalized trapezoidal area under a 0..1 audience-retention curve."""
    if len(retention_points) < 2:
        raise ValueError("at least two retention points are required")
    if any(point < 0 or point > 1 for point in retention_points):
        raise ValueError("retention points must be within [0, 1]")
    area = sum((a + b) / 2 for a, b in pairwise(retention_points))
    return round(area / (len(retention_points) - 1), 4)
