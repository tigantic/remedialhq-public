#!/usr/bin/env python3
from __future__ import annotations

import csv
import json
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
CONFIG = ROOT / "config/revenue.json"
OUTPUT_DIR = ROOT / "artifacts/revenue"


def require_unit_rate(value: Any, label: str) -> float:
    rate = float(value)
    if not 0.0 <= rate <= 1.0:
        raise ValueError(f"{label} must be between 0 and 1")
    return rate


def require_nonnegative(value: Any, label: str) -> float:
    number = float(value)
    if number < 0.0:
        raise ValueError(f"{label} must be nonnegative")
    return number


def require_positive(value: Any, label: str) -> float:
    number = float(value)
    if number <= 0.0:
        raise ValueError(f"{label} must be greater than zero")
    return number


def calculate_first_dollar(row: dict[str, Any]) -> dict[str, float]:
    offer = row["offer"]
    funnel = row["funnel"]
    payments = row["payments"]
    owner_time = row["owner_time"]

    prospects = require_nonnegative(funnel["personalized_prospects"], "personalized_prospects")
    reply_rate = require_unit_rate(funnel["reply_rate"], "reply_rate")
    sample_rate = require_unit_rate(
        funnel["sample_request_rate_from_replies"],
        "sample_request_rate_from_replies",
    )
    purchase_rate = require_unit_rate(
        funnel["purchase_rate_from_samples"],
        "purchase_rate_from_samples",
    )
    refund_rate = require_unit_rate(funnel["refund_rate"], "refund_rate")
    percentage_fee = require_unit_rate(payments["percentage_fee"], "percentage_fee")

    pilot_price = require_nonnegative(offer["pilot_price"], "pilot_price")
    pilot_capacity = require_positive(offer["pilot_capacity"], "pilot_capacity")
    fixed_fee = require_nonnegative(payments["fixed_fee_per_charge"], "fixed_fee_per_charge")
    outreach_minutes = require_nonnegative(
        owner_time["outreach_minutes_per_prospect"],
        "outreach_minutes_per_prospect",
    )
    sample_hours_per_request = require_nonnegative(
        owner_time["sample_hours_per_request"], "sample_hours_per_request"
    )
    fulfillment_hours_per_pilot = require_nonnegative(
        owner_time["fulfillment_hours_per_non_refunded_pilot"],
        "fulfillment_hours_per_non_refunded_pilot",
    )
    owner_hour_cost = require_nonnegative(owner_time["owner_hour_cost"], "owner_hour_cost")
    replies = prospects * reply_rate
    samples = replies * sample_rate
    purchases = samples * purchase_rate
    expected_refunds = purchases * refund_rate
    non_refunded_purchases = purchases - expected_refunds
    booked_revenue = purchases * pilot_price
    refund_amount = booked_revenue * refund_rate
    payment_fees = booked_revenue * percentage_fee + purchases * fixed_fee
    net_cash = booked_revenue - refund_amount - payment_fees

    outreach_hours = prospects * outreach_minutes / 60
    sample_hours = samples * sample_hours_per_request
    fulfillment_hours = non_refunded_purchases * fulfillment_hours_per_pilot
    total_owner_hours = outreach_hours + sample_hours + fulfillment_hours
    owner_labor_cost = total_owner_hours * owner_hour_cost
    economic_contribution = net_cash - owner_labor_cost
    net_revenue_rate = 1 - refund_rate - percentage_fee
    price_to_cover_owner_time = (
        (owner_labor_cost + purchases * fixed_fee) / (purchases * net_revenue_rate)
        if purchases and net_revenue_rate > 0
        else 0.0
    )

    results = {
        "expected_replies": replies,
        "expected_sample_requests": samples,
        "expected_purchases": purchases,
        "expected_refunds": expected_refunds,
        "expected_non_refunded_pilots": non_refunded_purchases,
        "capacity_utilization": purchases / pilot_capacity,
        "booked_revenue": booked_revenue,
        "expected_refund_amount": refund_amount,
        "payment_fees": payment_fees,
        "net_cash_after_refunds_and_fees": net_cash,
        "outreach_hours": outreach_hours,
        "sample_hours": sample_hours,
        "fulfillment_hours": fulfillment_hours,
        "total_owner_hours": total_owner_hours,
        "owner_labor_cost": owner_labor_cost,
        "economic_contribution_after_owner_labor": economic_contribution,
        "net_cash_per_owner_hour": net_cash / total_owner_hours if total_owner_hours else 0.0,
        "modeled_price_to_cover_owner_time": price_to_cover_owner_time,
    }
    return {key: round(value, 2) for key, value in results.items()}


def calculate_audience(row: dict[str, Any]) -> dict[str, float]:
    components = {
        "long_form_ads": row["long_form_views"] / 1000 * row["long_form_rpm"],
        "short_form_ads": row["short_views"] / 1000 * row["short_rpm"],
        "web_display": row["web_pageviews"] / 1000 * row["web_page_rpm"],
        "affiliate": row["affiliate_clicks"] * row["affiliate_epc"],
        "sponsorship": row["sponsor_deals"] * row["sponsor_average"],
        "newsletter": row["newsletter_placements"] * row["newsletter_average"],
    }
    gross = sum(components.values())
    cost = float(row["estimated_operating_cost"])
    components.update(
        {
            "gross_revenue": gross,
            "operating_cost": cost,
            "contribution": gross - cost,
            "contribution_margin": (gross - cost) / gross if gross else 0.0,
        }
    )
    return {key: round(value, 2) for key, value in components.items()}


def main() -> None:
    config = json.loads(CONFIG.read_text(encoding="utf-8"))
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    validation_assumptions = config["first_dollar_validation"]
    validation = {
        "assumptions": validation_assumptions,
        "results": calculate_first_dollar(validation_assumptions),
    }
    audience_results = {
        name: {"assumptions": assumptions, "results": calculate_audience(assumptions)}
        for name, assumptions in config["scenarios"].items()
    }
    (OUTPUT_DIR / "scenarios.json").write_text(
        json.dumps(
            {
                "disclaimer": config["disclaimer"],
                "first_dollar_validation": validation,
                "audience_scenario_status": config["audience_scenario_status"],
                "scenarios": audience_results,
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
    (OUTPUT_DIR / "first_dollar_validation.json").write_text(
        json.dumps(
            {"disclaimer": config["disclaimer"], **validation},
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
    with (OUTPUT_DIR / "first_dollar_validation.csv").open(
        "w", newline="", encoding="utf-8"
    ) as handle:
        validation_writer = csv.writer(handle, lineterminator="\n")
        validation_writer.writerow(["metric", "value"])
        validation_writer.writerow(["status", validation_assumptions["status"]])
        validation_writer.writerow(["disclaimer", config["disclaimer"]])
        validation_writer.writerows(validation["results"].items())
    header = [
        "scenario",
        "status",
        "disclaimer",
        "long_form_ads",
        "short_form_ads",
        "web_display",
        "affiliate",
        "sponsorship",
        "newsletter",
        "gross_revenue",
        "operating_cost",
        "contribution",
        "contribution_margin",
    ]
    with (OUTPUT_DIR / "scenarios.csv").open("w", newline="", encoding="utf-8") as handle:
        audience_writer = csv.DictWriter(handle, fieldnames=header, lineterminator="\n")
        audience_writer.writeheader()
        for name, payload in audience_results.items():
            audience_writer.writerow(
                {
                    "scenario": name,
                    "status": config["audience_scenario_status"],
                    "disclaimer": config["disclaimer"],
                    **payload["results"],
                }
            )
    first_dollar = validation["results"]
    print(
        "first-dollar "
        f"prospects={validation_assumptions['funnel']['personalized_prospects']} "
        f"expected_purchases={first_dollar['expected_purchases']:.1f} "
        f"booked=${first_dollar['booked_revenue']:,.0f} "
        f"net_cash=${first_dollar['net_cash_after_refunds_and_fees']:,.0f} "
        f"economic_contribution=${first_dollar['economic_contribution_after_owner_labor']:,.0f}"
    )
    print(config["audience_scenario_status"])
    for name, payload in audience_results.items():
        result = payload["results"]
        print(
            f"{name:9s} gross=${result['gross_revenue']:,.0f} "
            f"contribution=${result['contribution']:,.0f} "
            f"margin={result['contribution_margin']:.1%}"
        )
    print(config["disclaimer"])


if __name__ == "__main__":
    main()
