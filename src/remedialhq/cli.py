from __future__ import annotations

import argparse
import hashlib
import json
import os
import stat
import sys
from dataclasses import asdict, fields
from pathlib import Path

from .auth import (
    authorize_youtube,
    install_secret_version,
    load_youtube_credentials,
    resolve_youtube_channel,
)
from .briefing import build_creator_brief
from .delivery_evidence import DeliveryEvidence, load_delivery_evidence
from .execution import execution_summary, load_execution_plan
from .gates import evaluate
from .ledger import HashLedger
from .outreach import load_outreach_plan
from .payment_evidence import LivePaymentEvidence, load_live_payment_evidence
from .pilots import (
    ContactChannel,
    FeedbackOutcome,
    OpaqueIdKind,
    OwnerTimeCategory,
    PilotEventType,
    PilotLedger,
    ProspectSegment,
    ReplyOutcome,
    RiskKind,
    RiskSeverity,
    SuppressionStatus,
    new_opaque_id,
    write_order_manifest,
)
from .pipeline import build_content_packages, load_claims, run_demo
from .publishers.youtube import YouTubePublisher
from .scoring import OpportunitySignals, score


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="remedialhq")
    sub = parser.add_subparsers(dest="command", required=True)

    status = sub.add_parser("status", help="show owner execution status and ready actions")
    status.add_argument("--plan", default="ops/execution_plan.json")
    status.add_argument("--limit", type=int, default=12)
    status.add_argument("--json", action="store_true", dest="as_json")

    demo = sub.add_parser("demo", help="run a deterministic gated dry run")
    demo.add_argument("--root", default=".")
    demo.add_argument("--output", default="artifacts/demo")

    verify = sub.add_parser("verify-ledger", help="verify a hash-chained ledger")
    verify.add_argument("path")

    rank = sub.add_parser("score", help="score one content opportunity")
    for field in fields(OpportunitySignals):
        rank.add_argument(f"--{field.name.replace('_', '-')}", type=float, required=True)

    auth = sub.add_parser("auth", help="complete an owner-controlled OAuth bootstrap")
    auth_sub = auth.add_subparsers(dest="provider", required=True)
    youtube = auth_sub.add_parser("youtube", help="authorize the ReMediaLHQ YouTube channel")
    youtube.add_argument("--client-secrets", required=True)
    youtube.add_argument("--token-output", required=True)
    youtube.add_argument("--no-browser", action="store_true")
    youtube.add_argument("--secret-project")
    youtube.add_argument("--secret-id")

    publish = sub.add_parser("publish-youtube", help="perform an explicit owner-authorized upload")
    publish.add_argument("--root", default=".")
    publish.add_argument("--token-file", required=True)
    publish.add_argument("--media", required=True)
    publish.add_argument("--thumbnail")
    publish.add_argument("--expected-channel-id", required=True)
    publish.add_argument("--privacy", choices=("private", "unlisted", "public"), default="private")
    publish.add_argument(
        "--authorize-visible",
        action="store_true",
        help="explicitly authorize an unlisted or public upload",
    )

    brief = sub.add_parser(
        "creator-brief", help="render a source-linked Creator Signal Desk brief"
    )
    brief.add_argument("--root", default=".")
    brief.add_argument("--output", required=True)
    brief.add_argument("--title", required=True)
    brief.add_argument("--audience", default="gaming creators")
    brief.add_argument("--claim-id", action="append", dest="claim_ids")
    brief.add_argument("--order-manifest")
    brief.add_argument("--pilot-ledger")
    brief.add_argument("--manifest-output")
    brief.add_argument("--angle", action="append", default=[])

    pilot = sub.add_parser("pilot", help="operate the private five-slot paid-pilot ledger")
    pilot_sub = pilot.add_subparsers(dest="pilot_command", required=True)

    def pilot_command(name: str, help_text: str) -> argparse.ArgumentParser:
        command = pilot_sub.add_parser(name, help=help_text)
        command.add_argument("--ledger", default="local-private/pilot-events.jsonl")
        command.add_argument("--occurred-at")
        return command

    identifier = pilot_sub.add_parser("new-id", help="generate a privacy-safe opaque ID")
    identifier.add_argument(
        "kind",
        choices=tuple(kind.name.casefold().replace("_", "-") for kind in OpaqueIdKind),
    )

    initialize = pilot_sub.add_parser(
        "init",
        help="initialize the private ledger with lifetime-slot reconciliation",
    )
    initialize.add_argument("--ledger", default="local-private/pilot-events.jsonl")
    initialize.add_argument("--reconciliation-evidence", required=True)
    initialize.add_argument("--prior-ledger")

    outreach_validate = pilot_sub.add_parser(
        "outreach-validate",
        help="validate a private qualified-prospect plan without sending outreach",
    )
    outreach_validate.add_argument("--input", required=True)

    outreach_import = pilot_command(
        "outreach-import",
        "import one complete private 50-prospect outreach plan",
    )
    outreach_import.add_argument("--input", required=True)

    outreach_amend = pilot_command(
        "outreach-amend",
        "replace one pre-contact opted-out prospect using a revised private plan",
    )
    outreach_amend.add_argument("--input", required=True)

    outreach_queue = pilot_sub.add_parser(
        "outreach-queue",
        help="show the privacy-minimized campaign queue and next controls",
    )
    outreach_queue.add_argument("--ledger", default="local-private/pilot-events.jsonl")
    outreach_queue.add_argument("--as-of")

    add_prospect = pilot_command("add-prospect", "add one qualified prospect")
    add_prospect.add_argument("--prospect-id")
    add_prospect.add_argument(
        "--segment", choices=tuple(item.value for item in ProspectSegment), required=True
    )

    contacted = pilot_command("contact", "record first contact through a public channel")
    contacted.add_argument("--prospect-id", required=True)
    contacted.add_argument(
        "--channel", choices=tuple(item.value for item in ContactChannel), required=True
    )

    suppression_check = pilot_command(
        "suppression-check",
        "record a fresh clear or opted-out suppression-list check",
    )
    suppression_check.add_argument("--prospect-id", required=True)
    suppression_check.add_argument(
        "--status",
        choices=(SuppressionStatus.CLEAR.value, SuppressionStatus.OPTED_OUT.value),
        required=True,
    )
    suppression_check.add_argument("--evidence-sha256", required=True)

    replied = pilot_command("reply", "record an enumerated reply outcome")
    replied.add_argument("--prospect-id", required=True)
    replied.add_argument(
        "--outcome", choices=tuple(item.value for item in ReplyOutcome), required=True
    )

    sample = pilot_command("sample", "record a sample request")
    sample.add_argument("--prospect-id", required=True)

    scope = pilot_command("scope", "confirm pre-payment scope and evidence claims")
    scope.add_argument("--prospect-id", required=True)
    scope.add_argument("--scope-ref")
    scope.add_argument("--deadline", required=True)
    scope.add_argument("--terms-version", required=True)
    scope.add_argument("--claim-id", action="append", required=True, dest="claim_ids")

    amend_scope = pilot_command(
        "amend-scope",
        "replace active scope and require fresh acceptance",
    )
    amend_scope.add_argument("--prospect-id", required=True)
    amend_scope.add_argument("--supersedes-scope-ref", required=True)
    amend_scope.add_argument("--scope-ref")
    amend_scope.add_argument("--deadline", required=True)
    amend_scope.add_argument("--terms-version", required=True)
    amend_scope.add_argument(
        "--claim-id",
        action="append",
        required=True,
        dest="claim_ids",
    )

    customer_acceptance = pilot_command(
        "customer-acceptance",
        "record explicit written customer acceptance before checkout",
    )
    customer_acceptance.add_argument("--prospect-id", required=True)
    customer_acceptance.add_argument("--scope-ref", required=True)
    customer_acceptance.add_argument("--acceptance-ref")
    customer_acceptance.add_argument("--evidence-sha256", required=True)

    checkout = pilot_command("checkout", "record that a checkout was sent")
    checkout.add_argument("--prospect-id", required=True)
    checkout.add_argument("--checkout-ref")

    purchase = pilot_command("purchase", "record an evidenced live founding purchase")
    purchase.add_argument("--prospect-id", required=True)
    purchase.add_argument("--order-id", required=True)
    purchase.add_argument("--payment-evidence", required=True)
    purchase.add_argument("--fee-cents", type=int, required=True)

    accept_order = pilot_command(
        "accept-order", "record post-payment seller acceptance before fulfillment"
    )
    accept_order.add_argument("--prospect-id", required=True)
    accept_order.add_argument("--scope-ref", required=True)
    accept_order.add_argument("--acceptance-ref")
    accept_order.add_argument("--evidence-sha256", required=True)

    reject_order = pilot_command(
        "reject-order", "reject a captured order so it can only be refunded"
    )
    reject_order.add_argument("--prospect-id", required=True)
    reject_order.add_argument("--rejection-ref")

    cancellation = pilot_command(
        "cancel", "record an opaque cancellation request and stop fulfillment"
    )
    cancellation.add_argument("--prospect-id", required=True)
    cancellation.add_argument("--cancellation-ref")

    opted_out = pilot_command("opt-out", "suppress future prospect contact")
    opted_out.add_argument("--prospect-id", required=True)
    opted_out.add_argument("--evidence-sha256")

    owner_time = pilot_command("time", "record owner time without a free-form note")
    owner_time.add_argument("--prospect-id", required=True)
    owner_time.add_argument("--time-entry-id")
    owner_time.add_argument(
        "--category", choices=tuple(item.value for item in OwnerTimeCategory), required=True
    )
    owner_time.add_argument("--minutes", type=int, required=True)

    risk = pilot_command("risk", "record an enumerated material risk incident")
    risk.add_argument("--incident-id")
    risk.add_argument("--prospect-id")
    risk.add_argument("--kind", choices=tuple(item.value for item in RiskKind), required=True)
    risk.add_argument(
        "--severity", choices=tuple(item.value for item in RiskSeverity), required=True
    )

    fulfillment = pilot_command("start", "record that paid fulfillment started")
    fulfillment.add_argument("--prospect-id", required=True)

    completed = pilot_command("complete-artifact", "record local artifact completion")
    completed.add_argument("--prospect-id", required=True)
    completed.add_argument("--artifact", required=True)

    delivered = pilot_command("deliver", "record externally evidenced delivery")
    delivered.add_argument("--prospect-id", required=True)
    delivered.add_argument("--order-id", required=True)
    delivered.add_argument("--delivery-evidence", required=True)

    feedback = pilot_command("feedback", "record enumerated buyer feedback")
    feedback.add_argument("--prospect-id", required=True)
    feedback.add_argument("--feedback-id")
    feedback.add_argument(
        "--outcome",
        action="append",
        choices=tuple(item.value for item in FeedbackOutcome),
        required=True,
        dest="outcomes",
    )

    refund = pilot_command("refund", "record a verified full refund")
    refund.add_argument("--prospect-id", required=True)
    refund.add_argument("--order-id", required=True)
    refund.add_argument("--refund-evidence", required=True)

    summary = pilot_sub.add_parser("summary", help="show aggregate pilot metrics and gate")
    summary.add_argument("--ledger", default="local-private/pilot-events.jsonl")
    verify_pilot = pilot_sub.add_parser("verify", help="verify pilot hash and workflow history")
    verify_pilot.add_argument("--ledger", default="local-private/pilot-events.jsonl")
    order = pilot_sub.add_parser("order", help="show one privacy-minimized order projection")
    order.add_argument("--ledger", default="local-private/pilot-events.jsonl")
    order.add_argument("--order-id", required=True)
    orders = pilot_sub.add_parser("orders", help="show all privacy-minimized order projections")
    orders.add_argument("--ledger", default="local-private/pilot-events.jsonl")
    order_manifest = pilot_sub.add_parser(
        "order-manifest", help="write one ledger-anchored order manifest"
    )
    order_manifest.add_argument("--ledger", default="local-private/pilot-events.jsonl")
    order_manifest.add_argument("--order-id", required=True)
    order_manifest.add_argument("--output", required=True)
    return parser


def _status(args: argparse.Namespace) -> int:
    plan_path = Path(args.plan)
    if not plan_path.is_file():
        print(
            "owner execution plan is private or absent; pass --plan PATH to an available plan",
            file=sys.stderr,
        )
        return 2
    summary = execution_summary(load_execution_plan(plan_path))
    if args.as_json:
        print(json.dumps(summary, indent=2, sort_keys=True))
        return 0
    counts = summary["counts"]
    print(f"ReMediaLHQ execution status as of {summary['as_of']}")
    print(
        f"{summary['total']} tasks: {counts.get('DONE', 0)} done, "
        f"{counts.get('TODO', 0)} active, {counts.get('LATER', 0)} later-stage"
    )
    print("\nReady actions:")
    for task in summary["ready"][: max(0, args.limit)]:
        print(f"  {task['task_id']}  {task['action']}")
    return 0


def _authorize(args: argparse.Namespace) -> int:
    result = authorize_youtube(
        args.client_secrets,
        args.token_output,
        open_browser=not args.no_browser,
    )
    if args.secret_project:
        if not args.secret_id:
            raise ValueError("--secret-id is required with --secret-project")
        result["secret_manager"] = install_secret_version(
            args.secret_project, args.secret_id, args.token_output
        )
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


def _publish_youtube(args: argparse.Namespace) -> int:
    root = Path(args.root).resolve()
    if args.privacy != "private" and not args.authorize_visible:
        raise PermissionError("visible publication requires --authorize-visible")
    authority = json.loads(
        (root / "config/publication_authority.json").read_text(encoding="utf-8")
    )
    youtube_authority = authority.get("platforms", {}).get("youtube", {})
    if not youtube_authority.get("private_upload_authorized"):
        raise PermissionError("repository authority does not permit a private YouTube upload")
    if args.privacy != "private" and not (
        authority.get("global_publication_enabled")
        and youtube_authority.get("visible_upload_authorized")
    ):
        raise PermissionError("repository authority does not permit a visible YouTube upload")
    packages = [
        package
        for package in build_content_packages(root)
        if package.platform.casefold() == "youtube"
    ]
    if len(packages) != 1:
        raise RuntimeError(f"expected one YouTube package, received {len(packages)}")
    claim_map = {
        claim.claim_id: claim
        for claim in load_claims(root / "data/claims/seed_claims.jsonl")
    }
    gate_report = evaluate(
        packages[0], [claim_map[claim_id] for claim_id in packages[0].claim_ids]
    )
    if gate_report.decision.value != "PASS":
        raise PermissionError("content gates did not pass")
    credentials = load_youtube_credentials(args.token_file, persist_refresh=False)
    channel = resolve_youtube_channel(credentials)
    if channel["channel_id"] != args.expected_channel_id:
        raise PermissionError("authorized YouTube channel does not match --expected-channel-id")
    publisher = YouTubePublisher(
        credentials,
        args.media,
        privacy_status=args.privacy,
        public_publication_authorized=args.authorize_visible,
        thumbnail_path=args.thumbnail,
        asset_root=root,
    )
    result = publisher.publish(packages[0])
    print(json.dumps(result.to_dict(), indent=2, sort_keys=True))
    return 0


def _creator_brief(args: argparse.Namespace) -> int:
    result = build_creator_brief(
        args.root,
        args.output,
        title=args.title,
        audience=args.audience,
        claim_ids=args.claim_ids,
        angles=args.angle,
        order_manifest=args.order_manifest,
        pilot_ledger=args.pilot_ledger,
        manifest_output=args.manifest_output,
    )
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


def _sha256_artifact(path: str | Path) -> str:
    artifact = Path(path)
    PilotLedger._assert_safe_ancestors(artifact)
    try:
        before = os.lstat(artifact)
    except OSError:
        before = None
    if before is None or stat.S_ISLNK(before.st_mode) or not stat.S_ISREG(before.st_mode):
        raise FileNotFoundError("--artifact must identify a readable file")
    digest = hashlib.sha256()
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(artifact, flags)
    except OSError as exc:
        raise FileNotFoundError("--artifact must identify a readable file") from exc
    try:
        opened = os.fstat(descriptor)
        if (
            not stat.S_ISREG(opened.st_mode)
            or (before.st_dev, before.st_ino) != (opened.st_dev, opened.st_ino)
        ):
            raise FileNotFoundError("--artifact must identify a stable regular file")
        with os.fdopen(descriptor, "rb") as handle:
            descriptor = -1
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    return digest.hexdigest()


def _pilot(args: argparse.Namespace) -> int:
    command = args.pilot_command
    if command == "new-id":
        kind_name = args.kind.replace("-", "_").upper()
        print(new_opaque_id(OpaqueIdKind[kind_name]))
        return 0

    if command == "outreach-validate":
        plan = load_outreach_plan(args.input)
        print(json.dumps(plan.validation_report(), indent=2, sort_keys=True))
        return 0

    if command == "init":
        reconciliation_digest = _sha256_artifact(args.reconciliation_evidence)
        prior_slots = 0
        prior_head: str | None = None
        if args.prior_ledger:
            prior_slots, prior_head = PilotLedger.reconcile_prior_ledger(
                args.prior_ledger
            )
        ledger = PilotLedger.initialize(
            args.ledger,
            prior_consumed_slots=prior_slots,
            reconciliation_evidence_sha256=reconciliation_digest,
            prior_ledger_head_sha256=prior_head,
        )
        print(
            json.dumps(
                {
                    "ledger": str(ledger.path),
                    "prior_consumed_slots": prior_slots,
                    "reconciliation_evidence_sha256": reconciliation_digest,
                    "remaining_founding_slots": ledger.metrics().remaining_founding_slots,
                },
                indent=2,
                sort_keys=True,
            )
        )
        return 0

    ledger = PilotLedger(args.ledger)
    if command == "outreach-import":
        plan = load_outreach_plan(args.input)
        result = ledger.import_outreach_plan(plan, occurred_at=args.occurred_at)
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0
    if command == "outreach-amend":
        plan = load_outreach_plan(args.input)
        result = ledger.amend_outreach_plan(plan, occurred_at=args.occurred_at)
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0
    if command == "outreach-queue":
        queue = ledger.outreach_queue(as_of=args.as_of)
        print(
            json.dumps(
                {
                    "campaign_ref": queue[0].campaign_ref if queue else None,
                    "entries": [asdict(entry) for entry in queue],
                    "prospects": len(queue),
                },
                indent=2,
                sort_keys=True,
            )
        )
        return 0
    if command == "summary":
        result = asdict(ledger.metrics())
        result["private_mode_enforced"] = ledger.private_mode_enforced
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0
    if command == "verify":
        ok, message = ledger.verify()
        print(message)
        return 0 if ok else 2
    if command == "order":
        print(json.dumps(asdict(ledger.order(args.order_id)), indent=2, sort_keys=True))
        return 0
    if command == "orders":
        print(
            json.dumps(
                [asdict(order) for order in ledger.orders()],
                indent=2,
                sort_keys=True,
            )
        )
        return 0
    if command == "order-manifest":
        order = ledger.order(args.order_id)
        output_path = Path(args.output)
        if output_path.resolve() == ledger.path.resolve():
            raise ValueError("--output must not overwrite the pilot ledger")
        manifest_sha256 = write_order_manifest(
            output_path,
            order,
            ledger_head_sha256=ledger.head,
        )
        print(
            json.dumps(
                {
                    "manifest_sha256": manifest_sha256,
                    "order_id": order.order_id,
                    "output": str(output_path),
                },
                indent=2,
                sort_keys=True,
            )
        )
        return 0

    event: PilotEventType
    payload: dict[str, object]
    payment_evidence: LivePaymentEvidence | None = None
    delivery_evidence: DeliveryEvidence | None = None
    if command == "add-prospect":
        event = PilotEventType.PROSPECT_ADDED
        payload = {
            "prospect_id": args.prospect_id or new_opaque_id(OpaqueIdKind.PROSPECT),
            "segment": args.segment,
        }
    elif command == "contact":
        event = PilotEventType.CONTACTED
        payload = {"prospect_id": args.prospect_id, "channel": args.channel}
    elif command == "suppression-check":
        event = PilotEventType.SUPPRESSION_CHECKED
        payload = {
            "prospect_id": args.prospect_id,
            "status": args.status,
            "evidence_sha256": args.evidence_sha256,
        }
    elif command == "reply":
        event = PilotEventType.REPLIED
        payload = {"prospect_id": args.prospect_id, "outcome": args.outcome}
    elif command == "sample":
        event = PilotEventType.SAMPLE_REQUESTED
        payload = {"prospect_id": args.prospect_id}
    elif command == "scope":
        event = PilotEventType.SCOPE_CONFIRMED
        payload = {
            "prospect_id": args.prospect_id,
            "scope_ref": args.scope_ref or new_opaque_id(OpaqueIdKind.SCOPE),
            "deadline": args.deadline,
            "terms_version": args.terms_version,
            "claim_ids": args.claim_ids,
        }
    elif command == "amend-scope":
        event = PilotEventType.SCOPE_AMENDED
        payload = {
            "prospect_id": args.prospect_id,
            "supersedes_scope_ref": args.supersedes_scope_ref,
            "scope_ref": args.scope_ref or new_opaque_id(OpaqueIdKind.SCOPE),
            "deadline": args.deadline,
            "terms_version": args.terms_version,
            "claim_ids": args.claim_ids,
        }
    elif command == "customer-acceptance":
        event = PilotEventType.CUSTOMER_ACCEPTANCE_RECORDED
        payload = {
            "prospect_id": args.prospect_id,
            "scope_ref": args.scope_ref,
            "customer_acceptance_ref": args.acceptance_ref
            or new_opaque_id(OpaqueIdKind.CUSTOMER_ACCEPTANCE),
            "acceptance_evidence_sha256": args.evidence_sha256,
        }
    elif command == "checkout":
        event = PilotEventType.CHECKOUT_SENT
        payload = {
            "prospect_id": args.prospect_id,
            "checkout_ref": args.checkout_ref or new_opaque_id(OpaqueIdKind.CHECKOUT),
        }
    elif command == "purchase":
        event = PilotEventType.PURCHASED
        payment_evidence = load_live_payment_evidence(
            args.payment_evidence,
            expected_order_id=args.order_id,
        )
        payload = {
            "prospect_id": args.prospect_id,
            "order_id": args.order_id,
            "fee_cents": args.fee_cents,
        }
    elif command == "accept-order":
        event = PilotEventType.ORDER_ACCEPTED
        payload = {
            "prospect_id": args.prospect_id,
            "scope_ref": args.scope_ref,
            "order_acceptance_ref": args.acceptance_ref
            or new_opaque_id(OpaqueIdKind.ORDER_ACCEPTANCE),
            "acceptance_evidence_sha256": args.evidence_sha256,
        }
    elif command == "reject-order":
        event = PilotEventType.ORDER_REJECTED
        payload = {
            "prospect_id": args.prospect_id,
            "order_rejection_ref": args.rejection_ref
            or new_opaque_id(OpaqueIdKind.ORDER_REJECTION),
        }
    elif command == "cancel":
        event = PilotEventType.CANCELLATION_REQUESTED
        payload = {
            "prospect_id": args.prospect_id,
            "cancellation_ref": args.cancellation_ref
            or new_opaque_id(OpaqueIdKind.CANCELLATION),
        }
    elif command == "opt-out":
        event = PilotEventType.OPTED_OUT
        payload = {
            "prospect_id": args.prospect_id,
            **(
                {"evidence_sha256": args.evidence_sha256}
                if args.evidence_sha256
                else {}
            ),
        }
    elif command == "time":
        event = PilotEventType.OWNER_TIME_RECORDED
        payload = {
            "prospect_id": args.prospect_id,
            "time_entry_id": args.time_entry_id
            or new_opaque_id(OpaqueIdKind.TIME_ENTRY),
            "category": args.category,
            "minutes": args.minutes,
        }
    elif command == "risk":
        event = PilotEventType.RISK_INCIDENT_RECORDED
        payload = {
            "incident_id": args.incident_id or new_opaque_id(OpaqueIdKind.INCIDENT),
            "kind": args.kind,
            "severity": args.severity,
            **({"prospect_id": args.prospect_id} if args.prospect_id else {}),
        }
    elif command == "start":
        event = PilotEventType.FULFILLMENT_STARTED
        payload = {"prospect_id": args.prospect_id}
    elif command == "complete-artifact":
        event = PilotEventType.ARTIFACT_COMPLETED
        payload = {
            "prospect_id": args.prospect_id,
            "deliverable_sha256": _sha256_artifact(args.artifact),
        }
    elif command == "deliver":
        event = PilotEventType.DELIVERED
        order = ledger.order(args.order_id)
        if order.prospect_id != args.prospect_id:
            raise ValueError("--prospect-id does not match --order-id")
        if order.deliverable_sha256 is None:
            raise ValueError("delivery requires a completed artifact")
        delivery_evidence = load_delivery_evidence(
            args.delivery_evidence,
            expected_order_id=args.order_id,
            expected_artifact_sha256=order.deliverable_sha256,
        )
        payload = {
            "prospect_id": args.prospect_id,
            "order_id": args.order_id,
        }
    elif command == "feedback":
        event = PilotEventType.FEEDBACK_RECORDED
        payload = {
            "prospect_id": args.prospect_id,
            "feedback_id": args.feedback_id or new_opaque_id(OpaqueIdKind.FEEDBACK),
            "outcomes": args.outcomes,
        }
    elif command == "refund":
        event = PilotEventType.REFUNDED
        payment_evidence = load_live_payment_evidence(
            args.refund_evidence,
            expected_order_id=args.order_id,
        )
        payload = {
            "prospect_id": args.prospect_id,
            "order_id": args.order_id,
        }
    else:
        raise RuntimeError(f"unsupported pilot command: {command}")

    record = ledger.record(
        event,
        payload,
        occurred_at=args.occurred_at,
        payment_evidence=payment_evidence,
        delivery_evidence=delivery_evidence,
    )
    print(json.dumps(record, indent=2, sort_keys=True))
    return 0


def main() -> None:
    args = _parser().parse_args()
    if args.command == "status":
        raise SystemExit(_status(args))
    if args.command == "demo":
        result = run_demo(args.root, args.output)
        print(json.dumps(result, indent=2, sort_keys=True))
        raise SystemExit(0 if result["ledger_verified"] else 2)
    if args.command == "verify-ledger":
        ok, message = HashLedger(Path(args.path)).verify()
        print(message)
        raise SystemExit(0 if ok else 2)
    if args.command == "score":
        values = {field.name: getattr(args, field.name) for field in fields(OpportunitySignals)}
        print(f"{score(OpportunitySignals(**values)):.4f}")
        return
    if args.command == "auth" and args.provider == "youtube":
        raise SystemExit(_authorize(args))
    if args.command == "publish-youtube":
        raise SystemExit(_publish_youtube(args))
    if args.command == "creator-brief":
        raise SystemExit(_creator_brief(args))
    if args.command == "pilot":
        raise SystemExit(_pilot(args))
    raise RuntimeError("unreachable")


if __name__ == "__main__":
    main()
