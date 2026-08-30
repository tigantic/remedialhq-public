# Release Notes: v0.7.2

Release date: August 30, 2026

## Hardened production runtime

- Replaced the vulnerable general-purpose runtime with digest-pinned Chainguard Python 3.14 builder and runtime images.
- Split media and development dependencies away from the deployed service. The runtime lock contains only the application and required cloud adapters.
- Runs as UID and GID 65532 with no package manager, shell, pip, setuptools, or wheel in the final image.
- Generated a complete Syft CycloneDX inventory from the exact immutable validation image.

## Fail-closed vulnerability policy

- Trivy result: PASS with 0 Critical and 0 High findings.
- Grype result: PASS with 0 Critical and 0 High findings.
- Both reports must identify the same immutable image ID. Missing tools, malformed reports, identity mismatches, unfixed findings, and any Critical or High finding fail the release.
- CI and deployment workflows enforce the same independent dual-scanner policy before an image can advance.

## Supply-chain controls

- The source-controlled workflow produces BuildKit provenance and SBOM attestations, verifies their attachment to the application manifest, signs the immutable image digest with keyless Cosign, and verifies the signature before deployment.
- Google Artifact Analysis APIs are enabled. The workflow waits for complete OS and Python analysis, explicitly requests SBOM export once, and then requires an exact-image signed SPDX reference before evaluating findings.
- A bucket-restricted read grant lets the workflow download only Artifact Analysis SBOM objects, match the referenced bytes to the signed hash, and validate the image-bound SPDX 2.3 inventory.
- The authenticated read-only Google API response is the signature trust boundary. The workflow does not claim independent cryptographic verification against Google's unavailable KMS public key.
- Google's exact singleton `[null]` clean response is preserved as raw evidence and narrowly normalized to zero finding objects. Every other malformed null shape fails closed.
- A prior v0.7.0 cloud build produced Google-signed SLSA provenance but failed the vulnerability threshold and was not deployed.
- A separate v0.7.1 audit produced signed SLSA level 3 provenance, a signed SPDX reference, and zero Google finding objects. It was not deployed because the GitHub-hosted workflow did not execute.
- The GitHub-hosted keyless path remains unexecuted because the repository's Actions jobs were not allocated a runner. Source-controlled controls are not represented as executed evidence.

## Deliberately pending

Cloud Run remains private, manually held at zero instances, and on the accepted v0.6.1 digest until every v0.7.2 cloud gate passes. The qualified 14-day outreach run, paid-pilot fulfillment, GitHub Actions runner entitlement resolution, root-account hardening, registrar renewal and MFA checks, YouTube feature verification, application and ledger subdomains, analytics, newsletter automation, OAuth grants, live source collection, and automated channel publication remain open. This release does not claim first revenue or autonomous public operation.
