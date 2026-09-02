# ReMediaLHQ YouTube API Compliance Audit Package

## Package status

| Field | Value |
| --- | --- |
| Task | RMH-114 |
| Prepared | 2026-09-01 |
| Owner-independent package | Assembled and source-bound |
| Public policy deployment | **Verified on Sites version 19 at remedialhq.com** |
| YouTube audit submission | **Not submitted** |
| Blocking prerequisite | **RMH-113 private and unlisted soak evidence is pending** |
| Repository publication authority | `SITE_ONLY_GRANTED`; global publication disabled; YouTube private and visible upload authority both disabled |
| Sensitive material | Excluded; this package contains no OAuth client secret, access token, refresh token, channel ID, Google Cloud project ID, or private owner contact |

This is a reviewable audit draft, not proof that RMH-114 is complete. The updated public policies are deployed and exact-content readback is complete. The owner-controlled RMH-113 soak, completion of the official audit form, and a submission receipt or case identifier remain required. The integrity-bound evidence is listed in `ops/YOUTUBE_API_COMPLIANCE_EVIDENCE_MANIFEST.json`.

## API client and use case

ReMediaLHQ is an owner-operated editorial production workflow for one expressly authorized ReMediaLHQ YouTube channel. It uses YouTube API Services to:

1. identify the channel selected by the authorizing Google account;
2. upload an owner-reviewed video and optional thumbnail with an expressly selected privacy status;
3. detect an exact prior publication marker and fail closed before any duplicate upload or unreviewed remote mutation;
4. read video status needed to verify the upload and processing result; and
5. retrieve the authorized channel's YouTube Analytics reports for owner review.

The public website does not ask visitors or Creator Signal Desk customers to connect a YouTube account. The OAuth client is used only by the channel owner or an operator expressly authorized by that owner. ReMediaLHQ does not request a YouTube username or password, download YouTube audiovisual content, sell YouTube API data, build cross-channel profiles, or expose authorized data to the public.

## Owner-only fields for the official form

The submitter must enter these values directly in the official YouTube audit form or owner-private evidence store. They must not be added to this repository or to a public attachment:

- Google Cloud project ID and project number;
- OAuth client ID and consent-screen configuration identifiers;
- authorized YouTube channel ID and any nonpublic channel evidence;
- submitter legal identity, private email address, phone number, and account identifiers;
- current quota, requested quota, audit or support case number, and any Google correspondence; and
- raw OAuth responses, client-secret files, access tokens, refresh tokens, or secret-store references.

No audit reviewer needs the value of a client secret or bearer token. Demonstrations and screenshots must redact those values and any unrelated account data.

## Public disclosures

The canonical public routes are:

- Privacy Policy: <https://remedialhq.com/privacy>
- Terms of Use: <https://remedialhq.com/terms>
- Data Deletion Requests: <https://remedialhq.com/data-deletion>

All three source pages identify ReMediaLHQ's use of YouTube API Services, enumerate the requested scopes and API-data categories, state the limited use, and link to the [YouTube Terms of Service](https://www.youtube.com/t/terms) and [Google Privacy Policy](https://policies.google.com/privacy). The privacy and deletion pages also give the Google security-settings revocation route, the direct ReMediaLHQ request route, and the applicable refresh, retention, and deletion periods.

The official form must not represent these updated disclosures as live until the exact source pages in this package have been deployed and read back successfully at the canonical URLs.

## Scope, operation, and data map

| OAuth scope | Current or prerequisite operation | Data and purpose |
| --- | --- | --- |
| `https://www.googleapis.com/auth/youtube.upload` | `videos.insert` and `thumbnails.set` in the upload adapter | Sends only the reviewed video, thumbnail, title, description, tags, category, made-for-kids declaration, synthetic-media declaration, notification choice, and owner-selected privacy status. The adapter exposes no existing-video update path. |
| `https://www.googleapis.com/auth/youtube.readonly` | `channels.list(mine=true)`, `search.list(forMine=true)`, and `videos.list` | Resolves the authorized channel ID, title, and URL; checks for an earlier upload and verifies the exact marker against its full description; and reads the uploaded video's privacy or processing state for duplicate prevention and post-upload verification. |
| `https://www.googleapis.com/auth/yt-analytics.readonly` | `reports.query` in the read-only post-upload verifier | Reads only the authorized channel's video Analytics views and estimated watch minutes for owner review. The implementation and offline fixture validation exist; owner-token live readback remains an RMH-112/RMH-113 prerequisite before submission. |
| `https://www.googleapis.com/auth/youtube.force-ssl` | `channels.list(mine=true)`, `playlists.list(mine=true)`, `playlists.insert`, and `watermarks.set` in the fixed channel-setup command | Confirms the exact authorized channel, reconciles the seven approved playlist titles, creates only missing playlists with Private visibility, and applies only the reviewed channel watermark at offset zero. This setup token is separate from the default upload token. |

The authorization helper requests exactly the three upload and readback scopes by default. Its separate `--channel-setup` mode requests only `youtube.force-ssl`. Both modes run Google's installed-application consent flow, resolve exactly one authorized channel, serialize the resulting credential into owner-controlled storage, and write a local credential with owner-only mode `0600` where that permission can be enforced. A credential can be installed as a new Secret Manager version. Runtime loading validates the credential and refreshes it only when it is expired and has an active refresh grant.

The upload adapter builds the YouTube Data API v3 client from that credential. It defaults to `private`; an `unlisted` or `public` privacy state requires separate visible-publication authority. It verifies that the video and required thumbnail are declared, digest-matched assets in the gated content package and that the media has a matching storyboard review record. Before credentials can reach the adapter, `preview-youtube-upload` writes a create-only owner-private preview at mode `0600`. That preview binds the exact target channel, privacy state, canonical package digest, selected video and thumbnail digests, final title, description, tags, category, made-for-kids and synthetic-media declarations, subscriber-notification choice, deterministic marker, independence notice, and one canonical owner-private consumption directory. `confirm-youtube-upload` requires the operator to supply the exact preview SHA-256 and records a separate create-only express confirmation. The adapter revalidates every binding, copies the verified video and thumbnail into unlinked descriptor-backed snapshots, and atomically creates a preview-digest-scoped single-use consumption record before constructing the YouTube client. Copying or hard-linking either confirmation cannot create another consumption scope. After consumption, the API request uses only the validated preview metadata and the pinned descriptors. Reusing a consumed confirmation is rejected. A failure after consumption requires a new preview and confirmation.

The adapter performs bounded resumable-upload retries within one confirmed insert execution. Before insertion, it searches the owned channel for the deterministic marker, reads every returned candidate's full description, and accepts only the marker as its own exact line. Any exact existing marker causes a fail-closed stop with no update, thumbnail change, or new upload. Any candidate set that cannot be verified exactly also fails closed. A future remote reconciliation operation would require its own separately rendered preview and confirmation. For an initial upload, the command requires a create-only owner-private API-evidence destination and writes a sanitized response envelope atomically with mode `0600`. The read-only verifier binds that envelope to the exact channel, video, privacy state, processing result, thumbnail response, and Analytics row.

## Authority and user control

The repository authority snapshot is deliberately fail-closed:

- `authority_status` is `SITE_ONLY_GRANTED`;
- `global_publication_enabled` is `false`;
- `platforms.youtube.private_upload_authorized` is `false`; and
- `platforms.youtube.visible_upload_authorized` is `false`.

The current state therefore authorizes the public site and policy pages only. It does not authorize a private, unlisted, or public YouTube upload. The owner must separately authorize the applicable upload state after prerequisite testing. The adapter also defaults to private and rejects a visible privacy state without a separate explicit authorization. These controls must remain disabled by default during RMH-113.

Before each upload, the owner or expressly authorized operator must run the offline preview command and review the target channel, reviewed media and thumbnail digests, title and description, tags and category, made-for-kids and synthetic-media declarations, notification setting, deterministic marker, independence notice, and exact `private`, `unlisted`, or `public` choice. The operator then copies the displayed preview SHA-256 into the separate confirmation command. The upload command accepts only that exact unconsumed preview-confirmation pair. The operator retains final authority over the upload and its visibility. This implementation does not establish that the required live owner exercise or RMH-113 soak has occurred.

## Data handling

### Accessed, collected, and stored

ReMediaLHQ may process:

- OAuth grant metadata, granted scopes, access and refresh credentials, and credential expiry;
- authorized channel ID, title, and URL;
- the owner-selected video and thumbnail sent to YouTube;
- video ID, title, description, tags, category, privacy and processing status, thumbnail result, and deterministic publication marker; and
- YouTube Analytics dimensions, metrics, and reports for the authorized channel and its videos.

The workflow does not need a public user profile, YouTube login password, contacts, comments, subscriptions, liked videos, or downloaded copies of YouTube audiovisual content.

### Use and sharing

The data is used only to authenticate the grant, identify the selected channel, upload reviewed content, prevent duplicate or unreviewed marker collisions, set the thumbnail, apply or verify the expressly selected privacy state, confirm processing, and review the authorized channel's performance. Authorized data is available only to the authorizing user and agents expressly approved by that user. Data is sent to Google and YouTube through the requested API calls and may be handled by a security or storage provider only as reasonably necessary to protect the owner-controlled credential or operate the authorized workflow. It is not sold, rented, used for advertising profiles, or combined across unrelated content owners.

### Refresh, retention, revocation, and deletion

- An expired OAuth credential is refreshed only when an active refresh grant exists. A replacement credential is persisted only in owner-controlled private storage when secure persistence is enabled.
- Authorization credentials are retained only as long as necessary for the active consent and disclosed purpose.
- Stored YouTube Analytics data and statistics may be retained while needed for the consented purpose, but authorization and the continued existence of the YouTube resource must be rechecked at least every 30 days.
- Other stored Authorized Data and limited Non-Authorized Data must be refreshed or deleted within 30 calendar days. User-facing API data must reflect the freshest available result.
- A user may revoke access through [Google security settings](https://security.google.com/settings/security/permissions) or send a request through <https://remedialhq.com/data-deletion>.
- After a direct withdrawal or deletion request, ReMediaLHQ must stop API use, revoke the applicable Google authorization, and delete the local credential and related Authorized Data as soon as possible and within seven calendar days.
- If the user revokes through Google, or a credential can no longer be refreshed, associated API data must be deleted after the change is detected as soon as possible and no later than 30 calendar days.
- Deleting data stored by ReMediaLHQ does not delete a video or other data stored by YouTube. YouTube-hosted data must be deleted through YouTube or another authorized API client that supports that action.

No committed repository artifact is an approved store for a credential, raw OAuth response, private channel evidence, or identity-bearing audit correspondence.

## Known implementation gaps

The public policies state the operating rules ReMediaLHQ must follow. They do not by themselves prove that every lifecycle control is automated. As of this package date:

- the installed-application OAuth command now refuses to start Google authorization until a create-only owner-private record proves explicit acceptance of the exact current ReMediaLHQ Privacy Policy and Terms for the exact requested scopes; focused tests cover partial consent, policy drift, scope drift, future timestamps, repository storage, and evidence reuse;
- the `youtube-revoke` command now requires explicit confirmation, obtains Google revocation before deleting the exact local credential, writes redacted create-only owner-private evidence, and has focused fail-closed tests; a live owner-token exercise remains pending;
- the repository has no scheduled 30-day authorization, resource-existence, refresh, or deletion reconciler;
- the upload command has a separate immutable preview, canonical preview-digest consumption scope, exact-digest express confirmation, descriptor-pinned media, preview-only request construction after consumption, and a fail-closed exact-marker collision check; a live owner exercise remains pending;
- the read-only verifier implements the YouTube Analytics query and strict fixture validation, but owner-token live readback and soak evidence do not yet exist.

These are audit-readiness gaps, not completed controls. They must be resolved by implementation and focused tests or by a reviewer-acceptable, owner-controlled operating procedure with evidence, as applicable. In particular, an unused scope must not be requested merely for possible future use. The final submission must reflect the implementation that actually exists at submission time.

## Official-policy crosswalk

| Requirement | ReMediaLHQ evidence or control | State |
| --- | --- | --- |
| Disclose use of YouTube API Services | All three policy pages, their focused tests, and the exact-content live readback | **Deployed and verified** |
| Link YouTube Terms and bind connected-feature users | `site/terms.html`, plus links on privacy and deletion pages | **Deployed and verified** |
| Link Google Privacy Policy | All three policy pages | **Deployed and verified** |
| Explain data accessed, stored, used, and shared | `site/privacy.html`, `site/terms.html`, `site/data-deletion.html`, and this package | Prepared locally |
| Provide Google revocation route and developer contact | Privacy and deletion pages link Google security settings and `support@remedialhq.com`; `remedialhq auth youtube-revoke` revokes Google access before deleting the exact local credential | **Implemented and tested; live operational exercise pending** |
| Limit scopes to implemented, disclosed features | Scope map above; upload, readback, and Analytics-query implementations exist; owner-token live evidence awaits RMH-112/RMH-113 | **Pending live prerequisite evidence** |
| Record policy acceptance before OAuth | `remedialhq auth youtube-policy-acceptance` creates scope-bound owner-private evidence and `remedialhq auth youtube` validates it before loading the Google OAuth library | **Implemented and tested; live owner evidence pending** |
| Preserve user control over writes and privacy state | Private default, separate visible authority, reviewed content package, exact target-channel check, immutable full-input preview, express digest confirmation, canonical single-use consumption, pinned media descriptors, and no unpreviewed existing-video mutation path | **Implemented and tested; RMH-113 live exercise evidence pending** |
| Refresh or delete stored API data on schedule | Public policy commitment exists; no scheduled 30-day reconciler exists | **Implementation or reviewer-acceptable operating-control evidence pending** |
| Delete on request and after revocation | Public deletion route and seven-/30-day handling are described; the fail-closed revoke-and-delete command is implemented and tested | **Live operational exercise evidence pending** |
| Protect credentials | Owner-private token file, `0600` enforcement, optional Secret Manager installation; secrets excluded from package | Code control exists; owner environment evidence remains private |

Primary policy references checked for this draft:

- [YouTube API Services Terms of Service](https://developers.google.com/youtube/terms/api-services-terms-of-service)
- [YouTube API Services Developer Policies](https://developers.google.com/youtube/terms/developer-policies)
- [YouTube Terms of Service](https://www.youtube.com/t/terms)
- [Google Privacy Policy](https://policies.google.com/privacy)

## Evidence required before submission

### Pending RMH-113 soak evidence

RMH-113 remains `TODO`/`WAITING`, and no completion evidence is recorded. Do not mark it complete or describe the soak as performed. A sanitized RMH-113 evidence bundle must show, at minimum:

1. the repository authority and runtime publication controls disabled by default;
2. an owner-authorized private upload to the expected channel with reviewed media and thumbnail digests;
3. processing completion, exact channel identity, privacy state, thumbnail result, and Analytics retrieval;
4. an explicitly authorized transition to `unlisted`, followed by readback of that exact state;
5. bounded retry within the same confirmed insert, plus an exact-marker collision that fails closed without a duplicate upload or remote mutation;
6. reversion to the disabled-by-default state after the test;
7. a revocation or test-credential cleanup exercise and the associated data-deletion record; and
8. timestamps and nonsecret API response summaries sufficient to trace the steps without exposing tokens, owner identity, private channel identifiers, or unrelated account data.

The soak evidence must also identify how the operator accepted the current ReMediaLHQ Privacy Policy and Terms before OAuth, retained the immutable preview and express confirmation for the exact upload inputs, and satisfied the 30-day lifecycle requirement. The focused preview and confirmation tests must be added to the evidence manifest before submission.

The public compliance attachment may contain only a redacted summary and cryptographic digests of any owner-private evidence. Raw credentials, private identifiers, and owner contact details stay outside Git.

### Verified current public-policy deployment evidence

OpenAI Sites version 19 deployed the three exact policy sources at the canonical HTTPS routes. At `2026-09-02T15:32:01Z`, the live verifier read back all 28 deployable files, including the three policies, and matched them byte-for-byte to engine source commit `0a23892156da53bdad4b956b449b076162aac013`, Sites source commit `98c4e3360a8d3df605055371e368651400e8f57e`, and canonical site digest `1443f5afcc6c9a85469112f54964e325307ed2e067f0859e8464ea90691b0936`. The sanitized report location and digest are recorded in the evidence manifest. The readback also verified HTTPS, canonical routing, read-only method policy, production security headers, and the separately isolated `youtube.force-ssl` channel-setup disclosure without retaining owner data or request logs.

### Pending official submission evidence

Only after the prerequisite evidence exists should the owner:

1. open the official YouTube API compliance audit or quota-extension form from the Google account that controls the API project;
2. enter the owner-only identifiers directly in the form;
3. use the answers and evidence map in this package, updating any fact that changed after 2026-09-01;
4. attach only reviewer-required, redacted screenshots or demonstrations;
5. submit the form; and
6. retain a sanitized receipt containing the submission time, form or case type, and case identifier, plus any later decision.

The submission itself is owner-controlled and has not occurred. A prepared package, a browser-open form, or a draft response is not submission evidence. RMH-114 cannot be marked complete until the official form is submitted and the required evidence is retained; if the execution plan requires approval rather than submission alone, the resulting YouTube decision must also be retained.

## Suggested audit-form answers

**What does the API client do?**

It is an owner-operated editorial publishing workflow for one expressly authorized ReMediaLHQ YouTube channel. It confirms the authorized channel, uploads owner-reviewed video and thumbnail assets with an owner-selected privacy state, fails closed when an exact prior marker exists, verifies the resulting video state, and retrieves the channel's own Analytics reports.

**Who uses it?**

Only the channel owner or an operator expressly authorized by that owner. Public website visitors and Creator Signal Desk customers do not connect YouTube accounts.

**Why are these scopes required?**

`youtube.upload` performs only the approved insert and thumbnail operation; `youtube.readonly` identifies the authorized channel, detects exact prior markers, and verifies the upload; `yt-analytics.readonly` retrieves the authorized channel's Analytics reports; `youtube.force-ssl` is isolated to the fixed private-playlist and watermark setup command. The final submission must attach actual Analytics retrieval evidence from the RMH-112/RMH-113 prerequisite rather than describing it as a future use.

**How does the user control API actions?**

The operator reviews the target channel, media, metadata, declarations, notification setting, and privacy state before execution. The adapter defaults to private. Unlisted or public visibility requires separate repository and runtime authorization, and current repository authority enables neither private nor visible YouTube uploads.

**How is data handled?**

Authorized data is limited to the categories described in the public Privacy Policy, used only for the connected workflow, visible only to the authorizing user and expressly approved agents, and not sold or combined across unrelated owners. Credentials stay in owner-controlled private storage. Retention, 30-day refresh checks, seven-day direct-request deletion, Google revocation handling, and local-versus-YouTube deletion boundaries are disclosed publicly.

## Final reviewer checklist

- [x] Owner-independent draft package exists.
- [x] Local source evidence has an integrity manifest.
- [x] Source policies contain the required links and disclosures.
- [x] Current authority is represented as disabled, not production-approved.
- [x] Secrets and owner-private values are excluded.
- [x] Privacy/Terms acceptance is required and recorded before OAuth; owner-private live evidence waits on the OAuth client prerequisite.
- [x] Programmatic Google revocation and exact local-credential deletion are implemented and tested; live owner-token exercise evidence remains pending.
- [ ] The 30-day authorization/resource refresh-or-delete control is implemented and tested, or an audit-accepted alternative is evidenced.
- [ ] The operator's exact preflight review and express upload consent are evidenced.
- [x] The read-only RMH-112 verifier and strict offline fixture tests exist.
- [ ] RMH-112 verification evidence exists.
- [ ] RMH-113 private/unlisted soak evidence exists.
- [x] Updated public policies are deployed and read back.
- [ ] Official form owner-only fields are filled with current values.
- [ ] Audit form is submitted.
- [ ] Sanitized submission receipt or case identifier is retained.
- [ ] Any required YouTube decision is retained.
