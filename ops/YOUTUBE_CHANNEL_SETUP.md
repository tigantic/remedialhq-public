# ReMediaLHQ YouTube Channel Setup

## Identity

```text
Channel name: ReMediaL HQ
Handle: @ReMediaLHQ
URL: https://www.youtube.com/@ReMediaLHQ
Country: United States
Language: English (United States)
Business contact: sponsors@remedialhq.com
Website: https://remedialhq.com
Default visibility: Private
Category: Gaming
```

## Owner-session settings packet

Apply these values in YouTube Studio and verify them again before the first private upload:

```text
Settings > Channel > Basic info
Country of residence: United States
Keywords: GTA 6, GTA VI, Grand Theft Auto VI, GTA 6 news, GTA 6 gameplay, GTA 6 analysis, GTA 6 guides, Rockstar Games, gaming news, entertainment intelligence, video game analysis, ReMediaLHQ

Settings > Upload defaults > Basic info
Visibility: Private
Category: Gaming
Title: Leave blank
Description: Leave blank
Tags: Leave blank

Settings > Upload defaults > Advanced settings
License: Standard YouTube License
Video language: English (United States)
Caption certification: None
Comments: Hold potentially inappropriate comments for review
Show how many viewers like this video: On
```

Leaving default title, description, and tags blank prevents old story copy from leaking into later uploads. Publication remains private unless an owner changes the visibility for one specific video.

## Exact upload preview and single-use confirmation

Do not start OAuth or upload while repository publication authority remains disabled. Once the owner is ready for the private RMH-111 exercise, create an owner-private directory outside the repository with mode `0700`. First render the complete upload request without credentials or network access:

```bash
python -m remedialhq.cli preview-youtube-upload \
  --root . \
  --media artifacts/launch/remedialhq-launch-short-visual-prototype.mp4 \
  --thumbnail brand/thumbnail-episode-001.png \
  --expected-channel-id UCm6r0Dl4So4COH00U1qCE2w \
  --privacy private \
  --consumption-directory /owner-private/youtube/consumptions \
  --preview-output /owner-private/youtube/rmh-111-preview.json
```

Review every displayed field, including the channel, privacy state, package digest, video digest, thumbnail digest, title, description, tags, category, made-for-kids declaration, synthetic-media declaration, subscriber-notification choice, independence notice, and deterministic marker. Then copy the displayed preview SHA-256 into a separate express-confirmation command:

```bash
python -m remedialhq.cli confirm-youtube-upload \
  --root . \
  --preview /owner-private/youtube/rmh-111-preview.json \
  --confirmation-output /owner-private/youtube/rmh-111-confirmation.json \
  --confirm-preview-sha256 <exact-preview-sha256>
```

The live `publish-youtube` command requires both files. It revalidates them against the current package and selected bytes, copies the verified video and thumbnail into unlinked open-descriptor snapshots, then atomically creates `<preview-sha256>.consumed.json` in the preview's canonical consumption directory before constructing a YouTube client. The same preview cannot be used twice through a copied or hard-linked confirmation. After consumption, only the exact preview request and pinned bytes are used. If an exact existing publication marker is found, or if a marker candidate cannot be verified against its full description, the adapter stops without an update, thumbnail change, or new upload. If any attempt fails after consumption, render and confirm a new preview. Keep the preview, confirmation, and consumption record owner-private and outside Git.

## Current video watermark

Upload `brand/youtube-video-watermark-current.png` and select **Entire video** for display time.

```text
Dimensions: 150 x 150
SHA-256: 8ad2b256526c26101a98f5caeedce8434da6da3ecbf1311a642c544e464ff118
Brand source: public ReMediaL HQ channel avatar verified 2026-08-31
```

Do not upload `brand/video-watermark.png`; that file belongs to the superseded green repository identity.

## Description

```text
ReMediaLHQ tracks major entertainment releases using an evidence-led framework: Confirmed, Observed, Reported, and Inferred.

Original analysis, source-linked reporting, launch intelligence, practical guides, and signal extracted from the hype.

Website: https://remedialhq.com
Editorial: editorial@remedialhq.com
Corrections: corrections@remedialhq.com
Business: sponsors@remedialhq.com
```

## Initial playlists

```text
GTA VI Confirmed
GTA VI Observed
GTA VI Reports
GTA VI Analysis
GTA VI Guides
GTA VI Shorts
ReMediaLHQ Investigations
```

## Initial channel keywords

```text
GTA 6, GTA VI, Grand Theft Auto VI, GTA 6 news, GTA 6 gameplay, GTA 6 analysis, GTA 6 guides, Rockstar Games, gaming news, entertainment intelligence, video game analysis, ReMediaLHQ
```
