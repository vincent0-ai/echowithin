# Release: v1.14.0 Android App Release Manifest & APK

## Model Attribution
- Model: Gemini (via Antigravity)

## Desktop Vault Long-Press Fix

### Model Attribution
- Model: Copilot SDK in VS Code

### Summary of Changes
- Unified desktop and mobile vault trigger handling with Pointer Events.
- Added native gesture suppression and a profile-picture discovery hint.
- Bumped the stylesheet asset version.
- Validation: `python -m pytest tests/test_vault.py -q` (10 passed).

## Summary of Changes
- **APK Update**:
  - Built new Android release debug APK for v1.14.0 (versionCode 49) with CommonMark/GFM rendering engine, tap-to-edit, live editor styling, search tag filter chips, version history diffs, offline sync hardening (WorkManager + SQLite v8), and baseline profiles.
  - Uploaded APK to `static/downloads/app-debug.apk`.
- **Update Manifest**:
  - Updated `static/update-manifest.json` with `versionCode = 49`, `versionName = "1.14.0"`, updated changelog, and computed SHA-256 hash.

## Personalized Home and Trusted Circles

### Model Attribution
- Model: Copilot SDK in VS Code

### Summary of Changes
- Added the Account Settings Home focus selector so users can change their onboarding focus later.
- Added separate Trusted Circles collections, indexes, navigation, creation, private feed, invite links, membership, roles, and leave flow.
- Circle post content is encrypted with the existing application encryption helper; invite tokens are stored hashed and expire after seven days.
- Kept Trusted Circles separate from Communities.
- Privacy impact: Circle membership and encrypted posts are stored in dedicated private collections; invite links are limited by expiry and use count.
- Validation: 48 focused tests passed and changed Python files compiled successfully. Direct template startup validation was blocked by the local MongoDB authentication configuration.

## Trusted Circle Controls and Vault Document Actions

### Model Attribution
- Model: Copilot SDK in VS Code

### Summary of Changes
- Added approval-required Circle membership requests with owner/moderator approval and denial.
- Added Circle mute controls, encrypted polls, and encrypted events.
- Added direct Vault item deletion controls and a consistent document preview panel with info, download, and delete actions.
- Preserved bulk selection for deleting multiple Vault items at once.
- Privacy impact: Circle requests and membership controls remain private to Circle members; Vault deletion continues through the authenticated protected delete endpoints.
- Validation: 12 focused Vault/onboarding tests passed, Python compilation passed, and `git diff --check` passed.

## Navigation Focus Defaults

### Model Attribution
- Model: Copilot SDK in VS Code

### Summary of Changes
- Kept Profile visible as a default top-level destination for every onboarding focus.
- Limited use-case personalization to the ordering and prioritization of the other direct links.
- Removed the duplicate Trusted Circles link from the discussion-focused navigation.
- Kept secondary destinations in More.
- Validation: 38 onboarding/authentication tests passed and `git diff --check` passed.

## Circle Activity Integration

### Model Attribution
- Model: Copilot SDK in VS Code

### Summary of Changes
- Reviewed the existing game system: PIN-based party rooms support polls, trivia, Would You Rather, Two Truths and a Lie, Story Chain, and Caption This.
- Added Circle-hosted game links that reuse the existing game creation and lobby flows.
- Circle-hosted lobbies are tagged to their Circle and shown to members in the Circle activity area.
- Added Circle-native poll voting and event RSVP actions with encrypted payload updates.
- Added quick access from Circles to host poll/trivia games and join a game by PIN.
- Added a Circle lobby index for efficient activity loading.
- Privacy impact: Circle lobby association is only exposed through a Circle the user belongs to; game creation validates Circle membership.
- Validation: 48 focused tests passed, Python compilation passed, and `git diff --check` passed.

## Mobile Onboarding Interaction

### Model Attribution
- Model: Copilot SDK in VS Code

### Summary of Changes
- Hardened the Home onboarding choice interaction for mobile taps.
- Added same-origin credentials and explicit JSON success handling before navigating Home.
- Added a direct navigation fallback instead of relying on a generic reload.
- Styled the Home focus Change control as a visible button.
- Privacy impact: no new data is collected; the existing onboarding preference endpoint remains the only persistence path.
- Validation: 38 onboarding/authentication tests passed and `git diff --check` passed.
