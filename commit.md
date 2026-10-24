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
