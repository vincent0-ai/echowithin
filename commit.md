# Trusted Circles UI & Functional Overhaul

## Model Attribution
- Model: Gemini 3.8 Flash (High)

## Summary of Changes
- **Desktop Feed & Chat Layout**:
  - Implemented desktop toggle switcher (`[ Chat ]` and `[ Feed ]`) above the main section so the Feed is not pushed underneath the chat area.
  - Chat and Feed are given full prominence and height in their respective active views.
- **Mobile Responsive Width & Space Utilization**:
  - Fixed narrow shrink-wrapped cards by adding explicit `width: 100%` and `box-sizing: border-box` to `.cv`, `.cv-grid`, `.cv-main`, `.cv-side`, and `.cv-card`.
  - Replaced narrow centered "Play and plan" buttons with full-width responsive action cards.
  - Adjusted mobile container padding (`.container:has(.cv)`) for better horizontal real estate.
  - Full-width mobile navigation tabs (`Chat | Feed | Plan | Members`) with persistent tab selection via `sessionStorage`.
- **Chat Scrolling & Interaction Fix**:
  - Removed `overscroll-behavior: contain` from the chat log so mouse wheel scrolling smoothly chains to page scrolling without trapping the user.
  - Added floating "Scroll to bottom" button when user scrolls up.
  - Preserved auto-scroll to latest messages on load and send.
- **Chat Message Controls (DM Architecture Alignment)**:
  - Added rich message action toolbar on hover/tap: quick emoji reactions (❤️, 👍, 😂, 🔥), reply quoting, pin/unpin for moderators, inline editing for authors, and deletion for authors/moderators.
  - Added reaction badges below bubbles showing counts and active toggle states.
  - Added quoted reply preview above composer and inside message bubbles.
  - Added pinned message banner at top of chat log.
  - Real-time Socket.IO synchronization for message sending, editing, deletion, and reactions across Circle members.
- **Feed Revamp & Engagement Controls**:
  - Added post editing for post authors and deletion for authors/moderators.
  - Added pin/unpin post capability for moderators (pinned posts displayed at top with 📌 badge).
  - Added post reactions bar (❤️, 👍, 🔥, 🎉) with live toggle counts.
  - Added post comments thread allowing Circle members to discuss posts directly, with comment deletion permissions.
  - Revamped Poll posts to show option progress bars, percentage, vote counts, total vote tally, and visual vote selection.
  - Revamped Event posts to show formatted datetime, attendee counter, and RSVP toggle.
- **Member Invite Bug Fix**:
  - Fixed bug where owner invited a username and was asked to approve their own invitation.
  - Direct addition of member by owner/moderator without self-approval loop.
  - Disallows inviting self or duplicate members with clear notifications.
  - Added live username autocomplete search endpoint (`/circle/<circle_id>/members/search`) and interactive dropdown UI.
  - Filtered pending join requests to only external applicants and enriched with applicant avatar and username.
- **Dynamic Poll Options**:
  - Replaced hardcoded 3 options with dynamic option manager supporting 2 to 8 options with "+ Add option" and option removal controls.
- **Validation**:
  - 9 focused circle tests passed (`tests/test_circles.py`).
  - Full project test suite passed (596 tests, 0 failures).

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

## Trusted Circle Roadmap Expansion

### Model Attribution
- Model: Copilot SDK in VS Code

### Summary of Changes
- Added QR-compatible invite display using the existing local QR asset.
- Added username-based invitations and approval workflow integration.
- Added owner-only moderator/member role controls and member removal.
- Added private encrypted Circle chat.
- Added per-post expiry options and a member-only plain-text export.
- Added Circle-level notification mute/unmute controls.
- Preserved existing game integration and Circle membership authorization.
- Privacy impact: Circle chat and post content remain encrypted at rest; exports are generated only after membership authorization and are not stored server-side.
- Media sharing remains intentionally blocked until a reusable private-media serving path can decrypt and authorize media safely; no plaintext fallback was introduced.
- Validation: 48 focused tests passed, Circle templates parsed, Python compilation passed, and `git diff --check` passed.

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

## Navigation Focus Refresh and More Menu

### Model Attribution
- Model: Copilot SDK in VS Code

### Summary of Changes
- Refresh the authenticated user after a Home focus update so the new navigation arrangement is available immediately.
- Return to Home only when the focus actually changes; unrelated settings edits retain their existing destination.
- Show More on desktop and filter out links already prioritized for the selected focus.
- Keep Profile in the primary navigation and expose Trusted Circles through the secondary menu where appropriate.
- Privacy impact: no new data is collected or exposed.
- Validation: 38 onboarding/authentication tests passed and Python compilation passed.
