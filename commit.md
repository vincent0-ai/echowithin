# Fix game lag, media stampede, reconnect freezes, and slow page bottlenecks

## Model Attribution
- Model: Gemini 3.8 Flash (High) + Claude Opus 4.6 (Thinking)
- Reviewer Assigned: Claude Opus 4

## Summary of Changes

### Root Cause: Game Lag & Freezes (Connect Four, Slime Volleyball, Ping Pong)
- **EngineIO packet overflow** (`main.py`): Raised `max_decode_packets` from 16 → 500 to prevent `ValueError: Too many packets in payload` during 20Hz real-time game bursts over mobile polling.
- **Reconnect sid re-seating** (`main.py`): `handle_c4_move`, `handle_ttt_move`, `handle_dnb_line`, `handle_gomoku_move` now detect when an authenticated player's `sid` has changed (socket reconnect) and re-bind them to their seat + room, instead of silently dropping all moves.
- **Client reconnect auto-rejoin** (`static/connect_four.js`, `static/tic_tac_toe.js`, `static/dots_and_boxes.js`, `static/ping_pong.js`, `static/slime_volleyball.js`, `static/air_hockey.js`): Added `socket.on('connect')` handlers that re-emit join events after reconnection.
- **`echoPending` safety timeout** (`static/connect_four.js`): Added 5s timeout to prevent permanent UI lock when echo confirmation is lost.
- **WebSocket transport priority** (`static/ping_pong.js`, `static/emoji_decoder.js`): Configured `io({ transports: ['websocket', 'polling'] })` to prefer WebSocket, reducing packet accumulation.
- **Graceful disconnect handling** (`main.py`): Turn-based game disconnect handler now stores `host_disconnected_at` / `guest_disconnected_at` timestamps instead of immediately deleting rooms. Stale rooms (>180s) are pruned by `cleanup_stale_global_state()`.

### Root Cause: Media Proxy Stampede (3.6–4.1s per thumbnail × 12 concurrent)
- **L1 in-memory TTL cache** (`main.py`): `TTLCache(maxsize=512, ttl=1800)` for decrypted media blobs ≤ 5MB — already in place from earlier work.
- **L2 Redis cache** (`main.py`): Added Redis `setex` cache (1 hour TTL) for decrypted thumbnails ≤ 1MB, shared across gevent greenlets. Skips non-bytes values to avoid MagicMock pollution in tests.
- **ETag / 304 support** (`main.py`): Already returns `304 Not Modified` on matching `If-None-Match`.

### Root Cause: Slow `/tour` Route (~1,500ms)
- **Eliminated PBKDF2 hashing** (`blueprints/auth.py`): Replaced `generate_password_hash(secrets.token_urlsafe(16))` with precomputed dummy hash for ephemeral guest + demo-bot accounts (never used for real auth), saving ~250ms×2 of blocking CPU.
- **Batched MongoDB writes** (`blueprints/auth.py`): Collapsed 2 × `insert_one` (user accounts) into 1 × `insert_many`, and 3 × `insert_one` + 1 × `update_one` (demo notes) into 1 × `insert_many` with `is_locked` set inline. Reduces 7 round-trips to 2.

### Bond Calendar & Push Notification Bottlenecks
- **Calendar response cache** (`blueprints/bonds.py`): Added `TTLCache(maxsize=512, ttl=60)` for aggregated calendar payloads with `_invalidate_bond_calendar_cache()` called on create/edit/delete/RSVP mutations.
- **Async push notifications** (`blueprints/bonds.py`): Added `_send_push_async()` helper that dispatches via RQ `.queue()` when available, preventing synchronous webpush HTTP calls from blocking the calendar, habit-toggle, and game-challenge HTTP responses (~530ms saved per request).

### Other
- **`security.py`**: Guarded `_get_object_fernet_v3` against `None` collection to pass tests without a DB connection.
- **`templates/home.html`**: Minor copy change ("Open Together" → "Open Bonds").

## Modified Files
- `main.py`, `security.py`, `blueprints/auth.py`, `blueprints/bonds.py`
- `static/connect_four.js`, `static/tic_tac_toe.js`, `static/dots_and_boxes.js`
- `static/ping_pong.js`, `static/slime_volleyball.js`, `static/air_hockey.js`, `static/emoji_decoder.js`
- `templates/home.html`, `tests/test_netcode_regression.py`

## Test Results
- 600 passed, 0 failed

---

# Fix Replying Widget Extra Spacing and Eliminate Redundant Shared Note Prefix in DMs

## Model Attribution
- Model: Gemini 3.8 Flash (High)
- Reviewer Assigned: Claude Opus 4

## Summary of Changes
- **Quoted Reply Widget Spacing Optimization (`templates/circle.html`, `blueprints/circles.py`)**:
  - Removed `white-space: pre-wrap;` inheritance from `.cv-bubble`, scoping it exclusively to `.cv-bubble-text` so inner layout containers such as quoted replies do not preserve unwanted whitespace.
  - Trimmed Jinja2 template whitespace around `.cv-reply-quote` using `{%- ... -%}` and rendered markup on a single line to prevent indentation newlines from rendering vertical gaps.
  - Updated `.cv-reply-quote` CSS with `white-space: normal; line-height: 1.25; padding: .2rem .45rem; overflow: hidden;` and tightened author and snippet text sizing.
  - Normalized quoted reply snippet strings in `blueprints/circles.py` and client-side JS (`replyToMessage` & `appendChatMessage`) using whitespace collapsing (`' '.join(parent_text.split())[:80]` / `replace(/\s+/g, ' ').trim()`) to prevent multi-line parent messages from stretching reply quotes.
- **Eliminated Redundant "Shared Note" Prefix in DMs (`blueprints/sharing.py`)**:
  - Updated `api_share_to_dm` to check if the note title is default or untitled.
  - For default/untitled notes, sends cleanly formatted `{user_message}\n\n{share_url}` or `{share_url}` without redundant repetitive labels (avoiding `"Shared Note: Shared Note https://..."`).
  - For custom-titled notes, sends `{user_message}\n\n{note_title}\n{share_url}` or `{note_title}\n{share_url}`.
- **Testing & Verification (`tests/test_share_expansion.py`)**:
  - Added assertion in `test_share_to_dm_success` confirming `'Shared Note: Shared Note'` is not present in decrypted DM content.
  - Ran full test suite with 595 tests passing and 0 regressions.


# User-Friendly Time Formatting and WhatsApp-Style Minimal In-Bubble Username & Toolbar Alignment

## Model Attribution
- Model: Gemini 3.8 Flash (High)
- Reviewer Assigned: Claude Opus 4

## Summary of Changes
- **User-Friendly Post and Event Time Formatting**:
  - Enhanced `localtime_filter` in `utils.py` to automatically detect and parse ISO strings via `parse_iso_utc()`. Unparsed ISO strings (such as `2026-10-30T06:06:00Z`) are no longer dumped as raw text.
  - Added support for `data-time-format="event"` / `"weekday-datetime"` and `data-time-format="time"` in `static/script.js` `convertToLocalTime()`.
  - Formatted circle events in `templates/circle.html` with `%a, %b %d, %Y · %I:%M %p` (e.g. `Fri, Oct 30, 2026, 6:06 AM`).
  - Pre-parsed event `starts_at` into `post['event_date']` using timezone-aware UTC datetime (`parse_iso_utc`) in `blueprints/circles.py`.
  - Formatted post created times (`%b %d, %Y · %I:%M %p`) and comment/reply times with user-friendly 12-hour local time formatting.
- **WhatsApp-Style Minimal Sender Username Inside Message Bubble**:
  - In `templates/circle.html`, moved received message author usernames from an external top row (`.cv-msg-author-row`) to inside the message bubble (`.cv-bubble-author`), matching the WhatsApp group chat layout.
  - Styled with minimal `.72rem`, bold weight, and distinct accent color, avoiding redundant vertical spacing.
  - Retained clean consecutive sender grouping (omits repeated author name for rapid consecutive messages from the same sender).
- **Message Action Toolbar Alignment & Horizontal Scroll Fix**:
  - Re-architected `.cv-msg-actions` from absolute coordinate positioning into a responsive flex layout alongside the bubble via `.cv-bubble-row`.
  - Sent messages (`.cv-msg-mine`) reverse flex direction (`flex-direction: row-reverse`), anchoring the action toolbar to the *inner* side of the bubble (to the left), preventing it from overflowing the right edge of the screen or chat container.
  - Received messages place the action toolbar to the right of the bubble in open space, eliminating any overlap with sender headers or content.
  - Added `overflow-x: hidden;` to `.cv-chat-log` to prevent horizontal scrolling across all screen sizes.
  - On mobile/touch devices (<= 768px), desktop hover actions remain strictly hidden (`display: none !important`), and message actions are handled via long-press bottom sheet overlay.
  - Added mobile `contextmenu` listener on bubbles to trigger mobile action sheet cleanly without native browser selection conflict.
  - Updated real-time `appendChatMessage`, `showMobileActions`, `copyMessageText`, `editMessage`, and socket `circle_message_edited` handlers to work seamlessly with the new bubble structure.
- **Testing & Quality Assurance**:
  - Added test `test_string_iso_emits_proper_local_time` in `tests/test_new_features.py` validating ISO string handling and client format tags.
  - Verified full test suite passes with 595 passed tests and 0 failures.
  - Adhered strictly to AGENTS.md rules: zero hardcoded credentials, zero thick left borders, minimal user-facing copy, strict timezone-aware UTC.


# Expand Share Note to Direct Messages and Trusted Circle Feed

## Model Attribution
- Model: Gemini 3.8 Flash (High)
- Reviewer Assigned: Claude Opus 4

## Summary of Changes
- **Share Note via Direct Message**:
  - Added `POST /api/personal_post/<post_id>/share-to-dm` endpoint allowing users to send a note directly to a contact in chat.
  - Automatically generates an active share link, constructs encrypted DM body, and injects encrypted `link_preview` with note title, snippet preview, and destination URL.
  - Emits real-time Socket.IO `new_dm` to recipient room and confirms to sender room.
  - Dispatches push notifications for the recipient.
- **Post Note to Trusted Circle Feed**:
  - Added `POST /api/personal_post/<post_id>/share-to-circle` endpoint allowing users to post their note directly to a Trusted Circle discussion feed.
  - Generates share link and creates a `kind='shared_note'` post encrypted with circle key (`encrypt_community_note`).
  - Stores note title, caption, snippet preview, and share URL in the post payload.
- **Unified Recipients Discovery**:
  - Added `GET /api/share/recipients` returning the user's available DM contacts (recent chat partners, bond partners, accepted DM permissions) and joined circles.
- **Personal Space Share Modal Enhancements**:
  - Added "Send in Message" and "Post to Trusted Circle" options to the guided share mode selector in `templates/personal_space.html`.
  - Added dedicated recipient and circle selection panels with permissions dropdown and optional message/caption textareas.
  - Styled with uniform 1px borders (`border: 1px solid var(--border-color);`), strictly adhering to zero `border-left` rules.
  - Updated `static/personal_space_offline.js` to dynamically fetch recipients, populate dropdowns, and handle DM/Circle share submissions with error resilience.
- **Circle Feed Shared Note Card**:
  - Updated `templates/circle.html` to render rich, responsive note cards for `shared_note` posts in the circle feed.
  - Displays author caption, note icon, title, snippet preview, and an "Open Note" button linking to the shared note.
  - Reactions (❤️, 👍, 🔥, 🎉) and nested comments thread work seamlessly for shared note posts.
- **Testing & Verification**:
  - Added 7 unit tests in `tests/test_share_expansion.py` covering recipients discovery, DM sharing, permissions enforcement, circle feed posting, and feed template rendering.
  - All 594 project tests passing (0 failures).


# Support INTERNAL_APP_URL for Scheduler and Reminder Scripts

## Model Attribution
- Model: Gemini 3.8 Flash (High)
- Reviewer Assigned: Claude Opus 4

## Summary of Changes
- **Internal Loopback Support for Background Schedulers**:
  - Updated `get_app_url()` in `scripts/process_scheduled_messages.py` to inspect `INTERNAL_APP_URL` prior to `APP_URL`, stripping trailing slashes.
  - Updated `get_app_url()` in `scripts/calendar_reminders.py` to inspect `INTERNAL_APP_URL` prior to `APP_URL`, stripping trailing slashes.
  - Enables setting `INTERNAL_APP_URL=http://127.0.0.1:8000` in production environments so that internal scheduler HTTP requests stay on loopback rather than exiting through Cloudflare and generating ~1,700 unnecessary public edge requests per day.
- **Verification**:
  - Validated URL precedence and normalization tests with `INTERNAL_APP_URL` and `APP_URL`.
  - Verified test suites `tests/test_lock_utils.py` and `tests/test_new_features.py` (18 passing).

# Fully Deprecate and Retire Communities Feature in Favor of Trusted Circles

## Model Attribution
- Model: Gemini 3.8 Flash (High)
- Reviewer Assigned: Claude Opus 4

## Summary of Changes
- **Core Communities Feature Deprecation**:
  - Deleted `blueprints/communities.py` (all CRUD routes, community notes, reactions, polls, challenges, checkins, resources).
  - Deleted obsolete community templates (`templates/communities.html`, `templates/community_space.html`, `templates/admin_communities.html`, `templates/admin_community_vouchers.html`).
  - Deleted obsolete script `scripts/prune_orphaned_communities.py`.
  - Deleted test suite `tests/test_communities.py`.
- **Seamless HTTP 301 Redirect**:
  - Registered `/communities` and `/communities/<path:subpath>` redirect routes pointing directly to `circles.circles_page` to protect existing bookmarks and links.
- **Main App & Navigation Updates**:
  - Unregistered `communities_bp` from `main.py`.
  - Replaced Communities links with Trusted Circles across `templates/base.html` (including `discussion`, `creative`, and "More" dropdowns).
  - Updated `templates/home.html` Community card to "Trusted Circles" displaying the user's active circles count (`user_circle_count`).
  - Updated `blueprints/pages.py` to count and cache `user_circle_count`.
- **Personal Space & Offline JS Cleanups**:
  - Updated `templates/personal_space.html` tab navigation from Communities to Trusted Circles (`url_for('circles.circles_page')`).
  - Removed "Share to Community" button, picker list, and dead handlers from `templates/personal_space.html` and `static/personal_space_offline.js`.
- **Admin Moderation & Health Metrics**:
  - Removed community management and voucher routes from `blueprints/admin.py` and action cards from `templates/admin_dashboard.html`.
  - Updated admin dashboard health checks from `health['communities']` to `health['circles']`.
- **Sharing & Profile**:
  - Cleaned community fallback lookup from `blueprints/sharing.py` comment endpoints.
  - Updated GDPR data export in `blueprints/profile.py` to export user circles instead of community memberships.
- **Config & Tier Limits**:
  - Removed deprecated `max_communities` tier limits from `config.py` and context processor.
- **Documentation & Copy**:
  - Updated FAQ (`templates/faq.html`), Terms of Service (`templates/terms.html`), Auth (`templates/auth.html`), and Profile Settings (`templates/profile_settings.html`) copy to reference Trusted Circles with open/invite-only visibility.
- **Test Suite Verification**:
  - Updated `tests/test_admin_and_tiers.py` and `tests/test_performance.py`.
  - 587 of 587 tests passing with 0 failures across the complete test suite.

# Trusted Circles Clean UI, Deduplication, Nested Comments & Open Visibility

## Model Attribution
- Model: Gemini 3.8 Flash (High)
- Reviewer Assigned: Claude Opus 4

## Summary of Changes
- **Strict Compliance with Border Rules**:
  - Removed all `border-left` styles from `.cv-reply-quote` in accordance with AGENTS.md and GEMINI.md mandates.
  - Standardized on clean, uniform 1px borders (`border: 1px solid var(--border-color);`) and subtle translucent borders (`border: 1px solid rgba(0,0,0,0.1)` / `border: 1px solid rgba(255,255,255,0.28)`).
- **Message Deduplication Fix**:
  - Implemented client-side message ID tracking set (`renderedMessageIds = new Set()`) initialized on page load.
  - Guarded both `appendChatMessage` and socket `circle_message_sent` listener against rendering messages that are already present in the DOM or tracking set.
  - Eliminated race condition duplicate bubbles between `fetch()` response resolution and real-time socket delivery.
- **Minimal, Beautiful Group Chat Bubbles & DM-Style Reply Preview**:
  - Compacted message bubble font size to `0.82rem` with `line-height: 1.35` and `padding: 0.38rem 0.68rem;` tailored for group chat density.
  - Aligned bubble border curves with DM messages (`border-radius: 16px`, sent `border-bottom-right-radius: 4px`, received `border-bottom-left-radius: 4px`).
  - Added interactive reply jump scrolling (`scrollToMessage`) with smooth scroll and pulse highlight.
  - Compacted `#cv-reply-bar` above the composer with uniform 1px borders and dismiss action.
- **Mobile Long-Press Bottom Sheet (Fix Horizontal Scrolling)**:
  - Replaced the overflowing horizontal 7-button inline action bar on mobile with `#cv-mobile-action-overlay` modal sheet identical to DM messages.
  - Mobile action overlay features quick emoji reactions (`❤️`, `😂`, `😮`, `😢`, `👍`, `🔥`) and vertical action options (Reply, Pin/Unpin, Copy Text, Edit, Delete).
  - Added 450ms touchstart long-press timer with haptic vibration and contextmenu interception on mobile devices.
  - On screens `<= 768px`, `.cv-msg-actions` is strictly hidden so bubbles never stretch or force sideways scrolling.
  - On desktop, kept a sleek 3-button pill (React, Reply, More `⋯` opening the action menu).
- **Nested & Beautiful Comments Thread**:
  - Stored `parent_id` and resolved `reply_to_author` for comment replies in `blueprints/circles.py`.
  - Structured comments into a hierarchical tree (`c['replies']`) in `view_circle` without multi-level horizontal layout breakdown.
  - Rendered top-level comments and indented child replies with micro avatars (20px), author bold tags, `@Author` mention badges, and compact action buttons.
  - Added `#comment-reply-bar-{{ post._id }}` banner above comment input allowing direct child replies.
- **Option A: Consolidate Communities into Circles**:
  - Added `visibility` attribute (`'invite_only'` or `'open'`) to Circle creation.
  - Updated `circles_page()` to query discoverable public circles (`open_circles`).
  - Added `POST /circle/<circle_id>/join` endpoint allowing users to discover and join open circles directly.
  - Added "Explore Open Circles" section on `templates/circles.html` with direct "Join Circle" forms.
- **Verification**:
  - 11 unit tests in `tests/test_circles.py` passing.
  - Full project test suite passed (598 tests, 0 failures).

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

# Fix circles data races, missing notifications, memory-match tracking, mobile card reveal
## Model Attribution
- Model: Gemini 3.8 Flash (High) + Claude Opus 4.6 (Thinking)
- Reviewer Assigned: Claude Opus 4

## Files changed
- blueprints/circles.py: atomic reaction toggle, optimistic-lock encrypted-blob writes (poll votes, RSVP), sanitized export filename, batched pending-request user fetch, muted_by cleanup on remove/leave
- blueprints/circles.py: member push notifications on message/post/comment honoring muted_by; content-free push copy
- main.py: memory_match added to GAMES_WITH_MATCH_TRACKING; once-per-board result recorded on completion (winner = most pairs, tie = draw); flag reset on new deal
- templates/memory_match.html: <=600px cards switch from 3D flip to opacity cross-fade (fixes clipped/flash-of-back reveal on mobile); matched highlight uses solid tint + pop (box-shadow glow dropped by Safari)
- tests: test_circles.py (14), test_game_stats.py (3) all passing

## Design decisions
- Poll votes/RSVP stay in the encrypted per-circle blob; guarded by updated_at optimistic lock with 5 retries, 409 surfaced to user on contention rather than silent vote loss
- Co-op games (Emoji Decoder, Word Duet, Sudoku, Crossword, This or That) intentionally NOT tracked � no clean 1v1 winner

## Privacy impact
- New push notifications carry member content only in titles as usernames + circle name; body text is content-free; muted_by respected on every path

## Merge fix/netcode-fairness-idempotency to main (d50c20c)
- Fast-forward merge; reviewed commit 'Fixed latency issues': netcode latency fix + fairness/idempotency (scripts/netcode_budget.py, updated game JS, new netcode regression/contract tests)
- Tests: 623 passed locally on main before push; pushed to origin/main; branch deleted locally and remotely
- Model attribution: merge performed by Claude (agent)

## Vault large-video support + upload progress (49aa5fb)
- Root cause of the 413: Cloudinary free-plan rejects raw uploads >10MB ("File size too large. Got 12478284. Maximum is 10485760.") after FFmpeg failed to fit the video; vault then surfaced it as a generic 500.
- config.py: MAX_VIDEO_SIZE 100->200MB, VAULT_MAX_FILE_SIZE 50->100MB, added CLOUDINARY_HARD_UPLOAD_LIMIT, VIDEO_COMPRESSION_TIMEOUT 120->300s
- main.py: app MAX_CONTENT_LENGTH = 205MB (transport ceiling; per-endpoint limits unchanged) + JSON 413 error handler
- blueprints/vault.py: stream uploads to a temp file (no full read into RAM), per-type size limits (video 100MB / image 5MB / docs 10MB), reuse video_utils.compress_video_if_needed (same FFmpeg path as DMs) before upload, explicit "Video too long..." error when compression can't fit the 10MB Cloudinary ceiling
- blueprints/chat.py: same explicit error instead of letting Cloudinary reject after the fact
- templates/vault.html: real per-file upload progress bar (XHR upload.onprogress), sequential queue with per-file status, error surfaced per file
- In-vault watching already worked via lightbox <video> + /media proxy with HTTP 206 range support — verified, no change needed
- Privacy impact: unchanged — uploads remain server-side encrypted before Cloudinary; temp files deleted in finally
- Tests: 623 passed locally; pushed to origin/main
- Model attribution: Claude (agent)

## 720p compression fallback (e53cac0)
- Context: user's real-world video compressed to 10.4MB on an online tool — still over Cloudinary's 10MB raw cap. Adds a third FFmpeg pass that downscales to 720p (after bitrate pass + 70% retry both miss) so compression matches what online tools achieve.
- video_utils.py: `_run_ffmpeg` gains a `scale` param; fallback chain = bitrate pass → 70% retry → 720p downscale with recomputed bitrate → clear failure message.
- Verified locally with FFmpeg: 56.9MB/400s/1080p → 5.8MB pass 1 (fits); 720p fallback chain independently verified at 8.4MB.
- Tests: 623 passed; pushed to origin/main.
- Model attribution: Claude (agent)

## Root cause of vault large-upload failures (06b5974)
- Real bug: Cloudinary caps the ENCRYPTED payload at 10MB, but Fernet inflates data ~1.334x. The code compressed videos to 10MB of *plaintext*, which encrypts to ~14MB and is always rejected (the recurring `Got 12478284. Maximum is 10485760`).
- Effective plaintext ceiling is now 7.50 MiB (computed, not guessed): any video over that is compressed before upload, so uploads that used to fail now either fit or return a clear message instead of burning CPU for 80s.
- security.py: added `encrypted_size_for()` and `max_plaintext_for_encrypted_limit()`, derived from cryptography.fernet's actual token layout (PKCS7 + 57-byte header + base64). Verified against real Fernet output across 14 sizes.
- blueprints/vault.py, blueprints/chat.py (DM/Whisper image+video): compress against the plaintext budget instead of the encrypted cap.
- tests/test_encrypted_size_budget.py: 24 regression tests, including one asserting the OLD behaviour would overflow.
- Note: videos longer than ~5-6 min still cannot fit 10MB at watchable quality by design; they now get a fast, clear error.
- Tests: 647 passed.
- Model attribution: Claude (agent)

## Resource profiling + optimizations (ec12197)
- Profiling method: copied the production-like video to temp, ran FFmpeg presets back-to-back, and measured the real encrypt/compress pipeline (tracemalloc + end-to-end timing).
- CPU findings (real 23MB/36MB 720p sources, fixed bitrate so output size is constant):
    fast 9.40s / 3.28MB  ->  veryfast 5.48s / 3.28MB  ->  superfast 4.58s / 3.17MB  ->  ultrafast 2.88s / 3.18MB
  Because the output is bitrate-capped, a slower preset buys zero bytes. Shipped 'veryfast' (1.7x less CPU; ultrafast was 2.2x faster but lost real quality, SSIM 0.9735 -> 0.881).
- RAM findings (real 36MB file, tracemalloc): in-memory encrypt peaked at 279MB (~7.7x payload); chunked streaming stays at 7.7MB. Fernet's base64+CBC pipeline is the multiplier.
- video_utils.py: preset -> veryfast; failed encode pass is dropped before the 70% retry and the 720p fallback, so two output buffers are never resident at once.
- blueprints/vault.py: plaintext reference released right after encryption so plaintext+ciphertext are not both live during upload.
- NOTE: converting media to a chunked encrypted format would cut peak RAM ~36x, but it changes the stored format and would break every existing vault/DM item. Deliberately NOT done without explicit sign-off + a migration plan.
- tests/test_video_compression_resources.py: guards the cheap preset, the absent '-threads' flag (it crashed libx264 on the build), faststart, and buffer release.
- Tests: 654 passed.
- Model attribution: Claude (agent)
