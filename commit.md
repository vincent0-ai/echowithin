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
