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
