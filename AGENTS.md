# Agent Instructions

These are the operational instructions for agents working in this repository.

If the logic requires some further modification note at the end.

1. Commit messages and model attribution
   
   - All agents MUST include a detailed commit message describing the changes made.
   - The commit message MUST include the agent's model name and everything saved here.(Write in this document)
   - Dont push the AGENTS.md to github-should remain local
2. Quality checks and reviewer assignment
   
   - Claude Opus 4 is assigned to check the last commit made by other models.
   - The reviewer will verify the commit is up to standard and free of bugs and fix issues where necessary.

3. Platform priorities
   
   - The platform prioritizes user privacy, security, and scalability.
   - All agents must follow best practices that protect these priorities when writing code, storing data, and describing changes.

4. Additional guidance
   
   - Be concise and explicit when describing the problem you are solving.
   - Reference any modified files and tests in the commit message.
   - When in doubt, err on the side of caution for privacy and security.
     WHEN CHANGING ANYTHING IN THE UI, MAKE SURE YOU CONTINUE USE THE PLATFORMS
     DESIGN, LAYOUT AND COLORS - NO UNNECESSARY ICONS AND GRADIENT COLORS
   5. If you are working on the android app found here: C:\Users\DevTech\AndroidStudioProjects\EchoWithin, you can make change in the backend carefully if required to make sure you dont interfere with the backend. Then Constraints & Preferences
      - Push to GitHub main branch on both repos
   - Upload new APK to static/downloads/app-debug.apk
     - Update static/update-manifest.json (versionCode, versionName, changelog, apkUrl)

## More good instruction

- Document non-obvious design decisions in the commit message or linked issue.
- If a change affects user data handling, include a short privacy impact note in the commit.

## Agent Session Log

### Model: opencode/minimax-m3-free

**Date:** 2026-06-06
**Changes:**

- **Site-wide timezone display bug ("Server Time: 19:17:26 UTC" bleed)** — The user reported that several screens still showed server-time (`UTC+00:00`) instead of the visitor's local time. We had already patched the messages & scheduling areas (sidebar timestamps, sent messages, scheduled message banner) but the same root-cause bug was alive in ~14 other call sites across the platform. Root cause has two heads:
  1. **MongoDB stores tz-naive datetimes.** Even when Python writes them as `datetime.datetime.now(datetime.timezone.utc)`, BSON strips the `tzinfo`. When the backend later calls `.isoformat()` on the read-back value, the output looks like `"2026-06-06T19:17:26"` — no `Z`, no `+00:00`. The browser's `new Date(iso)` constructor parses this as **local time**, which on a UTC server with a UTC+3 user produces a 3-hour offset, exactly the "Server Time" reading the user saw.
  2. **Raw Jinja `{{ value.strftime(...) }}`** in templates outputs UTC text directly into the HTML, so there's nothing for the existing `<time class="local-time">` JavaScript converter to grab onto — the user sees a UTC string forever.
- **Fix — single shared `parseServerTime(iso)` helper in `static/script.js`** that defensively appends `Z` to any ISO string without a timezone designator (`Z`, `+hh:mm`, `-hh:mm`), then returns a `Date` (or `null` for empty / invalid input). Exposed as `window.parseServerTime` so every page can call it without importing a module. The existing `time.local-time` converter and the `getRelativeTime` helper in `base.html` now both route through it.
- **Fix — `localtime_filter` (utils.py) hardened twice:**
  1. The `datetime` attribute on the rendered `<time>` element now uses `astimezone(UTC).isoformat().replace('+00:00', 'Z')` so the wire format is always Z-suffixed (no ambiguity for `parseServerTime` or for the older inline `new Date(iso)` callers we haven't migrated yet).
  2. The visible **fallback text** (shown before JS runs, on no-JS clients, and inside emails) now appends `" UTC"` when the format includes a time component (`%H/%I/%M/%S/%p/%X`). Date-only formats like `%B %Y` stay clean. This is the actual user-visible bandage: even if the JS converter never fires, the user now sees `"Jun 06, 2026 at 07:17 PM UTC"` instead of an ambiguous `"Jun 06, 2026 at 07:17 PM"` that *looks* local but is actually server-time. Same idea as the bottom server-time banner the user mentioned.
- **Fix — every `new Date(serverIso)` call-site now uses `parseServerTime`:**
  - `templates/personal_space.html`: version history list (`v.created_at`), search-result cards (`r.created_at`), shared-link expiry popover (`s.expires_at`), pending-sync notes badge (`n.created_at`).
  - `templates/shared_note.html`: time-capsule countdown (`data-unlock`) — the **highest-impact** of the bunch, the unlock target was previously shown in the visitor's local clock even when the sender picked a UTC moment — version history list, unlock history modal, comment "X minutes ago" timeAgo helper.
  - `templates/view_post.html`: comment timestamps.
  - `templates/blog.html`: surprise-unlocked activity feed (`p.unlocked_at`) and "Edited on …" post meta (`post.edited_at`).
  - `templates/admin_communities.html`: reports table created date.
  - `templates/messages.html`: sidebar last-message timestamps (replaces the brittle inline `if (!iso.endsWith('Z') && !iso.includes('+'))` regex with a single `parseServerTime` call), socketio incoming-message date dividers, `appendSystemMessage`, `updateUserStatus` "active now / last seen", scheduled-message banner.
  - `templates/base.html`: `getRelativeTime` (used by every `.relative-time` element across the platform, including blog post cards via `_macros.html`).
- **Fix — raw Jinja `strftime()` replaced with `|localtime` filter** so the timestamps become `<time class="local-time">` elements that the JS converter picks up:
  - `templates/view_post.html:346` — related posts "on {date}".
  - `templates/search_results.html:267` — search result created_at.
  - `templates/profile.html:69` — "Member since {month year}".
  - `templates/admin_premium_users.html:36` — premium expiry date.
  - `templates/weekly_newsletter.html:119` — newsletter post date (date-only, no `" UTC"` suffix added — emails have no JS so this stays human-readable).
- **Fix — `_macros.html` `relative-time` data-timestamp** — `post.edited_at.isoformat()` and `post.timestamp.isoformat()` now have an explicit `+ 'Z'` (with `.replace('+00:00Z', 'Z')` to handle the aware-datetime case) so the `getRelativeTime` JS doesn't have to guess. This was the silent cause of every blog/post card showing "1 hour ago" / "in 3 hours" when the actual diff was 0 seconds — the inline `new Date(naive_iso)` was off by the visitor's UTC offset.
- **Why this is safer than fixing the backend's `.isoformat()` calls one by one** — there are ~25 `.isoformat()` call sites across `api.py`, `blueprints/notes.py`, `blueprints/sharing.py`, `blueprints/chat.py`, `blueprints/blog.py`, `blueprints/admin.py` and many of them already correctly add `Z` (the ones the previous agent fixed for messages and scheduling). Touching all of them risks regressions. Instead, fix the **consumer** side once (`parseServerTime`) so it accepts both Z-suffixed and naive ISO strings uniformly, and ship the wire-format fix opportunistically (the new `localtime_filter` does it, the `_macros.html` data-timestamp does it). Backend cleanup can happen incrementally without risk.
  **Files touched:** `static/script.js`, `utils.py`, `templates/base.html`, `templates/_macros.html`, `templates/personal_space.html`, `templates/shared_note.html`, `templates/view_post.html`, `templates/blog.html`, `templates/admin_communities.html`, `templates/messages.html`, `templates/search_results.html`, `templates/profile.html`, `templates/admin_premium_users.html`, `templates/weekly_newsletter.html`, this `AGENTS.md`.
  **Verification:**
1. `python -c "import jinja2; e = jinja2.Environment(loader=jinja2.FileSystemLoader('templates'), autoescape=True); import os; [e.parse(open(os.path.join('templates', n), encoding='utf-8').read()) for n in os.listdir('templates') if n.endswith('.html')]; print('ALL templates parse OK')"` → `ALL templates parse OK`.
2. `python -c "import main"` → imports clean.
3. `node -e "new Function(require('fs').readFileSync('static/script.js','utf-8'))"` → `script.js syntax OK`.
4. `parseServerTime` unit-tested against 8 cases (naive, `Z`, `+00:00`, `+03:00`, `-05:00`, empty, null, Date pass-through, microseconds) — all produce the expected UTC `Date`.
5. `localtime_filter` unit-tested against (aware UTC, naive UTC, date-only format, `None`, non-datetime string) — all produce the expected `<time>` element or safe string fallback.
6. Final grep `templates/**.html` for residual `\.strftime\(` and naive `new Date(...\.(created_at|...))` — **zero matches** across the whole template tree.
   **Privacy Note:** Pure timezone-display fix. No new endpoints, no new cookies, no new third-party calls, no new data stored. The ISO string itself contains no new information — adding `Z` is just a parser-compatibility marker. The visible `" UTC"` suffix on fallback text is the only user-visible addition and it's strictly informational. Note timestamps remain end-to-end encrypted; this change only affects how the existing `created_at` / `updated_at` metadata (which has never been part of the encrypted payload) is *displayed*.

# 

- ### Model: Antigravity (Advanced Coding Agent)
  
  **Date:** 2026-06-21
  **Changes:**
- **Sync Duplication & ID Collision Fix (NotesRepository.kt)**:
  - Wrapped `syncNotesInternal()` inside a `syncMutex.withLock { ... }` block to ensure that concurrent sync invocations are serialized, preventing the creation of duplicate notes on the server during simultaneous sync triggers.
  - Replaced the timestamp-based local ID suffix with `java.util.UUID.randomUUID().toString()` in `createNote()`, ensuring 100% uniqueness of temporary offline note IDs and preventing local database overwriting during fast-loop imports.
- **Unit Testing (SyncDuplicationTest.kt)**:
  - Wrote JVM unit tests using reflection/mocking to verify unique local ID generation and serialization of concurrent sync executions under the mutex.
- **Pushed v1.8.2 APK**: Updated `versionCode 19 -> 20` and `versionName 1.8.1 -> 1.8.2`. Rebuilt APK, deployed to `static/downloads/app-debug.apk`, and updated `static/update-manifest.json` with the changelog.
  **Files touched:** `app/build.gradle.kts` (version bump), `app/src/main/java/com/example/echowithin/data/repository/NotesRepository.kt`, `app/src/test/java/com/example/echowithin/SyncDuplicationTest.kt` (NEW), `static/downloads/app-debug.apk`, `static/update-manifest.json`, this `AGENTS.md`.
  **Verification:** `./gradlew.bat testDebugUnitTest` and `./gradlew.bat assembleDebug` both completed successfully.
  **Privacy Note:** The UUID generation runs entirely locally on the client and does not share any new data or permissions.

### Model: Antigravity (Advanced Coding Agent)

**Date:** 2026-06-21
**Changes (v1.8.4):**

- **Sync Pagination & Local Deletion Fix (`NotesRepository.kt`, `api.py`)**:
  - Implemented pagination looping in `syncNotesInternal()` on the client to fetch all server notes page-by-page (using `has_more` metadata) instead of only page 1, preventing local deletion of notes beyond the first 50 notes.
  - Increased `per_page` maximum clamp on the backend notes endpoint from 50 to 100 to reduce network roundtrips.
  - Aborts the pull/delete phase of sync immediately if a page fetch fails, preventing accidental local deletion of notes.
- **Pin Note Feature (`HomeScreen.kt`, `NoteDetailScreen.kt`, `NotesRepository.kt`, `NotesViewModel.kt`, `NoteDatabaseHelper.kt`, `api.py`)**:
  - Added a backend endpoint `/notes/toggle_pin/<post_id>` to toggle a note's pin status in MongoDB.
  - Added repository methods, View Model support, and offline-to-online sync integration for note pins.
  - Updated SQLite database querying to sort notes by `is_pinned DESC, updated_at DESC`.
  - Added top-level Pin toggle icon button in the details screen TopAppBar and a push-pin badge indicator to notes in the home list.
- **Relocation of Action Buttons (`NoteDetailScreen.kt`)**:
  - Relocated the "Versions" and "Delete" buttons from the scrollable note body to the sticky bottom Row of actions. Reduced action button text size to `10.sp` and icon size to `12.dp` to fit all 6 actions in a single compact row.
  - Moved "Sync with original" action to the TopAppBar dropdown menu.
- **Line Spacing Bug Fix (`NoteDetailScreen.kt`)**:
  - Resolved duplicate line spaces in markdown rendering by removing the duplicate `append("
    ")` inside the empty-line check of `renderMarkdown()`.
- **Pushed v1.8.4 APK**: Updated `versionCode 20 -> 22` and `versionName 1.8.2 -> 1.8.4`. Rebuilt APK, deployed to `static/downloads/app-debug.apk`, and updated `static/update-manifest.json`.
  **Files touched:** `app/build.gradle.kts`, `app/src/main/java/com/example/echowithin/data/repository/NotesRepository.kt`, `app/src/main/java/com/example/echowithin/data/local/NoteDatabaseHelper.kt`, `app/src/main/java/com/example/echowithin/presentation/screens/NoteDetailScreen.kt`, `app/src/main/java/com/example/echowithin/presentation/screens/HomeScreen.kt`, `app/src/main/java/com/example/echowithin/presentation/viewmodel/NotesViewModel.kt`, `echowithin/api.py`, `echowithin/static/update-manifest.json`, both `AGENTS.md` files.
  **Verification:** Gradle unit tests and APK compilation both passed successfully.

### Model: Antigravity (Advanced Coding Agent)

**Date:** 2026-06-22
**Changes (v1.8.5):**

- **Backslash Escape Formatting Fix (`NoteDetailScreen.kt`, `HomeScreen.kt`, `SearchScreen.kt`)**:
  - Implemented backslash escape character support in the custom Compose markdown parser (`renderMarkdown`), so backslash-escaped characters (like `\*`, `\_`, `\[`, etc.) in imported notes render cleanly as literal characters without displaying the leading backslash.
  - Added a `stripBackslashEscapes` helper to `stripMarkdown()` in both the Home screen and Search screen, ensuring that note list previews and search result snippets do not display raw backslash characters before formatting elements.
- **Pushed v1.8.5 APK**: Updated `versionCode 22 -> 23` and `versionName 1.8.4 -> 1.8.5`. Rebuilt APK, deployed to `static/downloads/app-debug.apk`, and updated `static/update-manifest.json`.
  **Files touched:** `app/build.gradle.kts`, `app/src/main/java/com/example/echowithin/presentation/screens/NoteDetailScreen.kt`, `app/src/main/java/com/example/echowithin/presentation/screens/HomeScreen.kt`, `app/src/main/java/com/example/echowithin/presentation/screens/SearchScreen.kt`, `echowithin/static/update-manifest.json`, both `AGENTS.md` files.
  **Verification:** `./gradlew.bat testDebugUnitTest` passed and APK compiled successfully.

### Model: opencode/deepseek-v4-flash-free

**Date:** 2026-06-29
**Changes:**

- **Community features: polls, resources, check-in, welcome message** — Implemented the 4 remaining features identified as missing for real-world communities (events still pending).
  - **Polls**: Added `api_create_poll`, `api_vote_poll`, `api_close_poll` routes in communities.py. Single vote per user, changeable (old vote decremented), anonymous aggregates. Poll card UI in community_space.html with clickable options, percentage bars, leading option highlight, close button for admins.
  - **Resource Library**: Added `api_upload_resource`, `api_delete_resource` routes. Uploads via Cloudinary to `community_resources/{id}` folder. Grid layout in template with image preview, title, description, uploader, date, delete button (admin/uploader only).
  - **Check-in / Mood Tracking**: Added `api_checkin`, `api_checkin_trends` routes. Once per user per day, 5 moods (great/good/okay/down/tough). Inline bar in template with mood buttons, "Checked in today" state, aggregate counts shown.
  - **Welcome Banner**: Added `api_set_welcome`, `api_dismiss_welcome` routes. Uses existing `welcome_message` + `welcome_dismissed_by[]` fields on community doc. Green banner shown to members who haven't dismissed it.
  - **Admin modals**: Added welcome message editor (inside existing admin modal), create poll modal (with question, multi-line options, optional expiry), upload resource modal (title, description, file picker).
  - **JavaScript**: Added `dismissWelcome()`, `votePoll()`, `checkin()`, `deleteResource()` with fetch + CSRF.

**Files touched:** `echowithin/blueprints/communities.py` (10 new routes, view_community updated with polls/resources/checkin/welcome fetch), `echowithin/templates/community_space.html` (polls section, check-in bar, resources grid, admin welcome form, create poll modal, upload resource modal, JS functions, CSS for all new components), this `AGENTS.md`.

**Verification:** `python -m py_compile echowithin/blueprints/communities.py` → syntax OK.

**Privacy Note:** Check-in moods are stored per-user per-day but only aggregate counts are displayed to others (anonymous). Poll votes are stored per-user for dedup but only aggregate option counts are displayed. Resource uploads use existing Cloudinary infrastructure with no new data exposure. Welcome dismissals are stored as user ID list (only used to suppress the banner).
### Model: Gemini 3.5 Flash (Antigravity)

**Date:** 2026-07-10
**Changes:**

- **Remove Author Achievements from Blog Pages**:
  - Removed author achievement badges from the blog post cards in `templates/_macros.html` and `templates/blog.html`.
  - Removed author achievement badges from the post details page in `templates/view_post.html`.
  - Kept user achievements active on the profile page (`templates/profile.html`).
- **Synchronize Homepage Trending Feed**:
  - Extracted the main blog feed selection logic (recent posts + month selection + weighted older post memories) from `blog.py` into a helper function `get_latest_posts_feed()`.
  - Updated `pages.py` to retrieve `get_latest_posts_feed()[:5]` for homepage `hot_posts` trending list, ensuring the homepage trending posts include older "memories" and match the blog feed.
- **Remove Related Posts Section**:
  - Removed the related posts HTML block and toggle JavaScript from `templates/view_post.html`.
  - Removed the Typesense related posts retrieval/caching logic from the `view_post` endpoint in `blueprints/blog.py`, leaving `related_posts` as an empty list to avoid unnecessary queries.

**Files touched:** `templates/_macros.html`, `templates/blog.html`, `templates/view_post.html`, `blueprints/blog.py`, `blueprints/pages.py`, `AGENTS.md`.

**Verification:** Ran `python -m py_compile blueprints/blog.py blueprints/pages.py` which compiled successfully.

### Model: Antigravity (Advanced Coding Agent)

**Date:** 2026-07-15
**Changes (Whisper Mode + Bonds):**

- **Whisper Mode (Ephemeral Conversations)**:
  - Created `blueprints/whisper.py` with REST API: invite (rate-limited), respond (accept/decline), extend (request/approve), end, active session check, message history (reconnection), tier-based duration options.
  - Added SocketIO handlers in `main.py`: `whisper_message` (stores with TTL, broadcasts to partner), `whisper_typing`/`whisper_stop_typing`, `whisper_screenshot_alert` (stores system message, alerts both parties). Server-side expiry check deletes messages and marks session expired on timeout.
  - MongoDB collections: `whisper_sessions` (TTL index on `expires_at`, 24h cleanup), `whisper_messages` (TTL auto-delete at `expires_at`). Messages are plaintext, never written to `direct_messages`, never backed up.
  - Full UI in `templates/messages.html`: "Whisper" button in chat header, invite modal with tier-gated duration picker (free: 15/30 min, premium: 15/30/60/120 min), consent text, incoming invite modal, full-screen dark overlay for active sessions with countdown timer bar + MM:SS display, warning banner at 5 min (2 min for ≤15 min sessions) with "Extend" button, extension request/approval modals, end screen confirming permanent deletion. Messages use `user-select: none` CSS. Screenshot detection via `visibilitychange` + `blur` events.
  - Tier limits: free 3 sessions/day, 30 min max; premium 10 sessions/day, 120 min max.
- **Bonds (Partner Connection System)**:
  - Created `blueprints/bonds.py` with full REST API: bond request (with `can_dm` permission check, max 3 bonds, 7-day cooldown after breaking), respond, break (deletes all goals + journal), active list. Goals API: propose, approve, check-in (with streak tracking), milestone toggle, complete, abandon. Journal API: create, list, delete (own only).
  - Created `templates/bonds.html`: full bonds page with active bonds cards (partner avatar, label, bonded date, streak count), expandable Goals section (progress bars, milestones as checkboxes, check-in forms, propose/approve/complete/abandon actions), expandable Journal section (chronological entries, create/delete), pending requests with accept/decline, goal creation modal with title/description/category/target/unit/deadline/milestones.
  - MongoDB collections: `bonds` (compound indexes on user_a/user_b/status), `bond_goals` (indexed by bond_id/status), `bond_journal` (indexed by bond_id/created_at).
  - Added "Bonds" nav link in `templates/base.html` navbar.
  - Added bond request button in `templates/profile.html` with status display (bonded/pending/send request).
  - Updated `blueprints/profile.py` to pass `bond_status` to template context.
  - Tier limits: free/premium both 3 max bonds; free 5 goals/bond, premium 20 goals/bond.
  - Categories: Health, Finance, Education, Relationship, Personal Growth, Creative, Custom.
  - Push notifications for bond requests, goal proposals, goal completions.
- **Shared Backend Changes**:
  - Updated `database.py` with 5 new collection references.
  - Updated `config.py` with whisper and bond tier limits.
  - Updated `main.py`: imported and registered `whisper_bp` and `bonds_bp`, initialized all new collections with indexes, populated `database` module.

**Files touched:** `blueprints/whisper.py` (NEW), `blueprints/bonds.py` (NEW), `templates/bonds.html` (NEW), `templates/messages.html`, `templates/base.html`, `templates/profile.html`, `blueprints/profile.py`, `main.py`, `database.py`, `config.py`, `AGENTS.md`.

**Verification:**
1. `python -m py_compile` passed for all `.py` files: `whisper.py`, `bonds.py`, `profile.py`, `main.py`, `database.py`, `config.py`.
2. Jinja2 template parsing passed for `bonds.html`, `messages.html`, `profile.html`, `base.html`.

**Privacy Note:** Whisper messages are stored in plaintext (not encrypted) but auto-deleted via MongoDB TTL indexes. They are never written to the permanent `direct_messages` collection and never backed up. Screenshot detection is best-effort (browser visibility/blur events) and alerts both parties. Bond goals and journal entries are plaintext and permanently deleted when a bond is broken. No new third-party services, cookies, or external data exposure introduced.

### Model: opencode/deepseek-v4-pro

**Date:** 2026-07-15
**Changes (Premium Payment + Whisper Button Fixes):**

- **Premium Payment Callback ObjectId Bug (`blueprints/payments.py`)**:
  - The Paystack callback used `current_user.id` (a string, e.g., `"507f...911"`) to query MongoDB `{'_id': current_user.id}`, but MongoDB stores `_id` as `ObjectId` type. The `update_one` silently matched 0 documents — users saw "Payment successful!" but their tier was never updated.
  - Fixed by wrapping with `ObjectId(current_user.id)` and added a `modified_count == 0` log warning for debugging.
  - The webhook handler (line 131) was already using `ObjectId(user_id_str)` correctly — only the callback was broken.
- **Whisper Button Not Showing on Chat (`templates/messages.html`)**:
  - The whisper button had an inline `display:none` set server-side when no `active_chat` was present at page render. The whisper JS wrapper that should clear this was overwritten by the `DOMContentLoaded` handler due to script execution order (the whisper `<script>` block runs before `DOMContentLoaded` fires, so `window.loadChat` is redefined at line 2119, overwriting the wrapper at line 3792).
  - Fixed by adding the button display reset directly in the main `loadChat` function (line 2134-2135), which is the authoritative definition.
- **Whisper Socket Reference Bug (`templates/messages.html`)**:
  - The whisper IIFE used bare `socket.emit()` and `socket.on()` calls, but `socket` was never defined in scope — only `window.socket` existed (set by `base.html`).
  - Fixed by adding `const socket = window.socket;` at the top of the whisper IIFE so all socket references resolve correctly.

**Files touched:** `blueprints/payments.py`, `templates/messages.html`, `AGENTS.md`.

**Verification:**
1. `python -m py_compile` passed for `payments.py`.
2. Jinja2 template parsing passed for `messages.html`.

### Model: opencode/deepseek-v4-pro

**Date:** 2026-07-15
**Changes (Paystack Metadata Boolean Parsing Fix):**

- **Paystack metadata `is_donation` returned as string (`blueprints/payments.py`)**:
  - Paystack serializes boolean metadata values as strings (e.g., `"false"` instead of `false`). In Python, `bool("false")` is `True` — any non-empty string is truthy. This caused every premium payment to be treated as a donation, showing "Thank you for your generous donation..." instead of activating premium.
  - Added `_is_donation(metadata)` helper that normalizes the check: returns `True` for `True`, `true`, `1`, `yes`; returns `False` for `False`, `false`, `0`, `no`, `""`, `None`, and any other value.
  - Updated both `paystack_callback()` (line 97) and `paystack_webhook()` (line 145) to use the helper.
  - This also fixes the premium activation not working even with the ObjectId fix from the previous commit — the donation branch was always taken first.

**Files touched:** `blueprints/payments.py`, `AGENTS.md`.

**Verification:**
1. `python -m py_compile` passed for `payments.py`.

### Model: opencode/deepseek-v4-pro

**Date:** 2026-07-15
**Changes (DM Chat Deletion Soft-Delete):**

- **Chat deletion now per-user rather than destructive for both parties (`blueprints/chat.py`, `main.py`, `database.py`, `templates/messages.html`)**:
  - Previously, deleting a DM conversation did `delete_many` on the `direct_messages` collection, physically removing all messages between both users. Both parties lost the chat history.
  - Now uses a soft-delete approach via a new `hidden_chats` collection (`{user_id, partner_id, hidden_at}`) with a unique compound index. Deleting a chat inserts a record into `hidden_chats` instead of deleting messages.
  - **Contacts pipeline** (`messages_page`): After building contacts, query `hidden_chats` for the current user and filter out hidden partner IDs from the sidebar.
  - **Message history endpoint** (`api_message_history`): Returns empty `{messages: []}` if the chat is hidden for the current user.
  - **Deep-link protection** (`messages_page` with `?user=` param): Won't load the chat if hidden for the current user.
  - **Un-hide on new message** (`handle_send_dm` in `main.py`): When a new DM arrives, the recipient's `hidden_chats` entry is automatically deleted so the conversation re-appears in their sidebar.
  - **SocketIO event**: `chat_deleted` is now only emitted to the deleting user's room (not the other party), since the other party is unaffected.
  - **Frontend**: Updated confirmation prompt to "Delete this conversation for you? The other person will still see the messages."

**Files touched:** `blueprints/chat.py`, `main.py`, `database.py`, `templates/messages.html`, `AGENTS.md`.

**Verification:**
1. `python -m py_compile` passed for `chat.py`, `main.py`, `database.py`.
2. Jinja2 template parsing passed for `messages.html`.

### Model: opencode/deepseek-v4-pro

**Date:** 2026-07-15
**Changes (Platform-Wide 3-Day Deletion Backup):**

- **Unified backup collection with 3-day TTL for all deletable content**:
  - Renamed `deleted_messages_conf` to `deleted_items_conf` — a universal backup collection for ALL entity types (DMs, notes, posts, comments). TTL index on `expires_at` purges after 3 days, making deletions truly permanent.
  - Created `backup_before_delete(collection_name, doc, deleted_by_user_id)` helper in `utils.py`. Inserts a document into `deleted_items` with `{original_collection, original_id, user_id, data (full document), deleted_at, expires_at}`. Failure is silently caught to never block deletion.
  - **Personal Notes** (`api.py:api_delete_note`, `notes.py:delete_personal_post`): Back up each note document to `deleted_items` before the final `delete_many` from `personal_posts_conf`.
  - **Blog Posts** (`blog.py:delete_post`): Back up the post + all its comments before deleting from `posts_conf` and `comments_conf`.
  - **Blog Comments** (`blog.py:api_delete_comment`): Back up the comment + all sub-replies before `delete_many` from `comments_conf`.
  - **DM Single Message** (`chat.py:api_delete_message`): Back up the message document before `delete_one` from `direct_messages_conf`.
  - **DM Chat** (already done in previous commit): When both parties hide, all messages are backed up to `deleted_items_conf` before deletion.
  - After 3 days, MongoDB's TTL index on `deleted_items.expires_at` auto-deletes the backup — making the deletion permanently irrecoverable.

**Files touched:** `utils.py`, `database.py`, `main.py`, `blueprints/chat.py`, `blueprints/blog.py`, `blueprints/notes.py`, `api.py`, `AGENTS.md`.

**Verification:**
1. `python -m py_compile` passed for all 7 modified files.
