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

### Model: opencode/deepseek-v4-pro

**Date:** 2026-07-15
**Changes (Admin Cloudinary Cleanup + Atlas Backup Exclusion):**

- **`admin_delete_post` (`blueprints/admin.py`)** — was not deleting Cloudinary media at all, leaving orphaned images/videos. Also missing `backup_before_delete`. Fixed to mirror the user-facing `delete_post`: destroy `image_public_id`, `image_public_ids`, `video_public_id` from Cloudinary, backup comments + post to `deleted_items`, then delete from DB.
- **`delete_user` (`blueprints/admin.py`)** — was not cleaning up `profile_image_public_id` from Cloudinary. Fixed.
- **`api_admin_delete_community` (`blueprints/admin.py`)** — was not deleting community resources or their Cloudinary files. Fixed: iterate `community_resources`, destroy each `file_public_id` from Cloudinary, then `delete_many` from `community_resources_conf`.
- **`backup_to_atlas.py` (`scripts/`)** — excluded `deleted_items` collection from Atlas sync. Syncing it was wasteful and counter-productive: TTL-expired local documents appeared as "stale" on Atlas, triggering unnecessary `_deleted_at` marking and creating noisy write churn. The `deleted_items` collection is temporary trash, not permanent data.

**Files touched:** `blueprints/admin.py`, `scripts/backup_to_atlas.py`, `AGENTS.md`.

**Verification:**
1. `python -m py_compile` passed for both files.

### Model: opencode/deepseek-v4-pro

**Date:** 2026-07-15
**Changes (Whisper Pending Invites — Stuck & Unseen Fix):**

- **Problem**: Pending whisper invites blocked new invites indefinitely, but recipients had no way to see them if they missed the SocketIO event (not on the messages page at the time). The pending invite stayed in the DB forever with no UI to view or respond to it.
- **Auto-expiry**: Added `_expire_stale_pending()` that cancels pending invites older than 5 minutes (`PENDING_INVITE_TIMEOUT_MINUTES`). Called before every invite attempt and before the pending check — stale invites are auto-cleaned, unblocking new invites.
- **`GET /api/whisper/pending`**: New endpoint returns any pending invite for the current user (incoming or outgoing). Includes the session_id, partner username, and duration so the frontend can show the accept/decline modal or a status indicator. Also calls `_expire_stale_pending()` to clean up on each check.
- **Frontend page-load check** (`messages.html`): On page load, calls `/api/whisper/pending` and:
  - If incoming pending exists: shows the whisper incoming modal (same as SocketIO event)
  - If outgoing pending exists: shows a toast indicating the invite is waiting for response
  - SocketIO event handlers still work for real-time delivery

**Files touched:** `blueprints/whisper.py`, `templates/messages.html`, `AGENTS.md`.

**Verification:**
1. `python -m py_compile` passed for `whisper.py`.
2. Jinja2 template parsing passed for `messages.html`.

### Model: opencode/deepseek-v4-pro

**Date:** 2026-07-16
**Changes (Whisper DM Notifications — Visible Chat Feedback):**

- **Problem**: Sending a whisper invite gave no visible feedback — the modal closed, a brief toast appeared, but nothing showed in the chat. When accepted, the overlay sometimes didn't appear (SocketIO missed). No indication that a whisper happened or ended.
- **Added `_send_whisper_dm()` helper**: Inserts an unencrypted system message (`message_type: 'whisper_system'`) into `direct_messages` and emits it via SocketIO. These appear as regular messages in the DM chat for both parties.
- **DM notifications at every lifecycle event**:
  - **Invite sent**: "Whisper invite from X — 15 min" (recipient) / "You sent a whisper invite to X — 15 min" (sender)
  - **Invite declined**: "X declined the whisper invite" (sender)
  - **Session started**: "Whisper started — 15 min" (both)
  - **Session ended (manual)**: "Whisper session ended by X" (both)
  - **Session ended (timeout)**: "Whisper session ended (timeout)" (both)
- These DM messages persist in the regular chat history, so even if SocketIO events are missed, both parties see the whisper lifecycle clearly.

**Files touched:** `blueprints/whisper.py`, `main.py`, `AGENTS.md`.

**Verification:**
1. `python -m py_compile` passed for `whisper.py` and `main.py`.

### Model: opencode/deepseek-v4-pro

**Date:** 2026-07-15
**Changes (Whisper Session Fixes — Premature End + Start/End Markers):**

- **Premature session end bug (`main.py`)**:
  - The server-side expiry check compared an aware `datetime` (`now`) with a naive `datetime` (`expires_at` from MongoDB), causing a `TypeError` in Python 3. The generic except block silently caught this — messages failed to send, and the `whisper_expired` event was never emitted. The client-side timer eventually ended the session, appearing as a "premature end."
  - Fixed by normalizing `expires_at` to be timezone-aware before comparison.
  - Also fixed indentation that was broken by a previous edit.
- **Whisper start/end markers (`whisper.py`, `main.py`, `messages.html`)**:
  - **Start marker**: When a session is accepted, a system message "Whisper started — {duration} minutes" is inserted into `whisper_messages` with a 5-min buffer TTL. It appears in both parties' overlay when the session opens.
  - **End marker**: When a session is manually ended, a system message "Session ended by {username}" is inserted and emitted via SocketIO BEFORE the messages are deleted, so both parties see it momentarily before the end screen appears.
  - **Divider styling**: System messages now render with `<div class="whisper-divider"><span>text</span></div>` — a horizontal line with centered text (like date separators in chat). The `::before` and `::after` pseudo-elements create the lines.
  - Replaced `textContent` with `innerHTML` for system messages to support the divider structure.

**Files touched:** `blueprints/whisper.py`, `main.py`, `templates/messages.html`, `AGENTS.md`.

**Verification:**
1. `python -m py_compile` passed for `whisper.py` and `main.py`.
2. Jinja2 template parsing passed for `messages.html`.

### Model: opencode/deepseek-v4-pro

**Date:** 2026-07-16
**Changes (Whisper Stale Active Session Blocking):**

- **Problem**: Expired whisper sessions with `status: 'active'` blocked new invites. The user got "you already have an active whisper session" but reloading showed "Whisper Ended" because the `expires_at` had passed but the status was never updated.
- **Root cause**: `_get_active_session()` only checked `status: 'active'` without verifying `expires_at`. The `/api/whisper/active` endpoint had the same issue, returning stale active sessions to the frontend.
- **Fix in `_get_active_session()`**: After finding an active session, checks `expires_at`. If expired, auto-updates status to `'expired'`, deletes messages, and returns `None` — unblocking new invites.
- **Fix in `/api/whisper/active`**: Separated active and pending checks. Active sessions now go through `_get_active_session()` (which auto-expires). Pending invites go through a separate query with `_expire_stale_pending()` cleanup.

**Files touched:** `blueprints/whisper.py`, `AGENTS.md`.

**Verification:**
1. `python -m py_compile` passed for `whisper.py`.

### Model: opencode/minimax-m3-free

**Date:** 2026-07-16
**Changes (Whisper Modal Not Appearing + Double DM Messages):**

- **Whisper invite modal not appearing without page refresh (`templates/messages.html`)**:
  - `window.socket` (base.html) connects before DOMContentLoaded, so the `join_inbox` handler is registered too late — the socket never joins the user's room. The whisper IIFE listens on `window.socket`, so it never receives `whisper_invite_received` events.
  - Fix: Added `whisper_invite_received` handler on the messages page socket (created inside DOMContentLoaded, properly joins the room via `join_inbox` on connect).
  - Exposed `whisperState` as `window.whisperState` so both the messages page socket handler and the whisper IIFE can access it.
- **Double DM messages (`blueprints/whisper.py`)**:
  - Every lifecycle event (invite sent, session started, session ended) called `_send_whisper_dm` twice — once from each party's perspective — creating two separate DMs that both appeared in the chat.
  - Fix: Removed the second `_send_whisper_dm` call for all three events. A single DM from sender to recipient is visible from both perspectives (sender sees "sent", recipient sees "received").

**Files touched:** `blueprints/whisper.py`, `templates/messages.html`, `AGENTS.md`.

**Verification:**
1. `python -m py_compile` passed for `whisper.py`.
2. Jinja2 template parsing passed for `messages.html`.

### Model: Gemini 3.5 Flash (Antigravity)

**Date:** 2026-07-16
**Changes (Whisper Mode Real-time & Redirect Fixes):**

- **Unify Duplicate Socket Connections**:
  - Unified the duplicate Socket.IO connections in `messages.html`. Previously, `messages.html` established a second local socket connection `socket = io(...)` alongside the global `window.socket` (defined in `base.html`). Whisper event listeners were registered on `window.socket` (which was configured with only websockets and frequently failed/disconnected), while normal direct messaging used the local socket (which supported polling fallback).
  - Modified `base.html` to configure `window.socket` with full reconnection settings and polling transport fallback (`transports: ['websocket', 'polling']`).
  - Modified `messages.html` to reuse `window.socket` directly (`const socket = window.socket;`) as the single page socket.
  - Implemented `onSocketConnect` check: if the socket is already connected when the page loads, we execute the room joining/chat sync logic immediately instead of waiting for the `connect` event (which would have already fired).
  - Removed all duplicate whisper socket event listeners from the first script block in `messages.html`.
- **Global Whisper Redirection & Prompts**:
  - Registered global socket event listeners for `whisper_accept` and `whisper_invite_received` on `window.socket` inside `base.html`.
  - If a user is on another page and their whisper invite is accepted, they are automatically redirected to `/messages?user_id=partner_id` which automatically launches the whisper overlay.
  - If they receive a whisper invite while on another page, they receive a global `showCustomConfirm` prompt asking if they want to go to Messages to accept.
- **Harden End Session Flow**:
  - Modified `doEndWhisper()` to close the whisper overlay locally on the client immediately after a successful response from the `/api/whisper/end/<session_id>` endpoint.
  - Added a guard `if (!whisperState.active) return;` to `whisperSessionEnded` to prevent double-execution from both the local callback and the socket event.
  - Hardened `/api/whisper/end/<session_id>` in `whisper.py` to return success `200 OK` (with `already_ended: true`) if the session is already in `expired` state, avoiding 404 console errors.
- **Screenshot False Positive Fix**:
  - Removed `window.addEventListener('blur')` from `setupScreenshotDetection()` to prevent false screenshot alerts when browser dialogs (like end-session confirm boxes) open or when the page loses focus.

**Files touched:** `templates/base.html`, `templates/messages.html`, `blueprints/whisper.py`, `AGENTS.md`.

**Verification:**
1. `python -m py_compile` passed for `blueprints/whisper.py`.
2. Jinja2 template parsing passed for `templates/base.html` and `templates/messages.html`.

### Model: Gemini 3.5 Flash (Antigravity)

**Date:** 2026-07-17
**Changes (Navbar Logout Button Placement):**

- **Relocate Logout Button**:
  - Moved the logout button in `templates/base.html` from the right-aligned `nav-links` (desktop) and far-right `nav-left` (mobile) to a unified position immediately next to the social buttons in the `nav-left` row.
  - Replaced the separate `nav-logout-desktop` and `nav-logout-mobile` classes with a clean, unified `.nav-logout` class styling that features `margin-left: 1.5rem` to separate it from the social icons.
- **Navbar Styling Cleanup**:
  - Removed outdated classes `.nav-logout-desktop` and `.nav-logout-mobile` and the display-mode media query overrides from `templates/base.html` and `static/style.css`.
  - Added clean `.nav-logout` style rules, including hover transformations, color alignment, and custom dark mode overrides to ensure styling consistency with the platform design.
  - Updated the PWA JavaScript inside `templates/base.html` to reference `nav-logout` instead of the old `nav-logout-mobile` ID.

**Files touched:** `templates/base.html`, `static/style.css`, `AGENTS.md`.

**Verification:**
1. Checked Jinja2 template syntax in `templates/base.html`.
2. Verified stylesheet parsing and media query validity.


 
 # # #   M o d e l :   A n t i g r a v i t y   ( A d v a n c e d   C o d i n g   A g e n t ) 
 * * D a t e : * *   2 0 2 6 - 0 7 - 1 7 
 * * C h a n g e s   ( v 1 . 9 . 6 ) : * * 
 -   * * S o r t   U p d a t e   &   P e r s i s t e n c e   ( N o t e s V i e w M o d e l . k t ,   S e t t i n g s S c r e e n . k t ,   A p p N a v G r a p h . k t ) * * :   F i x e d   s o r t i n g   o p t i o n s   b y   a p p l y i n g   s o r t A n d F i l t e r N o t e s   o n   a l l   d a t a   l o a d   c a l l s ,   a n d   w i r i n g   a   s o r t   o r d e r   s e l e c t i o n   c a l l b a c k   f r o m   t h e   S e t t i n g s   s c r e e n   t o   u p d a t e   t h e   V i e w M o d e l . 
 -   * * O f f l i n e   P i n   S u p p o r t   ( N o t e s R e p o s i t o r y . k t ) * * :   A d d e d   t r y - c a t c h   h a n d l e r   t o   	 o g g l e N o t e P i n ( )   t o   f a l l   b a c k   t o   l o c a l   p i n   s t a t u s   u p d a t e   ( i s S y n c e d   =   f a l s e ,   p e n d i n g O p   =   ' e d i t ' )   w h e n   t h e   A P I   c a l l   f a i l s   o r   i s   o f f l i n e ,   r e t r y i n g   s y n c   a u t o m a t i c a l l y . 
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

### Model: opencode/deepseek-v4-pro

**Date:** 2026-07-15
**Changes (Admin Cloudinary Cleanup + Atlas Backup Exclusion):**

- **`admin_delete_post` (`blueprints/admin.py`)** — was not deleting Cloudinary media at all, leaving orphaned images/videos. Also missing `backup_before_delete`. Fixed to mirror the user-facing `delete_post`: destroy `image_public_id`, `image_public_ids`, `video_public_id` from Cloudinary, backup comments + post to `deleted_items`, then delete from DB.
- **`delete_user` (`blueprints/admin.py`)** — was not cleaning up `profile_image_public_id` from Cloudinary. Fixed.
- **`api_admin_delete_community` (`blueprints/admin.py`)** — was not deleting community resources or their Cloudinary files. Fixed: iterate `community_resources`, destroy each `file_public_id` from Cloudinary, then `delete_many` from `community_resources_conf`.
- **`backup_to_atlas.py` (`scripts/`)** — excluded `deleted_items` collection from Atlas sync. Syncing it was wasteful and counter-productive: TTL-expired local documents appeared as "stale" on Atlas, triggering unnecessary `_deleted_at` marking and creating noisy write churn. The `deleted_items` collection is temporary trash, not permanent data.

**Files touched:** `blueprints/admin.py`, `scripts/backup_to_atlas.py`, `AGENTS.md`.

**Verification:**
1. `python -m py_compile` passed for both files.

### Model: opencode/deepseek-v4-pro

**Date:** 2026-07-15
**Changes (Whisper Pending Invites — Stuck & Unseen Fix):**

- **Problem**: Pending whisper invites blocked new invites indefinitely, but recipients had no way to see them if they missed the SocketIO event (not on the messages page at the time). The pending invite stayed in the DB forever with no UI to view or respond to it.
- **Auto-expiry**: Added `_expire_stale_pending()` that cancels pending invites older than 5 minutes (`PENDING_INVITE_TIMEOUT_MINUTES`). Called before every invite attempt and before the pending check — stale invites are auto-cleaned, unblocking new invites.
- **`GET /api/whisper/pending`**: New endpoint returns any pending invite for the current user (incoming or outgoing). Includes the session_id, partner username, and duration so the frontend can show the accept/decline modal or a status indicator. Also calls `_expire_stale_pending()` to clean up on each check.
- **Frontend page-load check** (`messages.html`): On page load, calls `/api/whisper/pending` and:
  - If incoming pending exists: shows the whisper incoming modal (same as SocketIO event)
  - If outgoing pending exists: shows a toast indicating the invite is waiting for response
  - SocketIO event handlers still work for real-time delivery

**Files touched:** `blueprints/whisper.py`, `templates/messages.html`, `AGENTS.md`.

**Verification:**
1. `python -m py_compile` passed for `whisper.py`.
2. Jinja2 template parsing passed for `messages.html`.

### Model: opencode/deepseek-v4-pro

**Date:** 2026-07-16
**Changes (Whisper DM Notifications — Visible Chat Feedback):**

- **Problem**: Sending a whisper invite gave no visible feedback — the modal closed, a brief toast appeared, but nothing showed in the chat. When accepted, the overlay sometimes didn't appear (SocketIO missed). No indication that a whisper happened or ended.
- **Added `_send_whisper_dm()` helper**: Inserts an unencrypted system message (`message_type: 'whisper_system'`) into `direct_messages` and emits it via SocketIO. These appear as regular messages in the DM chat for both parties.
- **DM notifications at every lifecycle event**:
  - **Invite sent**: "Whisper invite from X — 15 min" (recipient) / "You sent a whisper invite to X — 15 min" (sender)
  - **Invite declined**: "X declined the whisper invite" (sender)
  - **Session started**: "Whisper started — 15 min" (both)
  - **Session ended (manual)**: "Whisper session ended by X" (both)
  - **Session ended (timeout)**: "Whisper session ended (timeout)" (both)
- These DM messages persist in the regular chat history, so even if SocketIO events are missed, both parties see the whisper lifecycle clearly.

**Files touched:** `blueprints/whisper.py`, `main.py`, `AGENTS.md`.

**Verification:**
1. `python -m py_compile` passed for `whisper.py` and `main.py`.

### Model: opencode/deepseek-v4-pro

**Date:** 2026-07-15
**Changes (Whisper Session Fixes — Premature End + Start/End Markers):**

- **Premature session end bug (`main.py`)**:
  - The server-side expiry check compared an aware `datetime` (`now`) with a naive `datetime` (`expires_at` from MongoDB), causing a `TypeError` in Python 3. The generic except block silently caught this — messages failed to send, and the `whisper_expired` event was never emitted. The client-side timer eventually ended the session, appearing as a "premature end."
  - Fixed by normalizing `expires_at` to be timezone-aware before comparison.
  - Also fixed indentation that was broken by a previous edit.
- **Whisper start/end markers (`whisper.py`, `main.py`, `messages.html`)**:
  - **Start marker**: When a session is accepted, a system message "Whisper started — {duration} minutes" is inserted into `whisper_messages` with a 5-min buffer TTL. It appears in both parties' overlay when the session opens.
  - **End marker**: When a session is manually ended, a system message "Session ended by {username}" is inserted and emitted via SocketIO BEFORE the messages are deleted, so both parties see it momentarily before the end screen appears.
  - **Divider styling**: System messages now render with `<div class="whisper-divider"><span>text</span></div>` — a horizontal line with centered text (like date separators in chat). The `::before` and `::after` pseudo-elements create the lines.
  - Replaced `textContent` with `innerHTML` for system messages to support the divider structure.

**Files touched:** `blueprints/whisper.py`, `main.py`, `templates/messages.html`, `AGENTS.md`.

**Verification:**
1. `python -m py_compile` passed for `whisper.py` and `main.py`.
2. Jinja2 template parsing passed for `messages.html`.

### Model: opencode/deepseek-v4-pro

**Date:** 2026-07-16
**Changes (Whisper Stale Active Session Blocking):**

- **Problem**: Expired whisper sessions with `status: 'active'` blocked new invites. The user got "you already have an active whisper session" but reloading showed "Whisper Ended" because the `expires_at` had passed but the status was never updated.
- **Root cause**: `_get_active_session()` only checked `status: 'active'` without verifying `expires_at`. The `/api/whisper/active` endpoint had the same issue, returning stale active sessions to the frontend.
- **Fix in `_get_active_session()`**: After finding an active session, checks `expires_at`. If expired, auto-updates status to `'expired'`, deletes messages, and returns `None` — unblocking new invites.
- **Fix in `/api/whisper/active`**: Separated active and pending checks. Active sessions now go through `_get_active_session()` (which auto-expires). Pending invites go through a separate query with `_expire_stale_pending()` cleanup.

**Files touched:** `blueprints/whisper.py`, `AGENTS.md`.

**Verification:**
1. `python -m py_compile` passed for `whisper.py`.

### Model: opencode/minimax-m3-free

**Date:** 2026-07-16
**Changes (Whisper Modal Not Appearing + Double DM Messages):**

- **Whisper invite modal not appearing without page refresh (`templates/messages.html`)**:
  - `window.socket` (base.html) connects before DOMContentLoaded, so the `join_inbox` handler is registered too late — the socket never joins the user's room. The whisper IIFE listens on `window.socket`, so it never receives `whisper_invite_received` events.
  - Fix: Added `whisper_invite_received` handler on the messages page socket (created inside DOMContentLoaded, properly joins the room via `join_inbox` on connect).
  - Exposed `whisperState` as `window.whisperState` so both the messages page socket handler and the whisper IIFE can access it.
- **Double DM messages (`blueprints/whisper.py`)**:
  - Every lifecycle event (invite sent, session started, session ended) called `_send_whisper_dm` twice — once from each party's perspective — creating two separate DMs that both appeared in the chat.
  - Fix: Removed the second `_send_whisper_dm` call for all three events. A single DM from sender to recipient is visible from both perspectives (sender sees "sent", recipient sees "received").

**Files touched:** `blueprints/whisper.py`, `templates/messages.html`, `AGENTS.md`.

**Verification:**
1. `python -m py_compile` passed for `whisper.py`.
2. Jinja2 template parsing passed for `messages.html`.

### Model: Gemini 3.5 Flash (Antigravity)

**Date:** 2026-07-16
**Changes (Whisper Mode Real-time & Redirect Fixes):**

- **Unify Duplicate Socket Connections**:
  - Unified the duplicate Socket.IO connections in `messages.html`. Previously, `messages.html` established a second local socket connection `socket = io(...)` alongside the global `window.socket` (defined in `base.html`). Whisper event listeners were registered on `window.socket` (which was configured with only websockets and frequently failed/disconnected), while normal direct messaging used the local socket (which supported polling fallback).
  - Modified `base.html` to configure `window.socket` with full reconnection settings and polling transport fallback (`transports: ['websocket', 'polling']`).
  - Modified `messages.html` to reuse `window.socket` directly (`const socket = window.socket;`) as the single page socket.
  - Implemented `onSocketConnect` check: if the socket is already connected when the page loads, we execute the room joining/chat sync logic immediately instead of waiting for the `connect` event (which would have already fired).
  - Removed all duplicate whisper socket event listeners from the first script block in `messages.html`.
- **Global Whisper Redirection & Prompts**:
  - Registered global socket event listeners for `whisper_accept` and `whisper_invite_received` on `window.socket` inside `base.html`.
  - If a user is on another page and their whisper invite is accepted, they are automatically redirected to `/messages?user_id=partner_id` which automatically launches the whisper overlay.
  - If they receive a whisper invite while on another page, they receive a global `showCustomConfirm` prompt asking if they want to go to Messages to accept.
- **Harden End Session Flow**:
  - Modified `doEndWhisper()` to close the whisper overlay locally on the client immediately after a successful response from the `/api/whisper/end/<session_id>` endpoint.
  - Added a guard `if (!whisperState.active) return;` to `whisperSessionEnded` to prevent double-execution from both the local callback and the socket event.
  - Hardened `/api/whisper/end/<session_id>` in `whisper.py` to return success `200 OK` (with `already_ended: true`) if the session is already in `expired` state, avoiding 404 console errors.
- **Screenshot False Positive Fix**:
  - Removed `window.addEventListener('blur')` from `setupScreenshotDetection()` to prevent false screenshot alerts when browser dialogs (like end-session confirm boxes) open or when the page loses focus.

**Files touched:** `templates/base.html`, `templates/messages.html`, `blueprints/whisper.py`, `AGENTS.md`.

**Verification:**
1. `python -m py_compile` passed for `blueprints/whisper.py`.
2. Jinja2 template parsing passed for `templates/base.html` and `templates/messages.html`.

### Model: Gemini 3.5 Flash (Antigravity)

**Date:** 2026-07-17
**Changes (Navbar Logout Button Placement):**

- **Relocate Logout Button**:
  - Moved the logout button in `templates/base.html` from the right-aligned `nav-links` (desktop) and far-right `nav-left` (mobile) to a unified position immediately next to the social buttons in the `nav-left` row.
  - Replaced the separate `nav-logout-desktop` and `nav-logout-mobile` classes with a clean, unified `.nav-logout` class styling that features `margin-left: 1.5rem` to separate it from the social icons.
- **Navbar Styling Cleanup**:
  - Removed outdated classes `.nav-logout-desktop` and `.nav-logout-mobile` and the display-mode media query overrides from `templates/base.html` and `static/style.css`.
  - Added clean `.nav-logout` style rules, including hover transformations, color alignment, and custom dark mode overrides to ensure styling consistency with the platform design.
  - Updated the PWA JavaScript inside `templates/base.html` to reference `nav-logout` instead of the old `nav-logout-mobile` ID.

**Files touched:** `templates/base.html`, `static/style.css`, `AGENTS.md`.

**Verification:**
1. Checked Jinja2 template syntax in `templates/base.html`.
2. Verified stylesheet parsing and media query validity.

### Model: Antigravity (Advanced Coding Agent)
**Date:** 2026-07-17
**Changes (v1.9.6):**

- **Sort Update & Persistence** (`NotesViewModel.kt`, `SettingsScreen.kt`, `AppNavGraph.kt`): Fixed sorting options by applying sortAndFilterNotes on all data load calls, and wiring a sort order selection callback from the Settings screen to update the ViewModel.
- **Offline Pin Support** (`NotesRepository.kt`): Added try-catch handler to toggleNotePin() to fallback to local pin status update (isSynced = false, pendingOp = 'edit') when the API call fails or is offline, retrying sync automatically.
- **Sync Mismatch & Draft Protection** (`NotesRepository.kt`, `NoteDatabaseHelper.kt`): Changed saveDraftLocally() to save drafts with pendingOp = 'draft' and updated the server pull reconciliation loop to prevent overwriting local drafts. Updated clearSyncedNotes() to preserve all local notes (including drafts) on logout/session expiration.
- **Export Crash Fix** (`HomeScreen.kt`, `NoteDetailScreen.kt`): Wrapped CreateDocument picker launch in a try-catch to prevent crash, with a fallback that writes to private cache and launches a system Share Sheet.
- **Draft Badge** (`HomeScreen.kt`): Rendered a 'Draft' badge in the note list next to notes with pendingOp == 'draft'.
- **Pushed v1.9.6 APK**: Updated VersionCode 29 -> 30 and VersionName 1.9.5 -> 1.9.6. Rebuilt APK, deployed to static/downloads/app-debug.apk, and updated static/update-manifest.json.

**Files touched:** `app/build.gradle.kts`, `app/src/main/java/com/example/echowithin/data/local/NoteDatabaseHelper.kt`, `app/src/main/java/com/example/echowithin/data/repository/NotesRepository.kt`, `app/src/main/java/com/example/echowithin/presentation/viewmodel/NotesViewModel.kt`, `app/src/main/java/com/example/echowithin/presentation/screens/SettingsScreen.kt`, `app/src/main/java/com/example/echowithin/presentation/screens/HomeScreen.kt`, `app/src/main/java/com/example/echowithin/presentation/screens/NoteDetailScreen.kt`, `app/src/main/java/com/example/echowithin/presentation/navigation/AppNavGraph.kt`, `echowithin/static/downloads/app-debug.apk`, `echowithin/static/update-manifest.json`, `this AGENTS.md`.

**Verification:** `.\gradlew compileDebugKotlin` completed successfully with zero errors.

### Model: Antigravity (Advanced Coding Agent)

**Date:** 2026-07-18
**Changes:**

- **Recovered Note Discussions**: Connected to the backup and official MongoDB database, merged the exported JSON documents from both `C:\Users\DevTech\Downloads\echowithin_db.note_discussions.json` and `C:\Users\DevTech\Desktop\Projects\echowithin\echowithin_db_export\note_discussions.json` (deduplicating and taking the most complete schemas), and successfully restored all 50 comments back to the active MongoDB collection.
- **Discussion Soft-Delete Strategy**:
  - Replaced the hard-delete cascade policy in both `sharing.py` and `blog.py` comment delete endpoints. When a comment with replies is deleted, it is now marked as `deleted` or `is_deleted` and has its author name/content updated to `"[deleted]"` to preserve the reply tree. Only comments with no active children are purged.
  - Updated comment fetch/retrieval API in `sharing.py` to check for `deleted` status and return `[deleted]` safely without attempting decryption.
  - Added support for admins to delete shared note comments on both backend (`blueprints/sharing.py` check `current_user.is_admin`) and frontend UI (`templates/shared_note.html` using `IS_ADMIN` check).
- **Collapsible Nested Replies in Shared Note**:
  - Updated `createCommentHTML` and `toggleReplies` in `shared_note.html` to allow users to toggle (Show/Hide) nested reply blocks under any comment.
  - Refined reply nesting visual styling (increased indentation margin/padding for clearer visual hierarchy, styled the replies border-left).
  - Added dark theme styles for `.reply-card` and `.replies-container` inside `style.css`.
- **Force Light Theme on Weekly Newsletter**:
  - Removed the `prefers-color-scheme: dark` media queries from the HTML template of `weekly_newsletter.html` so it always stays in the light theme format.
- **Removed Side Borders**:
  - Removed all remaining thick left borders across the platform, replacing them with a subtle 1px border or top border (including note lists, system health cards in the admin dashboard, etc.).
- **Fix Welcome Message Submission**:
  - Resolved form validation issue where submitting a community welcome message returned `"Message is required"`. Modified the `/welcome` route in `communities.py` to accept the form parameter `welcome_message` in addition to `message`.
- **Fix Onboarding Tour Placement**:
  - Scoped steps selectors inside `.note-actions` inside `initOnboardingTour()` in `personal_space.html`. This avoids targeting hidden buttons (such as the copy button inside the links dropdown) which was causing the tooltip to miscalculate coordinates and display in the top-left corner of the page.

**Files touched:** `blueprints/sharing.py`, `blueprints/blog.py`, `blueprints/communities.py`, `templates/personal_space.html`, `templates/shared_note.html`, `templates/view_post.html`, `templates/admin_dashboard.html`, `templates/weekly_newsletter.html`, `static/style.css`, `AGENTS.md`.