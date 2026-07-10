# Agent Instructions

These are the operational instructions for agents working in this repository.

If the logic requires some further modification note at the end.

1. Commit messages and model attribution
   
   - All agents MUST include a detailed commit message describing the changes made.
   - The commit message MUST include the agent's model name and everything saved here.(Write in this document)

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

**Files touched:** `templates/_macros.html`, `templates/blog.html`, `templates/view_post.html`, `blueprints/blog.py`, `blueprints/pages.py`, `AGENTS.md`.

**Verification:** Ran `python -m py_compile blueprints/blog.py blueprints/pages.py` which compiled successfully.
