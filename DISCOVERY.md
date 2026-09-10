# Real-Time Delivery Regression — Discovery Report

## Confirmed timeline
- **Regression Started:** Wednesday morning/noon, September 9, 2026.
- **Git Window Audited:** Commits between Tuesday Sep 8, 2026 (`0093cad`) and Wednesday night Sep 9, 2026 (`4a0ef98`).
- **Key Deployments in Regression Window (Sep 9 morning/noon):**
  - `2476802` (Sep 9 10:37 +0300): `fix(whisper): elevate modal z-index in templates/messages.html; tests/test_chat_whisper.py`
  - `a1a1cf7` (Sep 9 10:51 +0300): `feat(dm): add playable multiplayer Slime Volleyball auto-lobby invites in main.py, templates/messages.html, static/slime_volleyball.js, tests/test_forms_and_games.py`
  - `374275d` (Sep 9 11:07 +0300): `Add video support in whisper` (`main.py`, `blueprints/chat.py`, `blueprints/whisper.py`, `templates/messages.html`)
  - `03982f5` (Sep 9 11:54 +0300): `Add arcade matchmaking queue and leaderboards` (`main.py`, `blueprints/game.py`, `database.py`, `templates/base.html`, etc.)
  - `1c8b0d2` (Sep 9 13:39 +0300): `Fix arcade leaderboard CSRF exemption and sync`
  - `aea602b` (Sep 9 13:50 +0300): `Add mobile back navigation and clean minimalist game controls`
  - `2e5f0a6` (Sep 9 14:13 +0300): `Add offline play score queue and auto-sync on reconnect`

## Findings
### 1. The Polling Discrepancy (Why DMs update after 15s but Whisper requires reload)
- **Direct Messages (DMs)**:
  - `templates/messages.html:2437-2443`: `startChatSync()` executes `setInterval(() => { syncActiveChatHistory(); }, 15000);` (15-second polling interval).
  - `syncActiveChatHistory()` hits `GET /api/messages/history/<other_user_id>`.
  - In `blueprints/chat.py:186-190`, `api_message_history()` marks unread messages from that partner as read in MongoDB and emits `m.socketio.emit('messages_read', {'reader_id': str(current_user.id), 'sender_id': other_user_id}, room=f"user_{other_user_id}")`.
  - **Evidence**: When real-time push/socket delivery fails, DMs fall back to this 15-second background polling cycle. The sender's read-receipt ticks stay single until the recipient's 15s interval poll triggers.
- **Whisper Mode**:
  - Whisper Mode has **no interval polling** mechanism whatsoever (`startChatSync` is only in DM scope). History is only fetched once on session open or page load via `echoFetch('/api/whisper/history/' + session_id)` (`templates/messages.html:5702`).
  - **Evidence**: When real-time delivery fails in Whisper Mode, messages never appear on the recipient's screen and read receipts never update until the user manually refreshes the page.

### 2. Room Architecture & Feature Isolation
- **Private Room Convention**: Both DMs and Whisper Mode broadcast private events exclusively to room name `room=f"user_{user_id}"` (using the 24-hex string representation of MongoDB `ObjectId`):
  - `main.py:3253` (`handle_join_inbox`): `user_room = f"user_{current_user.id}"`; `join_room(user_room)`.
  - `main.py:3561` (`handle_send_dm`): `emit('new_dm', payload, room=f"user_{recipient_id_str}")`.
  - `main.py:3566` (`handle_send_dm`): `emit('message_confirmed', payload, room=f"user_{sender_id_str}")`.
  - `main.py:3570` (`handle_send_dm`): `emit('messages_read', ..., room=f"user_{sender_id_str}")`.
  - `main.py:3873` (`handle_whisper_message`): `emit('whisper_new_message', payload, room=f"user_{partner_id}")`.
  - `main.py:3876` (`handle_whisper_message`): `emit('whisper_message_confirmed', ..., room=f"user_{user_id_str}")`.
  - `main.py:3879` (`handle_whisper_message`): `emit('whisper_read_receipt', ..., room=f"user_{user_id_str}")`.
- **Other Real-Time Features**:
  - Collaborative Notes use `room=share_id` (`main.py:1656`).
  - Party Games use `room=lobby_id` (`main.py:1839`).
  - Arcade 1v1 Games (Slime Volleyball, Pong, Tic-Tac-Toe, Connect Four, Dots & Boxes) use `room=room_id` (`main.py:1895`).
  - Notes and Arcade 1v1 Games do NOT use `f"user_{user_id}"`, which isolates the issue specifically to user inbox rooms and active chat views.

### 3. Presence Tracking Eviction on Any Disconnect (`active_chat_views`)
- In `main.py:3290-3296`:
  ```python
  @socketio.on('disconnect')
  def handle_dm_disconnect(*args, **kwargs):
      user_id = str(current_user.id) if current_user.is_authenticated else request.sid
      if current_user.is_authenticated:
          active_chat_views.pop(user_id, None)
  ```
- **The Multi-Socket & Tab Flaw**:
  - `active_chat_views` is a server-side in-memory dictionary `dict[str, set[str]]` mapping `user_id` to sets of viewed partner IDs.
  - With the addition of multiplayer games (`a1a1cf7`, `03982f5`), auto-lobby invites open game links in new tabs/windows (`window.open(gameUrl, '_blank')`).
  - `templates/base.html:95` initializes a global `window.socket` across all authenticated pages. Furthermore, game scripts (`static/slime_volleyball.js:1166`, `static/tic_tac_toe.js:689`, `static/ping_pong.js:900`) create a secondary `GameState.socket = io(...)`.
  - When the user closes a game tab, navigates between pages, or when a mobile browser puts background tabs to sleep, a `disconnect` event fires for that socket.
  - The server handler executes `active_chat_views.pop(user_id, None)`, completely obliterating the user's active viewing status for the Messages page in the primary tab!

### 4. Client-Side Read Acknowledgment Missing for Incoming `new_dm`
- In `templates/messages.html:2474-2489`:
  ```javascript
  s.on('new_dm', (data) => {
      if (data.sender_id === activeRecipientId) {
          hideTypingIndicator();
          appendMessage(data, 'received', false, data.id, data.is_read);
          scrollToBottom();
      }
  ```
- When `new_dm` arrives in an active chat window, the client appends the bubble to the DOM, but **never emits a read acknowledgment or calls an endpoint to mark the message read**.
- The backend relies entirely on the optimistic assumption that `is_actively_reading` was `True` during `handle_send_dm`.
- Once `active_chat_views` is evicted (Finding 3), `is_actively_reading` is `False`. The backend saves `is_read = False` and does not emit `messages_read`. Because the client doesn't send a read ack upon rendering `new_dm`, the sender's checkmarks remain single until the 15s `startChatSync()` background poll runs.

### 5. Whisper Mode Never Emits `viewing_chat`
- In `templates/messages.html:5671` (`startWhisperSession`):
  - Whisper Mode activates the overlay modal, starts its local timer, and fetches history.
  - It **never emits `viewing_chat`** (`emitSocket('viewing_chat', { partner_id: ... })`).
  - In `main.py:3798-3800` (`handle_whisper_message`):
    ```python
    partner_viewing = active_chat_views.get(partner_id, set())
    is_actively_viewing = user_id_str in partner_viewing
    ```
  - Because Whisper never registered the view, `is_actively_viewing` is always `False`.
  - `handle_whisper_message` marks `is_read = False` and suppresses immediate `whisper_read_receipt` emission to the sender (`main.py:3878`).

### 6. Transport & Worker Performance
- Single worker architecture: `Procfile` specifies `-w 1` with `GeventWebSocketWorker` and `--timeout 120`.
- High-frequency game sync loops (18 Hz in `slime_volleyball.js:1132`, 30 Hz in `ping_pong.js:885`) transmit continuously through Socket.IO.
- Prior to commit `4a0ef98` (Wednesday 23:01), `send_push_notification_to_user()` was called **synchronously** inside `handle_send_dm` and `handle_whisper_message` whenever `is_actively_reading` was `False`. Making external HTTP webpush calls (VAPID / Apple push services / FCM) synchronously blocked the Gevent worker loop whenever presence was falsely marked offline.

## Ruled out
1. **Native Android App Changes**:
   - The Android app repository at `C:\Users\DevTech\AndroidStudioProjects\EchoWithin` has had no commits during the regression window.
   - The production APK deployed at `static/downloads/app-debug.apk` is v1.10.6 (versionCode 40) built on Aug 28, 2026.
2. **Python Package / Dependency Upgrades**:
   - Audited `requirements.txt`, lockfiles, and environment packages: `Flask-SocketIO==5.3.6`, `python-socketio==5.11.0`, `python-engineio==4.9.0`, `gevent==25.9.1`, `gevent-websocket==0.10.1`. No dependencies were updated in this window.
3. **Database Schema / MongoDB Mutations**:
   - `direct_messages` and `whisper_messages` collections maintain their existing schema and index definitions (`timestamp`, `sender_id`, `recipient_id`, `session_id`).
4. **Proxy / Reverse Proxy SSL & WebSocket Handshake**:
   - Verified live handshake against `https://echowithin.xyz/socket.io/?EIO=4&transport=polling`.
   - Handshake returns HTTP 200 with valid engine.io session ID and `upgrades: ["websocket"]`.

## Root cause hypothesis
### Hypothesis 1 (Primary — Confirmed): Presence State Eviction (`active_chat_views`) combined with Missing Client-Side `new_dm` Read Acks and Missing Whisper `viewing_chat`
- **Evidence**:
  1. `main.py:3290` clears `active_chat_views[user_id]` on ANY socket disconnect. With games opening new tabs and creating secondary sockets (`static/slime_volleyball.js:1166`), closing tabs or backgrounding immediately invalidates the user's active DM view on the server.
  2. In `templates/messages.html:2474`, receiving `new_dm` in an open conversation does not emit a read receipt or notify the server. When `active_chat_views` is evicted, the message stays unread until the 15,000 ms poll (`syncActiveChatHistory()`) hits `/api/messages/history`, producing the exact 15-second double-tick delay.
  3. In `templates/messages.html:5671`, Whisper Mode never emits `viewing_chat`. `is_actively_viewing` is therefore always `False` on the server. Because Whisper has no interval polling fallback, read receipts and real-time synchronization fail completely until page reload.
  4. In `main.py` before commit `4a0ef98`, whenever `is_actively_reading` dropped to `False`, `send_push_notification_to_user()` executed synchronously in the WebSocket event loop, introducing severe delivery latency to connected clients.

### Hypothesis 2 (Secondary — Contributing): Socket Connection Multiplicity & Inbox Room Re-Subscription
- **Evidence**:
  - Secondary socket instances created on game pages (`io({ transports: ['websocket', 'polling'] })`) connect without emitting `join_inbox`. When they disconnect, they trigger `handle_dm_disconnect` which clears presence for the authenticated user ID without checking connection/session counts.

## Open questions / needs more evidence
1. Should `active_chat_views` track active views per `request.sid` (or reference count connections per user) rather than a flat `dict[user_id, set[partner_ids]]` to make it multi-tab safe?
2. Should client `new_dm` handler emit an immediate `mark_messages_read` socket event when actively viewing the sender's conversation?
3. Should Whisper Mode register its active session with `active_chat_views` and join a dedicated session room (`room=f"whisper_{session_id}"`) for instant broadcast?
