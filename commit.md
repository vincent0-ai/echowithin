# Commit Summary

## Goal
Ensure mobile chat mode (`body.mobile-chat-open`) initializes immediately on page load/refresh when an active chat is present, preventing the navbar and footer from pushing the chat input bar off-screen.

## Description of Changes
- **DOMContentLoaded Mobile Mode Init**: Added `if (activeRecipientId && window.innerWidth <= 768) document.body.classList.add('mobile-chat-open')` on DOMContentLoaded so direct page loads and refreshes immediately hide top/bottom site chrome and set full-height `100dvh` bounds on mobile.

## Modified Files
- [templates/messages.html](file:///c:/Users/DevTech/Desktop/Projects/echowithin/echowithin/templates/messages.html)

## Model Attribution
- Model: Gemini 3.5 Flash (High)
