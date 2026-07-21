# Commit Summary

## Goal
Fix mobile/iOS chat layout issues (send button overflow, accidental reaction popup triggers, jumpy chat scrolling, and missing bottom typing indicator).

## Description of Changes
- **iOS Send Button Overflow**: Added `flex-shrink: 0` to all action buttons in the chat form and `min-width: 0; box-sizing: border-box; width: 100%` on flex wrappers and `.chat-input-area` to prevent horizontal scrolling on iOS Safari.
- **Accidental Reaction Popups**: Wrapped hover-triggered reaction bars and message action menus under `@media (hover: hover) and (pointer: fine)` so touch events on mobile do not trigger hover reactions. Integrated clean quick-reaction emojis into the mobile long-press menu overlay.
- **Movy / Jumpy Mobile Chat**: Removed jumpy `visualViewport` height mutation JS, locked overscroll behavior with `overscroll-behavior-y: contain` on `#chat-history`, and enforced `100dvh` fixed bounds on `body.mobile-chat-open`.
- **Bottom Typing Indicator**: Added a sticky `#bottom-typing-indicator` bar positioned directly above `#message-input` so typing/recording status is visible right above the virtual keyboard.

## Modified Files
- [templates/messages.html](file:///c:/Users/DevTech/Desktop/Projects/echowithin/echowithin/templates/messages.html)

## Model Attribution
- Model: Gemini 3.5 Flash (High)
