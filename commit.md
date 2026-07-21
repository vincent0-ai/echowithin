# Commit Summary

## Goal
Fix mobile keyboard issue where input area and send button were pushed down or hidden under the page footer when typing.

## Description of Changes
- **Hidden Footer in Chat View**: Added `display: none !important` on `footer`, `.footer`, and `.site-footer` when `mobile-chat-open` is active so the page footer doesn't take up vertical space or overlap input area.
- **Dynamic VisualViewport Height**: Bound `.messages-wrapper` height directly to `window.visualViewport.height` on mobile keyboard resize, keeping the entire chat container (header, history, input bar, and send button) pinned perfectly above the virtual keyboard.
- **Form Flex Shrink & Button Sizing**: Explicitly enforced `flex-shrink: 0` on `.action-btn` and `#send-btn` with reduced mobile gap (`0.35rem`) so all 5 input components remain fully visible on screen.

## Modified Files
- [templates/messages.html](file:///c:/Users/DevTech/Desktop/Projects/echowithin/echowithin/templates/messages.html)

## Model Attribution
- Model: Gemini 3.5 Flash (High)
