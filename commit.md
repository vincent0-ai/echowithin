# Commit Summary

## Goal
Fix iOS side-scrolling ("scroll aside") on message bubbles and provide phone diagnostic / testing tools for iOS web development.

## Description of Changes
- **Inline Reply Button**: Added `.inline-reply-btn` directly inside `.message-meta` on all message bubbles so iOS users can tap the reply icon (`<i class="fas fa-reply">`) directly without side-scrolling or long-pressing.
- **Native Touch Swipe-to-Reply**: Implemented `setupSwipeToReply` with smooth touch drag (`translateX`) and haptic feedback (`navigator.vibrate`) when swiping right on any message bubble on mobile.
- **Disabled Absolute Popups on Mobile**: Added `display: none !important` to `.message-actions` and `.reaction-bar` under `@media (max-width: 768px)` so absolute positioning elements never overflow or create horizontal scroll tracks on iOS Safari.

## Modified Files
- [templates/messages.html](file:///c:/Users/DevTech/Desktop/Projects/echowithin/echowithin/templates/messages.html)

## Model Attribution
- Model: Gemini 3.5 Flash (High)
