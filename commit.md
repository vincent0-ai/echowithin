# Commit Summary

## Goal
Fix section display behavior on the Bonds page so that clicking Mood, Question, Goals, or Journal displays one section at a time instead of stacking sections below each other.

## Description of Changes
- **Mutually Exclusive Section Toggling**: Updated `toggleSection(id, btn)` in `templates/bonds.html` to close any other open section inside the bond card whenever a new section button is clicked.
- **Button Active Highlighting**: Added `.btn-bond-section.active` CSS styles and updated button onclick handlers so the currently active section tab is visually highlighted.

## Modified Files
- [templates/bonds.html](file:///c:/Users/DevTech/Desktop/Projects/echowithin/echowithin/templates/bonds.html)

## Model Attribution
- Model: Gemini 3.5 Flash (High)
