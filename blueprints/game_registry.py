"""Shared registry for EchoWithin games.

Keep this file free of secrets and environment-specific values. It is imported
by both the Games page and Bond Challenge so those surfaces cannot drift.

Each entry carries its thumbnail (art_bg + art_svg), badge, and CTA label so the
Games page can render rich cards without hardcoding per-game HTML.
"""

from copy import deepcopy


GAMES = [
    {
        "id": "trivia",
        "name": "Trivia Challenge",
        "type": "party",
        "players": "2-30",
        "description": "Host a live question room with timed answers and podium results.",
        "icon": "fa-solid fa-bolt",
        "category": "party",
        "route": "/games/create?type=trivia",
        "bond_route": "/games/create?type=trivia",
        "badge": "Live Show",
        "cta": "Host Trivia",
        "art_bg": "#26170f",
        "art_svg": """<svg viewBox="0 0 320 120" width="100%" height="100%" preserveAspectRatio="xMidYMid slice" xmlns="http://www.w3.org/2000/svg">
            <defs>
              <linearGradient id="triv-bg" x1="0%" y1="0%" x2="100%" y2="100%">
                <stop offset="0%" stop-color="#341e14" />
                <stop offset="100%" stop-color="#1f120c" />
              </linearGradient>
            </defs>
            <rect width="320" height="120" fill="url(#triv-bg)" />
            <circle cx="45" cy="30" r="1.5" fill="#f5c452" opacity="0.6"/>
            <circle cx="280" cy="85" r="2" fill="#f5c452" opacity="0.5"/>
            <circle cx="35" cy="90" r="1.5" fill="#ffffff" opacity="0.4"/>
            <circle cx="290" cy="35" r="1.5" fill="#ffffff" opacity="0.5"/>
            <!-- 4 Kahoot-style Shape Tiles -->
            <rect x="94" y="20" width="60" height="34" rx="7" fill="#b8423f" />
            <polygon points="124,27 115,44 133,44" fill="#ffffff" />
            <rect x="166" y="20" width="60" height="34" rx="7" fill="#2c5f8a" />
            <polygon points="196,26 206,37 196,48 186,37" fill="#ffffff" />
            <rect x="94" y="66" width="60" height="34" rx="7" fill="#c68a35" />
            <circle cx="124" cy="83" r="9" fill="#ffffff" />
            <rect x="166" y="66" width="60" height="34" rx="7" fill="#3f7e52" />
            <rect x="188" y="75" width="16" height="16" rx="2" fill="#ffffff" />
            <!-- Center Emblem -->
            <circle cx="160" cy="60" r="15" fill="#1b100b" stroke="#f5c452" stroke-width="2" />
            <text x="160" y="66" font-size="14" text-anchor="middle" fill="#f5c452" font-weight="900" font-family="sans-serif">ΓÜí</text>
          </svg>""",
    },
    {
        "id": "poll",
        "name": "Interactive Polls",
        "type": "party",
        "players": "2-30",
        "description": "Create a quick live vote and compare responses together.",
        "icon": "fa-solid fa-chart-simple",
        "category": "party",
        "route": "/games/create?type=poll",
        "bond_route": "/games/create?type=poll",
        "badge": "Live Voting",
        "cta": "Host Poll",
        "art_bg": "#f6f1ea",
        "art_svg": """<svg viewBox="0 0 320 120" width="100%" height="100%" preserveAspectRatio="xMidYMid slice" xmlns="http://www.w3.org/2000/svg">
            <rect width="320" height="120" fill="#f6f1ea" />
            <line x1="60" y1="35" x2="260" y2="35" stroke="#e6ded3" stroke-width="1" stroke-dasharray="3,3" />
            <line x1="60" y1="65" x2="260" y2="65" stroke="#e6ded3" stroke-width="1" stroke-dasharray="3,3" />
            <line x1="60" y1="95" x2="260" y2="95" stroke="#d5cbbe" stroke-width="1.5" />
            <rect x="80" y="55" width="40" height="40" rx="5" fill="#5c3d2e" />
            <rect x="83" y="38" width="34" height="14" rx="3" fill="#ffffff" stroke="#e0d7cb" />
            <text x="100" y="49" font-size="9" text-anchor="middle" font-weight="700" fill="#5c3d2e" font-family="sans-serif">28%</text>
            <rect x="140" y="25" width="40" height="70" rx="5" fill="#2c5f8a" />
            <rect x="143" y="8" width="34" height="14" rx="3" fill="#2c5f8a" />
            <text x="160" y="19" font-size="9" text-anchor="middle" font-weight="700" fill="#ffffff" font-family="sans-serif">54% Γ£ô</text>
            <rect x="200" y="68" width="40" height="27" rx="5" fill="#3f7e52" />
            <rect x="203" y="51" width="34" height="14" rx="3" fill="#ffffff" stroke="#e0d7cb" />
            <text x="220" y="62" font-size="9" text-anchor="middle" font-weight="700" fill="#3f7e52" font-family="sans-serif">18%</text>
          </svg>""",
    },
    {
        "id": "wyr",
        "name": "Would You Rather",
        "type": "party",
        "players": "2-30",
        "description": "Debate a two-choice dilemma and see how the room splits.",
        "icon": "fa-solid fa-code-compare",
        "category": "party",
        "route": "/games/create?type=wyr",
        "bond_route": "/games/create?type=wyr",
        "badge": "Social Debate",
        "cta": "Host WYR",
        "art_bg": "#f7f0e7",
        "art_svg": """<svg viewBox="0 0 320 120" width="100%" height="100%" preserveAspectRatio="xMidYMid slice" xmlns="http://www.w3.org/2000/svg">
            <rect width="320" height="120" fill="#f7f0e7" />
            <g transform="translate(65, 22) rotate(-5)">
              <rect width="82" height="68" rx="8" fill="#b8423f" />
              <rect x="8" y="10" width="28" height="6" rx="2" fill="rgba(255,255,255,0.4)" />
              <text x="41" y="44" font-size="18" text-anchor="middle" font-weight="800" fill="#ffffff" font-family="sans-serif">THIS</text>
            </g>
            <g transform="translate(175, 22) rotate(5)">
              <rect width="82" height="68" rx="8" fill="#2c5f8a" />
              <rect x="8" y="10" width="28" height="6" rx="2" fill="rgba(255,255,255,0.4)" />
              <text x="41" y="44" font-size="18" text-anchor="middle" font-weight="800" fill="#ffffff" font-family="sans-serif">THAT</text>
            </g>
            <circle cx="160" cy="58" r="16" fill="#3e2217" stroke="#ffffff" stroke-width="2" />
            <text x="160" y="63" font-size="11" text-anchor="middle" font-weight="800" fill="#ffffff" font-family="sans-serif">VS</text>
          </svg>""",
    },
    {
        "id": "ttal",
        "name": "Two Truths & a Lie",
        "type": "party",
        "players": "2-30",
        "description": "Submit three statements and guess which one is the lie.",
        "icon": "fa-solid fa-user-secret",
        "category": "party",
        "route": "/games/create?type=ttal",
        "bond_route": "/games/create?type=ttal",
        "badge": "Deception",
        "cta": "Host TTAL",
        "art_bg": "#f5ede4",
        "art_svg": """<svg viewBox="0 0 320 120" width="100%" height="100%" preserveAspectRatio="xMidYMid slice" xmlns="http://www.w3.org/2000/svg">
            <rect width="320" height="120" fill="#f5ede4" />
            <rect x="42" y="24" width="68" height="72" rx="6" fill="#ffffff" stroke="#ded5c8" stroke-width="1.5" />
            <rect x="52" y="34" width="36" height="4" rx="2" fill="#c4b8aa" />
            <rect x="52" y="44" width="48" height="4" rx="2" fill="#ded5c8" />
            <rect x="52" y="54" width="40" height="4" rx="2" fill="#ded5c8" />
            <circle cx="76" cy="74" r="8" fill="rgba(63,126,82,0.15)" />
            <text x="76" y="78" font-size="10" text-anchor="middle" fill="#3f7e52" font-weight="800">Γ£ô</text>
            <rect x="126" y="24" width="68" height="72" rx="6" fill="#ffffff" stroke="#ded5c8" stroke-width="1.5" />
            <rect x="136" y="34" width="42" height="4" rx="2" fill="#c4b8aa" />
            <rect x="136" y="44" width="48" height="4" rx="2" fill="#ded5c8" />
            <rect x="136" y="54" width="34" height="4" rx="2" fill="#ded5c8" />
            <circle cx="160" cy="74" r="8" fill="rgba(63,126,82,0.15)" />
            <text x="160" y="78" font-size="10" text-anchor="middle" fill="#3f7e52" font-weight="800">Γ£ô</text>
            <rect x="210" y="24" width="68" height="72" rx="6" fill="#ffffff" stroke="#e8c2be" stroke-width="1.5" />
            <rect x="220" y="34" width="38" height="4" rx="2" fill="#c4b8aa" />
            <rect x="220" y="44" width="48" height="4" rx="2" fill="#ded5c8" />
            <rect x="220" y="54" width="42" height="4" rx="2" fill="#ded5c8" />
            <rect x="222" y="67" width="44" height="15" rx="3" fill="#b8423f" />
            <text x="244" y="78" font-size="9" text-anchor="middle" font-weight="800" fill="#ffffff" font-family="sans-serif">LIE !</text>
            <circle cx="212" cy="48" r="16" fill="none" stroke="#3e2217" stroke-width="3" />
            <line x1="223" y1="59" x2="235" y2="71" stroke="#3e2217" stroke-width="3.5" stroke-linecap="round" />
          </svg>""",
    },
    {
        "id": "story",
        "name": "Story Chain",
        "type": "party",
        "players": "2-30",
        "description": "Take turns writing one sentence at a time.",
        "icon": "fa-solid fa-feather-pointed",
        "category": "party",
        "route": "/games/create?type=story",
        "bond_route": "/games/create?type=story",
        "badge": "Collaborative",
        "cta": "Host Story",
        "art_bg": "#f6efe6",
        "art_svg": """<svg viewBox="0 0 320 120" width="100%" height="100%" preserveAspectRatio="xMidYMid slice" xmlns="http://www.w3.org/2000/svg">
            <rect width="320" height="120" fill="#f6efe6" />
            <rect x="75" y="24" width="80" height="72" rx="4" fill="#ffffff" stroke="#dfd6cb" stroke-width="1.5" />
            <rect x="165" y="24" width="80" height="72" rx="4" fill="#ffffff" stroke="#dfd6cb" stroke-width="1.5" />
            <line x1="88" y1="40" x2="142" y2="40" stroke="#cbbfae" stroke-width="3" stroke-linecap="round" />
            <line x1="88" y1="52" x2="146" y2="52" stroke="#ded4c5" stroke-width="3" stroke-linecap="round" />
            <line x1="88" y1="64" x2="134" y2="64" stroke="#ded4c5" stroke-width="3" stroke-linecap="round" />
            <line x1="88" y1="76" x2="140" y2="76" stroke="#ded4c5" stroke-width="3" stroke-linecap="round" />
            <line x1="178" y1="40" x2="232" y2="40" stroke="#ded4c5" stroke-width="3" stroke-linecap="round" />
            <line x1="178" y1="52" x2="228" y2="52" stroke="#ded4c5" stroke-width="3" stroke-linecap="round" />
            <line x1="178" y1="64" x2="234" y2="64" stroke="#cbbfae" stroke-width="3" stroke-linecap="round" />
            <g transform="translate(195, 20) rotate(35)">
              <path d="M0,0 Q18,-15 50,-25 Q35,-5 20,25 Z" fill="#5c3d2e" />
              <line x1="0" y1="0" x2="20" y2="38" stroke="#3e2217" stroke-width="2" />
              <polygon points="20,38 23,45 17,45" fill="#3e2217" />
            </g>
            <circle cx="160" cy="86" r="5" fill="none" stroke="#c68a35" stroke-width="2" />
            <line x1="150" y1="86" x2="155" y2="86" stroke="#c68a35" stroke-width="2" />
            <line x1="165" y1="86" x2="170" y2="86" stroke="#c68a35" stroke-width="2" />
          </svg>""",
    },
    {
        "id": "caption",
        "name": "Caption This",
        "type": "party",
        "players": "2-30",
        "description": "Write captions for a prompt and vote for the funniest one.",
        "icon": "fa-solid fa-comment-dots",
        "category": "party",
        "route": "/games/create?type=caption",
        "bond_route": "/games/create?type=caption",
        "badge": "Creativity",
        "cta": "Host Caption",
        "art_bg": "#f8f2eb",
        "art_svg": """<svg viewBox="0 0 320 120" width="100%" height="100%" preserveAspectRatio="xMidYMid slice" xmlns="http://www.w3.org/2000/svg">
            <rect width="320" height="120" fill="#f8f2eb" />
            <g transform="translate(125, 18) rotate(-4)">
              <rect width="70" height="84" rx="4" fill="#ffffff" stroke="#ded5c8" stroke-width="1.5" />
              <rect x="7" y="7" width="56" height="52" rx="2" fill="#ede5da" />
              <circle cx="22" cy="22" r="5" fill="#c68a35" />
              <polygon points="12,50 30,28 44,50" fill="#5c3d2e" />
              <polygon points="32,50 46,35 58,50" fill="#8c6d58" />
            </g>
            <g transform="translate(50, 24)">
              <rect width="72" height="32" rx="16" fill="#3e2217" />
              <polygon points="62,32 54,32 50,40" fill="#3e2217" />
              <text x="36" y="21" font-size="13" text-anchor="middle" font-weight="700" fill="#ffffff" font-family="sans-serif">ΓÇ£ ... ΓÇ¥</text>
            </g>
            <g transform="translate(198, 48)">
              <rect width="72" height="32" rx="16" fill="#c68a35" />
              <polygon points="20,32 28,32 18,40" fill="#c68a35" />
              <text x="36" y="21" font-size="12" text-anchor="middle" font-weight="800" fill="#ffffff" font-family="sans-serif">HA! ≡ƒÿé</text>
            </g>
          </svg>""",
    },
    {
        "id": "this_or_that",
        "name": "This or That",
        "type": "co-op",
        "players": "1-2",
        "description": "Pick between pairs and discover how often you match.",
        "icon": "fa-solid fa-arrows-left-right",
        "category": "coop",
        "route": "/games/this-or-that",
        "bond_route": "/games/this-or-that",
        "badge": "Co-op Match",
        "cta": "Play Together",
        "art_bg": "#f3ece2",
        "art_svg": """<svg viewBox="0 0 320 120" width="100%" height="100%" preserveAspectRatio="xMidYMid slice" xmlns="http://www.w3.org/2000/svg"><rect width="320" height="120" fill="#f3ece2" /><g transform="translate(58, 28) rotate(-4)"><rect width="92" height="64" rx="10" fill="#2c5f8a" /><rect x="10" y="10" width="30" height="6" rx="3" fill="rgba(255,255,255,0.4)" /><text x="46" y="48" font-size="17" text-anchor="middle" font-weight="800" fill="#ffffff" font-family="sans-serif">THIS</text></g><g transform="translate(170, 28) rotate(4)"><rect width="92" height="64" rx="10" fill="#3f7e52" /><rect x="10" y="10" width="30" height="6" rx="3" fill="rgba(255,255,255,0.4)" /><text x="46" y="48" font-size="17" text-anchor="middle" font-weight="800" fill="#ffffff" font-family="sans-serif">THAT</text></g><circle cx="160" cy="60" r="17" fill="#ffffff" stroke="#c68a35" stroke-width="2" /><text x="160" y="67" font-size="14" text-anchor="middle" fill="#c68a35" font-weight="800" font-family="sans-serif">?</text><rect x="128" y="92" width="64" height="14" rx="7" fill="#3e2217" /><text x="160" y="102" font-size="9" text-anchor="middle" font-weight="700" fill="#ffffff" font-family="sans-serif">82% MATCH</text></svg>""",
    },
    {
        "id": "emoji_decoder",
        "name": "Emoji Decoder",
        "type": "co-op",
        "players": "1-2",
        "description": "Give emoji clues while your partner guesses the phrase.",
        "icon": "fa-solid fa-icons",
        "category": "coop",
        "route": "/games/emoji-decoder",
        "bond_route": "/games/emoji-decoder",
        "badge": "Co-op Guessing",
        "cta": "Play Together",
        "art_bg": "#fdf6ec",
        "art_svg": """<svg viewBox="0 0 320 120" width="100%" height="100%" preserveAspectRatio="xMidYMid slice" xmlns="http://www.w3.org/2000/svg"><rect width="320" height="120" fill="#fdf6ec" /><rect x="52" y="30" width="52" height="52" rx="10" fill="#ffffff" stroke="#e0d3bd" stroke-width="1.5" /><text x="78" y="64" font-size="24" text-anchor="middle" font-family="sans-serif">C</text><rect x="112" y="30" width="52" height="52" rx="10" fill="#ffffff" stroke="#e0d3bd" stroke-width="1.5" /><text x="138" y="64" font-size="24" text-anchor="middle" font-family="sans-serif">M</text><rect x="172" y="30" width="52" height="52" rx="10" fill="#d1fae5" stroke="#10b981" stroke-width="2" /><text x="198" y="64" font-size="24" text-anchor="middle" font-family="sans-serif">N</text><rect x="52" y="90" width="172" height="12" rx="6" fill="#ede4d3" /><rect x="52" y="90" width="118" height="12" rx="6" fill="#c68a35" /><circle cx="252" cy="60" r="22" fill="none" stroke="#5c3d2e" stroke-width="3" /><line x1="267" y1="75" x2="278" y2="86" stroke="#5c3d2e" stroke-width="4" stroke-linecap="round" /><text x="252" y="68" font-size="16" text-anchor="middle" font-weight="800" fill="#5c3d2e" font-family="sans-serif">?</text></svg>""",
    },
    {
        "id": "team_crossword",
        "name": "Team Crossword",
        "type": "co-op",
        "players": "1-2",
        "description": "Solve a mini crossword together with live synced letters.",
        "icon": "fa-solid fa-table-cells",
        "category": "coop",
        "route": "/games/team-crossword",
        "bond_route": "/games/team-crossword",
        "badge": "Dual-Cursor Co-op",
        "cta": "Solve Together",
        "art_bg": "#fdfbf7",
        "art_svg": """<svg viewBox="0 0 320 120" width="100%" height="100%" preserveAspectRatio="xMidYMid slice" xmlns="http://www.w3.org/2000/svg">
            <rect width="320" height="120" fill="#fdfbf7" />
            <g transform="translate(110, 10)">
              <rect x="0" y="0" width="20" height="20" fill="#ffffff" stroke="#5c3d2e" stroke-width="1" />
              <text x="10" y="15" font-size="11" text-anchor="middle" fill="#5c3d2e" font-weight="700" font-family="sans-serif">H</text>
              <rect x="20" y="0" width="20" height="20" fill="#ffffff" stroke="#5c3d2e" stroke-width="1" />
              <text x="30" y="15" font-size="11" text-anchor="middle" fill="#5c3d2e" font-weight="700" font-family="sans-serif">E</text>
              <rect x="40" y="0" width="20" height="20" fill="#ffeedd" stroke="#e06a3b" stroke-width="2" />
              <text x="50" y="15" font-size="11" text-anchor="middle" fill="#e06a3b" font-weight="700" font-family="sans-serif">A</text>
              <rect x="60" y="0" width="20" height="20" fill="#ffffff" stroke="#5c3d2e" stroke-width="1" />
              <text x="70" y="15" font-size="11" text-anchor="middle" fill="#5c3d2e" font-weight="700" font-family="sans-serif">R</text>
              <rect x="80" y="0" width="20" height="20" fill="#ffffff" stroke="#5c3d2e" stroke-width="1" />
              <text x="90" y="15" font-size="11" text-anchor="middle" fill="#5c3d2e" font-weight="700" font-family="sans-serif">T</text>

              <rect x="0" y="20" width="20" height="20" fill="#ffffff" stroke="#5c3d2e" stroke-width="1" />
              <text x="10" y="35" font-size="11" text-anchor="middle" fill="#5c3d2e" font-weight="700" font-family="sans-serif">O</text>
              <rect x="20" y="20" width="20" height="20" fill="#26170f" stroke="#5c3d2e" stroke-width="1" />
              <rect x="40" y="20" width="20" height="20" fill="#ddf4ff" stroke="#2e86ab" stroke-width="2" />
              <text x="50" y="35" font-size="11" text-anchor="middle" fill="#2e86ab" font-weight="700" font-family="sans-serif">R</text>
              <rect x="60" y="20" width="20" height="20" fill="#ffffff" stroke="#5c3d2e" stroke-width="1" />
              <text x="70" y="35" font-size="11" text-anchor="middle" fill="#5c3d2e" font-weight="700" font-family="sans-serif">A</text>
              <rect x="80" y="20" width="20" height="20" fill="#ffffff" stroke="#5c3d2e" stroke-width="1" />
              <text x="90" y="35" font-size="11" text-anchor="middle" fill="#5c3d2e" font-weight="700" font-family="sans-serif">E</text>

              <rect x="0" y="40" width="20" height="20" fill="#ffffff" stroke="#5c3d2e" stroke-width="1" />
              <text x="10" y="55" font-size="11" text-anchor="middle" fill="#5c3d2e" font-weight="700" font-family="sans-serif">M</text>
              <rect x="20" y="40" width="20" height="20" fill="#ffffff" stroke="#5c3d2e" stroke-width="1" />
              <text x="30" y="55" font-size="11" text-anchor="middle" fill="#5c3d2e" font-weight="700" font-family="sans-serif">A</text>
              <rect x="40" y="40" width="20" height="20" fill="#ffffff" stroke="#5c3d2e" stroke-width="1" />
              <text x="50" y="55" font-size="11" text-anchor="middle" fill="#5c3d2e" font-weight="700" font-family="sans-serif">T</text>
              <rect x="60" y="40" width="20" height="20" fill="#ffffff" stroke="#5c3d2e" stroke-width="1" />
              <text x="70" y="55" font-size="11" text-anchor="middle" fill="#5c3d2e" font-weight="700" font-family="sans-serif">C</text>
              <rect x="80" y="40" width="20" height="20" fill="#ffffff" stroke="#5c3d2e" stroke-width="1" />
              <text x="90" y="55" font-size="11" text-anchor="middle" fill="#5c3d2e" font-weight="700" font-family="sans-serif">H</text>

              <rect x="0" y="60" width="20" height="20" fill="#ffffff" stroke="#5c3d2e" stroke-width="1" />
              <text x="10" y="75" font-size="11" text-anchor="middle" fill="#5c3d2e" font-weight="700" font-family="sans-serif">E</text>
              <rect x="20" y="60" width="20" height="20" fill="#ffffff" stroke="#5c3d2e" stroke-width="1" />
              <text x="30" y="75" font-size="11" text-anchor="middle" fill="#5c3d2e" font-weight="700" font-family="sans-serif">R</text>
              <rect x="40" y="60" width="20" height="20" fill="#26170f" stroke="#5c3d2e" stroke-width="1" />
              <rect x="60" y="60" width="20" height="20" fill="#ffffff" stroke="#5c3d2e" stroke-width="1" />
              <text x="70" y="75" font-size="11" text-anchor="middle" fill="#5c3d2e" font-weight="700" font-family="sans-serif">E</text>
              <rect x="80" y="60" width="20" height="20" fill="#ffffff" stroke="#5c3d2e" stroke-width="1" />
              <text x="90" y="75" font-size="11" text-anchor="middle" fill="#5c3d2e" font-weight="700" font-family="sans-serif">S</text>

              <rect x="0" y="80" width="20" height="20" fill="#ffffff" stroke="#5c3d2e" stroke-width="1" />
              <text x="10" y="95" font-size="11" text-anchor="middle" fill="#5c3d2e" font-weight="700" font-family="sans-serif">S</text>
              <rect x="20" y="80" width="20" height="20" fill="#ffffff" stroke="#5c3d2e" stroke-width="1" />
              <text x="30" y="95" font-size="11" text-anchor="middle" fill="#5c3d2e" font-weight="700" font-family="sans-serif">T</text>
              <rect x="40" y="80" width="20" height="20" fill="#ffffff" stroke="#5c3d2e" stroke-width="1" />
              <text x="50" y="95" font-size="11" text-anchor="middle" fill="#5c3d2e" font-weight="700" font-family="sans-serif">S</text>
              <rect x="60" y="80" width="20" height="20" fill="#ffffff" stroke="#5c3d2e" stroke-width="1" />
              <text x="70" y="95" font-size="11" text-anchor="middle" fill="#5c3d2e" font-weight="700" font-family="sans-serif">R</text>
              <rect x="80" y="80" width="20" height="20" fill="#ffffff" stroke="#5c3d2e" stroke-width="1" />
              <text x="90" y="95" font-size="11" text-anchor="middle" fill="#5c3d2e" font-weight="700" font-family="sans-serif">T</text>
            </g>
          </svg>""",
    },
    {
        "id": "memory_match",
        "name": "Memory Match",
        "type": "versus",
        "players": "1-2",
        "description": "Flip cards, find matching pairs, and keep the turn on a match.",
        "icon": "fa-solid fa-layer-group",
        "category": "coop",
        "route": "/games/memory-match",
        "bond_route": "/games/memory-match",
        "badge": "1v1 / Co-op",
        "cta": "Play Memory",
        "art_bg": "#f5f2ed",
        "art_svg": """<svg viewBox="0 0 320 120" width="100%" height="100%" preserveAspectRatio="xMidYMid slice" xmlns="http://www.w3.org/2000/svg">
            <rect width="320" height="120" fill="#f5f2ed" />
            <g transform="translate(68, 26)">
              <rect width="44" height="66" rx="6" fill="#ffffff" stroke="#cbbfae" stroke-width="1.5" />
              <rect x="5" y="5" width="34" height="56" rx="4" fill="#ede4d7" />
              <text x="22" y="38" font-size="20" text-anchor="middle" font-family="sans-serif">Γÿà</text>
            </g>
            <g transform="translate(122, 26)">
              <rect width="44" height="66" rx="6" fill="#ffffff" stroke="#3f7e52" stroke-width="2" />
              <rect x="5" y="5" width="34" height="56" rx="4" fill="#e8f5ec" />
              <text x="22" y="38" font-size="20" text-anchor="middle" font-family="sans-serif" fill="#2d6a3f">ΓÖÑ</text>
            </g>
            <g transform="translate(176, 26)">
              <rect width="44" height="66" rx="6" fill="#ffffff" stroke="#3f7e52" stroke-width="2" />
              <rect x="5" y="5" width="34" height="56" rx="4" fill="#e8f5ec" />
              <text x="22" y="38" font-size="20" text-anchor="middle" font-family="sans-serif" fill="#2d6a3f">ΓÖÑ</text>
            </g>
            <g transform="translate(230, 26)">
              <rect width="44" height="66" rx="6" fill="#ffffff" stroke="#cbbfae" stroke-width="1.5" />
              <rect x="5" y="5" width="34" height="56" rx="4" fill="#ede4d7" />
              <text x="22" y="38" font-size="20" text-anchor="middle" font-family="sans-serif">Γùå</text>
            </g>
          </svg>""",
    },
    {
        "id": "word_duet",
        "name": "Word Bond: Duet",
        "type": "co-op",
        "players": "1-2",
        "description": "Now a clearer Word Chain: take turns adding related words without repeats.",
        "icon": "fa-solid fa-link",
        "category": "coop",
        "route": "/games/word-duet",
        "bond_route": "/games/word-duet",
        "badge": "Co-op Deduction",
        "cta": "Play Duet",
        "art_bg": "#fdfbf7",
        "art_svg": """<svg viewBox="0 0 320 120" width="100%" height="100%" preserveAspectRatio="xMidYMid slice" xmlns="http://www.w3.org/2000/svg">
            <rect width="320" height="120" fill="#fdfbf7" />
            <rect x="35" y="22" width="46" height="32" rx="4" fill="#ffffff" stroke="#d5beaa" stroke-width="1.5" />
            <text x="58" y="42" font-size="9" text-anchor="middle" fill="#5c3d2e" font-weight="700" font-family="sans-serif">HEART</text>
            <rect x="87" y="22" width="46" height="32" rx="4" fill="#d1fae5" stroke="#10b981" stroke-width="1.5" />
            <text x="110" y="42" font-size="9" text-anchor="middle" fill="#065f46" font-weight="700" font-family="sans-serif">HOME</text>
            <rect x="139" y="22" width="46" height="32" rx="4" fill="#ffffff" stroke="#d5beaa" stroke-width="1.5" />
            <text x="162" y="42" font-size="9" text-anchor="middle" fill="#5c3d2e" font-weight="700" font-family="sans-serif">MOON</text>
            <rect x="191" y="22" width="46" height="32" rx="4" fill="#fee2e2" stroke="#ef4444" stroke-width="1.5" />
            <text x="214" y="42" font-size="9" text-anchor="middle" fill="#991b1b" font-weight="700" font-family="sans-serif">SHADOW</text>
            <rect x="243" y="22" width="46" height="32" rx="4" fill="#ffffff" stroke="#d5beaa" stroke-width="1.5" />
            <text x="266" y="42" font-size="9" text-anchor="middle" fill="#5c3d2e" font-weight="700" font-family="sans-serif">STAR</text>

            <rect x="61" y="64" width="46" height="32" rx="4" fill="#ffffff" stroke="#d5beaa" stroke-width="1.5" />
            <text x="84" y="84" font-size="9" text-anchor="middle" fill="#5c3d2e" font-weight="700" font-family="sans-serif">DREAM</text>
            <rect x="113" y="64" width="46" height="32" rx="4" fill="#d1fae5" stroke="#10b981" stroke-width="1.5" />
            <text x="136" y="84" font-size="9" text-anchor="middle" fill="#065f46" font-weight="700" font-family="sans-serif">OCEAN</text>
            <rect x="165" y="64" width="46" height="32" rx="4" fill="#ffffff" stroke="#d5beaa" stroke-width="1.5" />
            <text x="188" y="84" font-size="9" text-anchor="middle" fill="#5c3d2e" font-weight="700" font-family="sans-serif">LIGHT</text>
            <rect x="217" y="64" width="46" height="32" rx="4" fill="#d1fae5" stroke="#10b981" stroke-width="1.5" />
            <text x="240" y="84" font-size="9" text-anchor="middle" fill="#065f46" font-weight="700" font-family="sans-serif">PEACE</text>
          </svg>""",
    },
    {
        "id": "floppy_bird",
        "name": "Floppy Bird: Super Powers",
        "type": "solo",
        "players": "1",
        "description": "Dodge obstacles, collect powers, and chase a high score.",
        "icon": "fa-solid fa-dove",
        "category": "arcade",
        "route": "/games/floppy-bird",
        "bond_route": "/games/floppy-bird",
        "badge": "Solo Arcade",
        "cta": "Play Solo",
        "art_bg": "#dcecf2",
        "art_svg": """<svg viewBox="0 0 320 120" width="100%" height="100%" preserveAspectRatio="xMidYMid slice" xmlns="http://www.w3.org/2000/svg">
            <rect width="320" height="120" fill="#dcecf2" />
            <ellipse cx="60" cy="30" rx="28" ry="12" fill="rgba(255,255,255,0.7)" />
            <ellipse cx="260" cy="40" rx="32" ry="14" fill="rgba(255,255,255,0.7)" />
            <rect x="75" y="0" width="34" height="35" fill="#478a53" stroke="#2e5d36" stroke-width="1.5" />
            <rect x="71" y="30" width="42" height="10" rx="2" fill="#529c60" stroke="#2e5d36" stroke-width="1.5" />
            <rect x="75" y="85" width="34" height="35" fill="#478a53" stroke="#2e5d36" stroke-width="1.5" />
            <rect x="71" y="80" width="42" height="10" rx="2" fill="#529c60" stroke="#2e5d36" stroke-width="1.5" />
            <rect x="225" y="0" width="34" height="45" fill="#478a53" stroke="#2e5d36" stroke-width="1.5" />
            <rect x="221" y="40" width="42" height="10" rx="2" fill="#529c60" stroke="#2e5d36" stroke-width="1.5" />
            <rect x="225" y="95" width="34" height="25" fill="#478a53" stroke="#2e5d36" stroke-width="1.5" />
            <rect x="221" y="90" width="42" height="10" rx="2" fill="#529c60" stroke="#2e5d36" stroke-width="1.5" />
            <circle cx="115" cy="68" r="2" fill="#ea6e32" opacity="0.4" />
            <circle cx="128" cy="64" r="2" fill="#ea6e32" opacity="0.6" />
            <circle cx="140" cy="58" r="2.5" fill="#ea6e32" opacity="0.8" />
            <g transform="translate(155, 48)">
              <ellipse cx="0" cy="0" rx="16" ry="13" fill="#f4bc3c" stroke="#cf951f" stroke-width="1.5" />
              <circle cx="6" cy="-4" r="5" fill="#ffffff" />
              <circle cx="8" cy="-4" r="2.2" fill="#000000" />
              <polygon points="12,-1 22,2 12,6" fill="#ea6e32" />
              <ellipse cx="-5" cy="2" rx="7" ry="5" fill="#ffffff" stroke="#e0a82b" stroke-width="1" />
            </g>
            <polygon points="195,54 198,62 206,62 200,67 202,75 195,70 188,75 190,67 184,62 192,62" fill="#f5c452" stroke="#d4a034" stroke-width="1" />
          </svg>""",
    },
    {
        "id": "snake",
        "name": "Snake Classic",
        "type": "solo",
        "players": "1",
        "description": "A fast classic score chase with simple controls.",
        "icon": "fa-solid fa-route",
        "category": "arcade",
        "route": "/games/snake",
        "bond_route": "/games/snake",
        "badge": "Solo Arcade",
        "cta": "Play Solo",
        "art_bg": "#121a14",
        "art_svg": """<svg viewBox="0 0 320 120" width="100%" height="100%" preserveAspectRatio="xMidYMid slice" xmlns="http://www.w3.org/2000/svg">
            <rect width="320" height="120" fill="#121a14" />
            <defs>
              <pattern id="snake-grid" width="16" height="16" patternUnits="userSpaceOnUse">
                <rect width="16" height="16" fill="none" stroke="#1d281f" stroke-width="0.8" />
              </pattern>
            </defs>
            <rect x="32" y="16" width="256" height="88" fill="url(#snake-grid)" stroke="#233427" stroke-width="1.5" />
            <text x="44" y="32" font-size="9" fill="#3f7e52" font-family="monospace" font-weight="700">SCORE: 240</text>
            <rect x="80" y="52" width="14" height="14" rx="3" fill="#22c55e" opacity="0.6" />
            <rect x="96" y="52" width="14" height="14" rx="3" fill="#22c55e" opacity="0.75" />
            <rect x="112" y="52" width="14" height="14" rx="3" fill="#22c55e" opacity="0.85" />
            <rect x="128" y="52" width="14" height="14" rx="3" fill="#4ade80" />
            <rect x="144" y="52" width="14" height="14" rx="3" fill="#4ade80" />
            <rect x="160" y="52" width="14" height="14" rx="3" fill="#4ade80" />
            <rect x="160" y="68" width="14" height="14" rx="3" fill="#4ade80" />
            <rect x="176" y="68" width="15" height="14" rx="4" fill="#86efac" />
            <circle cx="187" cy="72" r="1.8" fill="#000000" />
            <circle cx="187" cy="78" r="1.8" fill="#000000" />
            <circle cx="224" cy="75" r="7" fill="#ef4444" />
            <path d="M224,68 Q226,64 229,65" fill="none" stroke="#15803d" stroke-width="1.5" stroke-linecap="round" />
            <ellipse cx="227" cy="65" rx="2.5" ry="1.5" fill="#22c55e" />
          </svg>""",
    },
    {
        "id": "tic_tac_toe",
        "name": "Tic-Tac-Toe",
        "type": "versus",
        "players": "2",
        "description": "Classic three-in-a-row with live turns.",
        "icon": "fa-solid fa-xmark",
        "category": "arcade",
        "route": "/games/tic-tac-toe",
        "bond_route": "/games/tic-tac-toe",
        "badge": "1v1 & Solo",
        "cta": "Play 1v1",
        "art_bg": "#f6f1ea",
        "art_svg": """<svg viewBox="0 0 320 120" width="100%" height="100%" preserveAspectRatio="xMidYMid slice" xmlns="http://www.w3.org/2000/svg">
            <rect width="320" height="120" fill="#f6f1ea" />
            <line x1="135" y1="18" x2="135" y2="102" stroke="#8c6d58" stroke-width="3" stroke-linecap="round" />
            <line x1="185" y1="18" x2="185" y2="102" stroke="#8c6d58" stroke-width="3" stroke-linecap="round" />
            <line x1="90" y1="46" x2="230" y2="46" stroke="#8c6d58" stroke-width="3" stroke-linecap="round" />
            <line x1="90" y1="74" x2="230" y2="74" stroke="#8c6d58" stroke-width="3" stroke-linecap="round" />
            <g transform="translate(112, 32)">
              <line x1="-9" y1="-9" x2="9" y2="9" stroke="#b8423f" stroke-width="3.5" stroke-linecap="round" />
              <line x1="9" y1="-9" x2="-9" y2="9" stroke="#b8423f" stroke-width="3.5" stroke-linecap="round" />
            </g>
            <circle cx="160" cy="60" r="10" fill="none" stroke="#2c5f8a" stroke-width="3.5" />
            <circle cx="208" cy="32" r="10" fill="none" stroke="#2c5f8a" stroke-width="3.5" />
            <g transform="translate(112, 60)">
              <line x1="-9" y1="-9" x2="9" y2="9" stroke="#b8423f" stroke-width="3.5" stroke-linecap="round" />
              <line x1="9" y1="-9" x2="-9" y2="9" stroke="#b8423f" stroke-width="3.5" stroke-linecap="round" />
            </g>
            <g transform="translate(112, 88)">
              <line x1="-9" y1="-9" x2="9" y2="9" stroke="#b8423f" stroke-width="3.5" stroke-linecap="round" />
              <line x1="9" y1="-9" x2="-9" y2="9" stroke="#b8423f" stroke-width="3.5" stroke-linecap="round" />
            </g>
            <line x1="112" y1="18" x2="112" y2="102" stroke="#c68a35" stroke-width="3" stroke-linecap="round" opacity="0.85" />
          </svg>""",
    },
    {
        "id": "connect_four",
        "name": "Connect Four",
        "type": "versus",
        "players": "2",
        "description": "Drop tokens and connect four before your partner does.",
        "icon": "fa-solid fa-circle-dot",
        "category": "arcade",
        "route": "/games/connect-four",
        "bond_route": "/games/connect-four",
        "badge": "1v1 & Solo",
        "cta": "Play 1v1",
        "art_bg": "#1c2733",
        "art_svg": """<svg viewBox="0 0 320 120" width="100%" height="100%" preserveAspectRatio="xMidYMid slice" xmlns="http://www.w3.org/2000/svg">
            <rect width="320" height="120" fill="#1c2733" />
            <rect x="70" y="16" width="180" height="92" rx="10" fill="#1d4ed8" />
            <rect x="76" y="22" width="168" height="80" rx="8" fill="#2563eb" />
            <circle cx="96" cy="40" r="9" fill="#1c2733" />
            <circle cx="96" cy="62" r="9" fill="#dc2626" />
            <circle cx="96" cy="84" r="9" fill="#facc15" />
            <circle cx="128" cy="40" r="9" fill="#1c2733" />
            <circle cx="128" cy="62" r="9" fill="#facc15" />
            <circle cx="128" cy="84" r="9" fill="#dc2626" />
            <circle cx="160" cy="40" r="9" fill="#facc15" />
            <circle cx="160" cy="62" r="9" fill="#dc2626" />
            <circle cx="160" cy="84" r="9" fill="#facc15" />
            <circle cx="192" cy="40" r="9" fill="#dc2626" />
            <circle cx="192" cy="62" r="9" fill="#facc15" />
            <circle cx="192" cy="84" r="9" fill="#dc2626" />
            <circle cx="224" cy="40" r="9" fill="#1c2733" />
            <circle cx="224" cy="62" r="9" fill="#1c2733" />
            <circle cx="224" cy="84" r="9" fill="#facc15" />
            <circle cx="160" cy="12" r="8" fill="#facc15" stroke="#ca8a04" stroke-width="1.5" />
            <line x1="160" y1="20" x2="160" y2="28" stroke="#facc15" stroke-width="1.5" stroke-dasharray="2,2" />
          </svg>""",
    },
    {
        "id": "dots_and_boxes",
        "name": "Dots and Boxes",
        "type": "versus",
        "players": "2",
        "description": "Draw lines, complete boxes, and control the board.",
        "icon": "fa-solid fa-border-all",
        "category": "arcade",
        "route": "/games/dots-and-boxes",
        "bond_route": "/games/dots-and-boxes",
        "badge": "1v1 & Solo",
        "cta": "Play 1v1",
        "art_bg": "#f7f2eb",
        "art_svg": """<svg viewBox="0 0 320 120" width="100%" height="100%" preserveAspectRatio="xMidYMid slice" xmlns="http://www.w3.org/2000/svg">
            <rect width="320" height="120" fill="#f7f2eb" />
            <rect x="100" y="25" width="55" height="40" fill="rgba(184,66,63,0.18)" rx="4" />
            <text x="127" y="50" font-size="18" text-anchor="middle" font-weight="800" fill="#b8423f" font-family="sans-serif">A</text>
            <rect x="155" y="25" width="55" height="40" fill="rgba(44,95,138,0.18)" rx="4" />
            <text x="182" y="50" font-size="18" text-anchor="middle" font-weight="800" fill="#2c5f8a" font-family="sans-serif">B</text>
            <line x1="100" y1="25" x2="210" y2="25" stroke="#3e2217" stroke-width="3" stroke-linecap="round" />
            <line x1="100" y1="65" x2="210" y2="65" stroke="#3e2217" stroke-width="3" stroke-linecap="round" />
            <line x1="100" y1="25" x2="100" y2="65" stroke="#3e2217" stroke-width="3" stroke-linecap="round" />
            <line x1="155" y1="25" x2="155" y2="65" stroke="#3e2217" stroke-width="3" stroke-linecap="round" />
            <line x1="210" y1="25" x2="210" y2="65" stroke="#3e2217" stroke-width="3" stroke-linecap="round" />
            <line x1="100" y1="65" x2="100" y2="105" stroke="#3e2217" stroke-width="3" stroke-linecap="round" />
            <line x1="100" y1="105" x2="155" y2="105" stroke="#b8423f" stroke-width="3" stroke-linecap="round" stroke-dasharray="4,4" />
            <circle cx="100" cy="25" r="4.5" fill="#3e2217" />
            <circle cx="155" cy="25" r="4.5" fill="#3e2217" />
            <circle cx="210" cy="25" r="4.5" fill="#3e2217" />
            <circle cx="100" cy="65" r="4.5" fill="#3e2217" />
            <circle cx="155" cy="65" r="4.5" fill="#3e2217" />
            <circle cx="210" cy="65" r="4.5" fill="#3e2217" />
            <circle cx="100" cy="105" r="4.5" fill="#3e2217" />
            <circle cx="155" cy="105" r="4.5" fill="#3e2217" />
            <circle cx="210" cy="105" r="4.5" fill="#3e2217" />
          </svg>""",
    },
    {
        "id": "ping_pong",
        "name": "Ping Pong",
        "type": "versus",
        "players": "2",
        "description": "Fast paddle rallies with live 1v1 sync.",
        "icon": "fa-solid fa-table-tennis-paddle-ball",
        "category": "arcade",
        "route": "/games/ping-pong",
        "bond_route": "/games/ping-pong",
        "badge": "1v1 & Solo",
        "cta": "Play 1v1",
        "art_bg": "#1c3827",
        "art_svg": """<svg viewBox="0 0 320 120" width="100%" height="100%" preserveAspectRatio="xMidYMid slice" xmlns="http://www.w3.org/2000/svg">
            <rect width="320" height="120" fill="#1c3827" />
            <rect x="40" y="16" width="240" height="88" fill="#1f422e" stroke="#ffffff" stroke-width="2" rx="4" />
            <line x1="40" y1="60" x2="280" y2="60" stroke="#ffffff" stroke-width="1.5" stroke-dasharray="4,4" />
            <line x1="160" y1="12" x2="160" y2="108" stroke="#e0e0e0" stroke-width="3" />
            <circle cx="160" cy="12" r="2.5" fill="#ffffff" />
            <circle cx="160" cy="108" r="2.5" fill="#ffffff" />
            <g transform="translate(85, 46) rotate(15)">
              <rect x="0" y="14" width="6" height="16" rx="2" fill="#c29b68" />
              <ellipse cx="3" cy="4" rx="13" ry="15" fill="#dc2626" stroke="#ffffff" stroke-width="1" />
            </g>
            <g transform="translate(230, 70) rotate(-20)">
              <rect x="0" y="14" width="6" height="16" rx="2" fill="#c29b68" />
              <ellipse cx="3" cy="4" rx="13" ry="15" fill="#2563eb" stroke="#ffffff" stroke-width="1" />
            </g>
            <path d="M102,48 Q150,85 215,62" fill="none" stroke="rgba(255,255,255,0.45)" stroke-width="2" stroke-dasharray="3,3" />
            <circle cx="175" cy="68" r="5" fill="#ffffff" />
          </svg>""",
    },
    {
        "id": "slime_volleyball",
        "name": "Slime Volleyball",
        "type": "versus",
        "players": "2",
        "description": "Bounce, jump, and spike in a playful live duel.",
        "icon": "fa-solid fa-volleyball",
        "category": "arcade",
        "route": "/games/slime-volleyball",
        "bond_route": "/games/slime-volleyball",
        "badge": "1v1 & Solo",
        "cta": "Play 1v1",
        "art_bg": "#fdf5ea",
        "art_svg": """<svg viewBox="0 0 320 120" width="100%" height="100%" preserveAspectRatio="xMidYMid slice" xmlns="http://www.w3.org/2000/svg">
            <rect width="320" height="120" fill="#fdf5ea" />
            <rect x="0" y="98" width="320" height="22" fill="#eedcc4" />
            <line x1="0" y1="98" x2="320" y2="98" stroke="#ddc5a4" stroke-width="2" />
            <rect x="157" y="52" width="6" height="46" fill="#ffffff" stroke="#3e2217" stroke-width="1.5" />
            <line x1="157" y1="62" x2="163" y2="62" stroke="#3e2217" stroke-width="1" />
            <line x1="157" y1="72" x2="163" y2="72" stroke="#3e2217" stroke-width="1" />
            <line x1="157" y1="82" x2="163" y2="82" stroke="#3e2217" stroke-width="1" />
            <path d="M60,98 A32,32 0 0,1 124,98 Z" fill="#3f7e52" />
            <circle cx="106" cy="80" r="5" fill="#ffffff" />
            <circle cx="108" cy="79" r="2.5" fill="#000000" />
            <path d="M196,98 A32,32 0 0,1 260,98 Z" fill="#b8423f" />
            <circle cx="214" cy="80" r="5" fill="#ffffff" />
            <circle cx="212" cy="79" r="2.5" fill="#000000" />
            <path d="M100,75 Q160,18 210,65" fill="none" stroke="#d5beaa" stroke-width="1.5" stroke-dasharray="3,3" />
            <circle cx="160" cy="30" r="11" fill="#ffffff" stroke="#3e2217" stroke-width="1.5" />
            <path d="M152,24 Q160,30 168,24 M152,36 Q160,30 168,36" fill="none" stroke="#3e2217" stroke-width="1" />
          </svg>""",
    },
    {
        "id": "gomoku",
        "name": "Gomoku",
        "type": "versus",
        "players": "2",
        "description": "Place five stones in a row before your opponent does.",
        "icon": "fa-solid fa-circle-nodes",
        "category": "arcade",
        "route": "/games/gomoku",
        "bond_route": "/games/gomoku",
        "badge": "1v1 & Solo",
        "cta": "Play 1v1",
        "art_bg": "#f6efe4",
        "art_svg": """<svg viewBox="0 0 320 120" width="100%" height="100%" preserveAspectRatio="xMidYMid slice" xmlns="http://www.w3.org/2000/svg">
            <rect width="320" height="120" fill="#f6efe4" />
            <g stroke="#c9b795" stroke-width="1.5">
              <line x1="90" y1="20" x2="230" y2="20" /><line x1="90" y1="40" x2="230" y2="40" />
              <line x1="90" y1="60" x2="230" y2="60" /><line x1="90" y1="80" x2="230" y2="80" />
              <line x1="90" y1="100" x2="230" y2="100" />
              <line x1="90" y1="20" x2="90" y2="100" /><line x1="125" y1="20" x2="125" y2="100" />
              <line x1="160" y1="20" x2="160" y2="100" /><line x1="195" y1="20" x2="195" y2="100" />
              <line x1="230" y1="20" x2="230" y2="100" />
            </g>
            <circle cx="125" cy="40" r="8" fill="#3e2217" /><circle cx="160" cy="40" r="8" fill="#3e2217" />
            <circle cx="195" cy="40" r="8" fill="#3e2217" /><circle cx="142" cy="60" r="8" fill="#ffffff" stroke="#3e2217" stroke-width="1.5" />
            <circle cx="177" cy="60" r="8" fill="#ffffff" stroke="#3e2217" stroke-width="1.5" />
            <circle cx="125" cy="80" r="8" fill="#3e2217" /><circle cx="160" cy="80" r="8" fill="#3e2217" />
          </svg>""",
    },
    {
        "id": "sudoku",
        "name": "Sudoku Together",
        "type": "co-op",
        "players": "1-2",
        "description": "Solve a fresh daily puzzle solo or with a partner.",
        "icon": "fa-solid fa-table-cells-large",
        "category": "coop",
        "route": "/games/sudoku",
        "bond_route": "/games/sudoku",
        "badge": "Co-op Puzzle",
        "cta": "Solve Together",
        "art_bg": "#fdfbf7",
        "art_svg": """<svg viewBox="0 0 320 120" width="100%" height="100%" preserveAspectRatio="xMidYMid slice" xmlns="http://www.w3.org/2000/svg">
            <rect width="320" height="120" fill="#fdfbf7" />
            <g transform="translate(115, 15)">
              <rect x="0" y="0" width="90" height="90" fill="#ffffff" stroke="#5c3d2e" stroke-width="2" />
              <line x1="30" y1="0" x2="30" y2="90" stroke="#cbbfae" stroke-width="1" />
              <line x1="60" y1="0" x2="60" y2="90" stroke="#cbbfae" stroke-width="1" />
              <line x1="0" y1="30" x2="90" y2="30" stroke="#cbbfae" stroke-width="1" />
              <line x1="0" y1="60" x2="90" y2="60" stroke="#cbbfae" stroke-width="1" />
              <text x="15" y="22" font-size="13" text-anchor="middle" fill="#5c3d2e" font-weight="700" font-family="sans-serif">5</text>
              <text x="45" y="52" font-size="13" text-anchor="middle" fill="#2c5f8a" font-weight="700" font-family="sans-serif">9</text>
              <text x="75" y="82" font-size="13" text-anchor="middle" fill="#5c3d2e" font-weight="700" font-family="sans-serif">3</text>
            </g>
          </svg>""",
    },
    {
        "id": "whack_a_mole",
        "name": "Whack-'Em-All",
        "type": "versus",
        "players": "1-2",
        "description": "Tap fast, score fast. Beat your best or duel a friend.",
        "icon": "fa-solid fa-hammer",
        "category": "arcade",
        "route": "/games/whack-a-mole",
        "bond_route": "/games/whack-a-mole",
        "badge": "Solo & Duel",
        "cta": "Play",
        "art_bg": "#f3ece2",
        "art_svg": """<svg viewBox="0 0 320 120" width="100%" height="100%" preserveAspectRatio="xMidYMid slice" xmlns="http://www.w3.org/2000/svg">
            <rect width="320" height="120" fill="#f3ece2" />
            <ellipse cx="110" cy="95" rx="26" ry="9" fill="#cbbfae" />
            <ellipse cx="160" cy="95" rx="26" ry="9" fill="#cbbfae" />
            <ellipse cx="210" cy="95" rx="26" ry="9" fill="#cbbfae" />
            <ellipse cx="110" cy="90" rx="20" ry="7" fill="#8a6f55" />
            <ellipse cx="210" cy="90" rx="20" ry="7" fill="#8a6f55" />
            <circle cx="160" cy="62" r="20" fill="#5c3d2e" />
            <circle cx="153" cy="58" r="3" fill="#ffffff" /><circle cx="167" cy="58" r="3" fill="#ffffff" />
            <ellipse cx="160" cy="70" rx="7" ry="5" fill="#f3ece2" />
          </svg>""",
    },
    {
        "id": "air_hockey",
        "name": "Air Hockey",
        "type": "versus",
        "players": "2",
        "description": "Slide, defend, and score in a fast live duel.",
        "icon": "fa-solid fa-disc",
        "category": "arcade",
        "route": "/games/air-hockey",
        "bond_route": "/games/air-hockey",
        "badge": "1v1 & Solo",
        "cta": "Play 1v1",
        "art_bg": "#eef2f5",
        "art_svg": """<svg viewBox="0 0 320 120" width="100%" height="100%" preserveAspectRatio="xMidYMid slice" xmlns="http://www.w3.org/2000/svg">
            <rect width="320" height="120" fill="#eef2f5" />
            <rect x="90" y="10" width="140" height="100" rx="30" fill="#ffffff" stroke="#2c5f8a" stroke-width="2" />
            <line x1="90" y1="60" x2="230" y2="60" stroke="#2c5f8a" stroke-width="1.5" stroke-dasharray="5,4" />
            <circle cx="160" cy="60" r="10" fill="none" stroke="#2c5f8a" stroke-width="1.5" />
            <circle cx="160" cy="30" r="11" fill="#b8423f" stroke="#ffffff" stroke-width="2" />
            <circle cx="160" cy="92" r="11" fill="#2c5f8a" stroke="#ffffff" stroke-width="2" />
            <circle cx="196" cy="60" r="6" fill="#3e2217" />
          </svg>""",
    },
]


# Solo-only games have no partner mode and are hidden from Bond Challenge.
SOLO_TYPES = {"solo"}


def is_bond_eligible(game):
    """True for co-op and multiplayer games (party, co-op, versus)."""
    return game.get("type") not in SOLO_TYPES and game.get("players") != "1"


def bond_games():
    """Games allowed in Bond Challenge: co-op + multiplayer only, no solo."""
    return deepcopy([g for g in GAMES if is_bond_eligible(g)])


GAME_BY_ID = {game["id"]: game for game in GAMES}
BOND_GAME_IDS = {game["id"] for game in GAMES if is_bond_eligible(game)}
BOND_GAME_LABELS = {game["id"]: game["name"] for game in GAMES if is_bond_eligible(game)}


def all_games():
    return deepcopy(GAMES)


def get_game(game_id):
    game = GAME_BY_ID.get(game_id)
    return deepcopy(game) if game else None


def game_label(game_id):
    game = GAME_BY_ID.get(game_id)
    return game["name"] if game else game_id


def game_route(game_id, *, for_bond=False):
    game = GAME_BY_ID.get(game_id)
    if not game:
        return "/games"
    key = "bond_route" if for_bond else "route"
    return game.get(key) or game.get("route") or "/games"
