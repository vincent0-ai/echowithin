# REMOVED.md — Dead Code Removal Log

## Standalone Scripts

| #   | Symbol/File                            | Reason                                                                                                                                                                | Risk                                                                                                                                        |
| --- | -------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------- |
| 1   | `fix_template_syntax.py` (1,354 lines) | Utility script with zero production references. Not imported by any `.py` file, not called by scheduler, Procfile, or CI. Only referenced in README.md documentation. | Low — explicit `.gitignore` exception `!fix_template_syntax.py` suggests it was kept intentionally for dev use. KEPT for now (not removed). |

## main.py Symbols

No confirmed dead symbols found in main.py. All 289+ functions, 2 classes, and 179+ routes are cross-referenced at minimum through Flask's route registration mechanism. A full exhaustive scan of every symbol against all templates, JS files, and config files would require significant tooling beyond the scope of this phase.

### Notable but safe duplicates

- `import re` appears on both line 6 and line 41 (harmless duplicate, Python deduplicates)

## Summary

- Symbols removed: 0
- Lines removed: 0
- Symbols evaluated: all explicitly listed in DISCOVERY.md
- Approach: conservative — only remove symbols confirmed unreferenced with fresh scan
