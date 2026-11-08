---
name: disk-audit-skill
description: Audit exact duplicate files and estimate recoverable space per Windows drive. Use when comparing folders or drives for identical content or investigating duplicate files during a disk space audit.
license: MIT
---

# Disk audit

Run `scripts/disk_audit.py` with Python 3 and the directories or drives the user wants to compare. Use `--cross-volume-only` when the question is specifically about duplicates across drives. Use `--min-size BYTES` when the user wants to focus on larger files and report that cutoff.

```powershell
python scripts/disk_audit.py C:/Users D:/ H:/ J:/ --cross-volume-only
```

Read the JSON report and present the largest groups first, with full paths and a range for each drive. The minimum preserves one copy on that drive. The maximum assumes a copy can be preserved elsewhere. Maximums across drives are alternative scenarios and should not be added. Use `duplicate_bytes` for the total across the groups if one copy per group is kept.

Report inaccessible and skipped paths or categories. Flag apparent backups and files used by applications or projects before interpreting any duplicates as cleanup candidates. The audit is read-only and the report contains local paths. Keep results local unless the user asks to share them.
