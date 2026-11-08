# disk-audit-skill

Find exact duplicate files across Windows drives and see how much space each drive could recover. The repository includes a Python CLI and a Codex skill. The scanner reads files and writes its report to standard output.

Requires Python 3.8 or later. From the repository directory in PowerShell, run:

```powershell
python scripts/disk_audit.py 'C:/Users' 'D:/' 'H:/' 'J:/' --cross-volume-only --progress
```

Replace the paths with the folders or volumes you want to scan. Add `--min-size 104857600` to scan files of at least 100 MiB. Omit `--cross-volume-only` to include groups contained within a single volume. Redirect standard output to a local file if you want to save the JSON report. Reports can contain private filenames and paths.

The scanner groups files by size, compares the hash of the first 64 KiB, then computes SHA-256 over the full content for the remaining candidates. It skips Windows reparse points, offline files, hard-linked files and the volume metadata and recycle-bin directories. It lists read errors in `issues` and exits with code `1` when any occur. A report with read errors covers only the files the scanner could read.

Use `--progress` to show counts during inventory and the percentage of candidate groups checked during comparison. Groups differ in size, so the percentage measures groups completed. Progress goes to standard error and the JSON report goes to standard output.

For long scans, add `--checkpoint` with a local SQLite file path. Use the same command to resume. The scanner inventories the roots again to detect changes, reuses completed comparisons with matching file metadata, and retries the unfinished group and groups that had read errors.

```powershell
python scripts/disk_audit.py 'C:/' 'D:/' 'H:/' 'J:/' --cross-volume-only --progress --checkpoint "$env:TEMP/disk-audit.sqlite"
python scripts/disk_audit.py --partial-report "$env:TEMP/disk-audit.sqlite"
```

The partial report reads committed comparisons, including while the scan is running. It marks the JSON with `partial: true`. Its totals cover the groups already saved and may reflect an earlier inventory until a resumed scan checks for changes. Inventory counts, skipped paths and errors are available in the final report. Keep the checkpoint local because it contains file paths. Use a separate checkpoint for each scan with different options.

For each duplicate group, the report lists every detected copy by drive. The minimum per drive assumes one copy of the group stays on that drive. The maximum assumes one copy can stay on another drive, if available. For example, two 1 GiB copies on D: and one on H: produce a range of 1–2 GiB for D: and 0–1 GiB for H:. The total is 2 GiB because one copy must remain. Figures use logical file sizes. Actual free space can differ for compressed or sparse files.

To use this in Codex, place the `SKILL.md` and `scripts/` directory together under `.agents/skills/disk-audit-skill/` in the project where you want the skill available. Ask Codex to audit duplicate files across your chosen drives.

## Credits

- [Czkawka](https://github.com/qarmin/czkawka) inspired the staged duplicate scan, starting with size and using partial hashing to avoid unnecessary full reads.
- [file-organization](https://codexskills.dev/skills/automation/file-organization/) inspired the Codex workflow and the use of a report for human review before any file changes.

This project implements the scanner and skill independently and is distributed under the [MIT License](LICENSE).
