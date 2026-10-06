# Changelog

## 0.2.0

- **Opens as its own app window** (Chrome/Chromium/Brave/Edge `--app` mode) and quits when the window closes.
- **Changes tab**: every scan is saved; see which folders grew or shrank and which big files appeared or vanished since any earlier scan. The Overview shows the change since the last scan.
- **Duplicates: Merge** turns extra copies into hard links (stored once, every path still works), with undo.
- **AI models tab**: models grouped by app (Hugging Face, Ollama, ComfyUI, LM Studio, …), format, quantization, last use, and models stored in more than one app.
- **Similar media**: near-duplicate photos and videos with thumbnails (needs ffmpeg).
- **Dev junk**: node_modules, virtualenvs, Rust/Gradle/CMake build output, framework caches, with project age.
- **Backups tab**: Timeshift snapshots, the space each frees if deleted, schedule, filters, and the folders that bloat backups.
- **Activity tab**: log of every removal, restore from Trash, undo merges.
- **Low-space alerts**: optional hourly systemd user timer with desktop notifications.
- **Run as admin** from inside the app (password dialog via pkexec).
- Drive picker, "unused for a year" filter, keyboard navigation and shortcuts (`?`), "Ways to free space" suggestions on the Overview.
- Files on drives mounted under `/run/media` can now be cleaned up (previously blocked as a system path).
- Duplicate and photo checks no longer change files' access times.
- Test suite and GitHub Actions CI.

## 0.1.0

- First release: overview, treemap browser, largest files, file types, duplicates, cache cleanup, one-line installer.
