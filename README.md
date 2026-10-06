# DiskScope

**One app to find out what's eating your disk and clean it up.** It combines a folder treemap, a largest-files list, a file-type breakdown, a duplicate finder and a cache cleaner, so you don't need four separate tools.

It's a single Python file that uses only the standard library. It runs a private web UI on `127.0.0.1` and opens it in your browser. Nothing leaves your machine.

## Install

```bash
curl -fsSL https://raw.githubusercontent.com/0Beemik/DiskScope/main/install.sh | bash
```

This installs for your user only (no root needed), adds a `diskscope` command, and puts **DiskScope** in your app menu. Requirements: Linux and Python 3.8+.

Uninstall:

```bash
curl -fsSL https://raw.githubusercontent.com/0Beemik/DiskScope/main/install.sh | bash -s -- --uninstall
```

Or skip installing and just run it:

```bash
curl -fsSLO https://raw.githubusercontent.com/0Beemik/DiskScope/main/diskscope.py && python3 diskscope.py
```

## Usage

```bash
diskscope              # scan the whole drive (/)
diskscope ~/Projects   # scan one folder
sudo ~/.local/share/diskscope/diskscope.py   # admin: also see /timeshift, /var/lib/docker, logs...
```

You can also right-click DiskScope in the app menu and choose **DiskScope (admin)**. Other options: `--port N`, `--no-browser`, `--version`.

## What it does

| Tab | What you get |
|---|---|
| **Overview** | A bar showing where every byte of the drive goes: scanned files, folders you can't read, space **reserved by the filesystem**, and free space. This explains the "missing space" that other tools leave out. |
| **Browse** | A clickable treemap and sorted list of folders and files, with Open / Trash buttons. |
| **Largest files** | Top files, filterable by kind: AI models (`.safetensors`, `.gguf`, Hugging Face blobs…), video, images, disk images/VMs, archives. Select several and trash or delete them. |
| **File types** | Space used per extension. |
| **Duplicates** | Files over 1 MB with identical contents (checks size, then a quick fingerprint, then a full BLAKE2 hash). Warns before you break a model cache. |
| **Cleanup** | Sizes of known space hogs: uv/pip/npm/Gradle caches, Hugging Face, Ollama, LM Studio, Android emulators, Steam, Timeshift snapshots, journal logs, apt, Docker, Flatpak, Snap. Safe caches get one-click **Empty**; system items show the right command to run. Also lists empty folders. |

## Safety

- Every delete asks for confirmation. **Move to Trash** is the default; permanent delete is a separate button.
- It refuses to touch system locations (`/usr`, `/etc`, `/boot`, `/timeshift`, your home folder itself, …).
- Scans stay on one filesystem and count hard links once. Sizes are real disk usage, not apparent size.
- The web UI listens on `127.0.0.1` only, needs a random per-session token, and rejects requests whose `Host` isn't localhost.

## License

MIT
