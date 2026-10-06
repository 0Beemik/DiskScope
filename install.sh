#!/usr/bin/env bash
# DiskScope installer: installs for the current user only, no root needed.
#   curl -fsSL https://raw.githubusercontent.com/0Beemik/DiskScope/main/install.sh | bash
#   ... | bash -s -- --uninstall
set -euo pipefail

REPO_RAW="${DISKSCOPE_RAW:-https://raw.githubusercontent.com/0Beemik/DiskScope/main}"
APP_DIR="${XDG_DATA_HOME:-$HOME/.local/share}/diskscope"
BIN_DIR="$HOME/.local/bin"
DESKTOP="${XDG_DATA_HOME:-$HOME/.local/share}/applications/diskscope.desktop"
ICON="${XDG_DATA_HOME:-$HOME/.local/share}/icons/hicolor/scalable/apps/diskscope.svg"

say() { printf '\033[1;34m==>\033[0m %s\n' "$*"; }
die() { printf '\033[1;31merror:\033[0m %s\n' "$*" >&2; exit 1; }

if [ "${1:-}" = "--uninstall" ]; then
    rm -rf "$APP_DIR" "$BIN_DIR/diskscope" "$DESKTOP" "$ICON"
    command -v update-desktop-database >/dev/null && update-desktop-database "$(dirname "$DESKTOP")" 2>/dev/null || true
    say "DiskScope removed."
    exit 0
fi

[ "$(uname -s)" = "Linux" ] || die "DiskScope currently supports Linux only."
[ "$(id -u)" -ne 0 ] || die "Run this as your normal user, not with sudo. (You can still run 'sudo diskscope' afterwards.)"
command -v python3 >/dev/null || die "python3 is required (sudo apt install python3)."
python3 -c 'import sys; sys.exit(sys.version_info < (3, 8))' || die "Python 3.8 or newer is required."

fetch() {
    if command -v curl >/dev/null; then curl -fsSL "$1" -o "$2"
    elif command -v wget >/dev/null; then wget -qO "$2" "$1"
    else die "curl or wget is required."; fi
}

say "Downloading DiskScope..."
mkdir -p "$APP_DIR" "$BIN_DIR" "$(dirname "$DESKTOP")" "$(dirname "$ICON")"
tmp="$(mktemp -d)"; trap 'rm -rf "$tmp"' EXIT
fetch "$REPO_RAW/diskscope.py" "$tmp/diskscope.py"
fetch "$REPO_RAW/diskscope.svg" "$tmp/diskscope.svg"
python3 -m py_compile "$tmp/diskscope.py" 2>/dev/null || die "Downloaded file is not valid Python. Try again later."
install -m 755 "$tmp/diskscope.py" "$APP_DIR/diskscope.py"
install -m 644 "$tmp/diskscope.svg" "$ICON"
ln -sf "$APP_DIR/diskscope.py" "$BIN_DIR/diskscope"

# Admin launcher: needs a terminal for the sudo password prompt.
term=""
for t in x-terminal-emulator gnome-terminal konsole xfce4-terminal kitty alacritty tilix xterm; do
    if command -v "$t" >/dev/null; then term="$t"; break; fi
done
case "$term" in
    gnome-terminal) admin_exec="gnome-terminal -- sudo python3 $APP_DIR/diskscope.py /" ;;
    "")             admin_exec="" ;;
    *)              admin_exec="$term -e sudo python3 $APP_DIR/diskscope.py /" ;;
esac

{
    echo "[Desktop Entry]"
    echo "Type=Application"
    echo "Name=DiskScope"
    echo "Comment=See what's using your disk: folders, big files, duplicates, caches"
    echo "Exec=python3 $APP_DIR/diskscope.py /"
    echo "Icon=diskscope"
    echo "Terminal=false"
    echo "Categories=System;Utility;"
    echo "Keywords=disk;space;usage;storage;duplicates;cleanup;"
    if [ -n "$admin_exec" ]; then
        echo "Actions=admin;"
        echo
        echo "[Desktop Action admin]"
        echo "Name=DiskScope (admin – sees everything)"
        echo "Exec=$admin_exec"
    fi
} > "$DESKTOP"
command -v update-desktop-database >/dev/null && update-desktop-database "$(dirname "$DESKTOP")" 2>/dev/null || true

say "Installed DiskScope $(python3 "$APP_DIR/diskscope.py" --version | awk '{print $2}')"
echo "    Start it from your app menu, or run:  diskscope"
echo "    Full view incl. system folders:       sudo $APP_DIR/diskscope.py"
echo "    Uninstall:  curl -fsSL $REPO_RAW/install.sh | bash -s -- --uninstall"
case ":$PATH:" in *":$BIN_DIR:"*) ;; *) echo "    Note: $BIN_DIR is not on your PATH; add it to use the 'diskscope' command." ;; esac
