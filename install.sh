#!/usr/bin/env bash
# Crash Inspector installer (installs for the current user only)
#   ./install.sh              install or update
#   ./install.sh --uninstall  remove
# https://github.com/cyb3rl00m/crash-inspector
set -euo pipefail

APP_ID="io.github.cyb3rl00m.CrashInspector"
OLD_IDS=("io.github.crashinspector.CrashInspector")   # names used by early versions
SRC="$(cd "$(dirname "$0")" && pwd)"
BIN_DIR="$HOME/.local/bin"
APPS_DIR="$HOME/.local/share/applications"
ICON_DIR="$HOME/.local/share/icons/hicolor/scalable/apps"

remove_old() {
    for id in "${OLD_IDS[@]}"; do
        rm -f "$APPS_DIR/$id.desktop" "$ICON_DIR/$id.svg"
    done
}

if [[ "${1:-}" == "--uninstall" ]]; then
    remove_old
    rm -f "$BIN_DIR/crash-inspector" "$APPS_DIR/$APP_ID.desktop" "$ICON_DIR/$APP_ID.svg"
    update-desktop-database -q "$APPS_DIR" 2>/dev/null || true
    echo "Crash Inspector removed."
    exit 0
fi

if [[ $EUID -eq 0 ]]; then
    echo "Run this as your normal user (not with sudo). It asks for your password only if packages are missing."
    exit 1
fi

if command -v apt-get >/dev/null; then
    deps=(python3 python3-gi gir1.2-gtk-4.0 gir1.2-adw-1 pciutils)
    missing=()
    for p in "${deps[@]}"; do
        dpkg -s "$p" &>/dev/null || missing+=("$p")
    done
    if ((${#missing[@]})); then
        echo "Installing required packages: ${missing[*]}"
        sudo apt-get update -qq
        sudo apt-get install -y "${missing[@]}"
    fi
else
    echo "Not an apt-based system: make sure python3-gobject, GTK 4 and libadwaita are installed."
fi

remove_old
install -Dm755 "$SRC/crash-inspector.py" "$BIN_DIR/crash-inspector"
install -Dm644 "$SRC/$APP_ID.svg" "$ICON_DIR/$APP_ID.svg"
mkdir -p "$APPS_DIR"
cat > "$APPS_DIR/$APP_ID.desktop" <<EOF
[Desktop Entry]
Type=Application
Name=Crash Inspector
GenericName=System Crash Report
Comment=See every crash and error on this computer in one place
Exec=$BIN_DIR/crash-inspector
Icon=$APP_ID
Terminal=false
Categories=System;Monitor;GTK;
Keywords=crash;error;log;journal;kernel;panic;freeze;report;troubleshoot;system report;
StartupNotify=true
EOF

gtk-update-icon-cache -q -t "$HOME/.local/share/icons/hicolor" 2>/dev/null || true
update-desktop-database -q "$APPS_DIR" 2>/dev/null || true

echo
echo "Crash Inspector $("$BIN_DIR/crash-inspector" --version 2>/dev/null | awk '{print $3}') installed."
echo "Open 'Crash Inspector' from the app grid."

case ":$PATH:" in
    *":$BIN_DIR:"*)
        echo "Terminal mode: crash-inspector --text" ;;
    *)
        echo
        echo "The 'crash-inspector' terminal command works after you log out and back in."
        echo "Until then use: $BIN_DIR/crash-inspector --text" ;;
esac

if ! id -nG | grep -qwE 'adm|systemd-journal'; then
    echo
    echo "NOTE: your user can't read all system logs yet. For complete results run:"
    echo "    sudo usermod -aG adm \$USER"
    echo "then log out and back in."
fi
