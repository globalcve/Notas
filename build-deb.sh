#!/bin/bash
set -e

# Read version directly from Cargo.toml so it never drifts out of sync
VERSION=$(grep '^version' Cargo.toml | head -1 | sed 's/.*"\(.*\)".*/\1/')
PACKAGE="notas"
ARCH="amd64"  # Change to arm64 if needed

echo "╔════════════════════════════════════════════════════════════════════════════╗"
echo "║                                                                            ║"
echo "║   _   _       _                   _      _                                ║"
echo "║  | \ | | ___ | |_ __ _ ___     __| | ___| |__                            ║"
echo "║  |  \| |/ _ \| __/ _\` / __|   / _\` |/ _ \ '_ \                          ║"
echo "║  | |\  | (_) | || (_| \__ \  | (_| |  __/ |_) |                          ║"
echo "║  |_| \_|\___/ \__\__,_|___/ (_)__,_|\___|_.__/                           ║"
echo "║                                                                            ║"
echo "║  ____            _                      ____        _ _     _             ║"
echo "║ |  _ \ __ _  ___| | ____ _  __ _  ___  | __ ) _   _(_) | __| | ___ _ __ ║"
echo "║ | |_) / _\` |/ __| |/ / _\` |/ _\` |/ _ \ |  _ \| | | | | |/ _\` |/ _ \ '__| ║"
echo "║ |  __/ (_| | (__|   < (_| | (_| |  __/ | |_) | |_| | | | (_| |  __/ |   ║"
echo "║ |_|   \__,_|\___|_|\_\__,_|\__, |\___| |____/ \__,_|_|_|\__,_|\___|_|   ║"
echo "║                            |___/                                          ║"
echo "║                                                                            ║"
echo "╚════════════════════════════════════════════════════════════════════════════╝"

# ── Dependency checks ────────────────────────────────────────────────────────
MISSING_APT=()
MISSING_OTHER=()

# rustup / cargo
if ! command -v cargo &> /dev/null; then
    if ! command -v rustup &> /dev/null; then
        MISSING_OTHER+=("rustup  →  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh")
    else
        MISSING_OTHER+=("cargo toolchain  →  run: rustup default stable")
    fi
fi

# dpkg-deb
if ! command -v dpkg-deb &> /dev/null; then
    MISSING_APT+=("dpkg")
fi

# pkg-config
if ! command -v pkg-config &> /dev/null; then
    MISSING_APT+=("pkg-config")
fi

# libgtk-4-dev (check via pkg-config so version mismatches are caught too)
if command -v pkg-config &> /dev/null && ! pkg-config --exists gtk4 2>/dev/null; then
    MISSING_APT+=("libgtk-4-dev")
fi

# libadwaita-1-dev
if command -v pkg-config &> /dev/null && ! pkg-config --exists libadwaita-1 2>/dev/null; then
    MISSING_APT+=("libadwaita-1-dev")
fi

# Report and exit if anything is missing
if [ ${#MISSING_APT[@]} -gt 0 ] || [ ${#MISSING_OTHER[@]} -gt 0 ]; then
    echo ""
    echo "❌ Missing dependencies:"
    for dep in "${MISSING_OTHER[@]}"; do
        echo "   • $dep"
    done
    if [ ${#MISSING_APT[@]} -gt 0 ]; then
        echo "   • apt packages: ${MISSING_APT[*]}"
        echo ""
        echo "   Install with:"
        echo "   sudo apt install ${MISSING_APT[*]}"
    fi
    echo ""
    exit 1
fi

echo "✓ All build dependencies found"

# Font is bundled in the repo — always included
FONT_FILE="fonts/DotGothic16-Regular.ttf"
if [ ! -f "$FONT_FILE" ]; then
    echo "❌ Error: fonts/DotGothic16-Regular.ttf not found."
    echo "   It should be committed to the repository. Check your checkout."
    exit 1
fi
echo "✓ Found DotGothic16-Regular.ttf (bundled)"
INCLUDE_FONT=true

echo ""
echo "📦 Step 1: Building Notas with Cargo..."
cargo build --release

echo ""
echo "📁 Step 2: Creating package structure..."

# Create package directory structure
PKG_DIR="${PACKAGE}_${VERSION}_${ARCH}"
rm -rf "$PKG_DIR"
mkdir -p "$PKG_DIR/DEBIAN"
mkdir -p "$PKG_DIR/usr/bin"
mkdir -p "$PKG_DIR/usr/share/applications"
mkdir -p "$PKG_DIR/usr/share/metainfo"
mkdir -p "$PKG_DIR/usr/share/icons/hicolor/16x16/apps"
mkdir -p "$PKG_DIR/usr/share/icons/hicolor/32x32/apps"
mkdir -p "$PKG_DIR/usr/share/icons/hicolor/48x48/apps"
mkdir -p "$PKG_DIR/usr/share/icons/hicolor/64x64/apps"
mkdir -p "$PKG_DIR/usr/share/icons/hicolor/128x128/apps"
mkdir -p "$PKG_DIR/usr/share/icons/hicolor/256x256/apps"
mkdir -p "$PKG_DIR/usr/share/icons/hicolor/512x512/apps"

# Create font directory (always bundled)
mkdir -p "$PKG_DIR/usr/share/fonts/truetype/notas"

echo ""
echo "📋 Step 3: Copying files..."

# Copy binary
cp target/release/notas "$PKG_DIR/usr/bin/"
chmod 755 "$PKG_DIR/usr/bin/notas"

# Copy desktop file
cp notas.desktop "$PKG_DIR/usr/share/applications/"

# Copy metainfo
cp com.jegly.Notas.metainfo.xml "$PKG_DIR/usr/share/metainfo/"

# Copy icons
cp icons/hicolor/16x16/apps/notas.png "$PKG_DIR/usr/share/icons/hicolor/16x16/apps/"
cp icons/hicolor/32x32/apps/notas.png "$PKG_DIR/usr/share/icons/hicolor/32x32/apps/"
cp icons/hicolor/48x48/apps/notas.png "$PKG_DIR/usr/share/icons/hicolor/48x48/apps/"
cp icons/hicolor/64x64/apps/notas.png "$PKG_DIR/usr/share/icons/hicolor/64x64/apps/"
cp icons/hicolor/128x128/apps/notas.png "$PKG_DIR/usr/share/icons/hicolor/128x128/apps/"
cp icons/hicolor/256x256/apps/notas.png "$PKG_DIR/usr/share/icons/hicolor/256x256/apps/"
cp icons/hicolor/512x512/apps/notas.png "$PKG_DIR/usr/share/icons/hicolor/512x512/apps/"

# Copy font and its license
cp "$FONT_FILE" "$PKG_DIR/usr/share/fonts/truetype/notas/"
cp "fonts/OFL.txt" "$PKG_DIR/usr/share/fonts/truetype/notas/"
echo "✓ Bundled DotGothic16 font (OFL licensed)"
INCLUDE_FONT=true

# Calculate installed size (in KB)
INSTALLED_SIZE=$(du -sk "$PKG_DIR" | cut -f1)

echo ""
echo "📝 Step 4: Creating control file..."

# Create control file
cat > "$PKG_DIR/DEBIAN/control" << EOF
Package: ${PACKAGE}
Version: ${VERSION}
Section: utils
Priority: optional
Architecture: ${ARCH}
Installed-Size: ${INSTALLED_SIZE}
Depends: libgtk-4-1, libadwaita-1-0
Maintainer: Jegly <jjjegly@gmail.com>
Homepage: https://github.com/jegly/notas
Description: Secure encrypted notes application
 Notas is a privacy-focused encrypted notes application built with
 GTK4 and Rust. Features include AES-256-GCM encryption, Argon2id
 key derivation, auto-lock, clipboard clearing, and beautiful themes.
EOF

# Create postinst script
cat > "$PKG_DIR/DEBIAN/postinst" << 'EOF'
#!/bin/sh
set -e

# Update icon cache
if [ -x /usr/bin/gtk-update-icon-cache ]; then
    gtk-update-icon-cache -f -t /usr/share/icons/hicolor 2>/dev/null || true
fi

# Update desktop database
if [ -x /usr/bin/update-desktop-database ]; then
    update-desktop-database /usr/share/applications 2>/dev/null || true
fi

# Update font cache (for bundled DotGothic16 font)
if [ -x /usr/bin/fc-cache ]; then
    fc-cache -f /usr/share/fonts/truetype/notas 2>/dev/null || true
fi

exit 0
EOF
chmod 755 "$PKG_DIR/DEBIAN/postinst"

# Create postrm script
cat > "$PKG_DIR/DEBIAN/postrm" << 'EOF'
#!/bin/sh
set -e

# Update icon cache
if [ -x /usr/bin/gtk-update-icon-cache ]; then
    gtk-update-icon-cache -f -t /usr/share/icons/hicolor 2>/dev/null || true
fi

# Update desktop database
if [ -x /usr/bin/update-desktop-database ]; then
    update-desktop-database /usr/share/applications 2>/dev/null || true
fi

# Update font cache after removal
if [ -x /usr/bin/fc-cache ]; then
    fc-cache -f 2>/dev/null || true
fi

# Remove user data and config ONLY on an explicit purge (`apt purge notas`).
# postrm also runs with "upgrade" on every package upgrade and with "remove" on
# a plain uninstall — deleting the vault in those cases destroys the user's
# notes (upgrading 3.1.x -> 3.2.0 did exactly that). Purge is the one verb that
# means "and my data too".
if [ "$1" = "purge" ]; then
    REAL_USER="${SUDO_USER:-$(logname 2>/dev/null || true)}"
    if [ -n "$REAL_USER" ]; then
        USER_HOME=$(getent passwd "$REAL_USER" | cut -d: -f6)
        if [ -n "$USER_HOME" ]; then
            rm -rf "$USER_HOME/.local/share/notas"
            rm -rf "$USER_HOME/.config/notas"
        fi
    fi
fi

exit 0
EOF
chmod 755 "$PKG_DIR/DEBIAN/postrm"

echo ""
echo "🔨 Step 5: Building .deb package..."

# Build the package
dpkg-deb --build --root-owner-group "$PKG_DIR"

echo ""
echo "✅ Package built successfully!"
echo ""
echo "📦 Output: ${PKG_DIR}.deb"
if [ "$INCLUDE_FONT" = true ]; then
    echo "   ✓ Includes bundled DotGothic16 font"
fi
echo ""
echo "To install:"
echo "  sudo dpkg -i ${PKG_DIR}.deb"
echo ""
echo "To uninstall:"
echo "  sudo apt remove notas"
echo ""

# Clean up build directory (optional)
# rm -rf "$PKG_DIR"
