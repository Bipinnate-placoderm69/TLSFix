#!/bin/zsh
# build-deb.sh — package tlsfix as an installable .deb. Only HARD dep is mobilesubstrate
# (the dylib is the whole tweak); preferenceloader+applist are Recommends — they only power
# the Settings GUI and don't exist on iOS 3-4, so they must not block install there. Per-app
# toggle appears in Settings -> tlsfix when those are present; otherwise edit the plists by hand.
set -e
DIR="$(cd "$(dirname "$0")" && pwd)"
VER=$(awk '/^Version:/{print $2}' "$DIR/control")
STAGE="$DIR/.stage"
rm -rf "$STAGE"
mkdir -p "$STAGE/DEBIAN" \
         "$STAGE/Library/MobileSubstrate/DynamicLibraries" \
         "$STAGE/Library/PreferenceLoader/Preferences" \
         "$STAGE/Library/PreferenceBundles"
cp "$DIR/control" "$STAGE/DEBIAN/control"
# seed Safari-on default so the AppList UI and the runtime gate agree
cat > "$STAGE/DEBIAN/postinst" <<'POST'
#!/bin/sh
# Ensure the tweak directories stay traversable. dpkg can (re)create parent dirs from a files-only
# archive without the execute bit, which makes EVERY tweak's dylib un-openable (Substrate then logs
# "unable to open() binary file" for all of them). 0755 restores traversal.
for d in /Library/MobileSubstrate /Library/MobileSubstrate/DynamicLibraries \
         /Library/PreferenceBundles /Library/PreferenceLoader /Library/PreferenceLoader/Preferences; do
  [ -d "$d" ] && chmod 0755 "$d" 2>/dev/null || true
done
P=/var/mobile/Library/Preferences/com.tlsfix.plist
# Safari is on by default. iOS 8+ runs Safari/WebView TLS in the shared com.apple.WebKit.Networking
# process (not com.apple.mobilesafari), so enable that too (harmless on iOS <8, which lack it).
if [ ! -f "$P" ]; then
  cat > "$P" <<'PLIST'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict><key>enabled-com.apple.mobilesafari</key><true/><key>enabled-com.apple.WebKit.Networking</key><true/><key>enabled-com.apple.WebKit.WebContent</key><true/><key>tls13</key><true/><key>drainGuard</key><true/><key>systemFallback</key><true/></dict></plist>
PLIST
else
  # existing install: add the WebKit keys if absent (don't override an explicit user choice)
  if command -v defaults >/dev/null 2>&1; then
    for a in com.apple.WebKit.Networking com.apple.WebKit.WebContent; do
      defaults read /var/mobile/Library/Preferences/com.tlsfix "enabled-$a" >/dev/null 2>&1 \
        || defaults write /var/mobile/Library/Preferences/com.tlsfix "enabled-$a" -bool true
    done
  fi
fi
chown mobile:mobile "$P" 2>/dev/null || true
# AppList is broken on iOS 3.x and crashes Settings when its picker is opened. Disable the "TLSFix
# Apps" PreferenceLoader entry there (rename so PreferenceLoader ignores it); the toggles pane and
# the per-app com.tlsfix.plist keys still work. Other iOS versions keep the picker.
case "$(sw_vers -productVersion 2>/dev/null)" in
  3.*) [ -f /Library/PreferenceLoader/Preferences/tlsfix-apps.plist ] && \
         mv -f /Library/PreferenceLoader/Preferences/tlsfix-apps.plist \
               /Library/PreferenceLoader/Preferences/tlsfix-apps.plist_ 2>/dev/null || true ;;
esac
exit 0
POST
chmod 0755 "$STAGE/DEBIAN/postinst"
"$DIR/build.sh" >/dev/null 2>&1 || true
[ -f "$DIR/tlsfix.dylib" ] || { echo "build failed"; exit 1; }
ldid -S "$DIR/tlsfix.dylib"
cp "$DIR/tlsfix.dylib"       "$STAGE/Library/MobileSubstrate/DynamicLibraries/"
cp "$DIR/tlsfix.plist"       "$STAGE/Library/MobileSubstrate/DynamicLibraries/"
cp "$DIR/cacert.pem"         "$STAGE/Library/MobileSubstrate/DynamicLibraries/tlsfix-cacert.pem"
# PreferenceLoader entries: global-toggle switches (our bundle) + the AppList per-app picker
cp "$DIR/prefs/tlsfix.plist"      "$STAGE/Library/PreferenceLoader/Preferences/tlsfix.plist"
cp "$DIR/prefs/tlsfix-apps.plist" "$STAGE/Library/PreferenceLoader/Preferences/tlsfix-apps.plist"
# Settings-list icon (PreferenceLoader resolves the entry's `icon` next to the plist), @1x/@2x/@3x
cp "$DIR/prefsbundle/"tlsfix-icon*.png "$STAGE/Library/PreferenceLoader/Preferences/"
# the global-toggle Settings pane (PSListController PreferenceBundle)
"$DIR/build-prefs.sh" >/dev/null 2>&1 || true
[ -f "$DIR/TLSFix.bundle/TLSFix" ] || { echo "prefs bundle build failed"; exit 1; }
cp -R "$DIR/TLSFix.bundle" "$STAGE/Library/PreferenceBundles/TLSFix.bundle"
find "$STAGE" -type d -exec chmod 0755 {} +
find "$STAGE" -type f -exec chmod 0644 {} +
chmod 0755 "$STAGE/Library/MobileSubstrate/DynamicLibraries/tlsfix.dylib"
chmod 0755 "$STAGE/Library/PreferenceBundles/TLSFix.bundle/TLSFix"
chmod 0755 "$STAGE/DEBIAN/postinst"   # maintainer scripts must be executable (after the find)
OUT="$(cd "$DIR/.." && pwd)/tlsfix_${VER}_iphoneos-arm.deb"   # write the .deb to the repo root
rm -f "$OUT"
"${THEOS:-$HOME/theos}/bin/dm.pl" -b "$STAGE" "$OUT"
rm -rf "$STAGE"
echo "built: $OUT"
