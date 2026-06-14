#!/bin/zsh
# Build the TLSFix Settings PreferenceBundle as a FAT binary (armv6 + armv7 + arm64) so it loads in
# every Preferences.app the dylib targets: an armv6 device (iPod touch 1G/2G, iPhone 2G/3G) runs
# Settings as armv6, and an armv7/arm64-only bundle fails there with "error loading the preference
# bundle" / "mach-o, but wrong architecture". Preferences.framework is private and resolves at
# runtime inside Preferences.app (dynamic_lookup), like the main tweak.
set -e
DIR="$(cd "$(dirname "$0")" && pwd)"
SDK="$HOME/theos/sdks/iPhoneOS9.3.sdk"
PREFHDRS="$HOME/theos/vendor/include"
B="$DIR/TLSFix.bundle"
ARCHS=(armv6 armv7 arm64)
typeset -A MINV; MINV=(armv6 6.0 armv7 6.0 arm64 7.0)
rm -rf "$B"; mkdir -p "$B"
slices=()
for arch in "${ARCHS[@]}"; do
  out="$DIR/.TLSFixPrefs-$arch"
  xcrun --sdk iphoneos clang -arch "$arch" -miphoneos-version-min="${MINV[$arch]}" -bundle -fno-modules \
    -isysroot "$SDK" -I "$PREFHDRS" -ffile-prefix-map="$DIR=." \
    -D'API_AVAILABLE(...)=' -D'API_UNAVAILABLE(...)=' -D'API_DEPRECATED(...)=' -D'NS_SWIFT_NAME(...)=' \
    -framework Foundation -framework UIKit -framework CoreGraphics \
    -Wl,-ld_classic -Wl,-undefined,dynamic_lookup \
    -o "$out" "$DIR/prefsbundle/TLSFixPrefs.m" 2>&1 | grep -ivE 'deprecated|tbd file|built for iOS Simulator' || true
  [ -f "$out" ] || { echo "prefs build failed for $arch"; exit 1; }
  slices+=("$out")
done
lipo -create "${slices[@]}" -o "$B/TLSFix"
rm -f "${slices[@]}"
# The linker won't emit a 32-bit min < 6.0, but the bundle must dlopen on old iOS too (else Settings
# shows "error loading the preference bundle"). Patch the armv6/armv7 slices' min down to 2.0 (i.e.
# "any iOS"), so dyld never rejects them on version grounds. Deployment target is therefore iOS 2 in
# the Mach-O, though support is only documented as iOS 3+.
python3 "$DIR/tools/patch_iphoneos_min.py" "$B/TLSFix" armv6 2.0
python3 "$DIR/tools/patch_iphoneos_min.py" "$B/TLSFix" armv7 2.0
# The controller class is registered at RUNTIME (see TLSFixPrefs.m) rather than statically subclassed,
# so the bundle dlopens with only objc_* runtime imports (no _OBJC_METACLASS_$_NSObject) and the pane
# loads across iOS 3-9. (dynamic_lookup is fine here; the static-subclass symbol was the only blocker.)
cp "$DIR/prefsbundle/Info.plist" "$B/Info.plist"
cp "$DIR/prefsbundle/TLSFix.plist" "$B/TLSFix.plist"
cp "$DIR/prefsbundle/TLSFixLegacy.plist" "$B/TLSFixLegacy.plist"   # iOS<=3 variant (inline guide)
cp "$DIR/prefsbundle/TLSFix8.plist"     "$B/TLSFix8.plist"         # iOS 8+ variant (WebKit toggles)
ldid -S "$B/TLSFix"
lipo -info "$B/TLSFix"
echo "built: $B"
