#!/bin/zsh
# Build the Secure Transport -> mbedTLS shim as a FAT dylib spanning iOS 2-11.
# Per-arch slice with its own min-version; each links the matching lib/libmbed-<arch>.a
# (run ./build-mbedtls.sh first). Security/CF/MSHookFunction resolve at runtime (dynamic_lookup).
set -e
DIR="$(cd "$(dirname "$0")" && pwd)"
SDK="$HOME/theos/sdks/iPhoneOS9.3.sdk"
ARCHS=(${=TLSFIX_ARCHS:-armv7 arm64 armv6})
typeset -A MINV; MINV=(armv7 6.0 armv7s 6.0 arm64 7.0 armv6 6.0)
# 32-bit ARM (armv6/armv7) has no hardware divide, and old iOS (2-5) libSystem doesn't export the
# compiler-rt division builtins (___udivdi3, ___modsi3, ...) — with -undefined dynamic_lookup they'd
# be deferred to libSystem and abort the host (this is the ___udivdi3 crash that broke Safari on
# iOS 3.2.2). Apple's libclang_rt.ios.a doesn't carry the basic ones either (they're a libSystem
# detail on modern iOS), so we compile builtins.c into the 32-bit slices. arm64 keeps dynamic_lookup
# (its 128-bit ___udivti3 is in every arm64 libSystem, i.e. iOS 7+).

slices=()
for arch in "${ARCHS[@]}"; do
  min="${MINV[$arch]:-6.0}"
  lib="$DIR/lib/libmbed-$arch.a"
  [ -f "$lib" ] || { echo "missing $lib — run ./build-mbedtls.sh first"; exit 1; }
  out="$DIR/.tlsfix-$arch.dylib"
  bsrc=(); case "$arch" in armv6|armv7) bsrc=("$DIR/builtins.c") ;; esac   # 'builtins' is read-only in zsh
  xcrun --sdk iphoneos clang -arch "$arch" -miphoneos-version-min="$min" -dynamiclib -fno-modules \
    -isysroot "$SDK" -I "$DIR/include" -ffile-prefix-map="$DIR=." \
    "$lib" \
    -Wl,-ld_classic -Wl,-undefined,dynamic_lookup \
    -o "$out" "$DIR/Tweak.m" "${bsrc[@]}" 2>&1 | grep -ivE 'deprecated|tbd file|built for iOS Simulator' || true
  [ -f "$out" ] || { echo "build failed for $arch"; exit 1; }
  # sanity: the 32-bit slices must have NO division builtins left undefined (they'd abort on old
  # iOS whose libSystem lacks them). arm64's ___udivti3 is fine (every arm64 libSystem has it).
  if [ "$arch" = "armv6" ] || [ "$arch" = "armv7" ]; then
    und=$(nm -arch "$arch" -u "$out" 2>/dev/null | grep -cE "___u?divi?di3|___u?modi?si3|udivmod" || true)
    if [ "$und" -gt 0 ]; then echo "  WARNING: $arch still has $und undefined division builtins!"; fi
  fi
  slices+=("$out")
  echo "  slice $arch (min $min) ok"
done
lipo -create "${slices[@]}" -o "$DIR/tlsfix.dylib"
rm -f "${slices[@]}"
# The linker won't emit iOS min < 6.0, but the field is just metadata old dyld reads. Lower the
# 32-bit slices so they advertise support back to the first device of that arch (armv7=3GS/iOS3,
# armv6=2G/iOS2). arm64 stays 7.0 (first arm64 device shipped iOS 7).
[ -n "${ARCHS[(r)armv7]}" ] && python3 "$DIR/tools/patch_iphoneos_min.py" "$DIR/tlsfix.dylib" armv7 3.0
[ -n "${ARCHS[(r)armv6]}" ] && python3 "$DIR/tools/patch_iphoneos_min.py" "$DIR/tlsfix.dylib" armv6 2.0
lipo -info "$DIR/tlsfix.dylib"
echo "per-slice iOS min:"; for a in "${ARCHS[@]}"; do printf "  %-7s " "$a"; otool -arch "$a" -l "$DIR/tlsfix.dylib" 2>/dev/null | awk '/LC_VERSION_MIN_IPHONEOS/{f=1} f&&/version/{print $2; exit}'; done
