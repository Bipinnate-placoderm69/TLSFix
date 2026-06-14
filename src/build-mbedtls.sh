#!/bin/zsh
# build-mbedtls.sh — cross-compile mbedTLS 3.6.0 (full source incl. TLS 1.3) for each iOS arch.
# Produces lib/libmbed-<arch>.a per arch (default armv7 + arm64; armv6 best-effort via build-armv6).
# Pure C, so one source tree covers the whole iOS 2-11 span — only -arch / min-version differ.
set -e
DIR="$(cd "$(dirname "$0")" && pwd)"
SRC="${MBEDTLS_SRC:-$DIR/mbedtls-src}"
SDK="$HOME/theos/sdks/iPhoneOS9.3.sdk"
ARCHS=(${=TLSFIX_ARCHS:-armv7 arm64 armv6})
typeset -A MINV; MINV=(armv7 6.0 armv7s 6.0 arm64 7.0 armv6 6.0)

if [ ! -f "$SRC/library/ssl_tls13_client.c" ]; then
  echo "== cloning mbedTLS 3.6.0 (with submodules) =="
  rm -rf "$SRC"
  git clone --depth 1 -b mbedtls-3.6.0 --recurse-submodules https://github.com/Mbed-TLS/mbedtls.git "$SRC"
fi
mkdir -p "$DIR/lib"
for arch in "${ARCHS[@]}"; do
  min="${MINV[$arch]:-6.0}"
  echo "== mbedTLS: $arch (min $min), $(ls "$SRC"/library/*.c | wc -l | tr -d ' ') sources =="
  CFLAGS=(-arch "$arch" -miphoneos-version-min="$min" -isysroot "$SDK" -Os -fno-modules -Wno-everything
          -ffile-prefix-map="$SRC=mbedtls" -ffile-prefix-map="$DIR=."
          -I"$SRC/include" -I"$SRC/library"
          -DMBEDTLS_HAVE_TIME -DMBEDTLS_HAVE_TIME_DATE -DMBEDTLS_PLATFORM_MS_TIME_ALT -D_FORTIFY_SOURCE=0)
  OBJ="$DIR/.mbobj-$arch"; rm -rf "$OBJ"; mkdir -p "$OBJ"
  objs=()
  for f in "$SRC"/library/*.c "$DIR"/ms_time_ios.c; do
    o="$OBJ/$(basename "$f").o"
    xcrun --sdk iphoneos clang "${CFLAGS[@]}" -c "$f" -o "$o"
    objs+=("$o")
  done
  rm -f "$DIR/lib/libmbed-$arch.a"
  ar rcs "$DIR/lib/libmbed-$arch.a" "${objs[@]}"
  ranlib "$DIR/lib/libmbed-$arch.a" 2>/dev/null || true
  rm -rf "$OBJ"
  echo "   built lib/libmbed-$arch.a ($(ls -la "$DIR/lib/libmbed-$arch.a" | awk '{print $5}') bytes)"
done
rm -rf "$DIR/include"; cp -R "$SRC/include" "$DIR/include"
cp "$DIR/lib/libmbed-${ARCHS[1]}.a" "$DIR/lib/libmbed.a"   # legacy single-arch name
nm "$DIR/lib/libmbed-${ARCHS[1]}.a" 2>/dev/null | grep -qE 'ssl_tls13_process_server_hello|mbedtls_ssl_tls13' && echo "TLS 1.3 symbols: present" || echo "TLS 1.3 symbols: MISSING"
echo "== done: ${ARCHS[*]} =="
