// tlsfix — route iOS 6 Secure Transport HTTPS through mbedTLS (modern TLS 1.2 / 1.3).
//
// iOS 6's Secure Transport can't handshake modern servers (old ciphers/curves/ClientHello).
// CFNetwork/NSURLConnection drive an SSLContextRef via the SSL* C API. We keep the REAL
// SSLContextRef (so any SSL* we don't hook still operates on a valid context and can't crash)
// and attach an mbedTLS "shadow" that does the actual crypto: our hooks for the behavioural
// functions (handshake / read / write / state / trust) use the shadow, while CFNetwork keeps
// doing the sockets via the SSLReadFunc/SSLWriteFunc it installed.
#import <Foundation/Foundation.h>
#import <Security/Security.h>
#import <Security/SecureTransport.h>
#import <pthread.h>
#import <dlfcn.h>
#import <stdlib.h>

#include "mbedtls/ssl.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/error.h"
#include "mbedtls/x509_crt.h"
#include "psa/crypto.h"     // TLS 1.3 in mbedTLS 3.x runs through PSA

#ifndef MBEDTLS_ERR_NET_RECV_FAILED
#define MBEDTLS_ERR_NET_RECV_FAILED -0x004C
#endif
#ifndef MBEDTLS_ERR_NET_SEND_FAILED
#define MBEDTLS_ERR_NET_SEND_FAILED -0x004E
#endif

// Logging is OFF by default (gDebug, the "debug" pref). NSLog on every handshake wastes CPU/battery
// and spams syslog, so it's gated to a single branch unless explicitly turned on in Settings.
#define slog(fmt, ...) do { if (gDebug) NSLog((@"STTLS| " fmt), ##__VA_ARGS__); } while (0)

// resolved at runtime from libsubstrate (avoids a link-time dependency)
static int (*MSHookFunction)(void *symbol, void *replace, void **result) = 0;

// ---- Secure Transport constants (stable) -----------------------------------
#ifndef errSSLWouldBlock
#define errSSLWouldBlock      -9803
#endif
#define ST_ClosedGraceful     -9805
#define ST_ClosedAbort        -9806
#define ST_Connected           2     /* kSSLConnected (SSLSessionState) */
#define ST_TLS12               8     /* kTLSProtocol12 (SSLProtocol) */

// ---- shadow state ----------------------------------------------------------
typedef struct {
    SSLContextRef       ctx;
    SSLReadFunc         rf;
    SSLWriteFunc        wf;
    SSLConnectionRef    conn;
    char                host[256];
    int                 inited;     // mbedTLS objects set up
    int                 state;      // 0 none, 1 handshaking, 2 connected, -1 bypass
    int                 clientCert; // app set a client identity (mutual TLS) -> use system TLS
    unsigned            lastUse;    // for LRU eviction backstop
    mbedtls_ssl_context ssl;
    mbedtls_ssl_config  conf;
} Shadow;

#define MAXSH 256
static Shadow *gTab[MAXSH];
static unsigned gClock = 0;
static pthread_mutex_t gLock = PTHREAD_MUTEX_INITIALIZER;

static mbedtls_ctr_drbg_context gDrbg;
static mbedtls_entropy_context  gEntropy;
static int gDrbgReady = 0;
static pthread_mutex_t gRng = PTHREAD_MUTEX_INITIALIZER;

static mbedtls_x509_crt gCA;        // modern Mozilla root bundle
static int gCAok = 0;
#define CA_PATH "/Library/MobileSubstrate/DynamicLibraries/tlsfix-cacert.pem"

// ---- global toggles (com.tlsfix.plist, read once at init; default ON) -------
static int gAllowTLS13  = 1;  // key "tls13": allow negotiating TLS 1.3 (off -> cap at 1.2)
static int gDrainGuard  = 1;  // key "drainGuard": bound the post-handshake drain loop (safety)
static int gSysFallback = 1;  // key "systemFallback": on mbedTLS handshake fail, retry host on iOS's own stack (reaches TLS 1.0/1.1 sites)
static int gDebug       = 0;  // key "debug": NSLog handshake/SNI lines (OFF by default; battery/syslog cost)
#define DRAIN_MAX 64          // iteration cap when gDrainGuard is on

// SecTrustRefs we built (already verified by mbedTLS) -> rubber-stamp their SecTrustEvaluate,
// since iOS 6's SecTrust can't validate modern (esp. ECDSA) chains. The set RETAINS members
// (kCFTypeSetCallBacks) so a pointer can't be freed+reused while tracked (no false positives);
// bounded to the 64 most-recent via a ring that releases the evicted one.
static CFMutableSetRef gTrustSet = NULL;     // retains members
static void *gTrustRing[64];
static int gTrustIdx = 0;
static pthread_mutex_t gTrustLock = PTHREAD_MUTEX_INITIALIZER;
static void trust_remember(void *t) {
    pthread_mutex_lock(&gTrustLock);
    void *old = gTrustRing[gTrustIdx % 64];
    if (old && gTrustSet) CFSetRemoveValue(gTrustSet, old);   // release the evicted
    gTrustRing[gTrustIdx % 64] = t; gTrustIdx++;
    if (gTrustSet) CFSetAddValue(gTrustSet, t);               // retains t
    pthread_mutex_unlock(&gTrustLock);
}
static int trust_is_mine(void *t) {
    if (!gTrustSet) return 0;
    pthread_mutex_lock(&gTrustLock);
    int f = CFSetContainsValue(gTrustSet, t);
    pthread_mutex_unlock(&gTrustLock);
    return f;
}

// Hosts whose mbedTLS handshake failed — e.g. a server that only speaks TLS 1.0/1.1, which
// mbedTLS 3.x dropped, or any handshake mbedTLS can't complete. Their NEXT connection is routed
// to iOS's own Secure Transport (which still does 1.0/1.1). In-memory ring (self-heals on app
// relaunch), so a one-off transient failure can't permanently pin a host to the legacy stack.
static char gFailHosts[64][256];
static int gFailIdx = 0;
static pthread_mutex_t gFailLock = PTHREAD_MUTEX_INITIALIZER;
static int host_is_failed(const char *h) {
    if (!h || !h[0]) return 0;
    int f = 0;
    pthread_mutex_lock(&gFailLock);
    for (int i = 0; i < 64; i++) if (gFailHosts[i][0] && strcmp(gFailHosts[i], h) == 0) { f = 1; break; }
    pthread_mutex_unlock(&gFailLock);
    return f;
}
static void host_mark_failed(const char *h) {
    if (!h || !h[0] || host_is_failed(h)) return;
    pthread_mutex_lock(&gFailLock);
    strncpy(gFailHosts[gFailIdx % 64], h, 255); gFailHosts[gFailIdx % 64][255] = 0;
    gFailIdx++;
    pthread_mutex_unlock(&gFailLock);
}

static int rng_cb(void *p, unsigned char *out, size_t len) {
    pthread_mutex_lock(&gRng);
    int rc = mbedtls_ctr_drbg_random(&gDrbg, out, len);
    pthread_mutex_unlock(&gRng);
    return rc;
}

static int ensure_ready(void);          // per-app gate (cached pthread_once load after first call)

static void sh_destroy(Shadow *s) {     // caller must not hold gLock
    if (!s) return;
    if (s->inited) { mbedtls_ssl_free(&s->ssl); mbedtls_ssl_config_free(&s->conf); }
    free(s);
}
static Shadow *sh_get(SSLContextRef c) {
    // Fast bail for apps where tlsfix isn't enabled: skip the locked table scan entirely. The
    // dylib is injected into every UIKit app (com.apple.UIKit filter) but only activates for the
    // few enabled ones; this keeps the SSLRead/SSLWrite hooks ~free in all the others.
    if (ensure_ready() != 1) return NULL;
    Shadow *r = NULL;
    pthread_mutex_lock(&gLock);
    for (int i = 0; i < MAXSH; i++) if (gTab[i] && gTab[i]->ctx == c) { r = gTab[i]; r->lastUse = ++gClock; break; }
    pthread_mutex_unlock(&gLock);
    return r;
}
static Shadow *sh_create(SSLContextRef c) {
    Shadow *s = sh_get(c);
    if (s) return s;
    s = (Shadow *)calloc(1, sizeof(Shadow));
    s->ctx = c;
    Shadow *evicted = NULL;
    pthread_mutex_lock(&gLock);
    int slot = -1;
    for (int i = 0; i < MAXSH; i++) if (!gTab[i]) { slot = i; break; }
    if (slot < 0) {                                  // table full -> evict least-recently-used
        int lru = 0; for (int i = 1; i < MAXSH; i++) if (gTab[i]->lastUse < gTab[lru]->lastUse) lru = i;
        evicted = gTab[lru]; slot = lru;
    }
    s->lastUse = ++gClock;
    gTab[slot] = s;
    pthread_mutex_unlock(&gLock);
    if (evicted) sh_destroy(evicted);
    return s;
}
static void sh_free(SSLContextRef c) {       // detach under lock, destroy outside it
    if (ensure_ready() != 1) return;         // disabled app never created shadows -> nothing to scan
    Shadow *s = NULL;
    pthread_mutex_lock(&gLock);
    for (int i = 0; i < MAXSH; i++) if (gTab[i] && gTab[i]->ctx == c) { s = gTab[i]; gTab[i] = NULL; break; }
    pthread_mutex_unlock(&gLock);
    sh_destroy(s);
}

// ---- mbedTLS bio bridged to CFNetwork's SSLReadFunc/SSLWriteFunc -----------
static int bio_send(void *p, const unsigned char *buf, size_t len) {
    Shadow *s = (Shadow *)p;
    size_t n = len;
    OSStatus os = s->wf(s->conn, buf, &n);
    if (n > 0) return (int)n;
    if (os == errSSLWouldBlock) return MBEDTLS_ERR_SSL_WANT_WRITE;
    return MBEDTLS_ERR_NET_SEND_FAILED;
}
static int bio_recv(void *p, unsigned char *buf, size_t len) {
    Shadow *s = (Shadow *)p;
    size_t n = len;
    OSStatus os = s->rf(s->conn, buf, &n);
    if (n > 0) return (int)n;
    if (os == errSSLWouldBlock) return MBEDTLS_ERR_SSL_WANT_READ;
    if (os == ST_ClosedGraceful) return 0;
    return MBEDTLS_ERR_NET_RECV_FAILED;
}

static int mbed_init(Shadow *s) {
    mbedtls_ssl_init(&s->ssl);
    mbedtls_ssl_config_init(&s->conf);
    int ret = mbedtls_ssl_config_defaults(&s->conf, MBEDTLS_SSL_IS_CLIENT,
                                          MBEDTLS_SSL_TRANSPORT_STREAM, MBEDTLS_SSL_PRESET_DEFAULT);
    if (ret) return ret;
    if (gCAok) {
        mbedtls_ssl_conf_ca_chain(&s->conf, &gCA, NULL);
        mbedtls_ssl_conf_authmode(&s->conf, MBEDTLS_SSL_VERIFY_REQUIRED);  // real verify vs modern roots
    } else {
        mbedtls_ssl_conf_authmode(&s->conf, MBEDTLS_SSL_VERIFY_NONE);      // fallback if bundle missing
    }
    mbedtls_ssl_conf_rng(&s->conf, rng_cb, NULL);
    mbedtls_ssl_conf_min_tls_version(&s->conf, MBEDTLS_SSL_VERSION_TLS1_2);   // refuse 1.0/1.1
    mbedtls_ssl_conf_max_tls_version(&s->conf, gAllowTLS13 ? MBEDTLS_SSL_VERSION_TLS1_3
                                                           : MBEDTLS_SSL_VERSION_TLS1_2);   // 1.3 preferred (toggle), negotiates down
    if ((ret = mbedtls_ssl_setup(&s->ssl, &s->conf))) return ret;
    if (s->host[0]) mbedtls_ssl_set_hostname(&s->ssl, s->host);
    mbedtls_ssl_set_bio(&s->ssl, s, bio_send, bio_recv, NULL);
    s->inited = 1;
    return 0;
}


// ---- hooks -----------------------------------------------------------------
static OSStatus (*o_SetIOFuncs)(SSLContextRef, SSLReadFunc, SSLWriteFunc);
static OSStatus my_SetIOFuncs(SSLContextRef c, SSLReadFunc rf, SSLWriteFunc wf) {
    if (ensure_ready() != 1) return o_SetIOFuncs(c, rf, wf);   // per-app gate (lazy, Foundation-safe)
    OSStatus r = o_SetIOFuncs(c, rf, wf);
    Shadow *s = sh_create(c); s->rf = rf; s->wf = wf;
    return r;
}
static OSStatus (*o_SetConnection)(SSLContextRef, SSLConnectionRef);
static OSStatus my_SetConnection(SSLContextRef c, SSLConnectionRef conn) {
    if (ensure_ready() != 1) return o_SetConnection(c, conn);
    OSStatus r = o_SetConnection(c, conn);
    Shadow *s = sh_create(c); s->conn = conn;
    return r;
}
static OSStatus (*o_SetPeerDomainName)(SSLContextRef, const char *, size_t);
static OSStatus my_SetPeerDomainName(SSLContextRef c, const char *name, size_t len) {
    if (ensure_ready() != 1) return o_SetPeerDomainName(c, name, len);
    OSStatus r = o_SetPeerDomainName(c, name, len);
    Shadow *s = sh_create(c);     // may be called before SSLSetIOFuncs -> create here too
    if (name && len) {
        size_t n = len < 255 ? len : 255; memcpy(s->host, name, n); s->host[n] = 0;
        // if the handshake already started without SNI, restart it WITH the hostname
        if (s->inited && s->state != -1) {
            slog(@"late SNI '%s' -> re-init handshake", s->host);
            mbedtls_ssl_free(&s->ssl); mbedtls_ssl_config_free(&s->conf);
            s->inited = 0; s->state = 0;
        }
        slog(@"SetPeerDomainName ctx=%p '%s'", c, s->host);
    }
    return r;
}

static OSStatus (*o_Handshake)(SSLContextRef);
static OSStatus my_Handshake(SSLContextRef c) {
    Shadow *s = sh_get(c);
    if (!s || !s->rf || !s->wf || !s->conn || s->clientCert) return o_Handshake(c);  // can't shim -> system
    if (s->state == -1) return o_Handshake(c);
    if (gSysFallback && host_is_failed(s->host)) { s->state = -1; return o_Handshake(c); }  // known mbedTLS-incompatible -> system stack
    if (!s->inited) {
        int mi = mbed_init(s); if (mi) { s->state = -1; slog(@"mbed_init failed (-0x%x) for %s -> system TLS", -mi, s->host); return o_Handshake(c); }
        s->state = 1;
        slog(@"mbedTLS handshake start: %s", s->host[0] ? s->host : "(no SNI)");
    }
    int ret = mbedtls_ssl_handshake(&s->ssl);
    if (ret == MBEDTLS_ERR_SSL_WANT_READ || ret == MBEDTLS_ERR_SSL_WANT_WRITE) return errSSLWouldBlock;
    if (ret == 0) { s->state = 2; slog(@"mbedTLS handshake OK: %s [%s] (%s)", s->host, mbedtls_ssl_get_version(&s->ssl), mbedtls_ssl_get_ciphersuite(&s->ssl)); return noErr; }
    char eb[128] = {0}; mbedtls_strerror(ret, eb, sizeof(eb));
    slog(@"mbedTLS handshake FAIL %s: %s (-0x%x)%s", s->host, eb, -ret, gSysFallback ? " -> system stack on retry" : "");
    // ClientHello already went out on this socket, so we can't cleanly hand THIS connection to the
    // system stack — remember the host so its next connection bypasses to iOS Secure Transport.
    if (gSysFallback) host_mark_failed(s->host);
    s->state = -1;
    return ST_ClosedAbort;
}

static OSStatus (*o_Read)(SSLContextRef, void *, size_t, size_t *);
static OSStatus my_Read(SSLContextRef c, void *data, size_t len, size_t *processed) {
    Shadow *s = sh_get(c);
    if (!s || s->state != 2) return o_Read(c, data, len, processed);
    *processed = 0;
    int n, guard = 0;
    for (;;) {
        n = mbedtls_ssl_read(&s->ssl, (unsigned char *)data, len);
        // TLS 1.3 delivers post-handshake messages (NewSessionTicket / KeyUpdate) inline;
        // mbedTLS surfaces them as these "errors" — keep reading until application data.
        if (n == MBEDTLS_ERR_SSL_RECEIVED_NEW_SESSION_TICKET) continue;
#ifdef MBEDTLS_ERR_SSL_RECEIVED_EARLY_DATA
        if (n == MBEDTLS_ERR_SSL_RECEIVED_EARLY_DATA) continue;
#endif
        // mbedTLS can read a whole record off the transport yet return WANT_READ without
        // surfacing app data (a post-handshake message only half-processed). CFNetwork is
        // event-driven on the SOCKET and won't re-enter SSLRead until the socket is readable —
        // but those bytes are already drained into mbedTLS, so the socket never wakes again =>
        // permanent hang (rampant in TLS 1.3 due to NewSessionTickets). Drain everything mbedTLS
        // can process without touching the socket before we yield WouldBlock.
        if ((n == MBEDTLS_ERR_SSL_WANT_READ || n == MBEDTLS_ERR_SSL_WANT_WRITE)
            && mbedtls_ssl_check_pending(&s->ssl) && (!gDrainGuard || ++guard < DRAIN_MAX)) continue;
        break;
    }
    if (n == MBEDTLS_ERR_SSL_WANT_READ || n == MBEDTLS_ERR_SSL_WANT_WRITE) return errSSLWouldBlock;
    if (n == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY) return ST_ClosedGraceful;
    if (n < 0) return ST_ClosedAbort;
    *processed = (size_t)n;
    return noErr;
}
static OSStatus (*o_Write)(SSLContextRef, const void *, size_t, size_t *);
static OSStatus my_Write(SSLContextRef c, const void *data, size_t len, size_t *processed) {
    Shadow *s = sh_get(c);
    if (!s || s->state != 2) return o_Write(c, data, len, processed);
    *processed = 0;
    int n = mbedtls_ssl_write(&s->ssl, (const unsigned char *)data, len);
    if (n == MBEDTLS_ERR_SSL_WANT_READ || n == MBEDTLS_ERR_SSL_WANT_WRITE) return errSSLWouldBlock;
    if (n < 0) return ST_ClosedAbort;
    *processed = (size_t)n;
    return noErr;
}
static OSStatus (*o_DisposeContext)(SSLContextRef);
static OSStatus my_DisposeContext(SSLContextRef c) { sh_free(c); return o_DisposeContext(c); }
static OSStatus (*o_Close)(SSLContextRef);
static OSStatus my_Close(SSLContextRef c) {
    Shadow *s = sh_get(c);
    if (s && s->state == 2) mbedtls_ssl_close_notify(&s->ssl);
    return o_Close(c);
}
static OSStatus (*o_GetSessionState)(SSLContextRef, SSLSessionState *);
static OSStatus my_GetSessionState(SSLContextRef c, SSLSessionState *st) {
    Shadow *s = sh_get(c);
    if (s && s->state == 2) { if (st) *st = ST_Connected; return noErr; }
    return o_GetSessionState(c, st);
}
static OSStatus (*o_GetNegProto)(SSLContextRef, SSLProtocol *);
static OSStatus my_GetNegProto(SSLContextRef c, SSLProtocol *p) {
    Shadow *s = sh_get(c);
    if (s && s->state == 2) { if (p) *p = ST_TLS12; return noErr; }
    return o_GetNegProto(c, p);
}
// SSLGetProtocolVersion — the deprecated configured-version getter; report TLS12 for shimmed conns.
static OSStatus (*o_GetProtoVer)(SSLContextRef, SSLProtocol *);
static OSStatus my_GetProtoVer(SSLContextRef c, SSLProtocol *p) {
    Shadow *s = sh_get(c);
    if (s && s->state == 2) { if (p) *p = ST_TLS12; return noErr; }
    return o_GetProtoVer(c, p);
}
// SSLGetNegotiatedCipher — the real SSLContext never handshook (mbedTLS did), so without this an
// app querying the cipher gets garbage. SSLCipherSuite IS the IANA cipher-suite number, which is
// exactly what mbedTLS reports — hand that straight back (incl. TLS 1.3 suites like 0x1303).
static OSStatus (*o_GetNegCipher)(SSLContextRef, UInt32 *);
static OSStatus my_GetNegCipher(SSLContextRef c, UInt32 *cipher) {
    Shadow *s = sh_get(c);
    if (s && s->state == 2) { if (cipher) *cipher = (UInt32)mbedtls_ssl_get_ciphersuite_id_from_ssl(&s->ssl); return noErr; }
    return o_GetNegCipher(c, cipher);
}
static OSStatus (*o_GetBuffered)(SSLContextRef, size_t *);
static OSStatus my_GetBuffered(SSLContextRef c, size_t *sz) {
    Shadow *s = sh_get(c);
    if (s && s->state == 2) {
        // Only report genuinely-decrypted application data waiting. (Earlier this also added
        // check_pending, but that counts *any* buffered record incl. TLS1.3 NewSessionTickets,
        // which would make CFNetwork SSLRead expecting data it can't get -> unsound.)
        size_t avail = mbedtls_ssl_get_bytes_avail(&s->ssl);
        if (sz) *sz = avail;
        return noErr;
    }
    return o_GetBuffered(c, sz);
}

// build a CFArray of SecCertificateRef from the chain mbedTLS actually received (+1, caller owns)
static CFArrayRef sh_cert_array(Shadow *s) {
    const mbedtls_x509_crt *crt = mbedtls_ssl_get_peer_cert(&s->ssl);
    if (!crt) return NULL;
    CFMutableArrayRef arr = CFArrayCreateMutable(NULL, 0, &kCFTypeArrayCallBacks);
    for (const mbedtls_x509_crt *p = crt; p; p = p->next) {
        CFDataRef d = CFDataCreate(NULL, p->raw.p, p->raw.len);
        SecCertificateRef sc = d ? SecCertificateCreateWithData(NULL, d) : NULL;
        if (sc) { CFArrayAppendValue(arr, sc); CFRelease(sc); }
        if (d) CFRelease(d);
    }
    return arr;
}

// peer trust: hand CFNetwork a SecTrust built from the cert mbedTLS actually saw.
// Build a SecTrust from the cert chain mbedTLS actually saw. Returns 1 and sets *trust (+1, caller
// owns) on success; 0 if the caller should fall back to the system. Shared by both the modern
// (SSLCopyPeerTrust) and legacy (SSLGetPeerSecTrust) entry points — same Copy/Get semantics.
static int sh_build_trust(Shadow *s, SecTrustRef *trust) {
    CFArrayRef arr = sh_cert_array(s);
    if (!arr) return 0;
    CFStringRef hostStr = s->host[0] ? CFStringCreateWithCString(NULL, s->host, kCFStringEncodingUTF8) : NULL;
    SecPolicyRef pol = SecPolicyCreateSSL(true, hostStr);
    if (hostStr) CFRelease(hostStr);
    SecTrustRef t = NULL;
    OSStatus r = SecTrustCreateWithCertificates(arr, pol, &t);
    if (pol) CFRelease(pol);
    CFRelease(arr);
    if (r == errSecSuccess) { trust_remember(t); *trust = t; return 1; }
    return 0;
}
static OSStatus (*o_CopyPeerTrust)(SSLContextRef, SecTrustRef *);
static OSStatus my_CopyPeerTrust(SSLContextRef c, SecTrustRef *trust) {
    Shadow *s = sh_get(c);
    if (!s || s->state != 2 || !trust) return o_CopyPeerTrust(c, trust);
    if (sh_build_trust(s, trust)) return noErr;
    return o_CopyPeerTrust(c, trust);
}
// SSLGetPeerSecTrust — the iOS-3.x-era name for SSLCopyPeerTrust (same semantics: caller releases).
static OSStatus (*o_GetPeerSecTrust)(SSLContextRef, SecTrustRef *);
static OSStatus my_GetPeerSecTrust(SSLContextRef c, SecTrustRef *trust) {
    Shadow *s = sh_get(c);
    if (!s || s->state != 2 || !trust) return o_GetPeerSecTrust(c, trust);
    if (sh_build_trust(s, trust)) return noErr;
    return o_GetPeerSecTrust(c, trust);
}

// apps that read the chain directly (not via SSLCopyPeerTrust) must get mbedTLS's real chain,
// not the un-handshaked real context's (empty) one.
static OSStatus (*o_CopyPeerCerts)(SSLContextRef, CFArrayRef *);
static OSStatus my_CopyPeerCerts(SSLContextRef c, CFArrayRef *certs) {
    Shadow *s = sh_get(c);
    if (!s || s->state != 2 || !certs) return o_CopyPeerCerts(c, certs);
    CFArrayRef arr = sh_cert_array(s);
    if (!arr) return o_CopyPeerCerts(c, certs);
    *certs = arr;   // +1, caller owns
    return noErr;
}
// SSLGetPeerCertificates — the deprecated iOS-3.x-era name. Unlike SSLCopyPeerCertificates, its
// documented contract is that the caller releases the array AND each certificate, so hand back an
// extra retain per element to balance (otherwise an old, correct caller over-releases -> crash).
static OSStatus (*o_GetPeerCerts)(SSLContextRef, CFArrayRef *);
static OSStatus my_GetPeerCerts(SSLContextRef c, CFArrayRef *certs) {
    Shadow *s = sh_get(c);
    if (!s || s->state != 2 || !certs) return o_GetPeerCerts(c, certs);
    CFArrayRef arr = sh_cert_array(s);
    if (!arr) return o_GetPeerCerts(c, certs);
    for (CFIndex i = 0, n = CFArrayGetCount(arr); i < n; i++) CFRetain(CFArrayGetValueAtIndex(arr, i));
    *certs = arr;
    return noErr;
}

// client cert / mutual TLS: we can't export the (often non-extractable) private key into
// mbedTLS, so mark the connection and let it fall back to the system TLS stack (Apple servers
// accept old TLS from their own clients — push/iCloud keep working, just not upgraded).
static OSStatus (*o_SetCertificate)(SSLContextRef, CFArrayRef);
static OSStatus my_SetCertificate(SSLContextRef c, CFArrayRef certRefs) {
    if (ensure_ready() != 1) return o_SetCertificate(c, certRefs);
    Shadow *s = sh_create(c);
    s->clientCert = 1;
    slog(@"SSLSetCertificate -> client cert, bypass to system TLS");
    return o_SetCertificate(c, certRefs);
}

// mbedTLS already verified the chain+hostname against the modern bundle; tell CFNetwork the
// trust is valid (iOS 6 SecTrust would otherwise reject modern/ECDSA chains).
static OSStatus (*o_SecTrustEvaluate)(SecTrustRef, SecTrustResultType *);
static OSStatus my_SecTrustEvaluate(SecTrustRef t, SecTrustResultType *res) {
    if (gCAok && trust_is_mine((void *)t)) { if (res) *res = kSecTrustResultUnspecified; return errSecSuccess; }
    return o_SecTrustEvaluate(t, res);
}

static void hook(const char *name, void *repl, void **orig) {
    void *sym = dlsym(RTLD_DEFAULT, name);
    if (sym) MSHookFunction(sym, repl, orig);
}

// ---- lazy activation -------------------------------------------------------
// CRITICAL: do NO Foundation in the constructor. Under the broad com.apple.UIKit filter the
// ctor runs before Foundation / the main bundle are initialized, so touching [NSBundle
// mainBundle] etc. throws and crashes EVERY app. The ctor only installs the (pure-C) hooks;
// the per-app gate + heavy init run lazily on the first hook call, by which point the app is
// up and Foundation is safe. Disabled apps just pass through to the system stack.
static int g_state = 0;                          // 0 unchecked, 1 active, -1 disabled
static pthread_once_t g_once = PTHREAD_ONCE_INIT;

// AppList/PreferenceLoader write "enabled-<bundleid>" into com.tlsfix.plist. Default: Safari and the
// shared WebKit web-content/networking processes are on until a value is explicitly set. On iOS 8+
// Safari/WKWebView do their TLS in com.apple.WebKit.Networking (not com.apple.mobilesafari), so it
// must be on by default or web pages won't load there.
static int tlsfix_default_on(NSString *bid) {
    return [bid isEqualToString:@"com.apple.mobilesafari"]
        || [bid isEqualToString:@"com.apple.WebKit.Networking"]
        || [bid isEqualToString:@"com.apple.WebKit.WebContent"];
}
static int tlsfix_enabled_for_self(void) {
    NSString *bid = [[NSBundle mainBundle] bundleIdentifier];
    if (!bid) return 0;
    NSDictionary *prefs = [NSDictionary dictionaryWithContentsOfFile:@"/var/mobile/Library/Preferences/com.tlsfix.plist"];
    id v = [prefs objectForKey:[@"enabled-" stringByAppendingString:bid]];
    if (v == nil) return tlsfix_default_on(bid);
    return [v boolValue];
}
static void do_ready(void) {
    // NSAutoreleasePool, not @autoreleasepool: the latter compiles to objc_autoreleasePoolPush/Pop,
    // which exist only in the modern ObjC runtime (iOS 5+). NSAutoreleasePool works back to iOS 2.
    NSAutoreleasePool *pool = [[NSAutoreleasePool alloc] init];
    if (!tlsfix_enabled_for_self()) { g_state = -1; [pool release]; return; }
    // global toggles (default ON unless explicitly set false)
    NSDictionary *gp = [NSDictionary dictionaryWithContentsOfFile:@"/var/mobile/Library/Preferences/com.tlsfix.plist"];
    id t13 = [gp objectForKey:@"tls13"];          gAllowTLS13  = (t13 == nil) ? 1 : [t13 boolValue];
    id dg  = [gp objectForKey:@"drainGuard"];     gDrainGuard  = (dg  == nil) ? 1 : [dg  boolValue];
    id sf  = [gp objectForKey:@"systemFallback"]; gSysFallback = (sf  == nil) ? 1 : [sf  boolValue];
    id db  = [gp objectForKey:@"debug"];          gDebug       = (db  == nil) ? 0 : [db  boolValue];
    mbedtls_ctr_drbg_init(&gDrbg);
    mbedtls_entropy_init(&gEntropy);
    if (mbedtls_ctr_drbg_seed(&gDrbg, mbedtls_entropy_func, &gEntropy, (const unsigned char *)"tlsfix", 6) == 0)
        gDrbgReady = 1;
    psa_crypto_init();                              // TLS 1.3 path
    mbedtls_x509_crt_init(&gCA);
    gCAok = (mbedtls_x509_crt_parse_file(&gCA, CA_PATH) == 0);
    gTrustSet = CFSetCreateMutable(NULL, 0, &kCFTypeSetCallBacks);
    g_state = 1;
    slog(@"active for %@ (drbg=%d CA=%d tls13=%d drainGuard=%d sysFallback=%d)", [[NSBundle mainBundle] bundleIdentifier], gDrbgReady, gCAok, gAllowTLS13, gDrainGuard, gSysFallback);
    [pool release];
}
static int ensure_ready(void) { pthread_once(&g_once, do_ready); return g_state; }

__attribute__((constructor))
static void tlsfix_init(void) {
    // HARD SAFETY: never run inside SpringBoard/backboardd — a crash there boot-loops the
    // device. Pure-C check (getprogname), so it's safe even at this early ctor stage. This
    // holds even once the filter is broadened to com.apple.UIKit.
    const char *pn = getprogname();
    if (pn && (!strcmp(pn, "SpringBoard") || !strcmp(pn, "backboardd") ||
               !strcmp(pn, "assertiond")  || !strcmp(pn, "lockdownd"))) return;
    // pure C only beyond here — no Foundation (see note above).
    void *ms = dlopen("/usr/lib/libsubstrate.dylib", RTLD_LAZY);
    if (!ms) ms = dlopen("/Library/MobileSubstrate/MobileSubstrate.dylib", RTLD_LAZY);
    if (ms) MSHookFunction = dlsym(ms, "MSHookFunction");
    if (!MSHookFunction) return;
    {
        hook("SSLSetIOFuncs",                  (void *)my_SetIOFuncs,       (void **)&o_SetIOFuncs);
        hook("SSLSetConnection",               (void *)my_SetConnection,    (void **)&o_SetConnection);
        hook("SSLSetPeerDomainName",           (void *)my_SetPeerDomainName,(void **)&o_SetPeerDomainName);
        hook("SSLHandshake",                   (void *)my_Handshake,        (void **)&o_Handshake);
        hook("SSLRead",                        (void *)my_Read,             (void **)&o_Read);
        hook("SSLWrite",                       (void *)my_Write,            (void **)&o_Write);
        hook("SSLClose",                       (void *)my_Close,            (void **)&o_Close);
        hook("SSLDisposeContext",              (void *)my_DisposeContext,   (void **)&o_DisposeContext);
        hook("SSLGetSessionState",             (void *)my_GetSessionState,  (void **)&o_GetSessionState);
        hook("SSLGetNegotiatedProtocolVersion",(void *)my_GetNegProto,      (void **)&o_GetNegProto);
        hook("SSLGetBufferedReadSize",         (void *)my_GetBuffered,      (void **)&o_GetBuffered);
        hook("SSLCopyPeerTrust",               (void *)my_CopyPeerTrust,    (void **)&o_CopyPeerTrust);
        hook("SSLCopyPeerCertificates",        (void *)my_CopyPeerCerts,    (void **)&o_CopyPeerCerts);
        hook("SSLSetCertificate",              (void *)my_SetCertificate,   (void **)&o_SetCertificate);
        hook("SecTrustEvaluate",               (void *)my_SecTrustEvaluate, (void **)&o_SecTrustEvaluate);
        // deprecated iOS-3.x-era / query variants (skipped automatically where the symbol is absent)
        hook("SSLGetPeerSecTrust",             (void *)my_GetPeerSecTrust,  (void **)&o_GetPeerSecTrust);
        hook("SSLGetPeerCertificates",         (void *)my_GetPeerCerts,     (void **)&o_GetPeerCerts);
        hook("SSLGetProtocolVersion",          (void *)my_GetProtoVer,      (void **)&o_GetProtoVer);
        hook("SSLGetNegotiatedCipher",         (void *)my_GetNegCipher,     (void **)&o_GetNegCipher);
    }
}
