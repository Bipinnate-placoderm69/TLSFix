// TLSFix Settings pane. The controller class is built at RUNTIME (objc_allocateClassPair) instead
// of as a static @interface ...: PSListController. A static ObjC subclass emits a reference to
// _OBJC_METACLASS_$_NSObject, which before iOS 6 does NOT live in libobjc and can't be resolved when
// Settings dlopen()s the bundle -> the bundle fails to load on iOS 5 and *crashes* Settings on iOS
// 3.2.2. Building the class at runtime references only objc_* runtime functions (present and
// resolvable on every iOS via dynamic_lookup), so the same pane loads and renders the switches on
// iOS 3 through 10. The switches read/write /var/mobile/Library/Preferences/com.tlsfix.plist (the
// file Tweak.m reads at launch); per-app selection is the separate AppList "TLSFix Apps" entry.
#import <objc/runtime.h>
#import <objc/message.h>
#import <Foundation/Foundation.h>

// A runtime-created class isn't associated with the .bundle it lives in, so PSListController's
// -bundle (used by loadSpecifiersFromPlistName: to find TLSFix.plist) would point at the wrong
// bundle and the pane renders empty. Return our bundle explicitly.
static id TLSFix_bundle(id self, SEL _cmd) {
    return ((id (*)(id, SEL, id))objc_msgSend)(
        objc_getClass("NSBundle"), sel_registerName("bundleWithPath:"),
        @"/Library/PreferenceBundles/TLSFix.bundle");
}

static int TLSFix_osMajor(void) {
    Class UIDevice = objc_getClass("UIDevice");
    if (!UIDevice) return 0;
    id dev = ((id (*)(id, SEL))objc_msgSend)(UIDevice, sel_registerName("currentDevice"));
    id ver = dev ? ((id (*)(id, SEL))objc_msgSend)(dev, sel_registerName("systemVersion")) : nil;
    if (!ver) return 0;
    return ((int (*)(id, SEL))objc_msgSend)(ver, sel_registerName("intValue"));
}

// -specifiers: load the switch list for this OS. iOS 3.x: TLSFixLegacy (AppList picker is removed
// there, so an inline plist-editing guide replaces it). iOS 8+: TLSFix8 (adds the WebKit Networking /
// Content toggles, since web TLS runs in those shared processes). iOS 4-7: the normal TLSFix.
static id TLSFix_specifiers(id self, SEL _cmd) {
    Ivar iv = class_getInstanceVariable(objc_getClass("PSListController"), "_specifiers");
    id specs = iv ? object_getIvar(self, iv) : nil;
    if (!specs) {
        int maj = TLSFix_osMajor();
        id name = (maj > 0 && maj <= 3) ? @"TLSFixLegacy" : (maj >= 8 ? @"TLSFix8" : @"TLSFix");
        specs = ((id (*)(id, SEL, id, id))objc_msgSend)(
            self, sel_registerName("loadSpecifiersFromPlistName:target:"), name, self);
        if (iv && specs) object_setIvar(self, iv, [specs retain]);
    }
    return specs;
}

static id TLSFix_navigationTitle(id self, SEL _cmd) { return @"TLSFix"; }

// Set the nav-bar title explicitly: -navigationTitle alone isn't honored on some iOS versions
// (e.g. iOS 6 shows a blank title), and iOS 6 also clears it when the app returns from the
// background, so we re-assert it in viewWillAppear and on foreground/active notifications.
static void TLSFix_applyTitle(id self) {
    ((void (*)(id, SEL, id))objc_msgSend)(self, sel_registerName("setTitle:"), @"TLSFix");
    id navItem = ((id (*)(id, SEL))objc_msgSend)(self, sel_registerName("navigationItem"));
    if (navItem) ((void (*)(id, SEL, id))objc_msgSend)(navItem, sel_registerName("setTitle:"), @"TLSFix");
}
static Class TLSFix_super(void) { return class_getSuperclass(objc_getClass("TLSFixListController")); }

static void TLSFix_viewWillAppear(id self, SEL _cmd, BOOL animated) {
    struct objc_super sup = { self, TLSFix_super() };
    ((void (*)(struct objc_super *, SEL, BOOL))objc_msgSendSuper)(&sup, _cmd, animated);
    TLSFix_applyTitle(self);
}
// notification handler (takes the NSNotification arg)
static void TLSFix_reassert(id self, SEL _cmd, id note) { (void)note; TLSFix_applyTitle(self); }

static void TLSFix_viewDidLoad(id self, SEL _cmd) {
    struct objc_super sup = { self, TLSFix_super() };
    ((void (*)(struct objc_super *, SEL))objc_msgSendSuper)(&sup, _cmd);
    id nc = ((id (*)(id, SEL))objc_msgSend)(objc_getClass("NSNotificationCenter"), sel_registerName("defaultCenter"));
    SEL add = sel_registerName("addObserver:selector:name:object:");
    SEL re = sel_registerName("tlsfix_reassert:");
    // Use the string values of the notification names directly (== the constant's value) so we don't
    // hard-reference UIApplication*Notification symbols, which don't all exist on iOS 3.x.
    ((void (*)(id, SEL, id, SEL, id, id))objc_msgSend)(nc, add, self, re, @"UIApplicationWillEnterForegroundNotification", (id)0);
    ((void (*)(id, SEL, id, SEL, id, id))objc_msgSend)(nc, add, self, re, @"UIApplicationDidBecomeActiveNotification", (id)0);
}
// Remove the observer before dealloc; pre-iOS-9 NSNotificationCenter does not auto-zero observers,
// so a notification firing after dealloc would crash.
static void TLSFix_dealloc(id self, SEL _cmd) {
    id nc = ((id (*)(id, SEL))objc_msgSend)(objc_getClass("NSNotificationCenter"), sel_registerName("defaultCenter"));
    ((void (*)(id, SEL, id))objc_msgSend)(nc, sel_registerName("removeObserver:"), self);
    struct objc_super sup = { self, TLSFix_super() };
    ((void (*)(struct objc_super *, SEL))objc_msgSendSuper)(&sup, _cmd);
}

__attribute__((constructor))
static void TLSFix_register(void) {
    if (objc_getClass("TLSFixListController")) return;       // already registered
    Class sup = objc_getClass("PSListController");
    if (!sup) return;                                        // Preferences not loaded (not in Settings)
    Class c = objc_allocateClassPair(sup, "TLSFixListController", 0);
    if (!c) return;
    class_addMethod(c, sel_registerName("bundle"), (IMP)TLSFix_bundle, "@@:");
    class_addMethod(c, sel_registerName("specifiers"), (IMP)TLSFix_specifiers, "@@:");
    class_addMethod(c, sel_registerName("navigationTitle"), (IMP)TLSFix_navigationTitle, "@@:");
    class_addMethod(c, sel_registerName("viewWillAppear:"), (IMP)TLSFix_viewWillAppear, "v@:c");
    class_addMethod(c, sel_registerName("viewDidLoad"), (IMP)TLSFix_viewDidLoad, "v@:");
    class_addMethod(c, sel_registerName("tlsfix_reassert:"), (IMP)TLSFix_reassert, "v@:@");
    class_addMethod(c, sel_registerName("dealloc"), (IMP)TLSFix_dealloc, "v@:");
    objc_registerClassPair(c);
}
