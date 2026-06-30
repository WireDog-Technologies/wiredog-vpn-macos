/**
 * WireDog VPN — System Extension Activation (N-API addon)
 *
 * Calls OSSystemExtensionManager.shared.submitRequest() from within the
 * Electron process so it inherits the app's entitlements and provisioning
 * profile. No separate binary/profile needed.
 *
 * Exports one function:
 *   activate(extensionId: string, callback: (result: string) => void): void
 *
 * The callback may fire MORE THAN ONCE per activate() call: "PENDING" is an
 * interim notice (macOS needs the user to approve in System Settings), and a
 * terminal result ("ACTIVATED" / "REBOOT_REQUIRED" / "ERROR: ...") always
 * follows afterward once the request actually completes — including after the
 * user approves following a PENDING. Callers must not treat the callback as
 * one-shot.
 *
 * callback result values:
 *   "ACTIVATED"        – extension is active (or just became active)
 *   "PENDING"          – needs user approval in System Settings → General →
 *                         Login Items & Extensions → Network Extensions
 *   "REBOOT_REQUIRED"  – will activate after reboot (rare)
 *   "ERROR: <message>" – activation failed
 */

#include <napi.h>
#import <Foundation/Foundation.h>
#import <SystemExtensions/SystemExtensions.h>
#import <objc/runtime.h>
#include <memory>
#include <string>
#include <atomic>

// ── C++ holder for the TSFN ─────────────────────────────────────────────────

struct TSFNHolder {
    Napi::ThreadSafeFunction tsfn;
    std::atomic<bool> finished{false};

    // PENDING is not a terminal state — requestNeedsUserApproval can fire, and
    // later, once the user approves in System Settings, didFinishWithResult
    // fires for real on the *same* request/delegate. Both callbacks must reach
    // JS so the app can react to the actual completion, not just the interim
    // "needs approval" notice.
    void invokeNonTerminal(const std::string& result) {
        if (finished.load()) return; // already finished, tsfn already released
        std::string r = result;
        tsfn.NonBlockingCall([r](Napi::Env env, Napi::Function cb) {
            cb.Call({Napi::String::New(env, r)});
        });
    }

    // Terminal states (ACTIVATED / REBOOT_REQUIRED / ERROR) — guard against
    // being invoked more than once, and release the tsfn since no further
    // callbacks are expected after a request truly finishes.
    void invokeTerminal(const std::string& result) {
        bool expected = false;
        if (!finished.compare_exchange_strong(expected, true)) return;

        std::string r = result;
        tsfn.NonBlockingCall([r](Napi::Env env, Napi::Function cb) {
            cb.Call({Napi::String::New(env, r)});
        });
        tsfn.Release();
    }
};

// ── ObjC delegate ────────────────────────────────────────────────────────────

@interface WDSysExtDelegate : NSObject <OSSystemExtensionRequestDelegate> {
    std::shared_ptr<TSFNHolder> _holder;
}
- (instancetype)initWithHolder:(std::shared_ptr<TSFNHolder>)holder;
@end

@implementation WDSysExtDelegate

- (instancetype)initWithHolder:(std::shared_ptr<TSFNHolder>)holder {
    if (self = [super init]) {
        _holder = holder;
    }
    return self;
}

- (void)request:(OSSystemExtensionRequest *)request
    didFinishWithResult:(OSSystemExtensionRequestResult)result {
    if (result == OSSystemExtensionRequestWillCompleteAfterReboot) {
        _holder->invokeTerminal("REBOOT_REQUIRED");
    } else {
        _holder->invokeTerminal("ACTIVATED");
    }
}

- (void)request:(OSSystemExtensionRequest *)request didFailWithError:(NSError *)error {
    // Write error details to debug log file (os_log redacts dynamic strings)
    NSString *errorInfo = [NSString stringWithFormat:
        @"\n=== WireDog SysExt Error ===\n"
        @"Timestamp: %@\n"
        @"Domain: %@\n"
        @"Code: %ld\n"
        @"Description: %@\n"
        @"UserInfo: %@\n"
        @"Underlying errors: %@\n",
        [NSDate date],
        error.domain,
        (long)error.code,
        error.localizedDescription,
        error.userInfo,
        error.underlyingErrors];
    NSString *debugPath = [NSTemporaryDirectory() stringByAppendingPathComponent:@"wiredog-sysext-debug.log"];
    NSFileHandle *fh = [NSFileHandle fileHandleForWritingAtPath:debugPath];
    [fh seekToEndOfFile];
    [fh writeData:[errorInfo dataUsingEncoding:NSUTF8StringEncoding]];
    [fh closeFile];
    NSLog(@"[WireDog SysExt] Error details appended to %s", debugPath.UTF8String);

    // Code 10 = OSSystemExtensionErrorRequestSuperseded (newer request took over) — treat as active
    // Code 4 = OSSystemExtensionErrorExtensionNotFound — real failure, do not mask
    if ([error.domain isEqualToString:OSSystemExtensionErrorDomain] && error.code == 10) {
        _holder->invokeTerminal("ACTIVATED");
    } else {
        std::string msg = "ERROR: [domain=" + std::string(error.domain.UTF8String)
            + " code=" + std::to_string((long)error.code) + "] "
            + std::string(error.localizedDescription.UTF8String);
        _holder->invokeTerminal(msg);
    }
}

- (void)requestNeedsUserApproval:(OSSystemExtensionRequest *)request {
    // macOS has surfaced the Security prompt — user must approve in System Settings.
    // Not terminal: didFinishWithResult fires for real once the user approves.
    _holder->invokeNonTerminal("PENDING");
}

- (OSSystemExtensionReplacementAction)request:(OSSystemExtensionRequest *)request
    actionForReplacingExtension:(OSSystemExtensionProperties *)existing
    withExtension:(OSSystemExtensionProperties *)replacement {
    // Always replace to handle app updates
    return OSSystemExtensionReplacementActionReplace;
}

@end

// ── N-API entry point ────────────────────────────────────────────────────────

Napi::Value Activate(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();

    if (info.Length() < 2 || !info[0].IsString() || !info[1].IsFunction()) {
        Napi::TypeError::New(env, "activate(extensionId: string, callback: (result: string) => void)")
            .ThrowAsJavaScriptException();
        return env.Undefined();
    }

    std::string extensionId = info[0].As<Napi::String>().Utf8Value();
    Napi::Function callback = info[1].As<Napi::Function>();

    auto holder = std::make_shared<TSFNHolder>();
    holder->tsfn = Napi::ThreadSafeFunction::New(env, callback, "SysExtActivate", 0, 1);

    // OSSystemExtensionManager must be invoked on the main thread
    dispatch_async(dispatch_get_main_queue(), [extensionId, holder]() {
        NSString *extId = [NSString stringWithUTF8String:extensionId.c_str()];

        // Debug: dump main bundle info to verify NSSystemExtensionUsageDescription
        NSBundle *mainBundle = [NSBundle mainBundle];
        NSString *usageDesc = [mainBundle objectForInfoDictionaryKey:@"NSSystemExtensionUsageDescription"];
        NSURL *sysextDir = [[[mainBundle.bundleURL URLByAppendingPathComponent:@"Contents"]
                             URLByAppendingPathComponent:@"Library"]
                            URLByAppendingPathComponent:@"SystemExtensions"];
        NSArray *sysextContents = [[NSFileManager defaultManager] contentsOfDirectoryAtPath:sysextDir.path error:nil];

        // Write debug info to a file since os_log redacts dynamic strings
        NSString *debugInfo = [NSString stringWithFormat:
            @"=== WireDog SysExt Debug ===\n"
            @"Timestamp: %@\n"
            @"Main bundle path: %@\n"
            @"Main bundle ID: %@\n"
            @"NSSystemExtensionUsageDescription: %@\n"
            @"Extension ID requested: %@\n"
            @"Sysext dir: %@\n"
            @"Sysext dir contents: %@\n"
            @"Info.plist keys: %@\n",
            [NSDate date],
            mainBundle.bundlePath,
            mainBundle.bundleIdentifier,
            usageDesc ?: @"(nil)",
            extId,
            sysextDir.path,
            sysextContents ?: @"(directory not found)",
            [mainBundle.infoDictionary allKeys]];
        NSString *debugPath = [NSTemporaryDirectory() stringByAppendingPathComponent:@"wiredog-sysext-debug.log"];
        [debugInfo writeToFile:debugPath atomically:YES encoding:NSUTF8StringEncoding error:nil];
        NSLog(@"[WireDog SysExt] Debug written to %s", debugPath.UTF8String);

        WDSysExtDelegate *delegate = [[WDSysExtDelegate alloc] initWithHolder:holder];

        // Use a serial background queue for delegate callbacks so we don't block main
        dispatch_queue_t cbQueue = dispatch_queue_create("com.wiredog.sysext.cb",
                                                          DISPATCH_QUEUE_SERIAL);

        OSSystemExtensionRequest *request =
            [OSSystemExtensionRequest activationRequestForExtension:extId
                                                              queue:cbQueue];
        request.delegate = delegate;

        // Retain delegate for the lifetime of the request via object association
        objc_setAssociatedObject(request, "wdDelegate", delegate, OBJC_ASSOCIATION_RETAIN);

        [[OSSystemExtensionManager sharedManager] submitRequest:request];
    });

    return env.Undefined();
}

Napi::Object Init(Napi::Env env, Napi::Object exports) {
    exports.Set("activate", Napi::Function::New(env, Activate));
    return exports;
}

NODE_API_MODULE(wiredog_sysext, Init)
