/**
 * Objective-C++ N-API wrapper for the WireDog VPN native Swift addon.
 *
 * This thin wrapper bridges Node.js N-API calls to the Swift TunnelManager
 * and StatusObserver classes. The standard pattern for Electron + Swift:
 * write core logic in Swift, wrap with Obj-C++ for N-API compatibility.
 *
 * Exposed JavaScript API:
 *   native.loadManager()                  -> Promise<void>
 *   native.startTunnel(config)            -> Promise<void>
 *   native.stopTunnel()                   -> void
 *   native.getStatus()                    -> string
 *   native.getStats()                     -> Promise<{bytesIn, bytesOut}>
 *   native.onStatusChange(callback)       -> void
 */

#import <Foundation/Foundation.h>
#import <NetworkExtension/NetworkExtension.h>
#import <napi.h>
#include <memory>

// Import the Swift-generated Objective-C header (produced by `swift build`)
#import "WireDogNative-Swift.h"

// Global references
static TunnelManager *gTunnelManager = nil;
static FilterExtensionManager *gFilterManager = nil;
static Napi::ThreadSafeFunction gStatusCallback;

#pragma mark - Helper: Run async Swift operation and resolve/reject JS Promise

/**
 * loadManager() — Load or create the NETunnelProviderManager configuration.
 * Returns a Promise that resolves when the manager is ready.
 */
Napi::Value LoadManager(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();
    auto deferred = Napi::Promise::Deferred::New(env);

    if (!gTunnelManager) {
        gTunnelManager = [[TunnelManager alloc] init];
    }

    // Use a thread-safe function to resolve/reject the promise from the Swift callback thread
    auto tsfn = Napi::ThreadSafeFunction::New(
        env,
        Napi::Function::New(env, [](const Napi::CallbackInfo&) {}),
        "loadManagerCallback",
        0,
        1
    );

    // Capture deferred by shared_ptr so it stays alive across the async callback
    auto sharedDeferred = std::make_shared<Napi::Promise::Deferred>(std::move(deferred));

    [gTunnelManager loadManagerWithCompletionHandler:^(NSError * _Nullable error) {
        NSString *errorMsg = error ? [error localizedDescription] : nil;
        tsfn.BlockingCall([sharedDeferred, errorMsg](Napi::Env env, Napi::Function) {
            if (errorMsg) {
                sharedDeferred->Reject(Napi::Error::New(env, [errorMsg UTF8String]).Value());
            } else {
                sharedDeferred->Resolve(env.Undefined());
            }
        });
        tsfn.Release();
    }];

    return sharedDeferred->Promise();
}

/**
 * startTunnel(config) — Start the VPN tunnel with the given WireGuard config.
 * config is a JS object with: privateKey, address, dns, serverPublicKey,
 * endpoint, allowedIPs, persistentKeepalive, includeAllNetworks, excludeLocalNetworks
 */
Napi::Value StartTunnel(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();
    auto deferred = Napi::Promise::Deferred::New(env);

    if (info.Length() < 1 || !info[0].IsObject()) {
        deferred.Reject(Napi::Error::New(env, "Expected config object").Value());
        return deferred.Promise();
    }

    // Convert JS object to NSDictionary
    Napi::Object jsConfig = info[0].As<Napi::Object>();
    NSMutableDictionary *config = [NSMutableDictionary dictionary];

    auto names = jsConfig.GetPropertyNames();
    for (uint32_t i = 0; i < names.Length(); i++) {
        std::string key = names.Get(i).As<Napi::String>().Utf8Value();
        Napi::Value val = jsConfig.Get(key);
        NSString *nsKey = [NSString stringWithUTF8String:key.c_str()];

        if (val.IsString()) {
            config[nsKey] = [NSString stringWithUTF8String:val.As<Napi::String>().Utf8Value().c_str()];
        } else if (val.IsNumber()) {
            config[nsKey] = @(val.As<Napi::Number>().Int32Value());
        } else if (val.IsBoolean()) {
            config[nsKey] = @(val.As<Napi::Boolean>().Value());
        }
    }

    @try {
        NSError *error = nil;
        [gTunnelManager startTunnelWithConfig:config error:&error];
        if (error) {
            deferred.Reject(Napi::Error::New(env, [[error localizedDescription] UTF8String]).Value());
        } else {
            deferred.Resolve(env.Undefined());
        }
    } @catch (NSException *exception) {
        deferred.Reject(Napi::Error::New(env, [[exception reason] UTF8String]).Value());
    }

    return deferred.Promise();
}

/**
 * stopTunnel() — Stop the VPN tunnel. Synchronous.
 */
void StopTunnel(const Napi::CallbackInfo& info) {
    if (gTunnelManager) {
        [gTunnelManager stopTunnel];
    }
}

/**
 * getStatus() — Get current tunnel status string.
 * Returns: 'disconnected' | 'connecting' | 'connected' | 'disconnecting' | 'reasserting' | 'invalid'
 */
Napi::Value GetStatus(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();

    if (!gTunnelManager) {
        return Napi::String::New(env, "disconnected");
    }

    NSString *status = [gTunnelManager status];
    return Napi::String::New(env, [status UTF8String]);
}

/**
 * getStats() — Get traffic statistics from the Network Extension.
 * Returns: Promise<{bytesIn: number, bytesOut: number}>
 */
Napi::Value GetStats(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();
    auto deferred = Napi::Promise::Deferred::New(env);

    if (!gTunnelManager) {
        auto result = Napi::Object::New(env);
        result.Set("bytesIn", Napi::Number::New(env, 0));
        result.Set("bytesOut", Napi::Number::New(env, 0));
        deferred.Resolve(result);
        return deferred.Promise();
    }

    auto tsfn = Napi::ThreadSafeFunction::New(
        env,
        Napi::Function::New(env, [](const Napi::CallbackInfo&) {}),
        "getStatsCallback",
        0,
        1
    );
    auto sharedDeferred = std::make_shared<Napi::Promise::Deferred>(std::move(deferred));

    [gTunnelManager getStatsWithCompletion:^(NSError * _Nullable error, NSNumber * _Nullable bytesIn, NSNumber * _Nullable bytesOut) {
        NSString *errorMsg = error ? [error localizedDescription] : nil;
        uint64_t inBytes  = bytesIn  ? [bytesIn  unsignedLongLongValue] : 0;
        uint64_t outBytes = bytesOut ? [bytesOut unsignedLongLongValue] : 0;
        tsfn.BlockingCall([sharedDeferred, errorMsg, inBytes, outBytes](Napi::Env env, Napi::Function) {
            if (errorMsg) {
                sharedDeferred->Reject(Napi::Error::New(env, [errorMsg UTF8String]).Value());
            } else {
                auto result = Napi::Object::New(env);
                result.Set("bytesIn",  Napi::Number::New(env, (double)inBytes));
                result.Set("bytesOut", Napi::Number::New(env, (double)outBytes));
                sharedDeferred->Resolve(result);
            }
        });
        tsfn.Release();
    }];

    return sharedDeferred->Promise();
}

/**
 * onStatusChange(callback) — Register a callback for tunnel status changes.
 * The callback receives a single string argument (the new status).
 */
void OnStatusChange(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();

    if (info.Length() < 1 || !info[0].IsFunction()) {
        Napi::TypeError::New(env, "Expected callback function").ThrowAsJavaScriptException();
        return;
    }

    // Create a thread-safe function that can be called from any thread (Swift/ObjC)
    gStatusCallback = Napi::ThreadSafeFunction::New(
        env,
        info[0].As<Napi::Function>(),
        "vpnStatusCallback",
        0,  // unlimited queue
        1   // initial thread count
    );

    // Set up the Swift callback
    if (gTunnelManager) {
        [gTunnelManager setOnStatusChange:^(NSString *status) {
            gStatusCallback.BlockingCall([status](Napi::Env env, Napi::Function jsCallback) {
                jsCallback.Call({ Napi::String::New(env, [status UTF8String]) });
            });
        }];
    }
}

// ============================================================================
// Filter Extension Manager (NEAppProxyProviderManager)
// Requires app-proxy-provider entitlement on the Electron app (.app bundle).
// Cannot be called from the helper daemon — AMFI rejects app-proxy-provider
// on standalone daemon binaries.
// ============================================================================

/**
 * loadFilterManager() — Load or create the NEAppProxyProviderManager for WireDogFilter.
 * Must be called before startFilter(). Returns a Promise.
 */
Napi::Value LoadFilterManager(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();
    auto deferred = Napi::Promise::Deferred::New(env);

    if (!gFilterManager) {
        gFilterManager = [[FilterExtensionManager alloc] init];
    }

    auto tsfn = Napi::ThreadSafeFunction::New(
        env,
        Napi::Function::New(env, [](const Napi::CallbackInfo&) {}),
        "loadFilterManagerCallback", 0, 1
    );
    auto sharedDeferred = std::make_shared<Napi::Promise::Deferred>(std::move(deferred));

    [gFilterManager loadManagerWithCompletion:^(NSError * _Nullable error) {
        NSString *errorMsg = error ? [error localizedDescription] : nil;
        tsfn.BlockingCall([sharedDeferred, errorMsg](Napi::Env env, Napi::Function) {
            if (errorMsg) {
                sharedDeferred->Reject(Napi::Error::New(env, [errorMsg UTF8String]).Value());
            } else {
                sharedDeferred->Resolve(env.Undefined());
            }
        });
        tsfn.Release();
    }];

    return sharedDeferred->Promise();
}

/**
 * startFilter(mode, apps) — Start the WireDogFilter transparent proxy extension.
 * mode: 'exclude' | 'include'
 * apps: string[] of CFBundleIdentifier values
 * Returns a Promise.
 */
Napi::Value StartFilter(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();
    auto deferred = Napi::Promise::Deferred::New(env);

    if (!gFilterManager) {
        deferred.Reject(Napi::Error::New(env, "Filter manager not loaded — call loadFilterManager first").Value());
        return deferred.Promise();
    }

    if (info.Length() < 2 || !info[0].IsString() || !info[1].IsArray()) {
        deferred.Reject(Napi::Error::New(env, "startFilter(mode: string, apps: string[])").Value());
        return deferred.Promise();
    }

    std::string mode = info[0].As<Napi::String>().Utf8Value();
    Napi::Array jsApps = info[1].As<Napi::Array>();
    NSMutableArray *apps = [NSMutableArray arrayWithCapacity:jsApps.Length()];
    for (uint32_t i = 0; i < jsApps.Length(); i++) {
        std::string bundleId = jsApps.Get(i).As<Napi::String>().Utf8Value();
        [apps addObject:[NSString stringWithUTF8String:bundleId.c_str()]];
    }

    auto tsfn = Napi::ThreadSafeFunction::New(
        env,
        Napi::Function::New(env, [](const Napi::CallbackInfo&) {}),
        "startFilterCallback", 0, 1
    );
    auto sharedDeferred = std::make_shared<Napi::Promise::Deferred>(std::move(deferred));

    [gFilterManager startFilterWithMode:[NSString stringWithUTF8String:mode.c_str()]
                                   apps:apps
                              completion:^(NSError * _Nullable error) {
        NSString *errorMsg = error ? [error localizedDescription] : nil;
        tsfn.BlockingCall([sharedDeferred, errorMsg](Napi::Env env, Napi::Function) {
            if (errorMsg) {
                sharedDeferred->Reject(Napi::Error::New(env, [errorMsg UTF8String]).Value());
            } else {
                sharedDeferred->Resolve(env.Undefined());
            }
        });
        tsfn.Release();
    }];

    return sharedDeferred->Promise();
}

/**
 * stopFilter() — Stop the WireDogFilter transparent proxy extension. Synchronous.
 */
void StopFilter(const Napi::CallbackInfo& info) {
    if (gFilterManager) {
        [gFilterManager stopFilter];
    }
}

/**
 * Module initialization — register all exported functions
 */
Napi::Object Init(Napi::Env env, Napi::Object exports) {
    exports.Set("loadManager", Napi::Function::New(env, LoadManager));
    exports.Set("startTunnel", Napi::Function::New(env, StartTunnel));
    exports.Set("stopTunnel", Napi::Function::New(env, StopTunnel));
    exports.Set("getStatus", Napi::Function::New(env, GetStatus));
    exports.Set("getStats", Napi::Function::New(env, GetStats));
    exports.Set("onStatusChange", Napi::Function::New(env, OnStatusChange));
    exports.Set("loadFilterManager", Napi::Function::New(env, LoadFilterManager));
    exports.Set("startFilter", Napi::Function::New(env, StartFilter));
    exports.Set("stopFilter", Napi::Function::New(env, StopFilter));
    return exports;
}

NODE_API_MODULE(wiredog_native, Init)
