{
  "targets": [{
    "target_name": "wiredog_native",
    "sources": [
      "src/addon.mm"
    ],
    "include_dirs": [
      "<!@(node -p \"require('node-addon-api').include\")",
      "include"
    ],
    "libraries": [
      "-framework NetworkExtension",
      "-framework Foundation"
    ],
    "cflags!": ["-fno-exceptions"],
    "cflags_cc!": ["-fno-exceptions"],
    "xcode_settings": {
      "GCC_ENABLE_CPP_EXCEPTIONS": "YES",
      "CLANG_CXX_LIBRARY": "libc++",
      "MACOSX_DEPLOYMENT_TARGET": "12.0",
      "OTHER_CFLAGS": ["-fobjc-arc"],
      "OTHER_LDFLAGS": [
        "-Xlinker", "-rpath", "-Xlinker", "@loader_path",
        "-L<(module_root_dir)/.build/arm64-apple-macosx/release",
        "-lWireDogNative"
      ]
    },
    "defines": ["NAPI_DISABLE_CPP_EXCEPTIONS"]
  }]
}
