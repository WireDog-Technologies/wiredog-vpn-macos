{
  "targets": [{
    "target_name": "wiredog_sysext",
    "sources": ["src/sysext_activate.mm"],
    "include_dirs": [
      "<!@(node -p \"require('node-addon-api').include\")"
    ],
    "libraries": [
      "-framework SystemExtensions",
      "-framework Foundation"
    ],
    "cflags!": ["-fno-exceptions"],
    "cflags_cc!": ["-fno-exceptions"],
    "xcode_settings": {
      "GCC_ENABLE_CPP_EXCEPTIONS": "YES",
      "CLANG_CXX_LIBRARY": "libc++",
      "CLANG_ENABLE_OBJC_ARC": "YES",
      "MACOSX_DEPLOYMENT_TARGET": "12.0"
    },
    "defines": ["NAPI_DISABLE_CPP_EXCEPTIONS"]
  }]
}
