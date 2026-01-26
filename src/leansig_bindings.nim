import std/os

const projectDir = currentSourcePath().parentDir().parentDir()

# Default to static linking for portability
# Use --dynlibOverride to force dynamic linking
when defined(dynlibOverride):
  # Dynamic linking (via --dynlibOverride or -d:dynlibOverride)
  when defined(windows):
    const libLeanSig* = projectDir / "lib" / "leansig_ffi.dll"
  elif defined(macosx):
    const libLeanSig* = projectDir / "lib" / "libleansig_ffi.dylib"
  else:
    const libLeanSig* = projectDir / "lib" / "libleansig_ffi.so"

  proc leansig_lifetime*(): uint64 {.importc, dynlib: libLeanSig.}
else:
  # Static linking (default)
  when defined(windows):
    {.passL: projectDir / "lib" / "leansig_ffi.lib".}
  elif defined(macosx):
    {.passL: projectDir / "lib" / "libleansig_ffi.a".}
    {.passL: "-framework Security".}
    {.passL: "-framework SystemConfiguration".}
  else:
    {.passL: projectDir / "lib" / "libleansig_ffi.a".}
    {.passL: "-lpthread".}
    {.passL: "-ldl".}
    {.passL: "-lm".}

  proc leansig_lifetime*(): uint64 {.importc.}
