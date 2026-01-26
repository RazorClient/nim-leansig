import std/os

const projectDir = currentSourcePath().parentDir().parentDir()

when defined(useStaticLinking):
  # Static linking
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
else:
  # Dynamic linking (default)
  when defined(windows):
    const libLeanSig* = projectDir / "lib" / "leansig_ffi.dll"
  elif defined(macosx):
    const libLeanSig* = projectDir / "lib" / "libleansig_ffi.dylib"
  else:
    const libLeanSig* = projectDir / "lib" / "libleansig_ffi.so"

  proc leansig_lifetime*(): uint64 {.importc, dynlib: libLeanSig.}
