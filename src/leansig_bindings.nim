import std/os

const projectDir = currentSourcePath().parentDir().parentDir()

# Static linking only
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
