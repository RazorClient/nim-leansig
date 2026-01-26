import std/os

const projectDir = currentSourcePath().parentDir().parentDir()

when defined(windows):
  const libLeanSig* = projectDir / "lib" / "leansig_ffi.dll"
elif defined(macosx):
  const libLeanSig* = projectDir / "lib" / "libleansig_ffi.dylib"
else:
  const libLeanSig* = projectDir / "lib" / "libleansig_ffi.so"

proc leansig_lifetime*(): uint64
  {.importc, dynlib: libLeanSig.}
