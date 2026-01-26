when defined(windows):
  const libLeanSig* = "leansig_ffi.dll"
elif defined(macosx):
  const libLeanSig* = "libleansig_ffi.dylib"
else:
  const libLeanSig* = "libleansig_ffi.so"

type LeanSigHandle* = pointer

proc leansig_new*(): LeanSigHandle
  {.importc, dynlib: libLeanSig.}

proc leansig_free*(h: LeanSigHandle)
  {.importc, dynlib: libLeanSig.}

proc leansig_public_key_len*(h: LeanSigHandle): csize_t
  {.importc, dynlib: libLeanSig.}

proc leansig_secret_key_len*(h: LeanSigHandle): csize_t
  {.importc, dynlib: libLeanSig.}

proc leansig_signature_len*(h: LeanSigHandle): csize_t
  {.importc, dynlib: libLeanSig.}
