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

# Opaque types for FFI
type
  KeyPair* = object
  PrivateKey* = object
  PublicKey* = object
  Signature* = object

# Basic constants
proc leansig_lifetime*(): uint64 {.importc.}
proc leansig_message_length*(): uint {.importc.}

proc leansig_scheme_lifetime_v2*(schemeId: uint32): uint64 {.importc.}

proc leansig_keypair_generate_v2*(
  schemeId: uint32,
  seedPhrase: cstring,
  activationEpoch: csize_t,
  numActiveEpochs: csize_t,
): ptr KeyPair {.importc.}

proc leansig_keypair_prepare_to_epoch_v2*(
  keypair: ptr KeyPair, epoch: uint32
): int32 {.importc.}

proc leansig_sign_v2*(
  keypair: ptr KeyPair, message: ptr UncheckedArray[byte], epoch: uint32
): ptr Signature {.importc.}

proc leansig_verify_v2*(
  keypair: ptr KeyPair,
  message: ptr UncheckedArray[byte],
  epoch: uint32,
  signature: ptr Signature,
): int32 {.importc.}

proc leansig_signature_to_bytes_len_v2*(signature: ptr Signature): csize_t {.importc.}

proc leansig_signature_to_bytes_copy_v2*(
  signature: ptr Signature, outBuf: ptr UncheckedArray[byte], outLen: csize_t
): csize_t {.importc.}

proc leansig_signature_from_bytes_v2*(
  schemeId: uint32, bytesPtr: ptr UncheckedArray[byte], bytesLen: csize_t
): ptr Signature {.importc.}

proc leansig_last_error_len*(): csize_t {.importc.}
proc leansig_last_error_copy*(
  outBuf: ptr UncheckedArray[byte], outLen: csize_t
): csize_t {.importc.}

proc leansig_keypair_generate*(
  seedPhrase: cstring, activationEpoch: uint, numActiveEpochs: uint
): ptr KeyPair {.importc.}

proc leansig_keypair_free*(keypair: ptr KeyPair) {.importc.}

proc leansig_keypair_get_public_key*(keypair: ptr KeyPair): ptr PublicKey {.importc.}

proc leansig_keypair_get_private_key*(keypair: ptr KeyPair): ptr PrivateKey {.importc.}

proc leansig_sign*(
  privateKey: ptr PrivateKey, message: ptr UncheckedArray[byte], epoch: uint32
): ptr Signature {.importc.}

proc leansig_signature_free*(signature: ptr Signature) {.importc.}

proc leansig_verify*(
  publicKey: ptr PublicKey,
  message: ptr UncheckedArray[byte],
  epoch: uint32,
  signature: ptr Signature,
): int32 {.importc.}
