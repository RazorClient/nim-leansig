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

# Key generation and management
proc leansig_keypair_generate*(
  seedPhrase: cstring,
  activationEpoch: uint,
  numActiveEpochs: uint
): ptr KeyPair {.importc.}

proc leansig_keypair_free*(keypair: ptr KeyPair) {.importc.}

proc leansig_keypair_get_public_key*(
  keypair: ptr KeyPair
): ptr PublicKey {.importc.}

proc leansig_keypair_get_private_key*(
  keypair: ptr KeyPair
): ptr PrivateKey {.importc.}

# Signing and verification
proc leansig_sign*(
  privateKey: ptr PrivateKey,
  message: ptr UncheckedArray[byte],
  epoch: uint32
): ptr Signature {.importc.}

proc leansig_signature_free*(signature: ptr Signature) {.importc.}

proc leansig_verify*(
  publicKey: ptr PublicKey,
  message: ptr UncheckedArray[byte],
  epoch: uint32,
  signature: ptr Signature
): int32 {.importc.}
