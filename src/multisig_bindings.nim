import std/os

const projectDir = currentSourcePath().parentDir().parentDir()

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

type
  KeyPair* = object
  PublicKey* = object
  SecretKey* = object
  Signature* = object
  AggregateProof* = object

proc xmss_setup_prover*() {.importc.}
proc xmss_setup_verifier*() {.importc.}

proc xmss_message_length*(): csize_t {.importc.}

proc xmss_keypair_generate*(
  seedPhrase: cstring,
  firstSlot: uint64,
  logLifetime: csize_t
): ptr KeyPair {.importc.}

proc xmss_keypair_free*(kp: ptr KeyPair) {.importc.}

proc xmss_keypair_get_public_key*(kp: ptr KeyPair): ptr PublicKey {.importc.}
proc xmss_keypair_get_secret_key*(kp: ptr KeyPair): ptr SecretKey {.importc.}

proc xmss_sign*(
  sk: ptr SecretKey,
  message: ptr UncheckedArray[byte],
  slot: uint64
): ptr Signature {.importc.}

proc xmss_signature_free*(sig: ptr Signature) {.importc.}

proc xmss_verify*(
  pk: ptr PublicKey,
  message: ptr UncheckedArray[byte],
  slot: uint64,
  sig: ptr Signature
): bool {.importc.}

proc xmss_aggregate*(
  publicKeys: ptr ptr PublicKey,
  numKeys: csize_t,
  signatures: ptr ptr Signature,
  numSigs: csize_t,
  message: ptr UncheckedArray[byte],
  slot: uint64
): ptr AggregateProof {.importc.}

proc xmss_verify_aggregated*(
  publicKeys: ptr ptr PublicKey,
  numKeys: csize_t,
  message: ptr UncheckedArray[byte],
  proof: ptr AggregateProof,
  slot: uint64
): bool {.importc.}

proc xmss_aggregate_proof_len*(proof: ptr AggregateProof): csize_t {.importc.}

proc xmss_aggregate_proof_copy_bytes*(
  proof: ptr AggregateProof,
  buffer: ptr UncheckedArray[byte],
  bufferLen: csize_t
): csize_t {.importc.}

proc xmss_aggregate_proof_from_bytes*(
  bytes: ptr UncheckedArray[byte],
  len: csize_t
): ptr AggregateProof {.importc.}

proc xmss_aggregate_proof_free*(proof: ptr AggregateProof) {.importc.}
