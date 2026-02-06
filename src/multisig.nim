## High-level Nim API for leanMultisig XMSS aggregation

import std/strformat

import multisig_bindings

type
  XmssKeyPair* = object
    handle: ptr KeyPair

  XmssSignature* = object
    handle: ptr Signature

  XmssAggregateProof* = object
    handle: ptr AggregateProof

# Basic constants
proc xmssMsgLen*(): int =
  xmss_message_length().int

# Setup helpers
proc setupProver*() =
  xmss_setup_prover()

proc setupVerifier*() =
  xmss_setup_verifier()

# Key management
proc newXmssKeyPair*(
    seedPhrase: string, firstSlot: uint64 = 0, logLifetime: uint = 4
): XmssKeyPair =
  let kp = xmss_keypair_generate(cstring(seedPhrase), firstSlot, csize_t(logLifetime))
  if kp == nil:
    raise newException(ValueError, "Failed to generate XMSS keypair")
  XmssKeyPair(handle: kp)

proc free*(kp: var XmssKeyPair) =
  if kp.handle != nil:
    xmss_keypair_free(kp.handle)
    kp.handle = nil

# Signing / verification
proc sign*(kp: XmssKeyPair, message: openArray[byte], slot: uint64): XmssSignature =
  if kp.handle == nil:
    raise newException(ValueError, "Invalid XMSS keypair")
  if message.len != xmssMsgLen():
    raise newException(ValueError, &"Message must be {xmssMsgLen()} bytes")

  let sk = xmss_keypair_get_secret_key(kp.handle)
  if sk == nil:
    raise newException(ValueError, "Failed to access secret key")

  let sigPtr =
    xmss_sign(sk, cast[ptr UncheckedArray[byte]](unsafeAddr message[0]), slot)
  if sigPtr == nil:
    raise newException(ValueError, "Signing failed")

  XmssSignature(handle: sigPtr)

proc verify*(
    sig: XmssSignature, message: openArray[byte], kp: XmssKeyPair, slot: uint64
): bool =
  if sig.handle == nil or kp.handle == nil:
    return false
  if message.len != xmssMsgLen():
    raise newException(ValueError, &"Message must be {xmssMsgLen()} bytes")

  let pk = xmss_keypair_get_public_key(kp.handle)
  if pk == nil:
    return false

  xmss_verify(
    pk, cast[ptr UncheckedArray[byte]](unsafeAddr message[0]), slot, sig.handle
  )

proc free*(sig: var XmssSignature) =
  if sig.handle != nil:
    xmss_signature_free(sig.handle)
    sig.handle = nil

# Aggregation
proc aggregate*(
    keypairs: openArray[XmssKeyPair],
    signatures: openArray[XmssSignature],
    message: openArray[byte],
    slot: uint64,
): XmssAggregateProof =
  if keypairs.len == 0 or signatures.len == 0:
    raise newException(ValueError, "At least one keypair and signature required")
  if keypairs.len != signatures.len:
    raise newException(ValueError, "Keypair and signature counts must match")
  if message.len != xmssMsgLen():
    raise newException(ValueError, &"Message must be {xmssMsgLen()} bytes")

  var pkPtrs = newSeq[ptr PublicKey](keypairs.len)
  var sigPtrs = newSeq[ptr Signature](signatures.len)

  for i, kp in keypairs:
    if kp.handle == nil:
      raise newException(ValueError, "Invalid keypair handle")
    pkPtrs[i] = xmss_keypair_get_public_key(kp.handle)
    if pkPtrs[i] == nil:
      raise newException(ValueError, "Failed to read public key")

  for i, sig in signatures:
    if sig.handle == nil:
      raise newException(ValueError, "Invalid signature handle")
    sigPtrs[i] = sig.handle

  let proofPtr = xmss_aggregate(
    cast[ptr ptr PublicKey](unsafeAddr pkPtrs[0]),
    csize_t(pkPtrs.len),
    cast[ptr ptr Signature](unsafeAddr sigPtrs[0]),
    csize_t(sigPtrs.len),
    cast[ptr UncheckedArray[byte]](unsafeAddr message[0]),
    slot,
  )

  if proofPtr == nil:
    raise newException(ValueError, "Aggregation failed")

  XmssAggregateProof(handle: proofPtr)

proc verifyAggregated*(
    proof: XmssAggregateProof,
    keypairs: openArray[XmssKeyPair],
    message: openArray[byte],
    slot: uint64,
): bool =
  if proof.handle == nil:
    return false
  if keypairs.len == 0:
    return false
  if message.len != xmssMsgLen():
    raise newException(ValueError, &"Message must be {xmssMsgLen()} bytes")

  var pkPtrs = newSeq[ptr PublicKey](keypairs.len)
  for i, kp in keypairs:
    if kp.handle == nil:
      return false
    pkPtrs[i] = xmss_keypair_get_public_key(kp.handle)
    if pkPtrs[i] == nil:
      return false

  xmss_verify_aggregated(
    cast[ptr ptr PublicKey](unsafeAddr pkPtrs[0]),
    csize_t(pkPtrs.len),
    cast[ptr UncheckedArray[byte]](unsafeAddr message[0]),
    proof.handle,
    slot,
  )

proc toBytes*(proof: XmssAggregateProof): seq[byte] =
  if proof.handle == nil:
    return @[]
  let lenC = xmss_aggregate_proof_len(proof.handle)
  if lenC == 0:
    return @[]
  let len = int(lenC)
  result = newSeq[byte](len)
  let written = xmss_aggregate_proof_copy_bytes(
    proof.handle, cast[ptr UncheckedArray[byte]](unsafeAddr result[0]), lenC
  )
  if int(written) != len:
    result.setLen(0)

proc fromBytes*(bytes: openArray[byte]): XmssAggregateProof =
  if bytes.len == 0:
    raise newException(ValueError, "Empty proof bytes")
  let ptrProof = xmss_aggregate_proof_from_bytes(
    cast[ptr UncheckedArray[byte]](unsafeAddr bytes[0]), csize_t(bytes.len)
  )
  if ptrProof == nil:
    raise newException(ValueError, "Failed to reconstruct proof")
  XmssAggregateProof(handle: ptrProof)

proc free*(proof: var XmssAggregateProof) =
  if proof.handle != nil:
    xmss_aggregate_proof_free(proof.handle)
    proof.handle = nil
