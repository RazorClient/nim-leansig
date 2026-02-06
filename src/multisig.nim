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

proc messagePtr(message: openArray[byte]): ptr UncheckedArray[byte] {.inline.} =
  if message.len == 0:
    nil
  else:
    cast[ptr UncheckedArray[byte]](unsafeAddr message[0])

proc requireXmssMessageLength(message: openArray[byte]) =
  let expectedLength = int(xmss_message_length())
  if message.len != expectedLength:
    raise newException(ValueError, &"Message must be {expectedLength} bytes")

proc xmssMsgLen*(): int =
  xmss_message_length().int

proc setupProver*() =
  xmss_setup_prover()

proc setupVerifier*() =
  xmss_setup_verifier()

proc newXmssKeyPair*(
    seedPhrase: string, firstSlot: uint64 = 0, logLifetime: uint = 4
): XmssKeyPair =
  let keyPairHandle =
    xmss_keypair_generate(cstring(seedPhrase), firstSlot, csize_t(logLifetime))
  if keyPairHandle == nil:
    raise newException(ValueError, "Failed to generate XMSS keypair")
  XmssKeyPair(handle: keyPairHandle)

proc free*(keyPair: var XmssKeyPair) =
  if keyPair.handle != nil:
    xmss_keypair_free(keyPair.handle)
    keyPair.handle = nil

# Signing / verification
proc sign*(
    keyPair: XmssKeyPair, message: openArray[byte], slot: uint64
): XmssSignature =
  if keyPair.handle == nil:
    raise newException(ValueError, "Invalid XMSS keypair")
  requireXmssMessageLength(message)

  let secretKey = xmss_keypair_get_secret_key(keyPair.handle)
  if secretKey == nil:
    raise newException(ValueError, "Failed to access secret key")

  let signatureHandle = xmss_sign(secretKey, messagePtr(message), slot)
  if signatureHandle == nil:
    raise newException(ValueError, "Signing failed")

  XmssSignature(handle: signatureHandle)

proc verify*(
    signature: XmssSignature,
    message: openArray[byte],
    keyPair: XmssKeyPair,
    slot: uint64,
): bool =
  if signature.handle == nil or keyPair.handle == nil:
    return false
  requireXmssMessageLength(message)

  let publicKey = xmss_keypair_get_public_key(keyPair.handle)
  if publicKey == nil:
    return false

  xmss_verify(publicKey, messagePtr(message), slot, signature.handle)

proc free*(signature: var XmssSignature) =
  if signature.handle != nil:
    xmss_signature_free(signature.handle)
    signature.handle = nil

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
  requireXmssMessageLength(message)

  var publicKeyHandles = newSeq[ptr PublicKey](keypairs.len)
  var signatureHandles = newSeq[ptr Signature](signatures.len)

  for index, keyPair in keypairs:
    if keyPair.handle == nil:
      raise newException(ValueError, "Invalid keypair handle")
    publicKeyHandles[index] = xmss_keypair_get_public_key(keyPair.handle)
    if publicKeyHandles[index] == nil:
      raise newException(ValueError, "Failed to read public key")

  for index, signature in signatures:
    if signature.handle == nil:
      raise newException(ValueError, "Invalid signature handle")
    signatureHandles[index] = signature.handle

  let proofHandle = xmss_aggregate(
    cast[ptr ptr PublicKey](unsafeAddr publicKeyHandles[0]),
    csize_t(publicKeyHandles.len),
    cast[ptr ptr Signature](unsafeAddr signatureHandles[0]),
    csize_t(signatureHandles.len),
    messagePtr(message),
    slot,
  )

  if proofHandle == nil:
    raise newException(ValueError, "Aggregation failed")

  XmssAggregateProof(handle: proofHandle)

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
  requireXmssMessageLength(message)

  var publicKeyHandles = newSeq[ptr PublicKey](keypairs.len)
  for index, keyPair in keypairs:
    if keyPair.handle == nil:
      return false
    publicKeyHandles[index] = xmss_keypair_get_public_key(keyPair.handle)
    if publicKeyHandles[index] == nil:
      return false

  xmss_verify_aggregated(
    cast[ptr ptr PublicKey](unsafeAddr publicKeyHandles[0]),
    csize_t(publicKeyHandles.len),
    messagePtr(message),
    proof.handle,
    slot,
  )

proc toBytes*(proof: XmssAggregateProof): seq[byte] =
  if proof.handle == nil:
    return @[]
  let encodedLengthC = xmss_aggregate_proof_len(proof.handle)
  if encodedLengthC == 0:
    return @[]
  let encodedLength = int(encodedLengthC)
  result = newSeq[byte](encodedLength)
  let written = xmss_aggregate_proof_copy_bytes(
    proof.handle, cast[ptr UncheckedArray[byte]](unsafeAddr result[0]), encodedLengthC
  )
  if int(written) != encodedLength:
    result.setLen(0)

proc fromBytes*(encodedProof: openArray[byte]): XmssAggregateProof =
  if encodedProof.len == 0:
    raise newException(ValueError, "Empty proof bytes")
  let proofHandle = xmss_aggregate_proof_from_bytes(
    cast[ptr UncheckedArray[byte]](unsafeAddr encodedProof[0]),
    csize_t(encodedProof.len),
  )
  if proofHandle == nil:
    raise newException(ValueError, "Failed to reconstruct proof")
  XmssAggregateProof(handle: proofHandle)

proc free*(proof: var XmssAggregateProof) =
  if proof.handle != nil:
    xmss_aggregate_proof_free(proof.handle)
    proof.handle = nil
