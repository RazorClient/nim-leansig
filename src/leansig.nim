## High-level Nim API for leanSig post-quantum signatures

import leansig_bindings

type
  LeanSigKeyPair* = object
    keypair: ptr KeyPair

  LeanSigSignature* = object
    signature: ptr Signature

# Constants
proc messageLength*(): uint =
  leansig_message_length()

proc lifetime*(): uint64 =
  leansig_lifetime()

# KeyPair management
proc newLeanSigKeyPair*(
  seedPhrase: string,
  activationEpoch: uint = 0,
  numActiveEpochs: uint = 1000
): LeanSigKeyPair =
  result = LeanSigKeyPair(
    keypair: leansig_keypair_generate(
      cstring(seedPhrase),
      activationEpoch,
      numActiveEpochs
    )
  )
  if result.keypair == nil:
    raise newException(ValueError, "Failed to generate keypair")

proc free*(kp: var LeanSigKeyPair) =
  if kp.keypair != nil:
    leansig_keypair_free(kp.keypair)
    kp.keypair = nil

proc sign*(
  kp: LeanSigKeyPair,
  message: openArray[byte],
  epoch: uint32
): LeanSigSignature =
  if message.len != messageLength().int:
    raise newException(ValueError, "Message must be " & $messageLength() & " bytes")

  if kp.keypair == nil:
    raise newException(ValueError, "Invalid keypair")

  let privateKey = leansig_keypair_get_private_key(kp.keypair)
  if privateKey == nil:
    raise newException(ValueError, "Failed to get private key")

  let sigPtr = leansig_sign(privateKey, cast[ptr UncheckedArray[byte]](unsafeAddr message[0]), epoch)
  if sigPtr == nil:
    raise newException(ValueError, "Signing failed")

  result = LeanSigSignature(signature: sigPtr)

proc verify*(
  sig: LeanSigSignature,
  message: openArray[byte],
  kp: LeanSigKeyPair,
  epoch: uint32
): bool =
  if message.len != messageLength().int:
    raise newException(ValueError, "Message must be " & $messageLength() & " bytes")

  if sig.signature == nil or kp.keypair == nil:
    return false

  let publicKey = leansig_keypair_get_public_key(kp.keypair)
  if publicKey == nil:
    return false

  let result = leansig_verify(
    publicKey,
    cast[ptr UncheckedArray[byte]](unsafeAddr message[0]),
    epoch,
    sig.signature
  )

  return result == 1

proc free*(sig: var LeanSigSignature) =
  if sig.signature != nil:
    leansig_signature_free(sig.signature)
    sig.signature = nil
