## High-level Nim API for leanSig post-quantum signatures

import leansig_bindings

type
  LeanSigScheme* = enum
    lsTopLevelTargetSumLifetime18Dim64Base8 = 0,
    lsPoseidon18W1NoOff = 1,
    lsPoseidon18W1Off10 = 2,
    lsPoseidon18W2NoOff = 3,
    lsPoseidon18W2Off10 = 4,
    lsPoseidon18W4NoOff = 5,
    lsPoseidon18W4Off10 = 6,
    lsPoseidon18W8NoOff = 7,
    lsPoseidon18W8Off10 = 8,
    lsPoseidon20W1NoOff = 9,
    lsPoseidon20W1Off10 = 10,
    lsPoseidon20W2NoOff = 11,
    lsPoseidon20W2Off10 = 12,
    lsPoseidon20W4NoOff = 13,
    lsPoseidon20W4Off10 = 14,
    lsPoseidon20W8NoOff = 15,
    lsPoseidon20W8Off10 = 16,
    lsTopLevelTargetSumLifetime8Dim64Base8 = 17,
    lsCoreLargeBasePoseidon = 18,
    lsCoreLargeDimensionPoseidon = 19,
    lsCoreTargetSumPoseidon = 20

  LeanSigKeyPair* = object
    keypair: ptr KeyPair

  LeanSigSignature* = object
    signature: ptr Signature

proc schemeId(scheme: LeanSigScheme): uint32 {.inline.} =
  uint32(ord(scheme))

proc ffiLastError(): string =
  let errorLen = int(leansig_last_error_len())
  if errorLen <= 0:
    return ""

  var buf = newSeq[byte](errorLen + 1)
  discard leansig_last_error_copy(
    cast[ptr UncheckedArray[byte]](addr buf[0]),
    csize_t(buf.len)
  )

  result = newString(errorLen)
  for i in 0..<errorLen:
    result[i] = char(buf[i])

proc raiseFfiError(context: string) {.noreturn.} =
  let details = ffiLastError()
  if details.len > 0:
    raise newException(ValueError, context & ": " & details)
  raise newException(ValueError, context)

# Constants
proc messageLength*(): uint =
  leansig_message_length()

proc lifetime*(): uint64 =
  leansig_lifetime()

proc lifetime*(scheme: LeanSigScheme): uint64 =
  let lt = leansig_scheme_lifetime_v2(schemeId(scheme))
  if lt == 0:
    raiseFfiError("Failed to read scheme lifetime")
  lt

# KeyPair management
proc newLeanSigKeyPair*(
  seedPhrase: string,
  activationEpoch: uint = 0,
  numActiveEpochs: uint = 1000,
  scheme: LeanSigScheme = lsTopLevelTargetSumLifetime18Dim64Base8
): LeanSigKeyPair =
  result = LeanSigKeyPair(
    keypair: leansig_keypair_generate_v2(
      schemeId(scheme),
      cstring(seedPhrase),
      csize_t(activationEpoch),
      csize_t(numActiveEpochs)
    )
  )
  if result.keypair == nil:
    raiseFfiError("Failed to generate keypair")

proc free*(kp: var LeanSigKeyPair) =
  if kp.keypair != nil:
    leansig_keypair_free(kp.keypair)
    kp.keypair = nil

proc prepareToEpoch*(kp: var LeanSigKeyPair, epoch: uint32) =
  if kp.keypair == nil:
    raise newException(ValueError, "Invalid keypair")

  let rc = leansig_keypair_prepare_to_epoch_v2(kp.keypair, epoch)
  if rc != 1:
    raiseFfiError("Failed to prepare keypair")

proc sign*(
  kp: LeanSigKeyPair,
  message: openArray[byte],
  epoch: uint32
): LeanSigSignature =
  if message.len != messageLength().int:
    raise newException(ValueError, "Message must be " & $messageLength() & " bytes")

  if kp.keypair == nil:
    raise newException(ValueError, "Invalid keypair")

  let msgPtr =
    if message.len == 0:
      nil
    else:
      cast[ptr UncheckedArray[byte]](unsafeAddr message[0])

  let sigPtr = leansig_sign_v2(kp.keypair, msgPtr, epoch)
  if sigPtr == nil:
    raiseFfiError("Signing failed")

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

  let msgPtr =
    if message.len == 0:
      nil
    else:
      cast[ptr UncheckedArray[byte]](unsafeAddr message[0])

  let rc = leansig_verify_v2(kp.keypair, msgPtr, epoch, sig.signature)
  rc == 1

proc toBytes*(sig: LeanSigSignature): seq[byte] =
  if sig.signature == nil:
    raise newException(ValueError, "Invalid signature")

  let encodedLen = int(leansig_signature_to_bytes_len_v2(sig.signature))
  if encodedLen < 0:
    raiseFfiError("Failed to read signature size")
  if encodedLen == 0:
    return @[]

  result = newSeq[byte](encodedLen)
  let copied = int(leansig_signature_to_bytes_copy_v2(
    sig.signature,
    cast[ptr UncheckedArray[byte]](addr result[0]),
    csize_t(result.len)
  ))
  if copied != result.len:
    raiseFfiError("Failed to copy signature bytes")

proc signatureFromBytes*(
  scheme: LeanSigScheme,
  encoded: openArray[byte]
): LeanSigSignature =
  if encoded.len == 0:
    raise newException(ValueError, "Encoded signature must not be empty")

  let sigPtr = leansig_signature_from_bytes_v2(
    schemeId(scheme),
    cast[ptr UncheckedArray[byte]](unsafeAddr encoded[0]),
    csize_t(encoded.len)
  )
  if sigPtr == nil:
    raiseFfiError("Failed to decode signature")

  result = LeanSigSignature(signature: sigPtr)

proc free*(sig: var LeanSigSignature) =
  if sig.signature != nil:
    leansig_signature_free(sig.signature)
    sig.signature = nil
