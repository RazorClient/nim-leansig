## High-level Nim API for leanSig post-quantum signatures

import leansig_bindings

type
  LeanSigScheme* = enum
    lsTopLevelTargetSumLifetime18Dim64Base8 = 0
    lsPoseidon18W1NoOff = 1
    lsPoseidon18W1Off10 = 2
    lsPoseidon18W2NoOff = 3
    lsPoseidon18W2Off10 = 4
    lsPoseidon18W4NoOff = 5
    lsPoseidon18W4Off10 = 6
    lsPoseidon18W8NoOff = 7
    lsPoseidon18W8Off10 = 8
    lsPoseidon20W1NoOff = 9
    lsPoseidon20W1Off10 = 10
    lsPoseidon20W2NoOff = 11
    lsPoseidon20W2Off10 = 12
    lsPoseidon20W4NoOff = 13
    lsPoseidon20W4Off10 = 14
    lsPoseidon20W8NoOff = 15
    lsPoseidon20W8Off10 = 16
    lsTopLevelTargetSumLifetime8Dim64Base8 = 17
    lsCoreLargeBasePoseidon = 18
    lsCoreLargeDimensionPoseidon = 19
    lsCoreTargetSumPoseidon = 20

  LeanSigKeyPair* = object
    handle: ptr KeyPair

  LeanSigSignature* = object
    handle: ptr Signature

const
  ffiSuccessCode = 1'i32
  defaultActivationEpoch = 0'u
  defaultNumActiveEpochs = 1000'u

proc schemeId(scheme: LeanSigScheme): uint32 {.inline.} =
  uint32(ord(scheme))

proc messagePtr(message: openArray[byte]): ptr UncheckedArray[byte] {.inline.} =
  if message.len == 0:
    nil
  else:
    cast[ptr UncheckedArray[byte]](unsafeAddr message[0])

proc requireMessageLength(message: openArray[byte]) =
  let requiredLen = messageLength().int
  if message.len != requiredLen:
    raise newException(ValueError, "Message must be " & $requiredLen & " bytes")

proc requireValidKeyPair(keyPair: LeanSigKeyPair) =
  if keyPair.handle == nil:
    raise newException(ValueError, "Invalid keypair")

proc ffiLastError(): string =
  let errorLen = int(leansig_last_error_len())
  if errorLen <= 0:
    return ""

  var buf = newSeq[byte](errorLen + 1)
  discard leansig_last_error_copy(
    cast[ptr UncheckedArray[byte]](addr buf[0]), csize_t(buf.len)
  )

  result = newString(errorLen)
  for i in 0 ..< errorLen:
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
  let schemeLifetime = leansig_scheme_lifetime_v2(schemeId(scheme))
  if schemeLifetime == 0:
    raiseFfiError("Failed to read scheme lifetime")
  schemeLifetime

# KeyPair management
proc newLeanSigKeyPair*(
    seedPhrase: string,
    activationEpoch: uint = defaultActivationEpoch,
    numActiveEpochs: uint = defaultNumActiveEpochs,
    scheme: LeanSigScheme = lsTopLevelTargetSumLifetime18Dim64Base8,
): LeanSigKeyPair =
  result = LeanSigKeyPair(
    handle: leansig_keypair_generate_v2(
      schemeId(scheme),
      cstring(seedPhrase),
      csize_t(activationEpoch),
      csize_t(numActiveEpochs),
    )
  )
  if result.handle == nil:
    raiseFfiError("Failed to generate keypair")

proc free*(keyPair: var LeanSigKeyPair) =
  if keyPair.handle != nil:
    leansig_keypair_free(keyPair.handle)
    keyPair.handle = nil

proc prepareToEpoch*(keyPair: var LeanSigKeyPair, epoch: uint32) =
  requireValidKeyPair(keyPair)
  let status = leansig_keypair_prepare_to_epoch_v2(keyPair.handle, epoch)
  if status != ffiSuccessCode:
    raiseFfiError("Failed to prepare keypair")

proc sign*(
    keyPair: LeanSigKeyPair, message: openArray[byte], epoch: uint32
): LeanSigSignature =
  requireMessageLength(message)
  requireValidKeyPair(keyPair)

  let signatureHandle = leansig_sign_v2(keyPair.handle, messagePtr(message), epoch)
  if signatureHandle == nil:
    raiseFfiError("Signing failed")

  result = LeanSigSignature(handle: signatureHandle)

proc verify*(
    signature: LeanSigSignature,
    message: openArray[byte],
    keyPair: LeanSigKeyPair,
    epoch: uint32,
): bool =
  requireMessageLength(message)
  if signature.handle == nil or keyPair.handle == nil:
    return false

  let status =
    leansig_verify_v2(keyPair.handle, messagePtr(message), epoch, signature.handle)
  status == ffiSuccessCode

proc toBytes*(signature: LeanSigSignature): seq[byte] =
  if signature.handle == nil:
    raise newException(ValueError, "Invalid signature")

  let signatureSize = int(leansig_signature_to_bytes_len_v2(signature.handle))
  if signatureSize < 0:
    raiseFfiError("Failed to read signature size")
  if signatureSize == 0:
    return @[]

  result = newSeq[byte](signatureSize)
  let copied = int(
    leansig_signature_to_bytes_copy_v2(
      signature.handle,
      cast[ptr UncheckedArray[byte]](addr result[0]),
      csize_t(result.len),
    )
  )
  if copied != result.len:
    raiseFfiError("Failed to copy signature bytes")

proc signatureFromBytes*(
    scheme: LeanSigScheme, encodedSignature: openArray[byte]
): LeanSigSignature =
  if encodedSignature.len == 0:
    raise newException(ValueError, "Encoded signature must not be empty")

  let signatureHandle = leansig_signature_from_bytes_v2(
    schemeId(scheme),
    cast[ptr UncheckedArray[byte]](unsafeAddr encodedSignature[0]),
    csize_t(encodedSignature.len),
  )
  if signatureHandle == nil:
    raiseFfiError("Failed to decode signature")

  result = LeanSigSignature(handle: signatureHandle)

proc free*(signature: var LeanSigSignature) =
  if signature.handle != nil:
    leansig_signature_free(signature.handle)
    signature.handle = nil
