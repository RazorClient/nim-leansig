import unittest
import leansig

proc makeMessage(seed: uint64): seq[byte] =
  let msgLen = int(messageLength())
  result = newSeq[byte](msgLen)
  var state = seed xor 0x9E3779B97F4A7C15'u64
  for i in 0..<msgLen:
    state = state * 6364136223846793005'u64 + 1442695040888963407'u64
    result[i] = byte((state shr 24) and 0xFF)

proc seedPhrase(scheme: LeanSigScheme, seed: uint64): string =
  "scheme-" & $ord(scheme) & "-seed-" & $seed

proc keygenSmoke(scheme: LeanSigScheme, seed: uint64) =
  var kp = newLeanSigKeyPair(
    seedPhrase(scheme, seed),
    0,
    uint(lifetime(scheme)),
    scheme
  )
  kp.free()

proc runCorrectnessCase(
  scheme: LeanSigScheme,
  seed: uint64,
  epoch: uint32,
  activationEpoch: uint,
  numActiveEpochs: uint
) =
  var kp = newLeanSigKeyPair(
    seedPhrase(scheme, seed),
    activationEpoch,
    numActiveEpochs,
    scheme
  )
  defer: kp.free()

  kp.prepareToEpoch(epoch)
  let message = makeMessage(seed xor uint64(epoch))

  var sig = kp.sign(message, epoch)
  defer: sig.free()

  check sig.verify(message, kp, epoch)

proc readU32Le(data: openArray[byte], pos: int): uint32 =
  if pos < 0 or pos + 4 > data.len:
    raise newException(ValueError, "readU32Le out of bounds")

  result = uint32(data[pos])
  result = result or (uint32(data[pos + 1]) shl 8)
  result = result or (uint32(data[pos + 2]) shl 16)
  result = result or (uint32(data[pos + 3]) shl 24)

proc writeU32Le(data: var seq[byte], pos: int, value: uint32) =
  if pos < 0 or pos + 4 > data.len:
    raise newException(ValueError, "writeU32Le out of bounds")

  data[pos] = byte(value and 0xFF'u32)
  data[pos + 1] = byte((value shr 8) and 0xFF'u32)
  data[pos + 2] = byte((value shr 16) and 0xFF'u32)
  data[pos + 3] = byte((value shr 24) and 0xFF'u32)

template internalConsistencyPair(
  testName: string,
  schemeA: LeanSigScheme,
  schemeB: LeanSigScheme,
  seedA: uint64,
  seedB: uint64
) =
  test testName:
    keygenSmoke(schemeA, seedA)
    keygenSmoke(schemeB, seedB)

template correctnessPair(
  testName: string,
  schemeA: LeanSigScheme,
  seedA: uint64,
  epochA: uint32,
  schemeB: LeanSigScheme,
  seedB: uint64,
  epochB: uint32
) =
  test testName:
    runCorrectnessCase(schemeA, seedA, epochA, 0, uint(lifetime(schemeA)))
    runCorrectnessCase(schemeB, seedB, epochB, 0, uint(lifetime(schemeB)))

suite "leanSig Instantiations + Core via Nim API":
  suite "Instantiations - Standard Poseidon lifetime 2^18":
    internalConsistencyPair(
      "l18_w1_internal_consistency",
      lsPoseidon18W1NoOff,
      lsPoseidon18W1Off10,
      0xA5001001'u64,
      0xA5001002'u64
    )
    internalConsistencyPair(
      "l18_w2_internal_consistency",
      lsPoseidon18W2NoOff,
      lsPoseidon18W2Off10,
      0xA5002001'u64,
      0xA5002002'u64
    )
    internalConsistencyPair(
      "l18_w4_internal_consistency",
      lsPoseidon18W4NoOff,
      lsPoseidon18W4Off10,
      0xA5004001'u64,
      0xA5004002'u64
    )
    internalConsistencyPair(
      "l18_w8_internal_consistency",
      lsPoseidon18W8NoOff,
      lsPoseidon18W8Off10,
      0xA5008001'u64,
      0xA5008002'u64
    )

    correctnessPair(
      "l18_w1_correctness (slow-tests)",
      lsPoseidon18W1NoOff,
      0x18010001'u64,
      1032'u32,
      lsPoseidon18W1Off10,
      0x18010002'u64,
      32'u32
    )
    correctnessPair(
      "l18_w2_correctness (slow-tests)",
      lsPoseidon18W2NoOff,
      0x18020001'u64,
      436'u32,
      lsPoseidon18W2Off10,
      0x18020002'u64,
      312'u32
    )
    correctnessPair(
      "l18_w4_correctness (slow-tests)",
      lsPoseidon18W4NoOff,
      0x18040001'u64,
      21'u32,
      lsPoseidon18W4Off10,
      0x18040002'u64,
      3211'u32
    )
    correctnessPair(
      "l18_w8_correctness (slow-tests)",
      lsPoseidon18W8NoOff,
      0x18080001'u64,
      32'u32,
      lsPoseidon18W8Off10,
      0x18080002'u64,
      768'u32
    )

  # suite "Instantiations - Standard Poseidon lifetime 2^20 (commented out)":
    # Internal consistency cases (2^20)
    # internalConsistencyPair(
    #   "l20_w1_internal_consistency",
    #   lsPoseidon20W1NoOff,
    #   lsPoseidon20W1Off10,
    #   0xB5001001'u64,
    #   0xB5001002'u64
    # )
    # internalConsistencyPair(
    #   "l20_w2_internal_consistency",
    #   lsPoseidon20W2NoOff,
    #   lsPoseidon20W2Off10,
    #   0xB5002001'u64,
    #   0xB5002002'u64
    # )
    # internalConsistencyPair(
    #   "l20_w4_internal_consistency",
    #   lsPoseidon20W4NoOff,
    #   lsPoseidon20W4Off10,
    #   0xB5004001'u64,
    #   0xB5004002'u64
    # )
    # internalConsistencyPair(
    #   "l20_w8_internal_consistency",
    #   lsPoseidon20W8NoOff,
    #   lsPoseidon20W8Off10,
    #   0xB5008001'u64,
    #   0xB5008002'u64
    # )

    # Correctness cases (2^20, slow-tests)
    # correctnessPair(
    #   "l20_w1_correctness (slow-tests)",
    #   lsPoseidon20W1NoOff,
    #   0x20010001'u64,
    #   1032'u32,
    #   lsPoseidon20W1Off10,
    #   0x20010002'u64,
    #   32'u32
    # )
    # correctnessPair(
    #   "l20_w2_correctness (slow-tests)",
    #   lsPoseidon20W2NoOff,
    #   0x20020001'u64,
    #   436'u32,
    #   lsPoseidon20W2Off10,
    #   0x20020002'u64,
    #   312'u32
    # )
    # correctnessPair(
    #   "l20_w4_correctness (slow-tests)",
    #   lsPoseidon20W4NoOff,
    #   0x20040001'u64,
    #   21'u32,
    #   lsPoseidon20W4Off10,
    #   0x20040002'u64,
    #   3211'u32
    # )
    # correctnessPair(
    #   "l20_w8_correctness (slow-tests)",
    #   lsPoseidon20W8NoOff,
    #   0x20080001'u64,
    #   32'u32,
    #   lsPoseidon20W8Off10,
    #   0x20080002'u64,
    #   768'u32
    # )

  suite "Instantiations - Top-level Poseidon":
    test "top8_internal_consistency":
      keygenSmoke(lsTopLevelTargetSumLifetime8Dim64Base8, 0xC5000001'u64)

    test "top8_correctness (slow-tests)":
      runCorrectnessCase(
        lsTopLevelTargetSumLifetime8Dim64Base8,
        0x28000001'u64,
        213'u32,
        0,
        uint(lifetime(lsTopLevelTargetSumLifetime8Dim64Base8))
      )
      runCorrectnessCase(
        lsTopLevelTargetSumLifetime8Dim64Base8,
        0x28000002'u64,
        4'u32,
        0,
        uint(lifetime(lsTopLevelTargetSumLifetime8Dim64Base8))
      )

  suite "Core Algorithm - Generalized XMSS":
    test "core_large_base_poseidon":
      runCorrectnessCase(
        lsCoreLargeBasePoseidon,
        0x30000001'u64,
        0'u32,
        0,
        uint(lifetime(lsCoreLargeBasePoseidon))
      )
      runCorrectnessCase(
        lsCoreLargeBasePoseidon,
        0x30000002'u64,
        11'u32,
        0,
        uint(lifetime(lsCoreLargeBasePoseidon))
      )

    test "core_large_dimension_poseidon":
      runCorrectnessCase(
        lsCoreLargeDimensionPoseidon,
        0x30001001'u64,
        2'u32,
        0,
        uint(lifetime(lsCoreLargeDimensionPoseidon))
      )
      runCorrectnessCase(
        lsCoreLargeDimensionPoseidon,
        0x30001002'u64,
        19'u32,
        0,
        uint(lifetime(lsCoreLargeDimensionPoseidon))
      )

    test "core_ssz_panic_safety_malicious_offsets":
      let scheme = lsCoreTargetSumPoseidon
      var kp = newLeanSigKeyPair(
        seedPhrase(scheme, 0x30002001'u64),
        0,
        uint(lifetime(scheme)),
        scheme
      )
      defer: kp.free()

      let epoch = 2'u32
      kp.prepareToEpoch(epoch)
      let message = makeMessage(0x30002001'u64)

      var sig = kp.sign(message, epoch)
      defer: sig.free()

      let encodedValid = sig.toBytes()
      check encodedValid.len >= 8

      let sigFixedPartSize = int(readU32Le(encodedValid, 0))
      check sigFixedPartSize >= 8

      let rhoLen = sigFixedPartSize - 8
      let rhoStart = 4
      let rhoEnd = rhoStart + rhoLen
      let offsetHashesPos = rhoEnd

      check rhoEnd <= encodedValid.len
      check offsetHashesPos + 4 <= encodedValid.len

      let encodedLen1 =
        if sigFixedPartSize + 16 > 200:
          sigFixedPartSize + 16
        else:
          200
      var encoded = newSeq[byte](encodedLen1)
      writeU32Le(encoded, 0, uint32(sigFixedPartSize))
      for i in 0..<rhoLen:
        encoded[rhoStart + i] = encodedValid[rhoStart + i]
      writeU32Le(encoded, offsetHashesPos, 10'u32)

      expect(ValueError):
        var decoded = signatureFromBytes(scheme, encoded)
        decoded.free()

      let encodedLen2 =
        if sigFixedPartSize + 8 > 100:
          sigFixedPartSize + 8
        else:
          100
      var encoded2 = newSeq[byte](encodedLen2)
      writeU32Le(encoded2, 0, uint32(sigFixedPartSize))
      for i in 0..<rhoLen:
        encoded2[rhoStart + i] = encodedValid[rhoStart + i]
      writeU32Le(encoded2, offsetHashesPos, uint32(encoded2.len + 50))

      expect(ValueError):
        var decoded2 = signatureFromBytes(scheme, encoded2)
        decoded2.free()

  suite "Core Algorithm - Signature Scheme":
    test "core_signature_scheme_correctness (template coverage)":
      runCorrectnessCase(
        lsCoreTargetSumPoseidon,
        0x30003001'u64,
        2'u32,
        0,
        uint(lifetime(lsCoreTargetSumPoseidon))
      )
      runCorrectnessCase(
        lsCoreTargetSumPoseidon,
        0x30003002'u64,
        19'u32,
        0,
        uint(lifetime(lsCoreTargetSumPoseidon))
      )
      runCorrectnessCase(
        lsCoreTargetSumPoseidon,
        0x30003003'u64,
        0'u32,
        0,
        uint(lifetime(lsCoreTargetSumPoseidon))
      )
      runCorrectnessCase(
        lsCoreTargetSumPoseidon,
        0x30003004'u64,
        11'u32,
        0,
        uint(lifetime(lsCoreTargetSumPoseidon))
      )
