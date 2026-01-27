import unittest
import multisig

suite "XMSS Multisig Glue":
  setup:
    # Warm up verifier path; prover init is triggered automatically when aggregating.
    setupVerifier()

  test "message length constant":
    check xmssMsgLen() == 32

  test "keypair + sign/verify roundtrip":
    var kp = newXmssKeyPair("multisig-seed-1", 0, 3)
    defer: kp.free()

    let msgLen = xmssMsgLen()
    var message = newSeq[byte](msgLen)
    for i in 0..<msgLen:
      message[i] = byte(i mod 251)

    let slot: uint64 = 1

    var sig = kp.sign(message, slot)
    defer: sig.free()

    check sig.verify(message, kp, slot) == true

  test "aggregate two signatures":
    # Keep parameters small for a quick sanity check.
    var kp1 = newXmssKeyPair("multisig-seed-agg-1", 0, 3)
    var kp2 = newXmssKeyPair("multisig-seed-agg-2", 0, 3)
    defer:
      kp1.free()
      kp2.free()

    let msgLen = xmssMsgLen()
    var message = newSeq[byte](msgLen)
    for i in 0..<msgLen:
      message[i] = byte((i * 7) mod 251)

    let slot: uint64 = 2

    var sig1 = kp1.sign(message, slot)
    var sig2 = kp2.sign(message, slot)
    defer:
      sig1.free()
      sig2.free()

    # Prover init happens lazily inside aggregate; call once here.
    var proof = aggregate([kp1, kp2], [sig1, sig2], message, slot)
    defer: proof.free()

    check proof.toBytes().len > 0
    check proof.verifyAggregated([kp1, kp2], message, slot) == true
