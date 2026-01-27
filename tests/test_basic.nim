import unittest
import leansig
import std/sequtils

suite "leanSig Basic Tests":
  test "library loads correctly":
    let lt = lifetime()
    check lt > 0
    echo "Lifetime: ", lt

  test "message length is correct":
    let msgLen = messageLength()
    check msgLen > 0
    echo "Message length: ", msgLen

  test "keypair generation works":
    var kp = newLeanSigKeyPair("test seed phrase", 0, 100)
    defer: kp.free()
    # Just check that no exception was raised
    check true

  test "sign and verify works":
    var kp = newLeanSigKeyPair("test seed phrase", 0, 100)
    defer: kp.free()

    # Create a test message of correct length
    let msgLen = messageLength()
    var message = newSeq[byte](msgLen)
    for i in 0..<msgLen:
      message[i] = byte(i mod 256)

    let epoch: uint32 = 0

    # Sign the message
    var sig = kp.sign(message, epoch)
    defer: sig.free()
    # Just check no exception was raised
    check true

    # Verify the signature
    let valid = sig.verify(message, kp, epoch)
    check valid == true

  test "verification fails with wrong message":
    var kp = newLeanSigKeyPair("test seed phrase", 0, 100)
    defer: kp.free()

    let msgLen = messageLength()
    var message1 = newSeq[byte](msgLen)
    var message2 = newSeq[byte](msgLen)

    for i in 0..<msgLen:
      message1[i] = byte(i mod 256)
      message2[i] = byte((i + 1) mod 256)

    let epoch: uint32 = 0

    # Sign message1
    var sig = kp.sign(message1, epoch)
    defer: sig.free()

    # Try to verify with message2
    let valid = sig.verify(message2, kp, epoch)
    check valid == false

  test "verification fails with wrong epoch":
    var kp = newLeanSigKeyPair("test seed phrase", 0, 100)
    defer: kp.free()

    let msgLen = messageLength()
    var message = newSeq[byte](msgLen)
    for i in 0..<msgLen:
      message[i] = byte(i mod 256)

    # Sign at epoch 0
    var sig = kp.sign(message, 0)
    defer: sig.free()

    # Try to verify at epoch 1
    let valid = sig.verify(message, kp, 1)
    check valid == false

  test "multiple keypairs are independent":
    var kp1 = newLeanSigKeyPair("seed phrase 1", 0, 100)
    var kp2 = newLeanSigKeyPair("seed phrase 2", 0, 100)
    defer:
      kp1.free()
      kp2.free()

    let msgLen = messageLength()
    var message = newSeq[byte](msgLen)
    for i in 0..<msgLen:
      message[i] = byte(i mod 256)

    let epoch: uint32 = 0

    # Sign with kp1
    var sig1 = kp1.sign(message, epoch)
    defer: sig1.free()

    # Verify with kp2 should fail
    let valid = sig1.verify(message, kp2, epoch)
    check valid == false

  test "can sign multiple epochs":
    var kp = newLeanSigKeyPair("test seed phrase", 0, 100)
    defer: kp.free()

    let msgLen = messageLength()
    var message = newSeq[byte](msgLen)
    for i in 0..<msgLen:
      message[i] = byte(i mod 256)

    # Sign at different epochs
    for epoch in 0'u32..4'u32:
      var sig = kp.sign(message, epoch)
      defer: sig.free()
