import unittest
import leansig

test "leansig loads correctly":
  var ls = initLeanSig()

  check ls.publicKeyLen() > 0
  check ls.secretKeyLen() > 0
  check ls.signatureLen() > 0

  ls.close()
