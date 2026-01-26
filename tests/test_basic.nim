import unittest
import leansig

test "leansig loads correctly":
  let lt = lifetime()
  check lt > 0
