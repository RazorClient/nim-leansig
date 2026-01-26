import leansig_bindings

type LeanSig* = object
  h: LeanSigHandle

proc initLeanSig*(): LeanSig =
  result.h = leansig_new()

proc close*(s: var LeanSig) =
  leansig_free(s.h)
  s.h = nil

proc publicKeyLen*(s: LeanSig): int =
  int leansig_public_key_len(s.h)

proc secretKeyLen*(s: LeanSig): int =
  int leansig_secret_key_len(s.h)

proc signatureLen*(s: LeanSig): int =
  int leansig_signature_len(s.h)
