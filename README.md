# nim-leansig

Nim bindings for leanEthereum/leanSig.

## Build + Test

```bash
git clone --recurse-submodules https://github.com/you/nim-leansig
cd nim-leansig
nimble test
If library is not found:

export LD_LIBRARY_PATH=./lib
nimble test