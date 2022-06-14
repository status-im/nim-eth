import
  bearssl/rand

export rand

## Random helpers: similar as in stdlib, but with HmacDrbgContext rng
# TODO: Move these somewhere else?
const randMax = 18_446_744_073_709_551_615'u64

proc rand*(rng: var HmacDrbgContext, max: Natural): int =
  if max == 0: return 0

  var x: uint64
  while true:
    rng.generate(x)
    if x < randMax - (randMax mod (uint64(max) + 1'u64)): # against modulo bias
      return int(x mod (uint64(max) + 1'u64))

proc sample*[T](rng: var HmacDrbgContext, a: openArray[T]): T =
  a[rng.rand(a.high)]

proc shuffle*[T](rng: var HmacDrbgContext, a: var openArray[T]) =
  for i in countdown(a.high, 1):
    let j = rng.rand(i)
    swap(a[i], a[j])
