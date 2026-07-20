import ssz_serialization

proc `==`*[T; N: static[int]](a, b: List[T, N]): bool =
  if a.len != b.len:             # compare length first
    return false
  for i in 0..<a.len:
    if a[i] != b[i]:
      return false
  true

proc `==`*[N: static[int]](a, b: ByteList[N]): bool =
  a.asSeq == b.asSeq