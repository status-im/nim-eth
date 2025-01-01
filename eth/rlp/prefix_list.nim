include
  system/ansi_c,
  stew/ptrops

type
  PrefixTuple* = object
    listLen*: uint
    prefixLen*: uint

  PrefixList* = ptr object
    len*: uint
    data*: UncheckedArray[PrefixTuple]

proc listAlloc*(size: uint): PrefixList =
  let memSize = sizeof(uint).uint + size * sizeof(PrefixTuple).uint
  result = cast[PrefixList](c_malloc(memSize.csize_t))
  if result != nil:
    result.len = size

proc resize*(x: PrefixList, newSize: uint): PrefixList =
  let memSize = sizeof(uint).uint + newSize * sizeof(PrefixTuple).uint
  result = cast[PrefixList](c_realloc(x, memSize.csize_t))
  if result != nil:
    result.len = newSize

proc listFree*(x: PrefixList) =
  if x != nil:
    c_free(x)
