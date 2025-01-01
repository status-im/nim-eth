include 
  system/ansi_c,
  stew/ptrops

when defined(windows):
  proc alloca(size: csize_t): pointer {.header: "<malloc.h>".}
else:
  proc alloca(size: csize_t): pointer {.header: "<alloca.h>".}

const
  STACK_ALLOC_THRESHOLD = 1024
  STACK_MARKER = 0xFFFF
  HEAP_MARKER = 0xcccc
  
type
  VLAMem* = ptr object
    marker: uint
    data: UncheckedArray[byte]
    
proc vlaAlloc*(size: uint): VLAMem =
  const marker_size = sizeof(uint).uint
  #if size + marker_size < STACK_ALLOC_THRESHOLD:
  #  result = cast[VLAMem](alloca((size + marker_size).csize_t))
  #  if result != nil:
  #    result.marker = STACK_MARKER
  #else:
  result = cast[VLAMem](c_malloc((size + marker_size).csize_t))
  if result != nil:
    result.marker = HEAP_MARKER
    
proc vlaFree*(x: VLAMem) =
  if x != nil and x.marker == HEAP_MARKER:
    c_free(x)
    
func to*(x: VLAMem, T: type): T =
  cast[T](x.data[0].addr)
  