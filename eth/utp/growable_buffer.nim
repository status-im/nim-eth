# Copyright (c) 2021 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

import
  std/[options, math, sugar]

export options

# Buffer implementation similar to the one in in reference implementation.
# Main rationale for it, is to refer to items in buffer by their sequence number,
# and support out of order packets.
# Therefore it is super specific data structure, and it mostly usefull for
# utp implementation.
# Another alternative would be to use standard deque from deques module, and caluclate
# item indexes from their sequence numbers.
type
  GrowableCircularBuffer*[A] = object
    items: seq[Option[A]]
    mask: int

# provided size will always be adjusted to next power of two
proc init*[A](T: type GrowableCircularBuffer[A], size: Natural = 16): T =
  let powOfTwoSize = nextPowerOfTwo(size)
  T(
    items: newSeq[Option[A]](size),
    mask: powOfTwoSize - 1
  )

proc get*[A](buff: GrowableCircularBuffer[A], i: Natural): Option[A] =
  buff.items[i and buff.mask]

proc putImpl[A](buff: var GrowableCircularBuffer[A], i: Natural, elem: Option[A]) =
  buff.items[i and buff.mask] = elem

proc put*[A](buff: var GrowableCircularBuffer[A], i: Natural, elem: A) =
  buff.putImpl(i, some(elem))

proc delete*[A](buff: var GrowableCircularBuffer[A], i: Natural) =
  buff.putImpl(i, none[A]())

proc hasKey*[A](buff: GrowableCircularBuffer[A], i: Natural): bool =
  buff.get(i).isSome()

proc exists*[A](buff: GrowableCircularBuffer[A], i: Natural, check: proc (x: A): bool): bool =
  let maybeElem = buff.get(i)
  if (maybeElem.isSome()):
    let elem = maybeElem.unsafeGet()
    check(elem)
  else:
    false

proc `[]`*[A](buff: var GrowableCircularBuffer[A], i: Natural): var A =
  ## Returns contents of the `var GrowableCircularBuffer`. If it is not set, then an exception
  ## is thrown.
  buff.items[i and buff.mask].get()

proc len*[A](buff: GrowableCircularBuffer[A]): int =
  buff.mask + 1

# Item contains the element we want to make space for
# index is the index in the list.
proc ensureSize*[A](buff: var GrowableCircularBuffer[A], item: Natural, index: Natural) =
  # Increase size until is next power of 2 which consists given index
  proc getNextSize(currentSize: int, index: int): int =
    var newSize = currentSize
    while true:
      newSize = newSize * 2
      if not (index >= newSize):
        break
    newSize

  if (index > buff.mask):
    let currentSize = buff.mask + 1
    let newSize = getNextSize(currentSize, index)
    let newMask = newSize - 1
    var newSeq = newSeq[Option[A]](newSize)
    var i = 0
    while i <= buff.mask:
      let idx = item - index + i
      newSeq[idx and newMask] = buff.get(idx)
      inc i
    buff.items = move(newSeq)
    buff.mask = newMask

iterator items*[A](buff: GrowableCircularBuffer[A]): Option[A] =
  for e in buff.items:
    yield e
