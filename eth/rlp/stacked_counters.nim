{.push raises: [].}

type
  StaticStackedCounters*[N: static int, T] = object
    stack: array[N, tuple[item: T, count: int]]
    top: int

  DynamicStackedCounters*[T] = object
    stack: seq[tuple[item: T, count: int]]

proc push*[T](self: var StaticStackedCounters, item: T, count: int) =
  self.stack[self.top] = (item, count)
  self.top += 1

proc push*[T](self: var DynamicStackedCounters, item: T, count: int) =
  self.stack.add((item, count))

func isEmpty*(self: StaticStackedCounters): bool {.inline.} =
  self.top == 0

func isEmpty*(self: DynamicStackedCounters): bool {.inline.} =
  self.stack.len == 0

func decrementTop*(self: var StaticStackedCounters): bool {.inline.} =
  if self.top > 0:
    let count = addr self.stack[self.top - 1].count
    if count[] > 1:
      count[] -= 1
      return true
  false

func decrementTop*(self: var DynamicStackedCounters): bool {.inline.} =
  let top = self.stack.len
  if top > 0:
    let count = addr self.stack[top - 1].count
    if count[] > 1:
      count[] -= 1
      return true
  false

template topItem*(self: StaticStackedCounters): untyped =
  ## The item on top of the stack, which must not be empty
  self.stack[self.top - 1].item

template topItem*(self: DynamicStackedCounters): untyped =
  ## The item on top of the stack, which must not be empty
  self.stack[self.stack.len - 1].item

proc pop*[N: static int, T](self: var StaticStackedCounters[N, T], item: var T): bool =
  ## Decrements the counter on top of the stack - when it reaches zero, removes
  ## the top and returns true, with its item in `item`
  if self.top > 0:
    #decrement the counter
    self.stack[self.top - 1].count -= 1

    if self.stack[self.top - 1].count == 0:
      item = self.stack[self.top - 1].item
      self.top -= 1
      return true

  false

proc pop*[T](self: var DynamicStackedCounters[T], item: var T): bool =
  ## Decrements the counter on top of the stack - when it reaches zero, removes
  ## the top and returns true, with its item in `item`
  let top = self.stack.len
  if top > 0:
    #decrement the counter
    self.stack[top - 1].count -= 1

    if self.stack[top - 1].count == 0:
      item = self.stack[top - 1].item
      self.stack.setLen(top - 1)
      return true

  false

proc init*(self: var DynamicStackedCounters, stackLen: int, T: type) =
  self.stack = newSeqOfCap[(T, int)](stackLen)

proc clear*(self: var DynamicStackedCounters) =
  self.stack.setLen(0)

proc clear*(self: var StaticStackedCounters) =
  self.top = 0
