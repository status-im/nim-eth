import pkg/results

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

proc peek*(self: var StaticStackedCounters, T: type): Opt[T] =
  if self.top > 0:
    return Opt.some(self.stack[self.top - 1].item)

  return Opt.none(T)

proc peek*(self: var DynamicStackedCounters, T: type): Opt[T] =
  if self.stack.len > 0:
    return Opt.some(self.stack[self.stack.len - 1].item)

  return Opt.none(T)

proc pop*(self: var StaticStackedCounters, T: type): Opt[T] =
  if self.top > 0:
    #decrement the counter
    self.stack[self.top - 1].count -= 1

    if self.stack[self.top - 1].count == 0:
      let item = self.stack[self.top - 1].item
      self.top -= 1
      return Opt.some(item)

  Opt.none(T)

proc pop*(self: var DynamicStackedCounters, T: type): Opt[T] =
  let top = self.stack.len
  if top > 0:
    #decrement the counter
    self.stack[top - 1].count -= 1

    if self.stack[top - 1].count == 0:
      let item = self.stack[top - 1].item
      self.stack.setLen(top - 1)
      return Opt.some(item)

  Opt.none(T)

proc init*(self: var DynamicStackedCounters, stackLen: int, T: type) =
  self.stack = newSeqOfCap[(T, int)](stackLen)

proc clear*(self: var DynamicStackedCounters) =
  self.stack.setLen(0)

proc clear*(self: var StaticStackedCounters) =
  self.top = 0
