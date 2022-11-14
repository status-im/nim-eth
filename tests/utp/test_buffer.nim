# Copyright (c) 2020-2021 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.used.}

import
  std/sugar,
  unittest2,
  ../../eth/utp/growable_buffer

type TestObj = object
  foo: string

suite "Utp ring buffer":
  test "Empty buffer":
    let buff = GrowableCircularBuffer[int].init(size = 4)
    check:
      buff.len() == 4
      buff.get(0).isNone()

  test "Buffer should be initialised to next power of two":
    var elemsCounter = 0
    let buff = GrowableCircularBuffer[int].init(size = 17)
    check:
      buff.len() == 32

    for i in buff.items:
      inc elemsCounter

    check:
      elemsCounter == 32

  test "Adding elements to buffer":
    var buff = GrowableCircularBuffer[int].init(size = 4)
    buff.put(11, 11)
    buff.put(12, 12)
    buff.put(13, 13)
    buff.put(14, 14)

    check:
      buff.get(11) == some(11)
      buff.get(12) == some(12)
      buff.get(13) == some(13)
      buff.get(14) == some(14)

  test "Modifying existing element in buffer":
    var buff = GrowableCircularBuffer[TestObj].init(size = 4)
    let oldText = "test"
    let newText = "testChanged"

    buff.put(11, TestObj(foo: oldText))

    check:
      buff.get(11).get() == TestObj(foo: oldText)

    buff[11].foo = newText

    check:
      buff.get(11).get() == TestObj(foo: newText)

  test "Checking if element exists and has some properties":
    var buff = GrowableCircularBuffer[TestObj].init(size = 4)
    let text = "test"
    let textIdx = 11'u32

    check:
      not buff.exists(textIdx, x => x.foo == text)

    buff.put(textIdx, TestObj(foo: "old"))

    check:
      not buff.exists(textIdx, x => x.foo == text)

    buff[textIdx].foo = text

    check:
      buff.exists(textIdx, x => x.foo == text)

  test "Deleting elements from buffer":
    var buff = GrowableCircularBuffer[int].init(size = 4)
    buff.put(11, 11)

    check:
      buff.get(11) == some(11)

    buff.delete(11)

    check:
      buff.get(11) == none[int]()

  test "Adding elements to buffer while ensuring proper size":
    var buff = GrowableCircularBuffer[int].init(size = 4)

    buff.put(11, 11)
    buff.put(12, 12)
    buff.put(13, 13)
    buff.put(14, 14)

    # next element will be 5 in buffer, so it has index equal to 4
    buff.ensureSize(15, 4)
    buff.put(15, 15)

    check:
      # it grew to next power of two
      buff.len() == 8
      buff.get(11) == some(11)
      buff.get(12) == some(12)
      buff.get(13) == some(13)
      buff.get(14) == some(14)
      buff.get(15) == some(15)

  test "Adding out of order elements to buffer while ensuring proper size":
    var buff = GrowableCircularBuffer[int].init(size = 4)

    buff.put(11, 11)
    buff.put(12, 12)
    buff.put(13, 13)
    buff.put(14, 14)

    # element with nr 17 will be on needed on index 6
    buff.ensureSize(17, 6)
    buff.put(17, 17)

    check:
      # it growed to next power of two
      buff.len() == 8
      buff.get(11) == some(11)
      buff.get(12) == some(12)
      buff.get(13) == some(13)
      buff.get(14) == some(14)
      # elements 15 and 16 are not present yet
      buff.get(15) == none[int]()
      buff.get(16) == none[int]()
      buff.get(17) == some(17)

  test "Ensuring proper wrap around when adding elements to buffer":
    var buff = GrowableCircularBuffer[int].init(size = 2)

    buff.ensureSize(65535, 0)
    buff.put(65535, 65535)
    buff.ensureSize(0, 1)
    buff.put(0, 0)

    # index 2 will not fit in buffer of size 2 so it will need to be expanded to 4
    buff.ensureSize(1, 2)
    buff.put(1, 1)

    check:
      buff.len() == 4

    buff.ensureSize(2, 3)
    buff.put(2, 2)
    # index 4 will not fit in buffer size 4 so it will need to expanded
    buff.ensureSize(3, 4)
    buff.put(3, 3)

    # all elements should be available through old indexes
    check:
      buff.get(65535) == some(65535)
      buff.get(0) == some(0)
      buff.get(1) == some(1)
      buff.get(2) == some(2)
      buff.get(3) == some(3)
      buff.len() == 8

    var elemsCounter = 0
    for elem in buff.items:
      inc elemsCounter
    check:
      elemsCounter == 8
