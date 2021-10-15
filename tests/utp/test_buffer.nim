# Copyright (c) 2020-2021 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.used.}

import
  unittest,
  ../../eth/utp/growable_buffer

suite "Utp ring buffer":
  test "Empty buffer":
    let buff = GrowableCircularBuffer[int].init(size = 4)
    check:
      buff.len() == 4
      buff.get(0).isNone()
  
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
      # it growed to next power of two
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
