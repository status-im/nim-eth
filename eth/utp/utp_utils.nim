# Copyright (c) 2021 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [Defect].}

import
  chronos

# compare if lhs is less than rhs, taking wrapping
# into account. i.e high(lhs) < 0 == true
proc wrapCompareLess*(lhs: uint32, rhs: uint32): bool =
  let distDown = (lhs - rhs)
  let distUp = (rhs - lhs)
  # if the distance walking up is shorter, lhs
  # is less than rhs. If the distance walking down
  # is shorter, then rhs is less than lhs
  return distUp < distDown

proc wrapCompareLess*(lhs: uint16, rhs: uint16): bool =
  let distDown = (lhs - rhs)
  let distUp = (rhs - lhs)

  return distUp < distDown

proc max*(a, b: Duration): Duration =
  if (a > b):
    a
  else:
    b

proc min*(a, b: Duration): Duration =
  if (a < b):
    a
  else:
    b
