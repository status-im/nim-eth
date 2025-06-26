# eth
# Copyright (c) 2019-2024 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

const
  BLOB_START_MARKER* = byte(0x80)
  LIST_START_MARKER* = byte(0xc0)

  THRESHOLD_LEN* = 56

  LEN_PREFIXED_BLOB_MARKER* = byte(BLOB_START_MARKER + THRESHOLD_LEN - 1) # 183
  LEN_PREFIXED_LIST_MARKER* = byte(LIST_START_MARKER + THRESHOLD_LEN - 1) # 247
