{.used.}

import
  unittest,
  eth/trie/nibbles

suite "nibbles":
  test "zeroNibblesRange":
    # https://github.com/status-im/nim-eth/issues/6
    check zeroNibblesRange.len == 0

