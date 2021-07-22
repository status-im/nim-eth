{.used.}

import
  std/[unittest],
  ../../eth/net/utils,
  chronos


suite "Test IPv4/v6 related helper functions":
  test "isWrappedIPv4":
    check(isWrappedIPv4(initTAddress("::", 0)) == false)
    check(isWrappedIPv4(initTAddress("192.168.0.0", 0)) == false)
    check(isWrappedIPv4(initTAddress("::ffff:c0a8:8b32", 0)) == true)

  test "unwrapIPv4InIPv6":
    let ta6 = initTAddress("::ffff:c0a8:8b32", 0)
    let ta4 = initTAddress("192.168.139.50", 0)

    check(ta4 == unwrapIPv4InIPv6(ta6))

  test "wrapIPv4InIPv6":
    let ta4 = initTAddress("9.9.9.9", 0)
    let ta6 = initTAddress("::ffff:909:909", 0)

    check(ta6 == wrapIPv4InIPv6(ta4))

  test "both":
    let ta4 = initTAddress("9.9.9.9", 0)

    check(unwrapIPv4InIPv6(wrapIPv4InIPv6(ta4)) == ta4)