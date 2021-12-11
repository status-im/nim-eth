{.used.}

import
  std/options,
  unittest2,
  ../../eth/p2p/discoveryv5/lru

suite "LRUCache":
  const
    capacity = 10
    target = 4
  test "LRU value gets removed":
    var lru = LRUCache[int, int].init(capacity = capacity)

    # Fully fill the LRU
    for i in 0..<capacity:
      lru.put(i, i) # new key, so new put

    # Get value for each key
    for i in 0..<capacity:
      let val = lru.get(i)
      check:
        val.isSome()
        val.get() == i

    check lru.len() == capacity

    # Add one new key
    lru.put(capacity, 0)
    # Oldest one should be gone
    check:
      lru.len() == capacity
      lru.get(0).isNone()
      lru.get(capacity).isSome()

  test "LRU renew oldest by get":
    var lru = LRUCache[int, int].init(capacity = capacity)

    for i in 0..<capacity:
      lru.put(i, i)

    var val = lru.get(0)
    check:
      val.isSome
      val.get() == 0

    lru.put(capacity, 0)

    val = lru.get(0)
    check:
      lru.len() == capacity
      val.isSome()
      val.get() == 0

  test "LRU renew oldest by put":
    var lru = LRUCache[int, int].init(capacity = capacity)

    for i in 0..<capacity:
      lru.put(i, i)

    lru.put(0, 1)
    check lru.len() == capacity

    lru.put(capacity, 0)

    let val = lru.get(0)
    check:
      lru.len() == capacity
      val.isSome()
      val.get() == 1

  test "LRU renew by put":
    var lru = LRUCache[int, int].init(capacity = capacity)

    for i in 0..<capacity:
      lru.put(i, i)

    lru.put(target, 1)
    check lru.len() == capacity

    lru.put(capacity, 0)

    let val = lru.get(target)
    check:
      lru.len() == capacity
      val.isSome()
      val.get() == 1

  test "LRU renew by get":
    var lru = LRUCache[int, int].init(capacity = capacity)

    for i in 0..<capacity:
      lru.put(i, i)

    var val = lru.get(target)
    check:
      val.isSome
      val.get() == target

    lru.put(capacity, 0)

    val = lru.get(target)
    check:
      lru.len() == capacity
      val.isSome()
      val.get() == target

  test "LRU delete oldest and add":
    var lru = LRUCache[int, int].init(capacity = capacity)

    for i in 0..<capacity:
      lru.put(i, i)

    lru.del(0)
    check lru.len == capacity - 1

    lru.put(0, 1)
    check lru.len == capacity

    lru.put(capacity, 0)

    let val = lru.get(0)
    check:
      lru.len() == capacity
      val.isSome()
      val.get() == 1
  test "LRU delete not existing":
    var lru = LRUCache[int, int].init(capacity = capacity)

    for i in 0..<capacity:
      lru.put(i, i)

    lru.del(capacity)
    check lru.len == capacity
