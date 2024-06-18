# nim-eth
# Copyright (c) 2020-2024 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.
#

{.push raises: [].}

import std/[tables, lists], results

export results

type
  LRUCache*[K, V] = object of RootObj
    list: DoublyLinkedList[(K, V)] # Head is MRU k:v and tail is LRU k:v
    table: Table[K, DoublyLinkedNode[(K, V)]] # DoublyLinkedNode is already ref
    capacity: int

func init*[K, V](T: type LRUCache[K, V], capacity: int): LRUCache[K, V] =
  LRUCache[K, V](capacity: capacity) # Table and list init is done default

func get*[K, V](lru: var LRUCache[K, V], key: K): Opt[V] =
  let node = lru.table.getOrDefault(key, nil)
  if node.isNil:
    return Opt.none(V)

  lru.list.remove(node)
  lru.list.prepend(node)
  return Opt.some(node.value[1])

func put*[K, V](lru: var LRUCache[K, V], key: K, value: V) =
  let node = lru.table.getOrDefault(key, nil)
  if not node.isNil:
    lru.list.remove(node)
  else:
    if lru.table.len >= lru.capacity:
      lru.table.del(lru.list.tail.value[0])
      lru.list.remove(lru.list.tail)

  lru.list.prepend((key, value))
  lru.table[key] = lru.list.head

func del*[K, V](lru: var LRUCache[K, V], key: K) =
  var node: DoublyLinkedNode[(K, V)]
  if lru.table.pop(key, node):
    lru.list.remove(node)

func len*[K, V](lru: LRUCache[K, V]): int =
  lru.table.len
