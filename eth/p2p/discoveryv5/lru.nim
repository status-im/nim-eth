import std/[tables, lists, options]

{.push raises: [Defect].}

type
  LRUCache*[K, V] = object of RootObj
    list: DoublyLinkedList[(K, V)] # Head is MRU k:v and tail is LRU k:v
    table: Table[K, DoublyLinkedNode[(K, V)]] # DoublyLinkedNode is already ref
    capacity: int

func init*[K, V](T: type LRUCache[K, V], capacity: int): LRUCache[K, V] =
  LRUCache[K, V](capacity: capacity) # Table and list init is done default

func get*[K, V](lru: var LRUCache[K, V], key: K): Option[V] =
  let node = lru.table.getOrDefault(key, nil)
  if node.isNil:
    return none(V)

  lru.list.remove(node)
  lru.list.prepend(node)
  return some(node.value[1])

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
