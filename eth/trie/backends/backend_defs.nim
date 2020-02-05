type
  StorageError* = object of CatchableError

template raiseStorageInitError* =
  raise newException(StorageError, "failure to initialize storage")

template raiseKeyReadError*(key: auto) =
  raise newException(StorageError, "failed to read key " & $key)

template raiseKeyWriteError*(key: auto) =
  raise newException(StorageError, "failed to write key " & $key)

template raiseKeySearchError*(key: auto) =
  raise newException(StorageError, "failure during search for key " & $key)

template raiseKeyDeletionError*(key: auto) =
  raise newException(StorageError, "failure to delete key " & $key)

