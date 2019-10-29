--threads:on
--path:"$projectDir/.."
# rocksdb_backend newChainDB fails compiling without nimOldCaseObjects as
# rocksdb init does this type of assignment
--define:nimOldCaseObjects
