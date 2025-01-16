#!/bin/bash

# eth
# Copyright (c) 2019-2025 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

objs=("tx" "header" "blk" "blk80" "blk320" "blk640" "blk1280")

for obj in "${objs[@]}"; do
  nim compile --mm:orc -d:$obj -d:release --out:bench_"$obj"_default profiler.nim
  nim compile --mm:orc -d:$obj -d:opt -d:release --out:bench_"$obj"_two_pass profiler.nim
  nim compile --mm:orc -d:$obj -d:hash -d:release --out:bench_"$obj"_default_hash profiler.nim
  nim compile --mm:orc -d:$obj -d:hash -d:opt -d:release --out:bench_"$obj"_hash_writer profiler.nim
  nim compile --mm:refc -d:$obj -d:release --out:bench_"$obj"_default_refc profiler.nim
  nim compile --mm:refc -d:$obj -d:opt -d:release --out:bench_"$obj"_two_pass_refc profiler.nim
  nim compile --mm:refc -d:$obj -d:hash -d:release --out:bench_"$obj"_default_hash_refc profiler.nim
  nim compile --mm:refc -d:$obj -d:hash -d:opt -d:release --out:bench_"$obj"_hash_writer_refc profiler.nim
done

for obj in "${objs[@]}"; do
  source ./bench_"$obj"_default
  source ./bench_"$obj"_two_pass
  source ./bench_"$obj"_default_hash
  source ./bench_"$obj"_hash_writer
  source ./bench_"$obj"_default_refc
  source ./bench_"$obj"_two_pass_refc
  source ./bench_"$obj"_default_hash_refc
  source ./bench_"$obj"_hash_writer_refc
done
