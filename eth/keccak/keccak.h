// Copyright 2023 The BoringSSL Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#ifndef KECCAK_INTERNAL_H
#define ECCAK_INTERNAL_H

#include <stdint.h>

typedef struct {
  // Note: the state with 64-bit integers comes first so that the size of this
  // struct is easy to compute on all architectures without padding surprises
  // due to alignment.
  uint64_t state[25];
  int64_t absorb_offset;
} keccak_st;

void keccak_init(keccak_st *ctx);
void keccak_update(keccak_st *ctx, const uint8_t *in, size_t in_len);
#define keccak_update_char(ctx, in, in_len) keccak_update(ctx, (const uint8_t *) in, in_len)
void keccak_finish(keccak_st *ctx, uint8_t *out, size_t out_len);
void keccak256_20(const uint8_t *in, uint8_t *out);
void keccak256_32(const uint8_t *in, uint8_t *out);

#endif  // KECCAK_INTERNAL_H
