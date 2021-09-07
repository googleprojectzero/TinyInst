//===-------------------------- CompactUnwinder.hpp -----------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//
//  Does runtime stack unwinding using compact unwind encodings.
//
//===----------------------------------------------------------------------===//

#ifndef __COMPACT_UNWINDER_HPP__
#define __COMPACT_UNWINDER_HPP__

#define EXTRACT_BITS(value, mask)                                              \
  ((value >> __builtin_ctz(mask)) & (((1 << __builtin_popcount(mask))) - 1))

#endif // __COMPACT_UNWINDER_HPP__
