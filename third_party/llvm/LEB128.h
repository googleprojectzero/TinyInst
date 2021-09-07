//===- llvm/Support/LEB128.h - [SU]LEB128 utility functions -----*- C++ -*-===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This file declares some utility functions for encoding SLEB128 and
// ULEB128 values.
//
//===----------------------------------------------------------------------===//

#ifndef LLVM_SUPPORT_LEB128_H
#define LLVM_SUPPORT_LEB128_H

#include <vector>

/// Utility function to encode a value into SLEB128 and store it in a byte stream.
inline void encodeSLEB128(int64_t Value, std::vector<uint8_t> &byte_stream,
                              unsigned PadTo = 0) {
  unsigned Count = 0;
  bool More;
  do {
    uint8_t Byte = Value & 0x7f;
    // NOTE: this assumes that this signed shift is an arithmetic right shift.
    Value >>= 7;
    More = !((((Value == 0 ) && ((Byte & 0x40) == 0)) ||
              ((Value == -1) && ((Byte & 0x40) != 0))));
    Count++;
    if (More || Count < PadTo)
      Byte |= 0x80; // Mark this byte to show that more bytes will follow.
    byte_stream.push_back(Byte);
  } while (More);

  // Pad with 0x80 and emit a terminating byte at the end.
  if (Count < PadTo) {
    uint8_t PadValue = Value < 0 ? 0x7f : 0x00;
    for (; Count < PadTo - 1; ++Count)
      byte_stream.push_back(PadValue | 0x80);
    byte_stream.push_back(PadValue);
  }
}

/// Utility function to encode a value into ULEB128 and store it in a byte stream.
inline void encodeULEB128(uint64_t Value, std::vector<uint8_t> &byte_stream,
                              unsigned PadTo = 0) {
  unsigned Count = 0;
  do {
    uint8_t Byte = Value & 0x7f;
    Value >>= 7;
    Count++;
    if (Value != 0 || Count < PadTo)
      Byte |= 0x80; // Mark this byte to show that more bytes will follow.
    byte_stream.push_back(Byte);
  } while (Value != 0);

  // Pad with 0x80 and emit a null byte at the end.
  if (Count < PadTo) {
    for (; Count < PadTo - 1; ++Count)
      byte_stream.push_back('\x80');
    byte_stream.push_back('\x00');
  }
}

#endif // LLVM_SUPPORT_LEB128_H
