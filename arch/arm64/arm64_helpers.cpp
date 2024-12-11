/*
Copyright 2021 Google LLC

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

https ://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

#include "arch/arm64/arm64_helpers.h"

#include <algorithm>
#include <vector>

#include "common.h"


Register reg(arm64::Register r) {
  switch(r.name) {
        case arm64::Register::kX0:
      return X0;
    case arm64::Register::kX1:
      return X1;
    case arm64::Register::kX2:
      return X2;
    case arm64::Register::kX3:
      return X3;
    case arm64::Register::kX4:
      return X4;
    case arm64::Register::kX5:
      return X5;
    case arm64::Register::kX6:
      return X6;
    case arm64::Register::kX7:
      return X7;
    case arm64::Register::kX8:
      return X8;
    case arm64::Register::kX9:
      return X9;
    case arm64::Register::kX10:
      return X10;
    case arm64::Register::kX11:
      return X11;
    case arm64::Register::kX12:
      return X12;
    case arm64::Register::kX13:
      return X13;
    case arm64::Register::kX14:
      return X14;
    case arm64::Register::kX15:
      return X15;
    case arm64::Register::kX16:
      return X16;
    case arm64::Register::kX17:
      return X17;
    case arm64::Register::kX18:
      return X18;
    case arm64::Register::kX19:
      return X19;
    case arm64::Register::kX20:
      return X20;
    case arm64::Register::kX21:
      return X21;
    case arm64::Register::kX22:
      return X22;
    case arm64::Register::kX23:
      return X23;
    case arm64::Register::kX24:
      return X24;
    case arm64::Register::kX25:
      return X25;
    case arm64::Register::kX26:
      return X26;
    case arm64::Register::kX27:
      return X27;
    case arm64::Register::kX28:
      return X28;
    case arm64::Register::kX29:
      return X29;
    case arm64::Register::kX30:
      return X30;
    case arm64::Register::kXzr:
      return XZR;
    default:
      FATAL("unsupported register");
  }
}

uint32_t bits(uint32_t msb, uint32_t lsb, uint32_t val) {
  uint32_t mask = 0xffffffffu >> (32 - (msb - lsb + 1));
  return (val & mask) << lsb;
}

uint32_t bit(uint32_t lsb) {
  return 1 << lsb;
}

uint32_t EncodeSignedImmediate(const uint8_t msb, const uint8_t lsb, int32_t value) {
  int32_t min = ((2 << (msb - lsb)) / 2) * -1;
  int32_t max = ((2 << (msb - lsb)) / 2) - 1;
  if (value < min || value > max) {
    FATAL("number must be in range [%d, %d], was %d", min, max, value);
    return 0; // not reached
  }
  return bits(msb, lsb, value);
}

uint32_t EncodeUnsignedImmediate(const uint8_t msb, const uint8_t lsb, uint32_t value) {
  int32_t max = ((2 << (msb - lsb))) - 1;
  if (value > max) {
    FATAL("number must be in range [0, %d], was %d", max, value);
    return 0; // not reached
  }
  return bits(msb, lsb, value);
}

uint32_t ldr_lit(Register dst_reg, int64_t rip_offset, size_t size, bool is_signed) {
  uint32_t instr = 0;

  uint32_t opc = 0;
  /**/ if(!is_signed && size == 32) opc = 0b00; // LDR (literal) 32-bit
  else if(!is_signed && size == 64) opc = 0b01; // LDR (literal) 64-bit
  else if( is_signed && size == 32) opc = 0b10; // LDRSW (literal) 32-bit
  else FATAL("size must be either unsigned 32/64, or signed 32\n");

  if (rip_offset & 3) {
    FATAL("rip_offset must be aligned");
  }

  // load/store
  instr |= bits(28, 25, 0b0100);

  // load literal
  instr |= bits(29, 28, 0b01);

  // instr
  instr |= bits(31, 30, opc);
  instr |= EncodeSignedImmediate(23, 5, rip_offset >> 2);
  instr |= bits(4, 0, static_cast<uint32_t>(dst_reg));

  return instr;
}

uint32_t br(Register dst_reg) {
  uint32_t instr = 0;

  // branch exception
  instr |= bits(28, 25, 0b1010);


  // branch register
  instr |= bits(31, 29, 0b110);
  instr |= bits(25, 22, 0b1000);

  instr |= bits(20, 16, 0b11111);

  instr |= bits(9, 5, dst_reg);
  return instr;
}

uint32_t b_cond(const std::string &cond, int32_t off) {
  static const std::vector<std::string> condition_codes = {
      "eq", "ne", "cs", "cc", "mi", "pl", "vs", "vc",
      "hi", "ls", "ge", "lt", "gt", "le", "al", "al"
  };

  if(off & 3) {
    FATAL("offset must be aligned to 4, was: %d", off);
  }

  auto it = std::find(condition_codes.begin(), condition_codes.end(), cond);
  if(it == condition_codes.end()) {
    FATAL("unknown condition: %s", cond.c_str());
  }

  auto cond_bits = std::distance(condition_codes.begin(), it);

  uint32_t instr = 0;

  // branch exception
  instr |= bits(28, 25, 0b1010);
  // branch cond
  instr |= bits(31, 29, 0b010);
  // for cond branch all further instruction bits are 0

  // operands
  instr |= EncodeSignedImmediate(24, 5, off >> 2);
  instr |= bits(3, 0, static_cast<uint32_t>(cond_bits));
  return instr;
}

uint32_t load_store(uint8_t op, uint8_t size, Register data_reg, Register base_reg, int32_t offset) {
  uint32_t instr = 0;

  uint32_t size_bin = 0;
  /**/ if(size == 64) size_bin = 0b11;
  else if(size == 32) size_bin = 0b10;
  else if(size == 16) size_bin = 0b01;
  else if(size ==  8) size_bin = 0b00;
  else FATAL("size must be either 64, 32, 16, or 8\n");

  // load/store
  instr |= bits(28, 25, 0b0100);

  // sz
  instr |= bits(31, 30, size_bin);

  // unscaled imm, reg offset, unsigned imm
  instr |= bits(29, 28, 0b11);

  // LD*R/B/H or / ST*R/B/H
  instr |= bits(23, 22, op);

  instr |= bits(4, 0, static_cast<uint32_t>(data_reg));

  // base 
  instr |= bits(9, 5, static_cast<uint32_t>(base_reg));
  // offset
  instr |= EncodeSignedImmediate(20, 12, offset);

  return instr;
}

uint32_t movzn(Register dst_reg, int32_t imm) {
  uint32_t instr = 0;

  // 64 bit
  instr |= bit(31);

  // data processing imm
  instr |= bits(28, 25, 0b1000);

  // move wide imm
  instr |= bits(25, 23, 0b101);

  if(imm < 0) {
    // movn
    instr |= bits(30, 29, 0b00);
  }
  else {
    // movz
    instr |= bits(30, 29, 0b10);
  }

  instr |= EncodeUnsignedImmediate(20, 5, std::abs(imm));
  instr |= bits(4, 0, static_cast<uint32_t>(dst_reg));
  return instr;
}

uint32_t ldr(uint8_t size, Register data_reg, Register base_reg, int32_t offset) {
  // LD*R/B/H == 0b01
  return load_store(0b01, size, data_reg, base_reg, offset);
}

uint32_t str(uint8_t size, Register data_reg, Register base_reg, int32_t offset) {
  // LD*R/B/H == 0b00
  return load_store(0b00, size, data_reg, base_reg, offset);
}


// TODO: change op to reil instruction constant
uint32_t add_sub_reg_imm(uint8_t op, Register dst_reg, Register src_reg, uint32_t offset) {
  uint32_t instr = 0;

  // data process immm
  instr |= bits(28, 25, 0b01000);

  // add/sub imm
  instr |= bits(25, 23, 0b010);

  // 64 bit
  instr |= bit(31);

  // add or sub
  if(op == 1) {
    // sub
    instr |= bit(30);
  }
  else {
    // add
    // dont set bit
  }

  instr |= bits(4, 0, dst_reg);
  instr |= bits(9, 5, src_reg);
  instr |= EncodeUnsignedImmediate(21, 10, offset);

  return instr;
}


uint32_t cmp(Register src1, Register src2) {
  uint32_t instr = 0;

  // data processing register
  instr |= bits(28, 25, 0b0101);

  // data process reg
  instr |= bits(24, 21, 0b1000);

  // size ==  64 bit
  instr |= bit(31);

  // sub
  instr |= bit(30);

  // set flag
  instr |= bit(29);

  instr |= bits(20, 16, src2);
  instr |= bits(9, 5, src1);
  instr |= bits(4, 0, Register::XZR);
  return instr;
}



uint32_t sub_reg_imm(Register dst_reg, Register src_reg, uint32_t offset) {
  return add_sub_reg_imm(1, dst_reg, src_reg, offset);
}

uint32_t add_reg_imm(Register dst_reg, Register src_reg, uint32_t offset) {
  return add_sub_reg_imm(0, dst_reg, src_reg, offset);
}

uint32_t branch_imm(size_t instr_address, size_t address, bool do_link) {
  uint32_t instr = 0;

  // check 4 byte alignment
  if (address & 3 || instr_address & 3) {
    FATAL("Source and Target address (%lx/%lx) must be alignt to 4 bytes", instr_address, address);
  }

  int32_t offset = (int32_t)(address - instr_address);

  // bl xzr
  instr |= bits(28, 25, 0b1010);
  instr |= EncodeSignedImmediate(25,  0, offset>>2);

  if(do_link) {
    instr |= bit(31);
  }

  return instr;
}

uint32_t orr_shifted_reg(Register dst, Register rn, Register src) {
  uint32_t instr = 0;

  // data processing register
  instr |= bits(28, 25, 0b0101);

  // logical shifted Register

  // size = 64bit
  instr |= bit(31);

  // kOrrShiftedRegister
  instr |= bits(30, 29, 0b01);

  instr |= bits( 4,  0, dst);
  instr |= bits( 9,  5, rn);
  instr |= bits(20, 16, src);

  return instr;
}

// Encode arm64 Bitwise Exclusive OR (shifted register) instruction.
// (https://developer.arm.com/documentation/dui0801/g/A64-General-Instructions/EOR--shifted-register-)
uint32_t eor_shifted_reg(uint8_t sz, Register rd, Register rn, Register rm, arm64::Shift::Type shift_type, uint8_t shift_count) {
  uint32_t instr = 0;

  if(sz == 64) {
    instr |= bit(31);
  }
  else if (sz == 32) {

  }
  else {
    FATAL("eor: unexpected size. Valid is 32 or 64, was %d", sz);
  }

  // data processing register
  instr |= bits(29, 25, 0b0101);

  // logical shift instr
  // bit 28 not set
  // bit 24 not set

  // kEorShiftedRegister
  instr |= bits(30, 29, 0b10);

  // dst
  instr |= bits(4, 0, rd);

  // src1
  instr |= bits(9, 5, rn);

  // src2
  instr |= bits(20, 16, rm);

  // count
  instr |= EncodeUnsignedImmediate(15, 10, shift_count);

  switch (shift_type) {
    case arm64::Shift::kNone:
    case arm64::Shift::kLsl:
      break;
    case arm64::Shift::kLsr:
      instr |= bits(23, 22, 0b01);
      break;
    case arm64::Shift::kAsr:
      instr |= bits(23, 22, 0b10);
      break;
    case arm64::Shift::kRor:
      instr |= bits(23, 22, 0b11);
      break;
    default:
      FATAL("eor: unknown shift type: %d", shift_type);
  }

  return instr;
}

uint32_t movz_imm(Register dst, int32_t imm) {
  uint32_t instr = 0;

  // data processing immediate
  instr |= bits(28, 25, 0b1000);

  // mov wide immediate
  instr |= bits(25, 23, 0b101);

  // size == 64 bit
  instr |= bit(31);

  // kMovz
  instr |= bits(30, 29, 0b10);

  instr |= EncodeUnsignedImmediate(20, 5, imm);
  instr |= bits(4, 0, dst);
  return instr;
}

uint32_t mov(Register dst, Register src) {
  return orr_shifted_reg(dst, Register::XZR, src);
}

uint32_t b(size_t instr_address, size_t address) {
  return branch_imm(instr_address, address, false);
}

uint32_t bl(size_t instr_address, size_t address) {
  return branch_imm(instr_address, address, true);
}

uint32_t ldr_simd_x0_from_ldr_simd_literal(uint32_t orig_inst) {
  uint32_t instr = orig_inst & 0x1F;
  instr |= 0x3C400000;
  uint32_t opc = (orig_inst & 0xC0000000) >> 30;
  if(opc == 0b00) {
    // 32-bit
    instr |= bits(31, 30, 0b10);
    instr |= bits(23, 22, 0b01);
  } else if (opc == 0b01) {
    instr |= bits(31, 30, 0b11);
    instr |= bits(23, 22, 0b01);
  } else if (opc == 0b10) {
    instr |= bits(31, 30, 0b00);
    instr |= bits(23, 22, 0b11);
  } else {
    FATAL("Incorrect ldr_simd_literal instruction");
  }
  return instr;
}
