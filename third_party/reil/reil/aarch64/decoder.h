// Copyright 2018 Google LLC
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

#ifndef REIL_AARCH64_DECODER_H_

#include <cstdint>
#include <iostream>
#include <tuple>
#include <vector>

#include <variant>
#if 0
#include "absl/types/variant.h"
#endif

namespace reil {
namespace aarch64 {
namespace decoder {
enum Opcode {
  // PC-relative addressing
  kAdr,
  kAdrp,

  // Add/subtract immediate
  kAddImmediate,
  kSubImmediate,

  // Logical immediate
  kAndImmediate,
  kOrrImmediate,
  kEorImmediate,

  // Move wide immediate
  kMovk,
  kMovn,
  kMovz,

  // Bitfield
  kBfm,
  kSbfm,
  kUbfm,

  // Extract
  kExtr,

  // Conditional branch
  kBCond,

  // Exception generation
  kBrk,
  kDcps1,
  kDcps2,
  kDcps3,
  kHlt,
  kHvc,
  kSmc,
  kSvc,

  // System
  kAutia1716,
  kAutiasp,
  kAutiaz,
  kAutib1716,
  kAutibsp,
  kAutibz,
  kClrex,
  kDmb,
  kDsb,
  kEsb,
  kHint,
  kIsb,
  kMrs,
  kMsr,
  kNop,
  kPacia1716,
  kPaciasp,
  kPaciaz,
  kPacib1716,
  kPacibsp,
  kPacibz,
  kPsbCsync,
  kSev,
  kSevl,
  kSys,
  kSysl,
  kWfe,
  kWfi,
  kXpaclri,
  kYield,

  // Unconditional branch register
  kBlr,
  kBlraa,
  kBlraaz,
  kBlrab,
  kBlrabz,
  kBr,
  kBraa,
  kBraaz,
  kBrab,
  kBrabz,
  kDrps,
  kEret,
  kEretaa,
  kEretaaz,
  kEretab,
  kEretabz,
  kRet,
  kRetaa,
  kRetaaz,
  kRetab,
  kRetabz,

  // Unconditional branch immediate
  kB,
  kBl,

  // Compare and branch
  kCbnz,
  kCbz,

  // Test and branch
  kTbnz,
  kTbz,

  // Load/store exclusive
  kCas,
  kCasa,
  kCasal,
  kCasl,
  kCasp,
  kCaspa,
  kCaspal,
  kCaspl,
  kLdar,
  kLdaxp,
  kLdaxr,
  kLdlar,
  kLdxp,
  kLdxr,
  kStllr,
  kStlr,
  kStlxp,
  kStlxr,
  kStxp,
  kStxr,

  // Load literal
  kSimdLdrLiteral,
  kLdrLiteral,
  kLdrsLiteral,
  kPrfmLiteral,

  // Load/store pair
  kSimdLdnp,
  kSimdLdp,
  kSimdStnp,
  kSimdStp,
  kLdnp,
  kLdp,
  kLdpsw,
  kStnp,
  kStp,

  // Load/store
  kSimdLdr,
  kSimdLdur,
  kSimdStr,
  kSimdStur,
  kLdr,
  kLdrs,
  kLdtr,
  kLdtrs,
  kLdur,
  kLdurs,
  kPrfm,
  kStr,
  kSttr,
  kStur,

  // Data-processing (2 source)
  kAsr,
  kCrc32b,
  kCrc32cb,
  kCrc32ch,
  kCrc32cw,
  kCrc32cx,
  kCrc32h,
  kCrc32w,
  kCrc32x,
  kLsl,
  kLsr,
  kPacga,
  kRor,
  kSdiv,
  kUdiv,

  // Data-processing (1 source)
  kAutda,
  kAutdb,
  kAutia,
  kAutib,
  kClz,
  kCls,
  kPacda,
  kPacdb,
  kPacia,
  kPacib,
  kRbit,
  kRev,
  kRev16,
  kRev32,
  kXpacd,
  kXpaci,

  // Logical (shifted register)
  kAndShiftedRegister,
  kBicShiftedRegister,
  kOrrShiftedRegister,
  kOrnShiftedRegister,
  kEorShiftedRegister,
  kEonShiftedRegister,

  // Add/subtract (shifted register)
  kAddShiftedRegister,
  kSubShiftedRegister,

  // Add/subtract (extended register)
  kAddExtendedRegister,
  kSubExtendedRegister,

  // Add/subtract with carry
  kAdc,
  kSbc,

  // Conditional compare
  kCcmn,
  kCcmp,

  // Conditional select
  kCsel,
  kCsinc,
  kCsinv,
  kCsneg,

  // Data processing (3 source)
  kMadd,
  kMsub,
  kSmaddl,
  kSmulh,
  kSmsubl,
  kUmaddl,
  kUmulh,
  kUmsubl,

  // Unallocated encodings
  kUnallocated,
};

enum ConditionCode {
  kEq = 0b0000,
  kNe = 0b0001,
  kCs = 0b0010,
  kCc = 0b0011,
  kMi = 0b0100,
  kPl = 0b0101,
  kVs = 0b0110,
  kVc = 0b0111,
  kHi = 0b1000,
  kLs = 0b1001,
  kGe = 0b1010,
  kLt = 0b1011,
  kGt = 0b1100,
  kLe = 0b1101,
  kAl = 0b1110,
};

enum OperandType {
  kImmediate,
  kRegister,
  kSystemRegister,
  kShift,
  kExtend,
  kImmediateOffset,
  kRegisterOffset
};

struct Immediate {
  uint8_t size;
  uint64_t value;

  explicit Immediate(uint8_t size_, uint64_t value_)
      : size(size_), value(value_ & (0xffffffffffffffffull >> (64 - size_))) {}
};

struct Register {
  uint8_t size;
  enum Name {
    kX0 = 0,
    kX1,
    kX2,
    kX3,
    kX4,
    kX5,
    kX6,
    kX7,
    kX8,
    kX9,
    kX10,
    kX11,
    kX12,
    kX13,
    kX14,
    kX15,
    kX16,
    kX17,
    kX18,
    kX19,
    kX20,
    kX21,
    kX22,
    kX23,
    kX24,
    kX25,
    kX26,
    kX27,
    kX28,
    kX29,
    kX30,
    kXzr,

    kSp,
    kPc,

    kV0,
    kV1,
    kV2,
    kV3,
    kV4,
    kV5,
    kV6,
    kV7,
    kV8,
    kV9,
    kV10,
    kV11,
    kV12,
    kV13,
    kV14,
    kV15,
    kV16,
    kV17,
    kV18,
    kV19,
    kV20,
    kV21,
    kV22,
    kV23,
    kV24,
    kV25,
    kV26,
    kV27,
    kV28,
    kV29,
    kV30,
    kV31,

    kN,
    kZ,
    kC,
    kV,
  } name;

  explicit Register(uint8_t size_, enum Name name_)
      : size(size_), name(name_) {}
};

struct SystemRegister {
  enum Name {
    kUnknown = 0,
    kSPSel,
    kDAIFSet,
    kDAIFClr,
    kUAO,
    kPAN,
  } name;

  uint8_t op0;
  uint8_t op1;
  uint8_t op2;
  uint8_t crn;
  uint8_t crm;

  explicit SystemRegister(enum Name name_) : name(name_) {}

  explicit SystemRegister(uint8_t op0_, uint8_t op1_, uint8_t op2_,
                          uint8_t crn_, uint8_t crm_)
      : name(kUnknown), op0(op0_), op1(op1_), op2(op2_), crn(crn_), crm(crm_) {}
};

struct Shift {
  enum Type {
    kNone = 0,
    kLsl,
    kLsr,
    kAsr,
    kRol,
    kRor,
  } type;

  uint8_t count;

  explicit Shift(enum Type type_, uint8_t count_)
      : type(type_), count(count_) {}
};

struct Extend {
  enum Type {
    kNone,
    kUxtb,
    kUxth,
    kUxtw,
    kUxtx,
    kLsl,
    kSxtb,
    kSxth,
    kSxtw,
    kSxtx,
  } type;

  uint8_t count;

  explicit Extend(enum Type type_, uint8_t count_)
      : type(type_), count(count_) {}
};

struct ImmediateOffset {
  uint8_t size;
  Register base;
  Immediate offset;
  Shift shift;

  bool writeback;
  bool post_index;

  explicit ImmediateOffset(Register base_, Immediate offset_, Shift shift_,
                           uint8_t size_, bool writeback_ = false,
                           bool post_index_ = false)
      : size(size_),
        base(base_),
        offset(offset_),
        shift(shift_),
        writeback(writeback_),
        post_index(post_index_) {}
};

struct RegisterOffset {
  uint8_t size;
  Register base;
  Register offset;
  Extend extend;

  bool writeback;
  bool post_index;

  explicit RegisterOffset(Register base_, Register offset_, Extend extend_,
                          uint8_t size_, bool writeback_ = false,
                          bool post_index_ = false)
      : size(size_),
        base(base_),
        offset(offset_),
        extend(extend_),
        writeback(writeback_),
        post_index(post_index_) {}
};

typedef std::variant<Immediate, Register, SystemRegister, Shift, Extend,
                      ImmediateOffset, RegisterOffset>
    Operand;
#if 0
typedef absl::variant<Immediate, Register, SystemRegister, Shift, Extend,
                      ImmediateOffset, RegisterOffset>
    Operand;
#endif

struct Instruction {
  uint64_t address;
  enum Opcode opcode;

  std::vector<Operand> operands;

  ConditionCode cc;
  bool set_flags;

  Instruction() : address(0), opcode(kUnallocated), set_flags(false) {}
};

std::tuple<uint64_t, uint64_t> DecodeBitMasks(uint8_t size, Immediate imms,
                                              Immediate immr);
Instruction DecodeInstruction(uint64_t address, uint32_t opcode);

std::ostream &operator<<(std::ostream &stream, const Operand &opnd);
std::ostream &operator<<(std::ostream &stream, const Instruction &insn);
}  // namespace decoder
}  // namespace aarch64
}  // namespace reil

#define REIL_AARCH64_DECODER_H_
#endif  // REIL_AARCH64_DECODER_H_
