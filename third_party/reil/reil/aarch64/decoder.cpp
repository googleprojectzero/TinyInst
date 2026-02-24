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

#include "reil/aarch64/decoder.h"

#include <cstdint>
#include <tuple>

namespace reil {
namespace aarch64 {
namespace decoder {

static constexpr uint32_t bits(uint32_t opcode, uint8_t lsb, uint8_t msb) {
  return (opcode & ((0xffffffffu >> (32 - (msb - lsb + 1))) << lsb)) >> lsb;
}

static constexpr uint32_t bit(uint32_t opcode, uint8_t lsb) {
  return (opcode >> lsb) & 1;
}

static uint64_t sign_extend_bits(uint32_t opcode, uint8_t lsb, uint8_t msb) {
  uint32_t mask = (0xffffffffu >> (32 - (msb - lsb + 1))) << lsb;
  uint64_t sign_mask = 0;
  if ((opcode >> msb) & 1) {
    sign_mask = (0xffffffffffffffffull << (msb - lsb + 1));
  }
  return sign_mask | ((opcode & mask) >> lsb);
}

static Register v(uint8_t size, uint32_t opcode, uint8_t lsb, uint8_t msb) {
  return Register(size, static_cast<Register::Name>(Register::kV0 +
                                                    bits(opcode, lsb, msb)));
}

static Register x(uint8_t size, uint32_t opcode, uint8_t lsb, uint8_t msb) {
  return Register(size, static_cast<Register::Name>(bits(opcode, lsb, msb)));
}

static Register x_or_sp(uint8_t size, uint32_t opcode, uint8_t lsb,
                        uint8_t msb) {
  if (bits(opcode, lsb, msb) == 31) {
    return Register(size, Register::Name::kSp);
  } else {
    return Register(size, static_cast<Register::Name>(bits(opcode, lsb, msb)));
  }
}

static std::tuple<uint64_t, uint64_t> decode_bit_masks(uint64_t immN,
                                                       uint64_t imms,
                                                       uint64_t immr,
                                                       bool immediate) {
  // imms + 1 bits of 1, rotated by immr, then replicated to the target size.

  uint64_t element_size = 0;
  uint64_t element_mask = 0;
  if (immN) {
    element_size = 64;
    element_mask = 0xffffffffffffffffull;
  } else {
    element_size = 32;
    while (element_size >= 2 && !(element_size & (~imms))) {
      element_size >>= 1;
    }
    element_mask = (1ull << element_size) - 1;
  }

  uint64_t s = imms & (element_size - 1);
  uint64_t r = immr & (element_size - 1);
  uint64_t d = (s - r) & (element_size - 1);

  // TODO: validation for valid values?

  uint64_t welement = 0xffffffffffffffffull >> (64 - (s + 1));
  if (r != 0) {
    uint64_t welement_left = (welement << (element_size - r)) & element_mask;
    uint64_t welement_right = welement >> r;
    welement = welement_left | welement_right;
  }
  uint64_t telement = 0xffffffffffffffffull >> (64 - (d + 1));

  // always replicate to 64-bits and truncate later.
  uint64_t wmask = welement;
  uint64_t tmask = telement;
  while (element_size && element_size < 64) {
    wmask |= (wmask << element_size);
    tmask |= (tmask << element_size);
    element_size <<= 1;
  }

  return {wmask, tmask};
}

static Instruction UnallocatedEncoding() {
  Instruction insn;
  insn.opcode = kUnallocated;
  return insn;
}

static Instruction DecodePcRelativeAddressing(uint32_t opcode);
static Instruction DecodeAddSubtractImmediate(uint32_t opcode);
static Instruction DecodeLogicalImmediate(uint32_t opcode);
static Instruction DecodeMoveWideImmediate(uint32_t opcode);
static Instruction DecodeBitfield(uint32_t opcode);
static Instruction DecodeExtract(uint32_t opcode);

inline Instruction DecodeDataProcessingImmediate(uint32_t opcode) {
  uint32_t op0 = bits(opcode, 23, 25);
  if ((op0 & 0b110) == 0b000) {
    return DecodePcRelativeAddressing(opcode);
  } else if ((op0 & 0b110) == 0b010) {
    return DecodeAddSubtractImmediate(opcode);
  } else if (op0 == 0b100) {
    return DecodeLogicalImmediate(opcode);
  } else if (op0 == 0b101) {
    return DecodeMoveWideImmediate(opcode);
  } else if (op0 == 0b110) {
    return DecodeBitfield(opcode);
  } else if (op0 == 0b111) {
    return DecodeExtract(opcode);
  }

  return UnallocatedEncoding();
}

static Instruction DecodePcRelativeAddressing(uint32_t opcode) {
  Instruction insn;

  if (bit(opcode, 31)) {
    insn.opcode = kAdrp;
  } else {
    insn.opcode = kAdr;
  }

  insn.operands.push_back(x(64, opcode, 0, 4));
  insn.operands.push_back(Immediate(
      64, (sign_extend_bits(opcode, 5, 23) << 2) | bits(opcode, 29, 30)));

  Shift shift(Shift::kNone, 0);
  if (insn.opcode == kAdrp) {
    shift.type = Shift::kLsl;
    shift.count = 12;
  }

  insn.operands.push_back(shift);

  return insn;
}

static Instruction DecodeAddSubtractImmediate(uint32_t opcode) {
  Instruction insn;
  uint8_t size = 32 << bit(opcode, 31);

  insn.set_flags = bit(opcode, 29);
  if (bit(opcode, 30)) {
    insn.opcode = kSubImmediate;
  } else {
    insn.opcode = kAddImmediate;
  }

  if (insn.set_flags) {
    insn.operands.push_back(x(size, opcode, 0, 4));
  } else {
    insn.operands.push_back(x_or_sp(size, opcode, 0, 4));
  }

  insn.operands.push_back(x_or_sp(size, opcode, 5, 9));
  insn.operands.push_back(Immediate(size, bits(opcode, 10, 21)));

  Shift shift(Shift::kNone, 0);
  if (bits(opcode, 22, 23) == 1) {
    shift.type = Shift::kLsl;
    shift.count = 12;
  }

  insn.operands.push_back(shift);

  return insn;
}

static Instruction DecodeLogicalImmediate(uint32_t opcode) {
  Instruction insn;
  uint8_t size = 32 << bit(opcode, 31);

  switch (bits(opcode, 29, 30)) {
    case 0b00: {
      insn.opcode = kAndImmediate;
    } break;

    case 0b01: {
      insn.opcode = kOrrImmediate;
    } break;

    case 0b10: {
      insn.opcode = kEorImmediate;
    } break;

    case 0b11: {
      insn.opcode = kAndImmediate;
      insn.set_flags = true;
    } break;
  }

  if (insn.set_flags) {
    insn.operands.push_back(x(size, opcode, 0, 4));
  } else {
    insn.operands.push_back(x_or_sp(size, opcode, 0, 4));
  }

  insn.operands.push_back(x(size, opcode, 5, 9));

  uint64_t value, _;
  std::tie(value, _) = decode_bit_masks(bit(opcode, 22), bits(opcode, 10, 15),
                                        bits(opcode, 16, 21), true);

  insn.operands.push_back(Immediate(size, value));

  return insn;
}

static Instruction DecodeMoveWideImmediate(uint32_t opcode) {
  Instruction insn;
  uint8_t size = 32 << bit(opcode, 31);

  // check that the shift value is in range
  if (bits(opcode, 21, 22) << 4 >= size) {
    return UnallocatedEncoding();
  }

  switch (bits(opcode, 29, 30)) {
    case 0b00: {
      insn.opcode = kMovn;
    } break;

    case 0b10: {
      insn.opcode = kMovz;
    } break;

    case 0b11: {
      insn.opcode = kMovk;
    } break;

    default:
      return UnallocatedEncoding();
  }

  insn.operands.push_back(x(size, opcode, 0, 4));
  insn.operands.push_back(Immediate(size, bits(opcode, 5, 20)));
  insn.operands.push_back(Shift(Shift::kLsl, bits(opcode, 21, 22) << 4));

  return insn;
}

static Instruction DecodeBitfield(uint32_t opcode) {
  Instruction insn;
  uint8_t size = 32 << bit(opcode, 31);

  if (bit(opcode, 22) != bit(opcode, 31)) {
    return UnallocatedEncoding();
  }

  switch (bits(opcode, 29, 30)) {
    case 0b00: {
      insn.opcode = kSbfm;
    } break;

    case 0b01: {
      insn.opcode = kBfm;
    } break;

    case 0b10: {
      insn.opcode = kUbfm;
    } break;

    default:
      return UnallocatedEncoding();
  }

  insn.operands.push_back(x(size, opcode, 0, 4));
  insn.operands.push_back(x(size, opcode, 5, 9));
  insn.operands.push_back(Immediate(size, bits(opcode, 16, 21)));
  insn.operands.push_back(Immediate(size, bits(opcode, 10, 15)));

  return insn;
}

static Instruction DecodeExtract(uint32_t opcode) {
  Instruction insn;
  uint8_t size = 32 << bit(opcode, 31);

  if (bit(opcode, 22) != bit(opcode, 31)) {
    return UnallocatedEncoding();
  }

  insn.opcode = kExtr;

  insn.operands.push_back(x(size, opcode, 0, 4));
  insn.operands.push_back(x(size, opcode, 5, 9));
  insn.operands.push_back(x(size, opcode, 16, 20));
  insn.operands.push_back(Immediate(8, bits(opcode, 10, 15)));

  return insn;
}

static Instruction DecodeConditionalBranch(uint32_t opcode);
static Instruction DecodeExceptionGeneration(uint32_t opcode);
static Instruction DecodeSystem(uint32_t opcode);
static Instruction DecodeBranchRegister(uint32_t opcode);
static Instruction DecodeBranchImmediate(uint32_t opcode);
static Instruction DecodeCompareAndBranch(uint32_t opcode);
static Instruction DecodeTestAndBranch(uint32_t opcode);

static Instruction DecodeBranchExceptionGeneratingSystem(uint32_t opcode) {
  uint32_t op0 = bits(opcode, 29, 31);
  uint32_t op1 = bits(opcode, 22, 25);
  if (op0 == 0b010) {
    if ((op1 & 0b1000) == 0b0000) {
      return DecodeConditionalBranch(opcode);
    }
  } else if (op0 == 0b110) {
    if ((op1 & 0b1100) == 0b0000) {
      return DecodeExceptionGeneration(opcode);
    } else if (op1 == 0b0100) {
      return DecodeSystem(opcode);
    } else if ((op1 & 0b1000) == 0b1000) {
      return DecodeBranchRegister(opcode);
    }
  } else if ((op0 & 0b011) == 0b000) {
    return DecodeBranchImmediate(opcode);
  } else if ((op0 & 0b011) == 0b001) {
    if ((op1 & 0b1000) == 0b0000) {
      return DecodeCompareAndBranch(opcode);
    } else {
      return DecodeTestAndBranch(opcode);
    }
  }

  return UnallocatedEncoding();
}

static Instruction DecodeConditionalBranch(uint32_t opcode) {
  Instruction insn;

  insn.opcode = kBCond;
  insn.cc = (ConditionCode)bits(opcode, 0, 3);

  if (bit(opcode, 24) || bit(opcode, 4)) {
    return UnallocatedEncoding();
  }

  insn.operands.push_back(Immediate(64, sign_extend_bits(opcode, 5, 23) << 2));

  return insn;
}

static Instruction DecodeExceptionGeneration(uint32_t opcode) {
  Instruction insn;

  uint8_t opc = bits(opcode, 21, 23);
  uint8_t ll = bits(opcode, 0, 1);

  if (bits(opcode, 2, 4)) {
    return UnallocatedEncoding();
  }

  if (opc == 0b000) {
    if (ll == 0b01) {  // SVC
      insn.opcode = kSvc;
    } else if (ll == 0b10) {  // HVC
      insn.opcode = kHvc;
    } else if (ll == 0b11) {  // SMC
      insn.opcode = kSmc;
    } else {
      return UnallocatedEncoding();
    }
  } else if (opc == 0b001) {
    if (ll == 0b00) {  // BRK
      insn.opcode = kBrk;
    } else {
      return UnallocatedEncoding();
    }
  } else if (opc == 0b010) {
    if (ll == 0b00) {  // HLT
      insn.opcode = kHlt;
    } else {
      return UnallocatedEncoding();
    }
  } else if (opc == 0b101) {
    if (ll == 0b01) {  // DCPS1
      insn.opcode = kDcps1;
    } else if (ll == 0b10) {  // DCPS2
      insn.opcode = kDcps2;
    } else if (ll == 0b11) {  // DCPS3
      insn.opcode = kDcps3;
    } else {
      return UnallocatedEncoding();
    }
  } else {
    return UnallocatedEncoding();
  }

  insn.operands.push_back(Immediate(32, bits(opcode, 5, 20)));

  return insn;
}

static Instruction DecodeSystem(uint32_t opcode) {
  Instruction insn;

  uint8_t l = bit(opcode, 21);
  uint8_t op0 = bits(opcode, 19, 20);
  uint8_t op1 = bits(opcode, 16, 18);
  uint8_t op2 = bits(opcode, 5, 7);
  uint8_t crn = bits(opcode, 12, 15);
  uint8_t crm = bits(opcode, 8, 11);
  uint8_t rt = bits(opcode, 0, 4);

  uint8_t imm = bits(opcode, 5, 11);

  if (!l) {
    if (op0 == 0b00) {
      if (crn == 0b0100 && rt == 0b11111) {  // MSR (immediate)
        insn.opcode = kMsr;
        switch (op1 << 3 | op2) {
          case 0b000101: {
            insn.operands.push_back(SystemRegister(SystemRegister::kSPSel));
          } break;

          case 0b011110: {
            insn.operands.push_back(SystemRegister(SystemRegister::kDAIFSet));
          } break;

          case 0b011111: {
            insn.operands.push_back(SystemRegister(SystemRegister::kDAIFClr));
          } break;

          case 0b000011: {
            insn.operands.push_back(SystemRegister(SystemRegister::kUAO));
          } break;

          case 0b000100: {
            insn.operands.push_back(SystemRegister(SystemRegister::kPAN));
          } break;

          default:
            return UnallocatedEncoding();
        }
        insn.operands.push_back(Immediate(8, crm));
      } else if (op1 == 0b011) {
        if (crn == 0b0010) {
          switch (imm) {
            case 0b0000000: {  // NOP
              insn.opcode = kNop;
            } break;

            case 0b0000001: {  // YIELD
              insn.opcode = kYield;
            } break;

            case 0b0000010: {  // WFE
              insn.opcode = kWfe;
            } break;

            case 0b0000011: {  // WFI
              insn.opcode = kWfi;
            } break;

            case 0b0000100: {  // SEV
              insn.opcode = kSev;
            } break;

            case 0b0000101: {  // SEVL
              insn.opcode = kSevl;
            } break;

            case 0b0000111: {  // XPACLRI
              insn.opcode = kXpaclri;
            } break;

            case 0b0001000: {  // PACIA1716
              insn.opcode = kPacia1716;
            } break;

            case 0b0001010: {  // PACIB1716
              insn.opcode = kPacib1716;
            } break;

            case 0b0001100: {  // AUTIA1716
              insn.opcode = kAutia1716;
            } break;

            case 0b0001110: {  // AUTIA1716
              insn.opcode = kAutib1716;
            } break;

            case 0b0010000: {  // ESB
              insn.opcode = kEsb;
            } break;

            case 0b0010001: {  // PSB CSYNC
              insn.opcode = kPsbCsync;
            } break;

            case 0b0011000: {  // PACIAZ
              insn.opcode = kPaciaz;
            } break;

            case 0b0011001: {  // PACIASP
              insn.opcode = kPaciasp;
            } break;

            case 0b0011010: {  // PACIBZ
              insn.opcode = kPacibz;
            } break;

            case 0b0011011: {  // PACIBSP
              insn.opcode = kPacibsp;
            } break;

            case 0b0011100: {  // AUTIAZ
              insn.opcode = kAutiaz;
            } break;

            case 0b0011101: {  // AUTIASP
              insn.opcode = kAutiasp;
            } break;

            case 0b0011110: {  // AUTIBZ
              insn.opcode = kAutibz;
            } break;

            case 0b0011111: {  // AUTIBSP
              insn.opcode = kAutibsp;
            } break;

            default: {  // HINT
              insn.opcode = kHint;
              insn.operands.push_back(Immediate(8, crm));
            } break;
          }
        } else if (crn == 0b0011) {
          if (op2 == 0b010) {  // CLREX
            insn.opcode = kClrex;
          } else if (op2 == 0b100) {  // DSB
            insn.opcode = kDsb;
            insn.operands.push_back(Immediate(8, crm));
          } else if (op2 == 0b101) {  // DMB
            insn.opcode = kDmb;
            insn.operands.push_back(Immediate(8, crm));
          } else if (op2 == 0b110) {  // ISB
            insn.opcode = kIsb;
            insn.operands.push_back(Immediate(8, crm));
          } else {
            return UnallocatedEncoding();
          }
        }
      }
    } else if (op0 == 0b01) {  // SYS
      insn.opcode = kSys;
      insn.operands.push_back(Immediate(8, op1));
      insn.operands.push_back(Immediate(8, crn));
      insn.operands.push_back(Immediate(8, crm));
      insn.operands.push_back(Immediate(8, op2));
      insn.operands.push_back(x(64, opcode, 0, 4));
    } else if (op0) {  // MSR (register)
      insn.opcode = kMsr;
      insn.operands.push_back(SystemRegister(op0, op1, op2, crn, crm));
      insn.operands.push_back(x(64, opcode, 0, 4));
    }
  } else {
    if (op0 == 0b01) {  // SYSL
      insn.opcode = kSysl;
      insn.operands.push_back(x(64, opcode, 0, 4));
      insn.operands.push_back(Immediate(8, op1));
      insn.operands.push_back(Immediate(8, crn));
      insn.operands.push_back(Immediate(8, crm));
      insn.operands.push_back(Immediate(8, op2));
    } else if (op0) {  // MRS
      insn.opcode = kMrs;
      insn.operands.push_back(x(64, opcode, 0, 4));
      insn.operands.push_back(SystemRegister(op0, op1, op2, crn, crm));
    } else {
      return UnallocatedEncoding();
    }
  }
  return insn;
}

static Instruction DecodeBranchRegister(uint32_t opcode) {
  Instruction insn;

  uint8_t opc = bits(opcode, 21, 24);
  uint8_t op2 = bits(opcode, 16, 20);
  uint8_t op3 = bits(opcode, 10, 15);
  uint8_t op4 = bits(opcode, 0, 4);

  insn.operands.push_back(x(64, opcode, 5, 9));

  if (op2 != 0b11111 ||
      (op3 != 0b000000 && op3 != 0b000010 && op3 != 0b000011)) {
    return UnallocatedEncoding();
  }

  if (opc == 0b0000) {  // BR
    if (op3) {
      if (op3 == 0b000010 && op4 == 0b11111) {
        insn.opcode = kBraaz;
      } else if (op3 == 0b000011 && op4 == 0b11111) {
        insn.opcode = kBrabz;
      } else {
        return UnallocatedEncoding();
      }
    } else {
      insn.opcode = kBr;
    }
  } else if (opc == 0b0001) {  // BLR
    if (op3) {
      if (op3 == 0b000010 && op4 == 0b11111) {
        insn.opcode = kBlraaz;
      } else if (op3 == 0b000011 && op4 == 0b11111) {
        insn.opcode = kBlrabz;
      } else {
        return UnallocatedEncoding();
      }
    } else {
      insn.opcode = kBlr;
    }
  } else if (opc == 0b0010) {  // RET
    if (op3) {
      if (op3 == 0b000010 && op4 == 0b11111) {
        insn.opcode = kRetaa;
      } else if (op3 == 0b000011 && op4 == 0b11111) {
        insn.opcode = kRetab;
      } else {
        return UnallocatedEncoding();
      }
    } else {
      insn.opcode = kRet;
    }
  } else if (opc == 0b0100) {  // ERET
    if (op3) {
      if (op3 == 0b000010 && op4 == 0b11111) {
        insn.opcode = kEretaa;
      } else if (op3 == 0b000011 && op4 == 0b11111) {
        insn.opcode = kEretab;
      } else {
        return UnallocatedEncoding();
      }
    } else {
      insn.opcode = kEret;
    }
  } else if (opc == 0b0101) {  // DRPS
    insn.opcode = kDrps;
  } else if (opc == 0b1000) {  // BRA*
    if (op3 == 0b000010) {
      insn.opcode = kBraa;
    } else if (op3 == 0b000011) {
      insn.opcode = kBrab;
    } else {
      return UnallocatedEncoding();
    }
    insn.operands.push_back(x_or_sp(64, opcode, 0, 4));
  } else if (opc == 0b1001) {  // BLRA*
    if (op3 == 0b000010) {
      insn.opcode = kBlraa;
    } else if (op3 == 0b000011) {
      insn.opcode = kBlrab;
    } else {
      return UnallocatedEncoding();
    }
    insn.operands.push_back(x_or_sp(64, opcode, 0, 4));
  } else {
    return UnallocatedEncoding();
  }

  return insn;
}

static Instruction DecodeBranchImmediate(uint32_t opcode) {
  Instruction insn;

  insn.operands.push_back(Immediate(64, sign_extend_bits(opcode, 0, 25) << 2));

  if (bit(opcode, 31)) {
    insn.opcode = kBl;
  } else {
    insn.opcode = kB;
  }

  return insn;
}

static Instruction DecodeCompareAndBranch(uint32_t opcode) {
  Instruction insn;
  uint8_t size = 32 << bit(opcode, 31);

  if (!bit(opcode, 24)) {
    insn.opcode = kCbz;
  } else {
    insn.opcode = kCbnz;
  }

  insn.operands.push_back(x(size, opcode, 0, 4));
  insn.operands.push_back(Immediate(64, sign_extend_bits(opcode, 5, 23) << 2));

  return insn;
}

static Instruction DecodeTestAndBranch(uint32_t opcode) {
  Instruction insn;
  uint8_t size = 32 << bit(opcode, 31);

  if (!bit(opcode, 24)) {
    insn.opcode = kTbz;
  } else {
    insn.opcode = kTbnz;
  }

  insn.operands.push_back(x(size, opcode, 0, 4));
  insn.operands.push_back(
      Immediate(64, (bit(opcode, 31) << 5) | bits(opcode, 19, 23)));
  insn.operands.push_back(Immediate(64, sign_extend_bits(opcode, 5, 18) << 2));

  return insn;
}

static Instruction DecodeSIMDLoadLiteral(uint32_t opcode);
static Instruction DecodeSIMDLoadStorePair(uint32_t opcode);
static Instruction DecodeSIMDLoadStoreUnscaledImmediate(uint32_t opcode);
static Instruction DecodeSIMDLoadStoreRegisterOffset(uint32_t opcode);
static Instruction DecodeSIMDLoadStoreUnsignedImmediate(uint32_t opcode);

static Instruction DecodeLoadStoreExclusive(uint32_t opcode);
static Instruction DecodeLoadLiteral(uint32_t opcode);
static Instruction DecodeLoadStorePair(uint32_t opcode);
static Instruction DecodeLoadStoreUnscaledImmediate(uint32_t opcode);
static Instruction DecodeLoadStoreRegisterOffset(uint32_t opcode);
static Instruction DecodeLoadStoreUnsignedImmediate(uint32_t opcode);

static Instruction DecodeLoadStore(uint32_t opcode) {
  // uint8_t op0 = bit(opcode, 31);
  uint8_t op1 = bits(opcode, 28, 29);
  uint8_t op2 = bit(opcode, 26);
  uint8_t op3 = bits(opcode, 23, 24);
  uint8_t op4 = bits(opcode, 16, 21);
  uint8_t op5 = bits(opcode, 10, 11);

  if (op2 == 0b1) {
    // SIMD instructions
    if (op1 == 0b01 && ((op3 & 0b10) == 0b00)) {
      return DecodeSIMDLoadLiteral(opcode);
    } else if (op1 == 0b10) {
      return DecodeSIMDLoadStorePair(opcode);
    } else if (op1 == 0b11) {
      if ((op3 & 0b10) == 0b00) {
        if ((op4 & 0b100000) == 0b000000) {
          return DecodeSIMDLoadStoreUnscaledImmediate(opcode);
        } else if ((op4 & 0b100000) == 0b100000 && op5 == 0b10) {
          return DecodeSIMDLoadStoreRegisterOffset(opcode);
        }
      } else {
        return DecodeSIMDLoadStoreUnsignedImmediate(opcode);
      }
    }
  } else {
    // Scalar instructions
    if (op1 == 0b00 && op2 == 0b0 && ((op3 & 0b10) == 0b00)) {
      return DecodeLoadStoreExclusive(opcode);
    } else if (op1 == 0b01 && ((op3 & 0b10) == 0b00)) {
      return DecodeLoadLiteral(opcode);
    } else if (op1 == 0b10) {
      return DecodeLoadStorePair(opcode);
    } else if (op1 == 0b11) {
      if ((op3 & 0b10) == 0b00) {
        if ((op4 & 0b100000) == 0b000000) {
          return DecodeLoadStoreUnscaledImmediate(opcode);
        } else if ((op4 & 0b100000) == 0b100000 && op5 == 0b10) {
          return DecodeLoadStoreRegisterOffset(opcode);
        }
      } else {
        return DecodeLoadStoreUnsignedImmediate(opcode);
      }
    }
  }

  return UnallocatedEncoding();
}

static Instruction DecodeSIMDLoadLiteral(uint32_t opcode) {
  Instruction insn;
  insn.opcode = kSimdLdrLiteral;

  uint8_t opc = bits(opcode, 30, 31);
  uint8_t size = 32 << opc;

  if (opc == 0b11) {
    return UnallocatedEncoding();
  }

  insn.operands.push_back(v(size, opcode, 0, 4));
  Register base = Register(64, Register::kPc);
  Immediate offset = Immediate(64, sign_extend_bits(opcode, 5, 23) << 2);
  Shift shift = Shift(Shift::kNone, 0);

  insn.operands.push_back(ImmediateOffset(base, offset, shift, size));

  return insn;
}

static Instruction DecodeSIMDLoadStorePair(uint32_t opcode) {
  Instruction insn;

  uint8_t opc = bits(opcode, 30, 31);
  uint8_t size = 32 << opc;
  uint8_t op3 = bits(opcode, 23, 24);
  uint8_t load = bit(opcode, 22);

  if (opc == 0b11) {
    return UnallocatedEncoding();
  }

  insn.operands.push_back(v(size, opcode, 0, 4));
  insn.operands.push_back(v(size, opcode, 10, 14));

  Register base = x_or_sp(64, opcode, 5, 9);
  Immediate offset =
      Immediate(64, sign_extend_bits(opcode, 15, 21) << (2 + bit(opcode, 31)));
  Shift shift(Shift::kNone, 0);

  ImmediateOffset address(base, offset, shift, size * 2);

  if (load) {
    insn.opcode = kSimdLdp;

    if (op3 == 0b00) {  // LDNP
      insn.opcode = kSimdLdnp;
    } else if (op3 == 0b01) {  // LDP (post-indexed)
      address.writeback = true;
      address.post_index = true;
    } else if (op3 == 0b10) {  // LDP (offset)
      address.writeback = false;
      address.post_index = false;
    } else if (op3 == 0b11) {  // LDP (pre-indexed)
      address.writeback = true;
      address.post_index = false;
    }
  } else {
    insn.opcode = kSimdStp;

    if (op3 == 0b00) {  // STNP
      insn.opcode = kSimdStnp;
    } else if (op3 == 0b01) {  // STP (post-indexed)
      address.writeback = true;
      address.post_index = true;
    } else if (op3 == 0b10) {  // STP (offset)
      address.writeback = false;
      address.post_index = false;
    } else if (op3 == 0b11) {  // STP (pre-indexed)
      address.writeback = true;
      address.post_index = false;
    }
  }

  insn.operands.push_back(address);

  return insn;
}

static Instruction DecodeSIMDLoadStoreUnscaledImmediate(uint32_t opcode) {
  Instruction insn;
  uint8_t size = 8 << ((bit(opcode, 23) << 2) | bits(opcode, 30, 31));

  if (bit(opcode, 22)) {
    insn.opcode = kSimdLdr;
  } else {
    insn.opcode = kSimdStr;
  }

  Register base = x_or_sp(64, opcode, 5, 9);
  Immediate offset = Immediate(64, sign_extend_bits(opcode, 12, 20));
  Shift shift(Shift::kNone, 0);

  ImmediateOffset address(base, offset, shift, size);

  switch (bits(opcode, 10, 11)) {
    case 0b00: {  // unscaled immediate
      if (insn.opcode == kSimdStr) {
        insn.opcode = kSimdStur;
      } else if (insn.opcode == kSimdLdr) {
        insn.opcode = kSimdLdur;
      }
    } break;

    case 0b01: {  // immediate post-indexed
      address.writeback = true;
      address.post_index = true;
    } break;

    case 0b10: {  // unprivileged
      if (insn.opcode == kStr) {
        insn.opcode = kSttr;
      } else if (insn.opcode == kLdr) {
        insn.opcode = kLdtr;
      }
    } break;

    case 0b11: {  // immediate pre-indexed
      address.writeback = true;
      address.post_index = false;
    } break;
  }

  insn.operands.push_back(v(size, opcode, 0, 4));
  insn.operands.push_back(address);

  return insn;
}

static Instruction DecodeSIMDLoadStoreRegisterOffset(uint32_t opcode) {
  Instruction insn;
  uint8_t size = 8 << ((bit(opcode, 23) << 2) | bits(opcode, 30, 31));

  if (bit(opcode, 22)) {
    insn.opcode = kSimdLdr;
  } else {
    insn.opcode = kSimdStr;
  }

  Register base = x_or_sp(64, opcode, 5, 9);
  Register offset = x(64, opcode, 16, 20);
  Extend extend(Extend::kNone, bit(opcode, 12) ? bits(opcode, 30, 31) : 0);

  switch (bits(opcode, 13, 15)) {
    case 0b010: {  // UXTW
      extend.type = Extend::kUxtw;
    } break;

    case 0b011: {  // LSL
      extend.type = Extend::kLsl;
    } break;

    case 0b110: {  // SXTW
      extend.type = Extend::kSxtw;
    } break;

    case 0b111: {  // SXTX
      extend.type = Extend::kSxtx;
    } break;

    default:
      return UnallocatedEncoding();
  }

  insn.operands.push_back(v(size, opcode, 0, 4));
  insn.operands.push_back(RegisterOffset(base, offset, extend, size));

  return insn;
}

static Instruction DecodeSIMDLoadStoreUnsignedImmediate(uint32_t opcode) {
  Instruction insn;
  uint8_t size = 8 << ((bit(opcode, 23) << 2) | bits(opcode, 30, 31));

  if (bit(opcode, 22)) {
    insn.opcode = kSimdLdr;
  } else {
    insn.opcode = kSimdStr;
  }

  Register base = x_or_sp(64, opcode, 5, 9);
  Immediate offset =
      Immediate(64, bits(opcode, 10, 21) << bits(opcode, 30, 31));
  Shift shift(Shift::kNone, 0);

  insn.operands.push_back(v(size, opcode, 0, 4));
  insn.operands.push_back(ImmediateOffset(base, offset, shift, size));

  return insn;
}

static Instruction DecodeLoadStoreExclusive(uint32_t opcode) {
  Instruction insn;

  uint8_t size = 8 << bits(opcode, 30, 31);

  uint8_t o2_1_o1_o0 = (bits(opcode, 21, 23) << 1) | bit(opcode, 15);

  // TODO: fix these UnallocatedEncodings - need to test on hardware, seems to
  // be a difference between documentation and assembler...
  // uint8_t rt = bits(opcode, 16, 20);
  // if (o1 && o2 && rt != 0b11111) {
  //   return UnallocatedEncoding();
  // }
  // if (size < 32 && o1 && rt != 0b11111) {
  //   return UnallocatedEncoding();
  // }

  switch (o2_1_o1_o0) {
    case 0b0000: {
      insn.opcode = kStxr;
    } break;

    case 0b0001: {
      insn.opcode = kStlxr;
    } break;

    case 0b0010: {
      if (size < 32) {
        insn.opcode = kCasp;
        size <<= 1;
      } else {
        insn.opcode = kStxp;
      }
    } break;

    case 0b0011: {
      if (size < 32) {
        insn.opcode = kCaspl;
        size <<= 1;
      } else {
        insn.opcode = kStlxp;
      }
    } break;

    case 0b0100: {
      insn.opcode = kLdxr;
    } break;

    case 0b0101: {
      insn.opcode = kLdaxr;
    } break;

    case 0b0110: {
      if (size < 32) {
        insn.opcode = kCaspa;
        size <<= 1;
      } else {
        insn.opcode = kLdxp;
      }
    } break;

    case 0b0111: {
      if (size < 32) {
        insn.opcode = kCaspal;
        size <<= 1;
      } else {
        insn.opcode = kLdaxp;
      }
    } break;

    case 0b1000: {
      insn.opcode = kStllr;
    } break;

    case 0b1001: {
      insn.opcode = kStlr;
    } break;

    case 0b1010: {
      insn.opcode = kCas;
    } break;

    case 0b1011: {
      insn.opcode = kCasl;
    } break;

    case 0b1100: {
      insn.opcode = kLdlar;
    } break;

    case 0b1101: {
      insn.opcode = kLdar;
    } break;

    case 0b1110: {
      insn.opcode = kCasa;
    } break;

    case 0b1111: {
      insn.opcode = kCasal;
    } break;
  }

  if (insn.opcode == kStxr || insn.opcode == kStxp || insn.opcode == kStlxp ||
      insn.opcode == kStlxr) {
    insn.operands.push_back(x(32, opcode, 16, 20));
  } else if (insn.opcode == kCas || insn.opcode == kCasa ||
             insn.opcode == kCasal || insn.opcode == kCasl) {
    insn.operands.push_back(x(size, opcode, 16, 20));
  }

  insn.operands.push_back(x(size, opcode, 0, 4));
  if (insn.opcode == kCasp || insn.opcode == kCaspa || insn.opcode == kCaspal ||
      insn.opcode == kCaspal) {
    // TODO: duplicate w(s+1) and w(t+1)
  }
  if (insn.opcode == kLdxp || insn.opcode == kLdaxp || insn.opcode == kStxp ||
      insn.opcode == kStlxp) {
    insn.operands.push_back(x(size, opcode, 10, 14));
  }

  Register base = x_or_sp(64, opcode, 5, 9);
  Immediate offset = Immediate(64, 0);
  Shift shift = Shift(Shift::kNone, 0);

  if (insn.opcode == kLdxp || insn.opcode == kLdaxp || insn.opcode == kStxp ||
      insn.opcode == kStlxp) {
    insn.operands.push_back(ImmediateOffset(base, offset, shift, size * 2));
  } else {
    insn.operands.push_back(ImmediateOffset(base, offset, shift, size));
  }

  return insn;
}

static Instruction DecodeLoadLiteral(uint32_t opcode) {
  Instruction insn;

  uint8_t size = 64;
  uint8_t opc = bits(opcode, 30, 31);

  if (opc == 0b00) {  // LDR (literal) 32-bit
    insn.opcode = kLdrLiteral;
    size = 32;
  } else if (opc == 0b01) {  // LDR (literal) 64-bit
    insn.opcode = kLdrLiteral;
  } else if (opc == 0b10) {  // LDRSW (literal)
    insn.opcode = kLdrsLiteral;
    size = 32;
  } else if (opc == 0b11) {  // PRFM (literal)
    insn.opcode = kPrfmLiteral;
  }

  if (insn.opcode == kPrfmLiteral) {
    insn.operands.push_back(Immediate(8, bits(opcode, 0, 4)));
  } else if (insn.opcode == kLdrLiteral && size == 32) {
    insn.operands.push_back(x(32, opcode, 0, 4));
  } else {
    insn.operands.push_back(x(64, opcode, 0, 4));
  }

  Register base = Register(64, Register::kPc);
  Immediate offset = Immediate(64, sign_extend_bits(opcode, 5, 23) << 2);
  Shift shift = Shift(Shift::kNone, 0);

  insn.operands.push_back(ImmediateOffset(base, offset, shift, size));

  return insn;
}

static Instruction DecodeLoadStorePair(uint32_t opcode) {
  Instruction insn;

  uint8_t size = 32 << bit(opcode, 31);
  uint8_t opc = bits(opcode, 30, 31);
  uint8_t op3 = bits(opcode, 23, 24);
  uint8_t load = bit(opcode, 22);

  if (opc == 0b11) {
    return UnallocatedEncoding();
  }

  if ((opc & 0b01) == 0b01 && !load) {
    return UnallocatedEncoding();
  }

  insn.operands.push_back(x(size, opcode, 0, 4));
  insn.operands.push_back(x(size, opcode, 10, 14));

  Register base = x_or_sp(64, opcode, 5, 9);
  Immediate offset =
      Immediate(64, sign_extend_bits(opcode, 15, 21) << (2 + bit(opcode, 31)));
  Shift shift(Shift::kNone, 0);

  ImmediateOffset address(base, offset, shift, size * 2);

  if (load) {
    if ((opc & 0b01) == 0b01) {  // LDPSW
      insn.opcode = kLdpsw;
    } else {
      insn.opcode = kLdp;
    }

    if (op3 == 0b00) {  // LDNP
      insn.opcode = kLdnp;
    } else if (op3 == 0b01) {  // LDP (post-indexed)
      address.writeback = true;
      address.post_index = true;
    } else if (op3 == 0b10) {  // LDP (offset)
      address.writeback = false;
      address.post_index = false;
    } else if (op3 == 0b11) {  // LDP (pre-indexed)
      address.writeback = true;
      address.post_index = false;
    }
  } else {
    insn.opcode = kStp;

    if (op3 == 0b00) {  // STNP
      insn.opcode = kStnp;
    } else if (op3 == 0b01) {  // STP (post-indexed)
      address.writeback = true;
      address.post_index = true;
    } else if (op3 == 0b10) {  // STP (offset)
      address.writeback = false;
      address.post_index = false;
    } else if (op3 == 0b11) {  // STP (pre-indexed)
      address.writeback = true;
      address.post_index = false;
    }
  }

  insn.operands.push_back(address);

  return insn;
}

static void DecodeLoadStoreOpcode(uint32_t opcode, Instruction& insn) {
  uint8_t size = 8 << bits(opcode, 30, 31);

  switch (bits(opcode, 22, 23)) {
    case 0b00: {  // ST*R/B/H
      insn.opcode = kStr;
      insn.operands.push_back(x(size < 64 ? 32 : 64, opcode, 0, 4));
    } break;

    case 0b01: {  // LD*R/B/H
      insn.opcode = kLdr;
      insn.operands.push_back(x(size < 64 ? 32 : 64, opcode, 0, 4));
    } break;

    case 0b10: {         // LD*RS/B/H 64-bit variant
      if (size == 64) {  // PRFM
        insn.opcode = kPrfm;
        insn.operands.push_back(Immediate(8, bits(opcode, 0, 4)));
      } else {
        insn.opcode = kLdrs;
        insn.operands.push_back(x(64, opcode, 0, 4));
      }
    } break;

    case 0b11: {  // LD*RS/B/H 32-bit variant
      insn.opcode = kLdrs;
      insn.operands.push_back(x(32, opcode, 0, 4));
    } break;
  }
}

static Instruction DecodeLoadStoreUnscaledImmediate(uint32_t opcode) {
  Instruction insn;
  uint8_t size = 8 << bits(opcode, 30, 31);

  DecodeLoadStoreOpcode(opcode, insn);

  Register base = x_or_sp(64, opcode, 5, 9);
  Immediate offset = Immediate(64, sign_extend_bits(opcode, 12, 20));
  Shift shift(Shift::kNone, 0);

  ImmediateOffset address(base, offset, shift, size);

  switch (bits(opcode, 10, 11)) {
    case 0b00: {  // unscaled immediate
      if (insn.opcode == kStr) {
        insn.opcode = kStur;
      } else if (insn.opcode == kLdr) {
        insn.opcode = kLdur;
      } else if (insn.opcode == kLdrs) {
        insn.opcode = kLdurs;
      }
    } break;

    case 0b01: {  // immediate post-indexed
      address.writeback = true;
      address.post_index = true;
    } break;

    case 0b10: {  // unprivileged
      if (insn.opcode == kStr) {
        insn.opcode = kSttr;
      } else if (insn.opcode == kLdr) {
        insn.opcode = kLdtr;
      } else if (insn.opcode == kLdrs) {
        insn.opcode = kLdtrs;
      }
    } break;

    case 0b11: {  // immediate pre-indexed
      address.writeback = true;
      address.post_index = false;
    } break;
  }

  insn.operands.push_back(address);

  return insn;
}

static Instruction DecodeLoadStoreRegisterOffset(uint32_t opcode) {
  Instruction insn;
  uint8_t size = 8 << bits(opcode, 30, 31);

  DecodeLoadStoreOpcode(opcode, insn);

  Register base = x_or_sp(64, opcode, 5, 9);
  Register offset = x(64, opcode, 16, 20);
  Extend extend(Extend::kNone, bit(opcode, 12) ? bits(opcode, 30, 31) : 0);

  switch (bits(opcode, 13, 15)) {
    case 0b010: {  // UXTW
      extend.type = Extend::kUxtw;
    } break;

    case 0b011: {  // LSL
      extend.type = Extend::kLsl;
    } break;

    case 0b110: {  // SXTW
      extend.type = Extend::kSxtw;
    } break;

    case 0b111: {  // SXTX
      extend.type = Extend::kSxtx;
    } break;

    default:
      return UnallocatedEncoding();
  }

  insn.operands.push_back(RegisterOffset(base, offset, extend, size));

  return insn;
}

static Instruction DecodeLoadStoreUnsignedImmediate(uint32_t opcode) {
  Instruction insn;
  uint8_t size = 8 << bits(opcode, 30, 31);

  DecodeLoadStoreOpcode(opcode, insn);

  Register base = x_or_sp(64, opcode, 5, 9);
  Immediate offset =
      Immediate(64, bits(opcode, 10, 21) << bits(opcode, 30, 31));
  Shift shift(Shift::kNone, 0);

  insn.operands.push_back(ImmediateOffset(base, offset, shift, size));

  return insn;
}

static Instruction DecodeDataProcessingTwoSource(uint32_t opcode);
static Instruction DecodeDataProcessingOneSource(uint32_t opcode);
static Instruction DecodeLogicalShiftedRegister(uint32_t opcode);
static Instruction DecodeAddSubtractShiftedRegister(uint32_t opcode);
static Instruction DecodeAddSubtractExtendedRegister(uint32_t opcode);
static Instruction DecodeAddSubtractWithCarry(uint32_t opcode);
static Instruction DecodeConditionalCompare(uint32_t opcode);
static Instruction DecodeConditionalSelect(uint32_t opcode);
static Instruction DecodeDataProcessingThreeSource(uint32_t opcode);

static Instruction DecodeDataProcessingRegister(uint32_t opcode) {
  uint8_t op0 = bit(opcode, 30);
  uint8_t op1 = bit(opcode, 28);
  uint8_t op2 = bits(opcode, 21, 24);
  // uint8_t op3 = bit(opcode, 11);

  if (op1) {
    if (op2 == 0b0000) {
      return DecodeAddSubtractWithCarry(opcode);
    } else if (op2 == 0b0010) {
      return DecodeConditionalCompare(opcode);
    } else if (op2 == 0b0100) {
      return DecodeConditionalSelect(opcode);
    } else if (op2 == 0b0110) {
      if (!op0) {
        return DecodeDataProcessingTwoSource(opcode);
      } else {
        return DecodeDataProcessingOneSource(opcode);
      }
    } else if ((op2 & 0b1000) == 0b1000) {
      return DecodeDataProcessingThreeSource(opcode);
    }
  } else {
    if ((op2 & 0b1000) == 0b0000) {
      return DecodeLogicalShiftedRegister(opcode);
    } else if ((op2 & 0b1001) == 0b1000) {
      return DecodeAddSubtractShiftedRegister(opcode);
    } else {
      return DecodeAddSubtractExtendedRegister(opcode);
    }
  }

  return UnallocatedEncoding();
}

static Instruction DecodeDataProcessingTwoSource(uint32_t opcode) {
  Instruction insn;
  uint8_t size = 32 << bit(opcode, 31);
  uint8_t opc = bits(opcode, 10, 15);

  if (bit(opcode, 29)) {
    return UnallocatedEncoding();
  }

  switch (opc) {
    case 0b000010: {
      insn.opcode = kUdiv;
    } break;

    case 0b000011: {
      insn.opcode = kSdiv;
    } break;

    case 0b001000: {
      insn.opcode = kLsl;
    } break;

    case 0b001001: {
      insn.opcode = kLsr;
    } break;

    case 0b001010: {
      insn.opcode = kAsr;
    } break;

    case 0b001011: {
      insn.opcode = kRor;
    } break;

    case 0b001100: {
      insn.opcode = kPacga;
    } break;

    case 0b010000: {
      insn.opcode = kCrc32b;
    } break;

    case 0b010001: {
      insn.opcode = kCrc32h;
    } break;

    case 0b010010: {
      insn.opcode = kCrc32w;
    } break;

    case 0b010011: {
      insn.opcode = kCrc32x;
    } break;

    case 0b010100: {
      insn.opcode = kCrc32cb;
    } break;

    case 0b010101: {
      insn.opcode = kCrc32ch;
    } break;

    case 0b010110: {
      insn.opcode = kCrc32cw;
    } break;

    case 0b010111: {
      insn.opcode = kCrc32cx;
    } break;

    default: { return UnallocatedEncoding(); }
  }

  insn.operands.push_back(x(size, opcode, 0, 4));
  insn.operands.push_back(x(size, opcode, 5, 9));
  if (insn.opcode != kPacga) {
    insn.operands.push_back(x(size, opcode, 16, 20));
  } else {
    insn.operands.push_back(x_or_sp(size, opcode, 16, 20));
  }

  return insn;
}

static Instruction DecodeDataProcessingOneSource(uint32_t opcode) {
  Instruction insn;
  uint8_t size = 32 << bit(opcode, 31);

  uint8_t opc = bits(opcode, 10, 15);
  uint8_t opc2 = bits(opcode, 16, 20);

  if (bit(opcode, 29) || opc2 > 1) {
    return UnallocatedEncoding();
  }

  if (opc2 == 0) {
    switch (opc) {
      case 0b000000: {
        insn.opcode = kRbit;
      } break;

      case 0b000001: {
        insn.opcode = kRev16;
      } break;

      case 0b000010: {
        if (size == 64) {
          insn.opcode = kRev32;
        } else {
          insn.opcode = kRev;
        }
      } break;

      case 0b000011: {
        if (size == 32) {
          return UnallocatedEncoding();
        }
        insn.opcode = kRev;
      } break;

      case 0b000100: {
        insn.opcode = kClz;
      } break;

      case 0b000101: {
        insn.opcode = kCls;
      } break;

      default:
        return UnallocatedEncoding();
    }

    insn.operands.push_back(x(size, opcode, 0, 4));
    insn.operands.push_back(x(size, opcode, 5, 9));
  } else {
    if (size != 64) {
      return UnallocatedEncoding();
    }

    insn.operands.push_back(x(size, opcode, 0, 4));
    if (opc & 0b011000) {
      if (bits(opcode, 5, 9) != 0b11111) {
        return UnallocatedEncoding();
      }
      insn.operands.push_back(x(size, opcode, 5, 9));
    } else {
      insn.operands.push_back(x_or_sp(size, opcode, 5, 9));
    }

    if (opc > 0b010001) {
      return UnallocatedEncoding();
    } else if (opc == 0b010000) {
      insn.opcode = kXpaci;
    } else if (opc == 0b010001) {
      insn.opcode = kXpacd;
    } else {
      switch (opc & 0b000111) {
        case 0b000: {
          insn.opcode = kPacia;
        } break;

        case 0b001: {
          insn.opcode = kPacib;
        } break;

        case 0b010: {
          insn.opcode = kPacda;
        } break;

        case 0b011: {
          insn.opcode = kPacdb;
        } break;

        case 0b100: {
          insn.opcode = kAutia;
        } break;

        case 0b101: {
          insn.opcode = kAutib;
        } break;

        case 0b110: {
          insn.opcode = kAutda;
        } break;

        case 0b111: {
          insn.opcode = kAutdb;
        } break;
      }
    }
  }

  return insn;
}

static Instruction DecodeLogicalShiftedRegister(uint32_t opcode) {
  Instruction insn;
  uint8_t size = 32 << bit(opcode, 31);

  switch ((bits(opcode, 29, 30) << 1) | bit(opcode, 21)) {
    case 0b000: {
      insn.opcode = kAndShiftedRegister;
    } break;

    case 0b001: {
      insn.opcode = kBicShiftedRegister;
    } break;

    case 0b010: {
      insn.opcode = kOrrShiftedRegister;
    } break;

    case 0b011: {
      insn.opcode = kOrnShiftedRegister;
    } break;

    case 0b100: {
      insn.opcode = kEorShiftedRegister;
    } break;

    case 0b101: {
      insn.opcode = kEonShiftedRegister;
    } break;

    case 0b110: {
      insn.opcode = kAndShiftedRegister;
      insn.set_flags = true;
    } break;

    case 0b111: {
      insn.opcode = kBicShiftedRegister;
      insn.set_flags = true;
    } break;
  }

  insn.operands.push_back(x(size, opcode, 0, 4));
  insn.operands.push_back(x(size, opcode, 5, 9));
  insn.operands.push_back(x(size, opcode, 16, 20));

  Shift shift(Shift::kNone, bits(opcode, 10, 15));
  switch (bits(opcode, 22, 23)) {
    case 0b00: {
      shift.type = Shift::kLsl;
    } break;

    case 0b01: {
      shift.type = Shift::kLsr;
    } break;

    case 0b10: {
      shift.type = Shift::kAsr;
    } break;

    case 0b11: {
      shift.type = Shift::kRor;
    } break;
  }

  insn.operands.push_back(shift);

  return insn;
}

static Instruction DecodeAddSubtractShiftedRegister(uint32_t opcode) {
  Instruction insn;
  uint8_t size = 32 << bit(opcode, 31);

  if (bit(opcode, 30)) {
    insn.opcode = kSubShiftedRegister;
  } else {
    insn.opcode = kAddShiftedRegister;
  }

  if (bit(opcode, 29)) {
    insn.set_flags = true;
  }

  insn.operands.push_back(x(size, opcode, 0, 4));
  insn.operands.push_back(x(size, opcode, 5, 9));
  insn.operands.push_back(x(size, opcode, 16, 20));

  Shift shift(Shift::kNone, bits(opcode, 10, 15));
  switch (bits(opcode, 22, 23)) {
    case 0b00: {
      shift.type = Shift::kLsl;
    } break;

    case 0b01: {
      shift.type = Shift::kLsr;
    } break;

    case 0b10: {
      shift.type = Shift::kAsr;
    } break;

    case 0b11: {
      return UnallocatedEncoding();
    } break;
  }

  if (shift.count > size) {
    return UnallocatedEncoding();
  }

  insn.operands.push_back(shift);

  return insn;
}

static Instruction DecodeAddSubtractExtendedRegister(uint32_t opcode) {
  Instruction insn;
  uint8_t size = 32 << bit(opcode, 31);

  if (bits(opcode, 22, 23) || bits(opcode, 10, 12) > 0b100) {
    return UnallocatedEncoding();
  }

  if (bit(opcode, 30)) {
    insn.opcode = kSubExtendedRegister;
  } else {
    insn.opcode = kAddExtendedRegister;
  }

  if (bit(opcode, 29)) {
    insn.set_flags = true;
  }

  Register rd = x_or_sp(size, opcode, 0, 4);
  if (insn.set_flags) {
    rd = x(size, opcode, 0, 4);
  }

  Register rn = x_or_sp(size, opcode, 5, 9);
  Register rm = x(size, opcode, 16, 20);

  Extend extend(Extend::kNone, bits(opcode, 10, 12));

  switch (bits(opcode, 13, 15)) {
    case 0b000: {
      extend.type = Extend::kUxtb;
      rm.size = 32;
    } break;

    case 0b001: {
      extend.type = Extend::kUxth;
      rm.size = 32;
    } break;

    case 0b010: {
      if (rd.name == Register::kSp || rn.name == Register::kSp) {
        extend.type = Extend::kLsl;
      } else {
        extend.type = Extend::kUxtw;
      }
      rm.size = 32;
    } break;

    case 0b011: {
      extend.type = Extend::kUxtx;
    } break;

    case 0b100: {
      extend.type = Extend::kSxtb;
      rm.size = 32;
    } break;

    case 0b101: {
      extend.type = Extend::kSxth;
      rm.size = 32;
    } break;

    case 0b110: {
      extend.type = Extend::kSxtw;
      rm.size = 32;
    } break;

    case 0b111: {
      extend.type = Extend::kSxtx;
    } break;
  }

  insn.operands.push_back(rd);
  insn.operands.push_back(rn);
  insn.operands.push_back(rm);
  insn.operands.push_back(extend);

  return insn;
}

static Instruction DecodeAddSubtractWithCarry(uint32_t opcode) {
  Instruction insn;
  uint8_t size = 32 << bit(opcode, 31);

  if (bits(opcode, 10, 15)) {
    return UnallocatedEncoding();
  }

  if (bit(opcode, 30)) {
    insn.opcode = kSbc;
  } else {
    insn.opcode = kAdc;
  }

  if (bit(opcode, 29)) {
    insn.set_flags = true;
  }

  insn.operands.push_back(x(size, opcode, 0, 4));
  insn.operands.push_back(x(size, opcode, 5, 9));
  insn.operands.push_back(x(size, opcode, 16, 20));

  return insn;
}

static Instruction DecodeConditionalCompare(uint32_t opcode) {
  Instruction insn;
  uint8_t size = 32 << bit(opcode, 31);

  if (bit(opcode, 30)) {
    insn.opcode = kCcmn;
  } else {
    insn.opcode = kCcmp;
  }

  insn.operands.push_back(x(size, opcode, 5, 9));

  if (bit(opcode, 11)) {  // (immediate)
    insn.operands.push_back(Immediate(size, bits(opcode, 16, 20)));
  } else {  // (register)
    insn.operands.push_back(x(size, opcode, 16, 20));
  }

  insn.operands.push_back(Immediate(8, bits(opcode, 0, 3)));

  insn.cc = (ConditionCode)bits(opcode, 12, 15);

  return insn;
}

static Instruction DecodeConditionalSelect(uint32_t opcode) {
  Instruction insn;
  uint8_t size = 32 << bit(opcode, 31);

  if (bit(opcode, 29)) {
    return UnallocatedEncoding();
  }

  switch (((bit(opcode, 30) << 2) | bits(opcode, 10, 11))) {
    case 0b000: {
      insn.opcode = kCsel;
    } break;

    case 0b001: {
      insn.opcode = kCsinc;
    } break;

    case 0b100: {
      insn.opcode = kCsinv;
    } break;

    case 0b101: {
      insn.opcode = kCsneg;
    } break;

    default:
      return UnallocatedEncoding();
  }

  insn.operands.push_back(x(size, opcode, 0, 4));
  insn.operands.push_back(x(size, opcode, 5, 9));
  insn.operands.push_back(x(size, opcode, 16, 20));

  insn.cc = (ConditionCode)bits(opcode, 12, 15);

  return insn;
}

static Instruction DecodeDataProcessingThreeSource(uint32_t opcode) {
  Instruction insn;
  uint8_t size = 32 << bit(opcode, 31);

  if (bits(opcode, 29, 30)) {
    return UnallocatedEncoding();
  }

  switch ((bits(opcode, 21, 23) << 1) | bit(opcode, 15)) {
    case 0b0000: {
      insn.opcode = kMadd;
    } break;

    case 0b0001: {
      insn.opcode = kMsub;
    } break;

    case 0b0010: {
      insn.opcode = kSmaddl;
    } break;

    case 0b0011: {
      insn.opcode = kSmsubl;
    } break;

    case 0b0100:
    case 0b0101: {
      if (size != 64) {
        return UnallocatedEncoding();
      }
      insn.opcode = kSmulh;
    } break;

    case 0b1010: {
      insn.opcode = kUmaddl;
    } break;

    case 0b1011: {
      insn.opcode = kUmsubl;
    } break;

    case 0b1100:
    case 0b1101: {
      if (size != 64) {
        return UnallocatedEncoding();
      }
      insn.opcode = kUmulh;
    } break;

    default:
      return UnallocatedEncoding();
  }

  if (insn.opcode == kMadd || insn.opcode == kMsub || insn.opcode == kSmulh ||
      insn.opcode == kUmulh) {
    insn.operands.push_back(x(size, opcode, 0, 4));
    insn.operands.push_back(x(size, opcode, 5, 9));
    insn.operands.push_back(x(size, opcode, 16, 20));
    insn.operands.push_back(x(size, opcode, 10, 14));
  } else {
    insn.operands.push_back(x(64, opcode, 0, 4));
    insn.operands.push_back(x(32, opcode, 5, 9));
    insn.operands.push_back(x(32, opcode, 16, 20));
    insn.operands.push_back(x(64, opcode, 10, 14));
  }

  return insn;
}

std::tuple<uint64_t, uint64_t> DecodeBitMasks(uint8_t size, Immediate imms,
                                              Immediate immr) {
  return decode_bit_masks(size == 64 ? 1 : 0, imms.value, immr.value, false);
}

Instruction DecodeInstruction(uint64_t address, uint32_t opcode) {
  Instruction insn;
  uint32_t op0 = bits(opcode, 25, 28);
  if ((op0 & 0b1110) == 0b1000) {
    insn = DecodeDataProcessingImmediate(opcode);
  } else if ((op0 & 0b1110) == 0b1010) {
    insn = DecodeBranchExceptionGeneratingSystem(opcode);
  } else if ((op0 & 0b0101) == 0b0100) {
    insn = DecodeLoadStore(opcode);
  } else if ((op0 & 0b0111) == 0b0101) {
    insn = DecodeDataProcessingRegister(opcode);
  } /* else if (op0 == 0b0111 || op0 == 0b1111) {
    // Data processing - SIMD and floating point
  } */
  else {
    insn = UnallocatedEncoding();
  }

  insn.address = address;
  return insn;
}
}  // namespace decoder
}  // namespace aarch64
}  // namespace reil
