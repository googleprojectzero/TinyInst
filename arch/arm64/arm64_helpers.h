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

#ifndef ARCH_ARM64_ARM64_HELPERS_H
#define ARCH_ARM64_ARM64_HELPERS_H

#include <cstdint>
#include <cstddef>
#include <string>

#include "third_party/reil/reil/aarch64/decoder.h"
#include "arch/arm64/reg.h"

namespace arm64 = reil::aarch64::decoder;

Register reg(arm64::Register r);

uint32_t bits(uint32_t msb, uint32_t lsb, uint32_t val);
uint32_t bit(uint32_t lsb);

uint32_t EncodeSignedImmediate(const uint8_t msb, const uint8_t lsb, int32_t value);
uint32_t EncodeUnsignedImmediate(const uint8_t msb, const uint8_t lsb, uint32_t value);

uint32_t ldr(uint8_t size, Register data_reg, Register base_reg, int32_t offset);
uint32_t str(uint8_t size, Register data_reg, Register base_reg, int32_t offset);
uint32_t ldr_lit(Register dst_reg, int64_t rip_offset, size_t size, bool is_signed);
uint32_t load_store(uint8_t op, uint8_t size, Register data_reg, Register base_reg, int32_t offset);

uint32_t movzn(Register dst_reg, int32_t imm);
uint32_t movz_imm(Register dst, int32_t imm);
uint32_t mov(Register dst, Register src);

uint32_t add_sub_reg_imm(uint8_t op, Register dst_reg, Register src_reg, uint32_t offset);
uint32_t sub_reg_imm(Register dst_reg, Register src_reg, uint32_t offset);
uint32_t add_reg_imm(Register dst_reg, Register src_reg, uint32_t offset);
uint32_t orr_shifted_reg(Register dst, Register rn, Register src);
uint32_t eor_shifted_reg(uint8_t sz, Register rd, Register rn, Register rm, arm64::Shift::Type shift_type, uint8_t shift_count);

uint32_t cmp(Register src1, Register src2);

uint32_t branch_imm(size_t instr_address, size_t address, bool do_link);
uint32_t b(size_t instr_address, size_t address);
uint32_t bl(size_t instr_address, size_t address);
uint32_t br(Register dst_reg);
uint32_t b_cond(const std::string &cond, int32_t off);

uint32_t ldr_simd_x0_from_ldr_simd_literal(uint32_t orig_inst);

#endif  // ARCH_ARM64_ARM64_HELPERS_H
