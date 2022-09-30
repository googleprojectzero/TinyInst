#pragma once
#include "common.h"
#include "litecov.h"
#include "coverage.h"
#include "shim.h"
#include <cstdint>
#include <memory>
#include <type_traits>

using ModuleCovData = ::ModuleCovData;
using LiteCov = ::LiteCov;
using Coverage = ::Coverage;
using ModuleCoverage = ::ModuleCoverage;
using DebuggerStatus = ::DebuggerStatus;

static_assert(::std::is_enum<DebuggerStatus>::value, "expected enum");
static_assert(sizeof(DebuggerStatus) == sizeof(::std::uint32_t), "incorrect size");
static_assert(static_cast<::std::uint32_t>(DebuggerStatus::DEBUGGER_NONE) == 0, "disagrees with the value in #[cxx::bridge]");
static_assert(static_cast<::std::uint32_t>(DebuggerStatus::DEBUGGER_CONTINUE) == 1, "disagrees with the value in #[cxx::bridge]");
static_assert(static_cast<::std::uint32_t>(DebuggerStatus::DEBUGGER_PROCESS_EXIT) == 2, "disagrees with the value in #[cxx::bridge]");
static_assert(static_cast<::std::uint32_t>(DebuggerStatus::DEBUGGER_TARGET_START) == 3, "disagrees with the value in #[cxx::bridge]");
static_assert(static_cast<::std::uint32_t>(DebuggerStatus::DEBUGGER_TARGET_END) == 4, "disagrees with the value in #[cxx::bridge]");
static_assert(static_cast<::std::uint32_t>(DebuggerStatus::DEBUGGER_CRASHED) == 5, "disagrees with the value in #[cxx::bridge]");
static_assert(static_cast<::std::uint32_t>(DebuggerStatus::DEBUGGER_HANGED) == 6, "disagrees with the value in #[cxx::bridge]");
static_assert(static_cast<::std::uint32_t>(DebuggerStatus::DEBUGGER_ATTACHED) == 7, "disagrees with the value in #[cxx::bridge]");
