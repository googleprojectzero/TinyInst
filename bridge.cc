#include "common.h"
#include "litecov.h"
#include "coverage.h"
#include "shim.h"
#include <cstddef>
#include <cstdint>
#include <memory>
#include <new>
#include <type_traits>
#include <utility>

namespace rust {
inline namespace cxxbridge1 {
// #include "rust/cxx.h"

#ifndef CXXBRIDGE1_IS_COMPLETE
#define CXXBRIDGE1_IS_COMPLETE
namespace detail {
namespace {
template <typename T, typename = std::size_t>
struct is_complete : std::false_type {};
template <typename T>
struct is_complete<T, decltype(sizeof(T))> : std::true_type {};
} // namespace
} // namespace detail
#endif // CXXBRIDGE1_IS_COMPLETE

namespace {
template <bool> struct deleter_if {
  template <typename T> void operator()(T *) {}
};

template <> struct deleter_if<true> {
  template <typename T> void operator()(T *ptr) { ptr->~T(); }
};
} // namespace
} // namespace cxxbridge1
} // namespace rust

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

extern "C" {
::std::uint64_t cxxbridge1$GetCurTime() noexcept {
  ::std::uint64_t (*GetCurTime$)() = ::GetCurTime;
  return GetCurTime$();
}

void cxxbridge1$ModuleCovData$ClearInstrumentationData(::ModuleCovData &self) noexcept {
  void (::ModuleCovData::*ClearInstrumentationData$)() = &::ModuleCovData::ClearInstrumentationData;
  (self.*ClearInstrumentationData$)();
}

void cxxbridge1$ModuleCovData$ClearCmpCoverageData(::ModuleCovData &self) noexcept {
  void (::ModuleCovData::*ClearCmpCoverageData$)() = &::ModuleCovData::ClearCmpCoverageData;
  (self.*ClearCmpCoverageData$)();
}

::Coverage *cxxbridge1$coverage_new() noexcept {
  ::std::unique_ptr<::Coverage> (*coverage_new$)() = ::coverage_new;
  return coverage_new$().release();
}

::LiteCov *cxxbridge1$litecov_new() noexcept {
  ::std::unique_ptr<::LiteCov> (*litecov_new$)() = ::litecov_new;
  return litecov_new$().release();
}

void cxxbridge1$LiteCov$Init(::LiteCov &self, ::std::int32_t argc, char * *argv) noexcept {
  void (::LiteCov::*Init$)(::std::int32_t, char * *) = &::LiteCov::Init;
  (self.*Init$)(argc, argv);
}

void cxxbridge1$LiteCov$GetCoverage(::LiteCov &self, ::Coverage &coverage, bool clear_coverage) noexcept {
  void (::LiteCov::*GetCoverage$)(::Coverage &, bool) = &::LiteCov::GetCoverage;
  (self.*GetCoverage$)(coverage, clear_coverage);
}

void cxxbridge1$LiteCov$IgnoreCoverage(::LiteCov &self, ::Coverage &coverage) noexcept {
  void (::LiteCov::*IgnoreCoverage$)(::Coverage &) = &::LiteCov::IgnoreCoverage;
  (self.*IgnoreCoverage$)(coverage);
}

void cxxbridge1$LiteCov$ClearCoverage(::LiteCov &self) noexcept {
  void (::LiteCov::*ClearCoverage$)() = &::LiteCov::ClearCoverage;
  (self.*ClearCoverage$)();
}

bool cxxbridge1$LiteCov$HasNewCoverage(::LiteCov &self) noexcept {
  bool (::LiteCov::*HasNewCoverage$)() = &::LiteCov::HasNewCoverage;
  return (self.*HasNewCoverage$)();
}

void cxxbridge1$LiteCov$EnableInstrumentation(::LiteCov &self) noexcept {
  void (::LiteCov::*EnableInstrumentation$)() = &::LiteCov::EnableInstrumentation;
  (self.*EnableInstrumentation$)();
}

void cxxbridge1$LiteCov$DisableInstrumentation(::LiteCov &self) noexcept {
  void (::LiteCov::*DisableInstrumentation$)() = &::LiteCov::DisableInstrumentation;
  (self.*DisableInstrumentation$)();
}

::DebuggerStatus cxxbridge1$LiteCov$Run(::LiteCov &self, ::std::int32_t argc, char * *argv, ::std::uint32_t timeout) noexcept {
  ::DebuggerStatus (::LiteCov::*Run$)(::std::int32_t, char * *, ::std::uint32_t) = &::LiteCov::Run;
  return (self.*Run$)(argc, argv, timeout);
}

::DebuggerStatus cxxbridge1$LiteCov$Kill(::LiteCov &self) noexcept {
  ::DebuggerStatus (::LiteCov::*Kill$)() = &::LiteCov::Kill;
  return (self.*Kill$)();
}

::DebuggerStatus cxxbridge1$LiteCov$Continue(::LiteCov &self, ::std::uint32_t timeout) noexcept {
  ::DebuggerStatus (::LiteCov::*Continue$)(::std::uint32_t) = &::LiteCov::Continue;
  return (self.*Continue$)(timeout);
}

::DebuggerStatus cxxbridge1$LiteCov$Attach(::LiteCov &self, ::std::uint32_t pid, ::std::uint32_t timeout) noexcept {
  ::DebuggerStatus (::LiteCov::*Attach$)(::std::uint32_t, ::std::uint32_t) = &::LiteCov::Attach;
  return (self.*Attach$)(pid, timeout);
}

bool cxxbridge1$LiteCov$IsTargetAlive(::LiteCov &self) noexcept {
  bool (::LiteCov::*IsTargetAlive$)() = &::LiteCov::IsTargetAlive;
  return (self.*IsTargetAlive$)();
}

bool cxxbridge1$LiteCov$IsTargetFunctionDefined(::LiteCov &self) noexcept {
  bool (::LiteCov::*IsTargetFunctionDefined$)() = &::LiteCov::IsTargetFunctionDefined;
  return (self.*IsTargetFunctionDefined$)();
}

::std::uint64_t cxxbridge1$LiteCov$GetTargetReturnValue(::LiteCov &self) noexcept {
  ::std::uint64_t (::LiteCov::*GetTargetReturnValue$)() = &::LiteCov::GetTargetReturnValue;
  return (self.*GetTargetReturnValue$)();
}

static_assert(::rust::detail::is_complete<::Coverage>::value, "definition of Coverage is required");
static_assert(sizeof(::std::unique_ptr<::Coverage>) == sizeof(void *), "");
static_assert(alignof(::std::unique_ptr<::Coverage>) == alignof(void *), "");
void cxxbridge1$unique_ptr$Coverage$null(::std::unique_ptr<::Coverage> *ptr) noexcept {
  ::new (ptr) ::std::unique_ptr<::Coverage>();
}
void cxxbridge1$unique_ptr$Coverage$raw(::std::unique_ptr<::Coverage> *ptr, ::Coverage *raw) noexcept {
  ::new (ptr) ::std::unique_ptr<::Coverage>(raw);
}
const ::Coverage *cxxbridge1$unique_ptr$Coverage$get(const ::std::unique_ptr<::Coverage>& ptr) noexcept {
  return ptr.get();
}
::Coverage *cxxbridge1$unique_ptr$Coverage$release(::std::unique_ptr<::Coverage>& ptr) noexcept {
  return ptr.release();
}
void cxxbridge1$unique_ptr$Coverage$drop(::std::unique_ptr<::Coverage> *ptr) noexcept {
  ::rust::deleter_if<::rust::detail::is_complete<::Coverage>::value>{}(ptr);
}

static_assert(::rust::detail::is_complete<::LiteCov>::value, "definition of LiteCov is required");
static_assert(sizeof(::std::unique_ptr<::LiteCov>) == sizeof(void *), "");
static_assert(alignof(::std::unique_ptr<::LiteCov>) == alignof(void *), "");
void cxxbridge1$unique_ptr$LiteCov$null(::std::unique_ptr<::LiteCov> *ptr) noexcept {
  ::new (ptr) ::std::unique_ptr<::LiteCov>();
}
void cxxbridge1$unique_ptr$LiteCov$raw(::std::unique_ptr<::LiteCov> *ptr, ::LiteCov *raw) noexcept {
  ::new (ptr) ::std::unique_ptr<::LiteCov>(raw);
}
const ::LiteCov *cxxbridge1$unique_ptr$LiteCov$get(const ::std::unique_ptr<::LiteCov>& ptr) noexcept {
  return ptr.get();
}
::LiteCov *cxxbridge1$unique_ptr$LiteCov$release(::std::unique_ptr<::LiteCov>& ptr) noexcept {
  return ptr.release();
}
void cxxbridge1$unique_ptr$LiteCov$drop(::std::unique_ptr<::LiteCov> *ptr) noexcept {
  ::rust::deleter_if<::rust::detail::is_complete<::LiteCov>::value>{}(ptr);
}
} // extern "C"
