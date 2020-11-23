#ifndef MACOS_COV_H
#define MACOS_COV_H

#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <sys/shm.h>
#include <sys/time.h>

#include "common.h"
#include "tinyinst.h"
#include "coverage.h"

#define MAP_SIZE (1 << 16)

static unsigned char TRACE[] = {
  0x50,								// push		rax
  0x57,								// push		rdi
  0x56,								// push		rsi
  0x52,								// push		rdx
  0x48, 0x8B, 0x05, 0xAA, 0xAA, 0xAA, 0xAA,			// mov		rax, qword ptr [rip + 0xaaaaaaaa]
  0x48, 0x85, 0xC0,						// test		rax, rax
  0x75, 0x1F,							// jne		2f
  0x48, 0x31, 0xC0,						// xor		rax, rax
  0x48, 0x31, 0xFF,						// xor		rdi, rdi
  0x48, 0x31, 0xF6,						// xor		rsi, rsi
  0x48, 0x31, 0xD2,						// xor		rdx, rdx
  0xB8, 0x06, 0x01, 0x00, 0x02,					// mov		eax, 0x2000106
  0xBF, 0xBB, 0xBB, 0xBB, 0xBB,					// mov		edi, 0xbbbbbbbb
  0x0F, 0x05,							// syscall
  0x48, 0x89, 0x05, 0xCC, 0xCC, 0xCC, 0xCC,			// mov		qword ptr [rip + 0xcccccccc], rax
  0x48, 0x31, 0xF6,						// xor		rsi, rsi
  0x66, 0xBE, 0xDD, 0xDD,					// mov		si, 0xdddd
  0xFE, 0x04, 0x30,						// inc		byte ptr [rax + rsi]
  0x5A,								// pop		rdx
  0x5E,								// pop		rsi
  0x5F,								// pop		rdi
  0x58,								// pop		rax
};

struct pair_hash {
  template <class T1, class T2>
    std::size_t operator () (const std::pair<T1,T2> &p) const {
      auto h1 = std::hash<T1>{}(p.first);
      auto h2 = std::hash<T2>{}(p.second);

      return h1 ^ h2;
    }
};

class CovAgent : public TinyInst {
  public:
    virtual void Init(int argc, char **argv) override;

    unsigned int map_size;
    int share_coverage_id;
    unsigned char *share_coverage;
    void traceBB();
    void DeInit();
  protected:
    virtual void OnModuleInstrumented(ModuleInfo *module) override;
    virtual void OnModuleUninstrumented(ModuleInfo *module) override;

    virtual void OnProcessCreated() override;

    virtual void InstrumentBasicBlock(ModuleInfo *module, size_t bb_address) override;
  private:
    std::unordered_map<std::pair<std::string, size_t>, uint16_t, pair_hash> bb_mapper;
};

#endif // TINYITF_H
