#include "macos_cov.h"
#include <errno.h>

void CovAgent::Init(int argc, char **argv) {
    TinyInst::Init(argc, argv);
    bb_mapper.clear();
    map_size = MAP_SIZE;

    share_coverage_id = shmget(IPC_PRIVATE, map_size, IPC_CREAT | IPC_EXCL | 0600);
    if (share_coverage_id < 0)
	FATAL("shmget() failed when initializing: %s\n", strerror(errno));

    share_coverage = (unsigned char *)shmat(share_coverage_id, NULL, 0);
    if (share_coverage == (void *)-1)
	FATAL("shmat() failed when initialzing: %s\n", strerror(errno));
}

void CovAgent::OnModuleInstrumented(ModuleInfo *module) {
    module->client_data = 
	(unsigned char *)RemoteAllocateNear((uint64_t)module->instrumented_code_remote,
		(uint64_t)module->instrumented_code_remote
		+ module->instrumented_code_size,
		PAGE_SIZE, READWRITE);
    if (!module->client_data)
	FATAL("Could not allocate share coverage pointer\n");
}

void CovAgent::OnModuleUninstrumented(ModuleInfo *module) {
    if (module->client_data) {
	RemoteFree(module->client_data, PAGE_SIZE);
	module->client_data = NULL;
    }
}

void CovAgent::OnProcessCreated() {
    struct timeval tv;
    struct timezone tz;
    gettimeofday(&tv, &tz);

    unsigned rand_seed = tv.tv_sec ^ tv.tv_usec ^ mach_target->Pid();
    // srand(rand_seed);

    memset (share_coverage, 0, map_size);
    TinyInst::OnProcessCreated();
}

void CovAgent::InstrumentBasicBlock(ModuleInfo *module, size_t bb_address) {
    uint16_t coverage_code;
    uint64_t bb_code = (uint64_t)bb_address - (uint64_t)module->min_address;
    std::pair<std::string, size_t> bb_id = std::make_pair(module->module_name, bb_code); 
    if (bb_mapper.find(bb_id) != bb_mapper.end())
	coverage_code = bb_mapper[bb_id];
    else {
	coverage_code = rand() % map_size;
	bb_mapper[bb_id] = coverage_code;
    }

    size_t tramp_size;
    size_t tramp_addr;
    tramp_size = sizeof(TRACE);
    tramp_addr = GetCurrentInstrumentedAddress(module) - 1;
    WriteCode(module, TRACE, tramp_size);

    assert(*(uint32_t *)(module->instrumented_code_local + module->instrumented_code_allocated - (tramp_size - 7)) == 0xaaaaaaaa);

    size_t shm_ptr_addr = (size_t)module->client_data;
    size_t load_shm_ptr_addr_1 = tramp_addr + 4;
    *(uint32_t *)(module->instrumented_code_local + module->instrumented_code_allocated - (tramp_size - 7)) = (int32_t)(shm_ptr_addr - load_shm_ptr_addr_1 - 7 - 1);

    assert(*(uint32_t *)(module->instrumented_code_local + module->instrumented_code_allocated - (tramp_size - 0x22)) == 0xbbbbbbbb);
    // Fix shm_id
    *(uint32_t *)(module->instrumented_code_local + module->instrumented_code_allocated - (tramp_size - 0x22)) = share_coverage_id;

    assert(*(uint32_t *)(module->instrumented_code_local + module->instrumented_code_allocated - (tramp_size - 0x2b)) == 0xcccccccc);
    // Fix address of share_mem_ptr second time
    size_t load_shm_ptr_addr_2 = tramp_addr + 0x28;
    *(uint32_t *)(module->instrumented_code_local + module->instrumented_code_allocated - (tramp_size - 0x2b)) = (int32_t)(shm_ptr_addr - load_shm_ptr_addr_2 - 7 - 1);

    assert(*(uint16_t *)(module->instrumented_code_local + module->instrumented_code_allocated - (tramp_size - 0x34)) == 0xdddd);
    // Fix coverage_code
    *(uint16_t *)(module->instrumented_code_local + module->instrumented_code_allocated - (tramp_size - 0x34)) = coverage_code;

}

void CovAgent::traceBB() {
    for (auto iter = bb_mapper.begin(); iter != bb_mapper.end(); ++iter)
	if (share_coverage[iter->second])
	    SAY("%s+0x%zx\n", iter->first.first.c_str(), iter->first.second);
}

void CovAgent::DeInit() {
    shmdt(share_coverage);
    shmctl(share_coverage_id, IPC_RMID, NULL);
}

int main(int argc, char **argv) {
    CovAgent *agent = new CovAgent();
    agent->Init(argc, argv);

    int target_opt_ind = 0;
    for (int i=1; i<argc; ++i) {
	if (strcmp(argv[i], "--") == 0) {
	    target_opt_ind = i + 1;
	    break;
	}
    }

    int target_argc = (target_opt_ind) ? argc - target_opt_ind : 0;
    char **target_argv = (target_opt_ind) ? argv + target_opt_ind : NULL;
    int status = agent->Run(target_argc, target_argv, 0xffffffff);

    puts("#########################################");
    printf("Status code: %d\n", status);
    puts("Coverage:");
    agent->traceBB();
    puts("#########################################");
    agent->DeInit();
    return 0;
}
