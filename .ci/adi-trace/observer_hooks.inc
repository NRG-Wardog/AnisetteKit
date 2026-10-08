// DEBUG TEMPORARY: execution observations only; never change guest state.
static void adi_observe_instruction(EmulatorVM *vm, uint64_t pc) noexcept {
    if (!vm || !activeADIConsumptionDebug || activeADIConsumptionDebug->phase != ADIConsumptionDebug::OTP) return;
    ADIPreserveErrno saved;
    auto &trace = activeADIConsumptionDebug->execution;
    const auto location = vm->diagnostic_modules.locate(pc);
    if (!location.module) { trace.boundary(); return; }
    uint32_t value = 0;
    const bool readable = uc_reg_read(vm->uc, UC_ARM64_REG_W0, &value) == UC_ERR_OK;
    if (trace.observe(location, value == uint32_t(-45061), readable)) {
        uint32_t instruction = 0;
        if (uc_mem_read(vm->uc, pc, &instruction, sizeof(instruction)) != UC_ERR_OK) { trace.flags |= 1; return; }
        if ((instruction & 0xfffffc1fU) == 0xd65f0000U || instruction == 0xd65f0bffU || instruction == 0xd65f0fffU)
            trace.returns.push(location);
    }
}
static void adi_observe_loaded(EmulatorVM *vm, const uint8_t *bytes, size_t length,
                              const EmulatorVM::LibraryInfo &lib) noexcept {
    ADIPreserveErrno saved;
    unsigned role = lib.name == "libstoreservicescore.so" ? 1u : (lib.name == "libCoreADI.so" ? 2u : 0u);
    if (!role) return;
    auto &modules = vm->diagnostic_modules;
    if (!bytes || length < sizeof(Elf64_Ehdr) || length > 67108864) { modules.incomplete = true; return; }
    adi_execution::sha256(bytes,length,modules.hash[role-1]);
    Elf64_Ehdr header; std::memcpy(&header,bytes,sizeof(header));
    if (header.e_phoff > length || header.e_phentsize != sizeof(Elf64_Phdr) ||
        header.e_phnum > (length-header.e_phoff)/sizeof(Elf64_Phdr)) { modules.incomplete=true;return; }
    for(unsigned i=0;i<header.e_phnum;++i) {
        Elf64_Phdr segment;std::memcpy(&segment,bytes+header.e_phoff+i*sizeof(segment),sizeof(segment));
        if(segment.p_type != PT_LOAD || !(segment.p_flags & 1))continue;
        if(segment.p_vaddr<lib.min_vaddr || segment.p_vaddr>lib.max_vaddr || segment.p_memsz>lib.max_vaddr-segment.p_vaddr){modules.incomplete=true;continue;}
        const uint64_t start=lib.base_address+segment.p_vaddr-lib.min_vaddr;
        modules.add(role,lib.base_address,start,start+segment.p_memsz);
    }
}
static void adi_observe_guest_read(EmulatorVM *vm, uint64_t fd, uint64_t guest,
                                   const uint8_t *bytes, size_t length, int copied) noexcept {
    if(!activeADIConsumptionDebug || activeADIConsumptionDebug->lookup(int(fd))!=ADIConsumptionDebug::ExpectedBlob)return;
    ADIPreserveErrno saved;
    auto &trace=activeADIConsumptionDebug->execution;trace.active=true;
    if(!length)return;
    if(copied!=0 || !bytes || length>1048576){trace.guestResult(3);return;}
    uint8_t scratch[256];
    for(size_t offset=0;offset<length;){const size_t n=std::min(sizeof(scratch),length-offset);
        if(guest>UINT64_MAX-offset || uc_mem_read(vm->uc,guest+offset,scratch,n)!=UC_ERR_OK){trace.guestResult(3);return;}
        if(std::memcmp(scratch,bytes+offset,n)!=0){trace.guestResult(2);return;}offset+=n;}
    trace.guestResult(1);
}
// Fixed public symbol classes. Unknown symbols are identified only by their
// stub-table index; an exact ELF file permits later mapping without string logs.
static unsigned adi_import_code(const std::string &name) noexcept {
    static const char*const names[]={"open","close","read","write","ftruncate","mkdir","umask","chmod","lstat","fstat",
        "malloc","calloc","realloc","free","strlen","strcmp","strncmp","strcpy","strncpy","memcpy","memset","memcmp","memchr",
        "__errno","__errno_location","__system_property_get","arc4random","gettimeofday","getauxval","dlopen","dlsym",
        "__cxa_guard_acquire","__cxa_guard_release","__cxa_allocate_exception","__cxa_begin_catch","__dynamic_cast",
        "strtoll","strtol","strtoull","strtod","atof","pthread_rwlock_init","pthread_mutex_init","__android_log_print"};
    for(unsigned i=0;i<sizeof(names)/sizeof(names[0]);++i)if(name==names[i])return i+1;
    return 0;
}
struct ADIObservedImport {
    EmulatorVM *vm; ADIConsumptionDebug *owner; adi_execution::Import event{};
    ADIObservedImport(EmulatorVM *machine,uint64_t stub,const std::string &name) noexcept
        :vm(machine),owner(activeADIConsumptionDebug) {
        if(!owner)return;ADIPreserveErrno saved;owner->execution.active=true;
        owner->execution.modules=vm->diagnostic_modules;
        event.phase=unsigned(owner->phase);event.code=adi_import_code(name);
        event.index=stub>=kImportAddress && stub<kImportAddress+kImportSize ? unsigned((stub-kImportAddress)/8) : 8192;
        uint64_t lr=0;if(uc_reg_read(vm->uc,UC_ARM64_REG_LR,&lr)==UC_ERR_OK)event.caller=vm->diagnostic_modules.locate(lr);
        if(name=="strtoull")owner->execution.bugMask|=1;
        if(name=="atof")owner->execution.bugMask|=2;
        if(name=="pthread_mutex_init")owner->execution.bugMask|=4;
        if(name=="pthread_rwlock_init")owner->execution.bugMask|=8;
        if(event.code==0)owner->execution.bugMask|=16;
        owner->execution.boundary();
    }
    ~ADIObservedImport() noexcept {
        if(!owner)return;ADIPreserveErrno saved;
        uint64_t result=0;uint32_t error=0;
        event.result=uc_reg_read(vm->uc,UC_ARM64_REG_X0,&result)!=UC_ERR_OK?4:
            result==0?0:result==UINT64_MAX?1:result==uint64_t(int64_t(-45061))?2:3;
        event.error=uc_mem_read(vm->uc,vm->errno_addr,&error,sizeof(error))==UC_ERR_OK&&error<=4095?error:4096;
        owner->execution.imports.push(event);
    }
};
