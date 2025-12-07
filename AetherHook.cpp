/*
MIT License

Copyright (c) 2022 Qwanwin

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
 furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
*/
#include <sys/mman.h>
#include <unistd.h>
#include <regex.h>
#include <jni.h>
#include <string>
#include <dlfcn.h>
#include <link.h>
#include <elf.h>
#include <vector>
#include <unordered_map>
#include <android/log.h>

#ifdef __aarch64__
typedef Elf64_Ehdr ElfEhdr;
typedef Elf64_Phdr ElfPhdr;
typedef Elf64_Dyn ElfDyn;
typedef Elf64_Sym ElfSym;
typedef Elf64_Addr ElfAddr;
typedef Elf64_Word ElfWord;
#else
typedef Elf32_Ehdr ElfEhdr;
typedef Elf32_Phdr ElfPhdr;
typedef Elf32_Dyn ElfDyn;
typedef Elf32_Sym ElfSym;
typedef Elf32_Addr ElfAddr;
typedef Elf32_Word ElfWord;
#endif

#include "AetherHook.h"

namespace AetherHook {
namespace Internal {

    static std::atomic<int> g_debug_mode{0};
    static std::atomic<bool> g_initialized{false}; 

    static inline size_t page_size() {
        static size_t p = 0;
        if (!p) p = (size_t)sysconf(_SC_PAGESIZE);
        return p;
    }

    static int make_memory_writable(void *addr, size_t len) {
        if (!addr || len == 0) return -1;
        uintptr_t start = (uintptr_t)addr & ~(page_size() - 1);
        size_t full = ((uintptr_t)addr + len - start + page_size() - 1) & ~(page_size() - 1);
        if (mprotect((void*)start, full, PROT_READ | PROT_WRITE | PROT_EXEC) != 0) {
            if (g_debug_mode.load()) {
                __android_log_print(ANDROID_LOG_ERROR, AETHER_HOOK_LOG_TAG, "mprotect failed addr=%p len=%zu errno=%d", addr, len, errno);
            }
            return -1;
        }
        return 0;
    }

    static void flush_icache(void *addr, size_t len) {
        if (!addr || len==0) return;
        __builtin___clear_cache((char*)addr, (char*)addr + len);
    }

    static bool match_regex(const char *text, const char *pattern) {
        if (!text || !pattern) return false;
        regex_t reg;
        int rc = regcomp(&reg, pattern, REG_EXTENDED | REG_NOSUB);
        if (rc != 0) {
            if (g_debug_mode.load()) {
                __android_log_print(ANDROID_LOG_ERROR, AETHER_HOOK_LOG_TAG, "regex compile failed for pattern: %s, rc=%d", pattern, rc);
            }
            return false;
        }
        rc = regexec(&reg, text, 0, NULL, 0);
        regfree(&reg);
        return (rc == 0);
    }

    static void* alloc_rwx(size_t sz) {
        size_t ps = page_size();
        size_t use = (sz + ps - 1) & ~(ps - 1);
        void *p = mmap(nullptr, use, PROT_READ|PROT_WRITE|PROT_EXEC, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
        if (p == MAP_FAILED) {
            if (g_debug_mode.load()) {
                 __android_log_print(ANDROID_LOG_ERROR, AETHER_HOOK_LOG_TAG, "Failed to allocate RWX memory: %s", strerror(errno));
            }
            return nullptr;
        }
        return p;
    }

} // namespace Internal

// Api
void initialize() {
    if (!Internal::g_initialized.exchange(true)) {
       
        logi("AetherHook initialized. Version: %s", version());
    }
}

void enable_debug(bool enable) {
    Internal::g_debug_mode.store(enable ? 1 : 0);
}

const char* version() {
    return "AetherHook-1.1-Revised";
}

void logi(const char* fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    __android_log_vprint(ANDROID_LOG_INFO, AETHER_HOOK_LOG_TAG, fmt, ap);
    va_end(ap);
}

void logd(const char* fmt, ...) {
    if (Internal::g_debug_mode.load()) {
        va_list ap;
        va_start(ap, fmt);
        __android_log_vprint(ANDROID_LOG_DEBUG, AETHER_HOOK_LOG_TAG, fmt, ap);
        va_end(ap);
    }
}

void loge(const char* fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    __android_log_vprint(ANDROID_LOG_ERROR, AETHER_HOOK_LOG_TAG, fmt, ap);
    va_end(ap);
}

int refresh(int sync) {

    PLT::apply_all_hooks();

    Inline::apply_all_hooks();
    if (Internal::g_debug_mode.load()) {
        logd("AetherHook::refresh completed");
    }
    return 0;
}

// PLT
namespace PLT {

    struct HookEntry {
        std::string path_regex;
        std::string symbol;
        void *new_func;
        void **old_func_out;
        bool applied;
    };

    static std::vector<HookEntry> g_plt_hooks;
    static std::mutex g_plt_mutex;

    static void apply_hooks_to_module(struct dl_phdr_info *info) {
        if (!info) return;
        const char *modname = (info->dlpi_name && info->dlpi_name[0]) ? info->dlpi_name : "(self)";
        uintptr_t base = (uintptr_t)info->dlpi_addr;
        const ElfPhdr *pt_dynamic = nullptr;

        for (int i=0; i<info->dlpi_phnum; i++) {
            const ElfPhdr *p = info->dlpi_phdr + i;
            if (p->p_type == PT_DYNAMIC) { pt_dynamic = p; break; }
        }
        if (!pt_dynamic) return;
        ElfDyn *dyn = (ElfDyn*)(base + pt_dynamic->p_vaddr);

        ElfSym *symtab = nullptr;
        const char *strtab = nullptr;
        uint64_t jmprel_off = 0;
        size_t jmprel_sz = 0;
        bool is_rela = false;

        for (ElfDyn *d = dyn; d->d_tag != DT_NULL; ++d) {
            switch (d->d_tag) {
                case DT_SYMTAB: symtab = (ElfSym*)(base + d->d_un.d_ptr); break;
                case DT_STRTAB: strtab = (const char*)(base + d->d_un.d_ptr); break;
                case DT_JMPREL: jmprel_off = (uint64_t)d->d_un.d_ptr; break;
                case DT_PLTRELSZ: jmprel_sz = (size_t)d->d_un.d_val; break;
                case DT_PLTREL: if (d->d_un.d_val == DT_RELA) is_rela = true; break;
                default: break;
            }
        }
        if (!jmprel_off || !jmprel_sz || !symtab || !strtab) return;

        std::lock_guard<std::mutex> lk(g_plt_mutex);
        for (auto &entry : g_plt_hooks) {
            if (entry.applied) continue;
            if (!Internal::match_regex(modname, entry.path_regex.c_str())) continue;

            #if __LP64__
                typedef Elf64_Rela   ElfRela;
                typedef Elf64_Rel    ElfRel;
                #define ELF_R_SYM ELF64_R_SYM
                #define ELF_R_TYPE ELF64_R_TYPE
            #else
                typedef Elf32_Rela   ElfRela;
                typedef Elf32_Rel    ElfRel;
                #define ELF_R_SYM ELF32_R_SYM
                #define ELF_R_TYPE ELF32_R_TYPE
            #endif

            uintptr_t rel_base = base + jmprel_off;
            size_t rel_count = jmprel_sz / (is_rela ? sizeof(ElfRela) : sizeof(ElfRel));

            for (size_t ri=0; ri<rel_count; ++ri) {
                uint32_t symidx;
                uint32_t rtype;
                uintptr_t r_offset;

                if (is_rela) {
                    ElfRela *rela = (ElfRela*)(rel_base + ri * sizeof(ElfRela));
                    symidx = ELF_R_SYM(rela->r_info);
                    rtype = ELF_R_TYPE(rela->r_info);
                    r_offset = (uintptr_t)rela->r_offset;
                } else {
                    ElfRel *rel = (ElfRel*)(rel_base + ri * sizeof(ElfRel));
                    symidx = ELF_R_SYM(rel->r_info);
                    rtype = ELF_R_TYPE(rel->r_info);
                    r_offset = (uintptr_t)rel->r_offset;
                }

                #if defined(__aarch64__)
                    const uint32_t JUMP_SLOT = R_AARCH64_JUMP_SLOT;
                #elif defined(__arm__)
                    const uint32_t JUMP_SLOT = R_ARM_JUMP_SLOT;
                #else
                    const uint32_t JUMP_SLOT = 0;
                #endif

                if (rtype != JUMP_SLOT) continue;

                const char *name = strtab + symtab[symidx].st_name;
                if (!name) continue;
                if (strcmp(name, entry.symbol.c_str()) != 0) continue;

                uintptr_t got_addr = base + r_offset;
                void **got_ptr = (void**)got_addr;
                void *orig = *got_ptr;

                if (entry.old_func_out && orig) *(entry.old_func_out) = orig;

                if (Internal::make_memory_writable(got_ptr, sizeof(void*)) != 0) {
                    loge("Failed to make GOT entry writable for %s in %s at %p", name, modname, got_ptr);
                    continue;
                }

                __atomic_store_n(got_ptr, entry.new_func, __ATOMIC_SEQ_CST);
                Internal::flush_icache(got_ptr, sizeof(void*));
                entry.applied = true;
                logi("PLT hook applied: '%s' in '%s' patched. New func: %p, Old func: %p", name, modname, entry.new_func, orig);
                break;
            }
        }
    }

    static int phdr_cb(struct dl_phdr_info *info, size_t size, void *data) {
        (void)size; (void)data;
        apply_hooks_to_module(info);
        return 0;
    }

    inline int register_hook(const char *pathname_regex, const char *symbol, void *new_func, void **old_func_out) {
        if (!pathname_regex || !symbol || !new_func) {
            loge("Invalid arguments for PLT::register_hook");
            return -1;
        }
        HookEntry e;
        e.path_regex = pathname_regex;
        e.symbol = symbol;
        e.new_func = new_func;
        e.old_func_out = old_func_out;
        e.applied = false;
        {
            std::lock_guard<std::mutex> lk(g_plt_mutex);
            g_plt_hooks.push_back(e);
        }
        if (Internal::g_debug_mode.load()) {
             logd("Registered PLT hook: regex='%s', symbol='%s'", pathname_regex, symbol);
        }
        return 0;
    }

    inline void apply_all_hooks() {
        dl_iterate_phdr(phdr_cb, nullptr);
    }

} // namespace PLT


// Inline Hook (AArch64) 
namespace Inline {

#if defined(__aarch64__)

    struct InlineHookEntry {
        uintptr_t target_addr;
        void *replacement;
        void *trampoline;
        size_t stolen_bytes;
        bool applied;
    };

    static std::vector<InlineHookEntry> g_inline_hooks;
    static std::mutex g_inline_mutex;

    // Logika AArch64
    static inline int64_t sign_extend(uint64_t val, int bits) {
        if (bits <= 0 || bits >= 64) return (int64_t)val;
        uint64_t mask = 1ULL << (bits - 1);
        return (val & mask) ? (int64_t)(val | (~0ULL << bits)) : (int64_t)val;
    }

    enum AArch64_InstType {
        INST_TYPE_UNKNOWN,
        INST_TYPE_ADR_ADRP,
        INST_TYPE_LDR_LIT,
        INST_TYPE_B_BL,
        INST_TYPE_B_COND,
        INST_TYPE_CBNZ_CBZ,
        INST_TYPE_TBNZ_TBZ,
        INST_TYPE_OTHER
    };

    static AArch64_InstType decode_aarch64_inst(uint32_t instruction) {
        if ((instruction & 0x9F000000) == 0x10000000 || (instruction & 0x9F000000) == 0x90000000)
            return INST_TYPE_ADR_ADRP;
        if ((instruction & 0x3B000000) == 0x18000000 || (instruction & 0x3B000000) == 0x58000000 ||
            (instruction & 0x3B000000) == 0x1C000000 || (instruction & 0x3B000000) == 0x5C000000)
            return INST_TYPE_LDR_LIT;
        if ((instruction & 0xFC000000) == 0x14000000 || (instruction & 0xFC000000) == 0x94000000)
            return INST_TYPE_B_BL;
        if ((instruction & 0xFF000010) == 0x54000000)
            return INST_TYPE_B_COND;
        if ((instruction & 0x7E000000) == 0x34000000)
            return INST_TYPE_CBNZ_CBZ;
        if ((instruction & 0x7C000000) == 0x36000000)
            return INST_TYPE_TBNZ_TBZ;
        return INST_TYPE_OTHER;
    }

    static uint32_t relocate_aarch64_inst(uint32_t original_inst, uintptr_t original_pc, uintptr_t new_pc) {
        AArch64_InstType type = decode_aarch64_inst(original_inst);

        if (Internal::g_debug_mode.load()) {
             __android_log_print(ANDROID_LOG_VERBOSE, AETHER_HOOK_LOG_TAG, "Relocating inst 0x%08x from 0x%lx to 0x%lx, type=%d", original_inst, original_pc, new_pc, type);
        }

        switch (type) {
            case INST_TYPE_ADR_ADRP: {
                uint32_t immlo = (original_inst >> 29) & 0x3;
                uint32_t immhi = (original_inst >> 5) & 0x7FFFF;
                int64_t imm = sign_extend((immhi << 2) | immlo, 21);
                bool is_adrp = (original_inst & 0x9F000000) == 0x90000000;

                uintptr_t target = is_adrp ? (original_pc & ~0xFFF) + (imm << 12) : original_pc + imm;
                int64_t new_imm = is_adrp ?
                    ((int64_t)(target & ~0xFFF) - (int64_t)(new_pc & ~0xFFF)) >> 12 :
                    (int64_t)target - (int64_t)new_pc;

                if (new_imm < -(1LL << 20) || new_imm >= (1LL << 20)) {
                     loge("AArch64 Relocation: ADR/ADRP overflow for 0x%08x", original_inst);
                    return 0;
                }

                uint32_t nlo = (uint32_t)new_imm & 0x3;
                uint32_t nhi = (uint32_t)(new_imm >> 2) & 0x7FFFF;
                return (original_inst & ~0x00FFFE03) | (nhi << 5) | (nlo << 29);
            }
            case INST_TYPE_LDR_LIT: {
                int64_t imm = sign_extend((original_inst >> 5) & 0x7FFFF, 19) << 2;
                uintptr_t target = original_pc + imm;
                int64_t new_imm = (int64_t)target - (int64_t)new_pc;
                if (new_imm < -(1LL << 20) || new_imm >= (1LL << 20)) {
                     loge("AArch64 Relocation: LDR literal overflow for 0x%08x", original_inst);
                    return 0;
                }
                uint32_t imm19 = ((uint32_t)(new_imm >> 2)) & 0x7FFFF;
                return (original_inst & ~0x00FFFE00) | (imm19 << 5);
            }
            case INST_TYPE_B_BL: {
                int64_t imm = sign_extend(original_inst & 0x03FFFFFF, 26) << 2;
                uintptr_t target = original_pc + imm;
                int64_t new_imm = (int64_t)target - (int64_t)new_pc;
                if (new_imm < -(1LL << 27) || new_imm >= (1LL << 27)) {
                     loge("AArch64 Relocation: B/BL overflow for 0x%08x", original_inst);
                    return 0;
                }
                uint32_t imm26 = ((uint32_t)(new_imm >> 2)) & 0x03FFFFFF;
                return (original_inst & ~0x03FFFFFF) | imm26;
            }
            case INST_TYPE_B_COND: {
                int64_t imm = sign_extend((original_inst >> 5) & 0x7FFFF, 19) << 2;
                uintptr_t target = original_pc + imm;
                int64_t new_imm = (int64_t)target - (int64_t)new_pc;
                if (new_imm < -(1LL << 20) || new_imm >= (1LL << 20)) {
                     loge("AArch64 Relocation: B.cond overflow for 0x%08x", original_inst);
                    return 0;
                }
                uint32_t imm19 = ((uint32_t)(new_imm >> 2)) & 0x7FFFF;
                return (original_inst & ~0x00FFFE00) | (imm19 << 5);
            }
            case INST_TYPE_CBNZ_CBZ: {
                int64_t imm = sign_extend((original_inst >> 5) & 0x7FFFF, 19) << 2;
                uintptr_t target = original_pc + imm;
                int64_t new_imm = (int64_t)target - (int64_t)new_pc;
                if (new_imm < -(1LL << 20) || new_imm >= (1LL << 20)) {
                     loge("AArch64 Relocation: CBZ/CBNZ overflow for 0x%08x", original_inst);
                    return 0;
                }
                uint32_t imm19 = ((uint32_t)(new_imm >> 2)) & 0x7FFFF;
                return (original_inst & ~0x00FFFE00) | (imm19 << 5);
            }
            case INST_TYPE_TBNZ_TBZ: {
                int64_t imm = sign_extend((original_inst >> 5) & 0x3FFF, 14) << 2;
                uintptr_t target = original_pc + imm;
                int64_t new_imm = (int64_t)target - (int64_t)new_pc;
                if (new_imm < -(1LL << 15) || new_imm >= (1LL << 15)) {
                     loge("AArch64 Relocation: TBZ/TBNZ overflow for 0x%08x", original_inst);
                    return 0;
                }
                uint32_t imm14 = ((uint32_t)(new_imm >> 2)) & 0x3FFF;
                return (original_inst & ~0x0007FE00) | (imm14 << 5);
            }
            case INST_TYPE_OTHER:
            default:
                return original_inst;
        }
    }

    static inline void write_inst32(uint32_t *dst, uint32_t inst) {
        __atomic_store_n(dst, inst, __ATOMIC_SEQ_CST);
    }

    static const uint32_t AARCH64_NOP = 0xD503201F;
    static const uint32_t AARCH64_BR_X17 = 0xD61F0220;

    static uint32_t encode_ldr_literal_x17(int32_t imm_bytes) {
        int32_t imm19 = imm_bytes >> 2;
        uint32_t imm19u = (uint32_t)(imm19 & 0x7FFFF);
        return 0x58000000 | (imm19u << 5) | 17;
    }

    static int create_aarch64_trampoline(uint8_t *orig, void *replace, void **out_trampoline, size_t *out_stolen) {
        if (!orig || !out_trampoline || !out_stolen) return -1;

        size_t need = 16; // Minimal ukuran patch (2 instruksi * 4 byte)
        size_t copied = 0;
        std::vector<uint32_t> insts;

        while (copied < need) {
            uint32_t inst = *(uint32_t*)(orig + copied);
            insts.push_back(inst);
            copied += 4;
            if (insts.size() > 256) { 
                 loge("create_trampoline: too many instructions when scanning");
                return -1;
            }
        }

        size_t tramp_size = insts.size() * 4 + 4 + 4 + 8; // instruksi + ldr + br + ptr
        void *tramp = Internal::alloc_rwx(tramp_size);
        if (!tramp) return -1;

        uint8_t *tp = (uint8_t*)tramp;
        uintptr_t tramp_pc = (uintptr_t)tp;

        for (size_t i = 0; i < insts.size(); ++i) {
            uint32_t orig_inst = insts[i];
            uintptr_t orig_inst_pc = (uintptr_t)orig + i * 4;
            uint32_t relocated = relocate_aarch64_inst(orig_inst, orig_inst_pc, tramp_pc + i * 4);
            if (relocated == 0) {
                 loge("create_trampoline: relocation failed for inst at %p (inst=0x%08x)", (void*)orig_inst_pc, orig_inst);
                munmap(tramp, tramp_size);
                return -1;
            }
            write_inst32((uint32_t*)(tp + i * 4), relocated);
        }

        size_t offset_after_insts = insts.size() * 4;
        write_inst32((uint32_t*)(tp + offset_after_insts), encode_ldr_literal_x17(8));
        offset_after_insts += 4;
        write_inst32((uint32_t*)(tp + offset_after_insts), AARCH64_BR_X17);
        offset_after_insts += 4;
        uintptr_t original_cont = (uintptr_t)orig + insts.size() * 4;
        *((uint64_t*)(tp + offset_after_insts)) = (uint64_t)original_cont;
        offset_after_insts += 8;

        Internal::flush_icache(tramp, offset_after_insts);

        *out_trampoline = tramp;
        *out_stolen = insts.size() * 4;
         logi("Created trampoline at %p (size=%zu), stolen_bytes=%zu, original_cont=%p", tramp, offset_after_insts, *out_stolen, (void*)original_cont);
        return 0;
    }

    static int apply_aarch64_patch(uint8_t *orig, void *replacement, size_t stolen_bytes) {
        if (!orig || !replacement || stolen_bytes < 16) return -1;

        if (Internal::make_memory_writable(orig, stolen_bytes) != 0) {
             loge("apply_aarch64_patch: make_memory_writable failed for %p", orig);
            return -1;
        }

        uint8_t patch[256];
        size_t pos = 0;
        write_inst32((uint32_t*)(patch + pos), encode_ldr_literal_x17(8)); pos += 4;
        write_inst32((uint32_t*)(patch + pos), AARCH64_BR_X17); pos += 4;
        *((uint64_t*)(patch + pos)) = (uint64_t)replacement; pos += 8;
        while (pos < stolen_bytes) {
            write_inst32((uint32_t*)(patch + pos), AARCH64_NOP); pos += 4;
        }

        memcpy(orig, patch, stolen_bytes);
        Internal::flush_icache(orig, stolen_bytes);
         logi("Patched function at %p -> %p (stolen=%zu)", orig, replacement, stolen_bytes);
        return 0;
    }

    // Api Inline 
    inline int register_hook(void *target_addr, void *new_func, void **old_func_out) {
        if (!target_addr || !new_func) {
             loge("Inline::register_hook invalid args");
            return -1;
        }
        InlineHookEntry e;
        e.target_addr = (uintptr_t)target_addr;
        e.replacement = new_func;
        e.trampoline = nullptr;
        e.stolen_bytes = 0;
        e.applied = false;
        {
            std::lock_guard<std::mutex> lk(g_inline_mutex);
            g_inline_hooks.push_back(e);
        }

        if (old_func_out) {
            void *tramp = nullptr;
            size_t stolen = 0;
            if (create_aarch64_trampoline((uint8_t*)target_addr, new_func, &tramp, &stolen) == 0) {
                *old_func_out = tramp;
                std::lock_guard<std::mutex> lk(g_inline_mutex);
                for (auto &it : g_inline_hooks) {
                    if (it.target_addr == (uintptr_t)target_addr && it.replacement == new_func) {
                        it.trampoline = tramp;
                        it.stolen_bytes = stolen;
                        break;
                    }
                }
            } else {
                 loge("Inline::register_hook create_trampoline failed for %p", target_addr);
                return -1;
            }
        }
        if (Internal::g_debug_mode.load()) {
             logd("Inline hook registered for %p -> %p", target_addr, new_func);
        }
        return 0;
    }

    inline void apply_all_hooks() {
        std::lock_guard<std::mutex> lk(g_inline_mutex);
        for (auto &entry : g_inline_hooks) {
            if (entry.applied) continue;

            uintptr_t tgt = entry.target_addr;
            if (!entry.trampoline) {
                void *tramp = nullptr;
                size_t stolen = 0;
                if (create_aarch64_trampoline((uint8_t*)tgt, entry.replacement, &tramp, &stolen) != 0) {
                     loge("apply_all_inline_hooks: failed to create trampoline for %p", (void*)tgt);
                    continue;
                }
                entry.trampoline = tramp;
                entry.stolen_bytes = stolen;
            }

            if (apply_aarch64_patch((uint8_t*)tgt, entry.replacement, entry.stolen_bytes) == 0) {
                entry.applied = true;
                 logi("Inline hook applied at %p -> %p (trampoline=%p)", (void*)tgt, entry.replacement, entry.trampoline);
            } else {
                 loge("apply_all_inline_hooks: failed to patch target %p", (void*)tgt);
            }
        }
    }

#else // Tidak AArch64
    inline int register_hook(void *target_addr, void *new_func, void **old_func_out) {
        (void)target_addr; (void)new_func; (void)old_func_out;
         loge("Inline hooks only implemented for AArch64");
        return -1;
    }
    inline void apply_all_hooks() { /* */ }
#endif // __aarch64__

} // namespace Inline

} // namespace AetherHook