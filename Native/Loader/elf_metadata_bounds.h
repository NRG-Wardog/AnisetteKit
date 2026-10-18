#ifndef ELF_METADATA_BOUNDS_H
#define ELF_METADATA_BOUNDS_H

#include "anisette_base.h"
#include <cstring>
#include <string>
#include <unordered_map>
#include <vector>
#include <utility>

// Host-only ELF metadata parsing. No guest instructions or Unicorn calls occur
// here. Counts come from ELF metadata, never from a scan until memory runs out.
namespace elf_metadata_bounds {

inline bool add(uint64_t a, uint64_t b, uint64_t &out) {
    if (b > UINT64_MAX - a) return false;
    out = a + b;
    return true;
}
inline bool multiply(uint64_t a, uint64_t b, uint64_t &out) {
    if (a && b > UINT64_MAX / a) return false;
    out = a * b;
    return true;
}
inline bool range(uint64_t size, uint64_t offset, uint64_t length) {
    return offset <= size && length <= size - offset;
}

// Mirrors the existing allocator's alignment without mutating it or invoking
// its abort-on-exhaustion path. Used only for loader-owned reservations.
inline bool allocation_fits(uint64_t base, uint64_t size, uint64_t offset,
                            uint64_t alignment, uint64_t bytes) {
    if (!alignment || (alignment & (alignment - 1))) return false;
    uint64_t aligned = 0, address = 0, end = 0;
    if (!add(bytes, alignment - 1, aligned)) return false;
    aligned &= ~(alignment - 1);
    if (!aligned) aligned = alignment;
    return range(size, offset, aligned) && add(base, offset, address) && add(address, aligned, end);
}

template <class T>
inline bool file_read(const uint8_t *data, size_t size, uint64_t offset, T &out) {
    if (!data || !range(size, offset, sizeof(T))) return false;
    std::memcpy(&out, data + static_cast<size_t>(offset), sizeof(T));
    return true;
}

struct Metadata {
    uint64_t min_vaddr = 0, max_vaddr = 0, dynamic = 0;
    uint64_t symtab = 0, strtab = 0, strsz = 0;
    uint64_t rela_address = 0, jmprel_address = 0;
    uint64_t init = 0, init_array = 0, init_arraysz = 0;
    size_t symbol_count = 0;
    std::vector<Elf64_Phdr> loads;
    std::vector<Elf64_Sym> symbols;
    std::vector<char> strings;
    std::vector<Elf64_Rela> rela, jmprel;
};

inline bool memory_range(const Metadata &m, uint64_t address, uint64_t size) {
    for (const auto &p : m.loads) {
        if (address >= p.p_vaddr && range(p.p_memsz, address - p.p_vaddr, size)) return true;
    }
    return false;
}
inline bool file_range(const Metadata &m, uint64_t address, uint64_t size, uint64_t &offset) {
    for (const auto &p : m.loads) {
        if (address >= p.p_vaddr && range(p.p_filesz, address - p.p_vaddr, size))
            return add(p.p_offset, address - p.p_vaddr, offset);
    }
    return false;
}
inline bool guest_address(const Metadata &m, uint64_t base, uint64_t address,
                          uint64_t size, uint64_t &out) {
    uint64_t end = 0;
    return address >= m.min_vaddr && memory_range(m, address, size) &&
           add(base, address - m.min_vaddr, out) && add(out, size, end);
}
inline bool symbol(const Metadata &m, uint64_t index, Elf64_Sym &out) {
    if (index >= m.symbol_count || index >= m.symbols.size()) return false;
    out = m.symbols[static_cast<size_t>(index)];
    return true;
}
inline bool name(const Metadata &m, uint64_t offset, std::string &out) {
    if (offset >= m.strsz || m.strsz > m.strings.size()) return false;
    const char *start = m.strings.data() + static_cast<size_t>(offset);
    const void *end = std::memchr(start, 0, static_cast<size_t>(m.strsz - offset));
    if (!end) return false;
    out.assign(start, static_cast<const char *>(end) - start);
    return true;
}

constexpr uint16_t undefined_section = 0;
constexpr uint16_t absolute_section = 0xfff1;
constexpr uint16_t reserved_section = 0xff00;
constexpr uint8_t tls_symbol_type = 6;
inline bool ordinary_definition(const Elf64_Sym &s) {
    return s.st_shndx != undefined_section && (s.st_info & 0xf) != tls_symbol_type;
}
inline bool definition_address(const Metadata &m, uint64_t base,
                               const Elf64_Sym &s, uint64_t &out) {
    if (!ordinary_definition(s)) return false;
    if (s.st_shndx == absolute_section) { out = s.st_value; return true; }
    return s.st_shndx < reserved_section && guest_address(m, base, s.st_value, s.st_size, out);
}
inline bool signed_add(uint64_t value, int64_t addend, uint64_t &out) {
    if (addend >= 0) return add(value, static_cast<uint64_t>(addend), out);
    const uint64_t magnitude = static_cast<uint64_t>(-(addend + 1)) + 1;
    if (magnitude > value) return false;
    out = value - magnitude;
    return true;
}

// R_AARCH64_RELATIVE uses the load bias plus a signed addend. Unlike a
// symbol definition, the resulting value need not itself point inside a load.
inline bool relative_address(const Metadata &m, uint64_t base, int64_t addend, uint64_t &out) {
    if (addend >= 0) {
        const uint64_t value = static_cast<uint64_t>(addend);
        if (value >= m.min_vaddr) return add(base, value - m.min_vaddr, out);
        const uint64_t difference = m.min_vaddr - value;
        if (difference > base) return false;
        out = base - difference;
        return true;
    }
    return base >= m.min_vaddr && signed_add(base - m.min_vaddr, addend, out);
}

// The output is published only after the complete metadata pass succeeds.
inline bool parse(const uint8_t *data, size_t size, Metadata &out, const char *&error) {
    error = nullptr;
    auto fail = [&](const char *why) { error = why; return false; };
    Metadata m;
    Elf64_Ehdr eh{};
    if (!file_read(data, size, 0, eh) ||
        std::memcmp(eh.e_ident, "\x7f\x45\x4c\x46\x02\x01\x01", 7) != 0 ||
        eh.e_type != 3 || eh.e_machine != 183 || eh.e_version != 1 ||
        eh.e_ehsize != sizeof(Elf64_Ehdr) || eh.e_phentsize != sizeof(Elf64_Phdr) ||
        !eh.e_phnum || eh.e_phnum == 0xffff)
        return fail("unsupported or invalid ELF header");
    uint64_t phbytes = 0;
    if (!multiply(eh.e_phnum, sizeof(Elf64_Phdr), phbytes) || !range(size, eh.e_phoff, phbytes))
        return fail("program header table outside file");
    Elf64_Phdr dynamic{};
    bool have_dynamic = false;
    m.min_vaddr = UINT64_MAX;
    for (size_t i = 0; i < eh.e_phnum; ++i) {
        Elf64_Phdr p{};
        if (!file_read(data, size, eh.e_phoff + i * sizeof(p), p)) return fail("program header read failed");
        if (p.p_type != PT_LOAD && p.p_type != PT_DYNAMIC) continue;
        uint64_t end = 0;
        if (p.p_filesz > p.p_memsz || !range(size, p.p_offset, p.p_filesz) ||
            !add(p.p_vaddr, p.p_memsz, end)) return fail("invalid segment bounds");
        if (p.p_type == PT_DYNAMIC) {
            if (have_dynamic) return fail("multiple dynamic segments unsupported");
            dynamic = p;
            have_dynamic = true;
            continue;
        }
        if (p.p_align > 1 && ((p.p_align & (p.p_align - 1)) ||
            (p.p_vaddr % p.p_align != p.p_offset % p.p_align))) return fail("invalid load alignment");
        if (!p.p_memsz) continue;
        // Conflicting mappings would make the file-backed metadata ambiguous.
        for (const auto &previous : m.loads) {
            uint64_t previous_end = 0;
            if (!add(previous.p_vaddr, previous.p_memsz, previous_end) ||
                (p.p_vaddr < previous_end && previous.p_vaddr < end))
                return fail("overlapping load segments unsupported");
        }
        uint64_t aligned_end = 0;
        if (!add(end, 0xffff, aligned_end)) return fail("load alignment overflow");
        aligned_end &= ~uint64_t(0xffff);
        const uint64_t start = p.p_vaddr & ~uint64_t(0xffff);
        if (start < m.min_vaddr) m.min_vaddr = start;
        if (aligned_end > m.max_vaddr) m.max_vaddr = aligned_end;
        m.loads.push_back(p);
    }
    if (m.loads.empty() || m.min_vaddr >= m.max_vaddr || !have_dynamic)
        return fail("missing load or dynamic segment");
    uint64_t dynamic_offset = 0;
    if (!dynamic.p_filesz || dynamic.p_filesz % sizeof(Elf64_Dyn) ||
        !memory_range(m, dynamic.p_vaddr, dynamic.p_memsz) ||
        !file_range(m, dynamic.p_vaddr, dynamic.p_filesz, dynamic_offset) || dynamic_offset != dynamic.p_offset)
        return fail("dynamic segment outside file-backed load");
    m.dynamic = dynamic.p_vaddr;
    std::unordered_map<int64_t, uint64_t> tags;
    bool terminated = false;
    for (uint64_t offset = 0; offset < dynamic.p_filesz; offset += sizeof(Elf64_Dyn)) {
        Elf64_Dyn d{};
        if (!file_read(data, size, dynamic_offset + offset, d)) return fail("dynamic read failed");
        if (d.d_tag == DT_NULL) { terminated = true; break; }
        switch (d.d_tag) {
            case DT_HASH: case DT_SYMTAB: case DT_SYMENT: case DT_STRTAB: case DT_STRSZ:
            case DT_RELA: case DT_RELASZ: case DT_RELAENT: case DT_REL: case DT_RELSZ:
            case DT_JMPREL: case DT_PLTRELSZ: case DT_PLTREL: case DT_INIT:
            case DT_INIT_ARRAY: case DT_INIT_ARRAYSZ:
                if (!tags.emplace(d.d_tag, d.d_un.d_val).second) return fail("duplicate dynamic metadata");
                break;
            default: break;
        }
    }
    if (!terminated) return fail("unterminated dynamic segment");
    auto has = [&](int64_t tag) { return tags.find(tag) != tags.end(); };
    auto value = [&](int64_t tag) -> uint64_t {
        const auto it = tags.find(tag);
        return it == tags.end() ? 0 : it->second;
    };
    if (!has(DT_HASH)) return fail("DT_HASH required; GNU-hash-only metadata unsupported");
    if (!has(DT_SYMTAB) || !has(DT_STRTAB) || !has(DT_STRSZ) || value(DT_SYMENT) != sizeof(Elf64_Sym))
        return fail("missing or invalid symbol/string metadata");
    if (value(DT_REL) || value(DT_RELSZ)) return fail("REL relocations unsupported");
    m.symtab = value(DT_SYMTAB);
    m.strtab = value(DT_STRTAB);
    m.strsz = value(DT_STRSZ);
    uint64_t hash_offset = 0;
    uint32_t buckets = 0, chains = 0;
    if (!file_range(m, value(DT_HASH), 8, hash_offset) ||
        !file_read(data, size, hash_offset, buckets) || !file_read(data, size, hash_offset + 4, chains) ||
        !buckets || !chains) return fail("invalid SysV hash header");
    uint64_t hash_words = 0, hash_bytes = 0, symbol_bytes = 0, symbol_offset = 0, string_offset = 0;
    if (!add(buckets, chains, hash_words) || !add(hash_words, 2, hash_words) ||
        !multiply(hash_words, 4, hash_bytes) || !file_range(m, value(DT_HASH), hash_bytes, hash_offset) ||
        !multiply(chains, sizeof(Elf64_Sym), symbol_bytes) || !file_range(m, m.symtab, symbol_bytes, symbol_offset) ||
        !m.strsz || !file_range(m, m.strtab, m.strsz, string_offset) ||
        symbol_bytes > SIZE_MAX || m.strsz > SIZE_MAX)
        return fail("hash, symbol or string table outside file-backed load");
    for (uint64_t word = 2; word < hash_words; ++word) {
        uint32_t index = 0;
        if (!file_read(data, size, hash_offset + word * 4, index) || index >= chains)
            return fail("hash symbol index out of range");
    }
    m.symbol_count = chains;
    m.symbols.resize(m.symbol_count);
    m.strings.resize(static_cast<size_t>(m.strsz));
    std::memcpy(m.symbols.data(), data + static_cast<size_t>(symbol_offset), static_cast<size_t>(symbol_bytes));
    std::memcpy(m.strings.data(), data + static_cast<size_t>(string_offset), m.strings.size());
    if (m.strings.front() || m.strings.back()) return fail("invalid string table terminator");
    const auto &null_symbol = m.symbols.front();
    if (null_symbol.st_name || null_symbol.st_info || null_symbol.st_other || null_symbol.st_shndx ||
        null_symbol.st_value || null_symbol.st_size) return fail("invalid null symbol");
    for (const auto &s : m.symbols) {
        std::string symbol_name;
        uint64_t ignored = 0;
        if (!name(m, s.st_name, symbol_name)) return fail("symbol name outside bounded string table");
        if (ordinary_definition(s) && !definition_address(m, 0, s, ignored))
            return fail("invalid or unsupported symbol definition");
    }
    // Recognized table tags form complete groups even when their byte size is
    // zero. An empty, complete group performs no table read.
    const bool have_rela = has(DT_RELA) || has(DT_RELASZ) || has(DT_RELAENT);
    const bool have_plt = has(DT_JMPREL) || has(DT_PLTRELSZ) || has(DT_PLTREL);
    if ((have_rela && !(has(DT_RELA) && has(DT_RELASZ) && has(DT_RELAENT))) ||
        (have_plt && !(has(DT_JMPREL) && has(DT_PLTRELSZ) && has(DT_PLTREL))))
        return fail("incomplete relocation metadata");
    // Other dynamic relocation encodings (for example RELR or Android packed
    // REL/RELA tags) are not interpreted or validated by this bounded parser.
    auto relocations = [&](int64_t address_tag, int64_t size_tag, std::vector<Elf64_Rela> &table) {
        const uint64_t bytes = value(size_tag);
        if (!bytes) return true;
        uint64_t offset = 0;
        if (!has(address_tag) || bytes % sizeof(Elf64_Rela) || bytes > SIZE_MAX ||
            !file_range(m, value(address_tag), bytes, offset)) return false;
        table.resize(static_cast<size_t>(bytes / sizeof(Elf64_Rela)));
        std::memcpy(table.data(), data + static_cast<size_t>(offset), static_cast<size_t>(bytes));
        for (const auto &r : table) {
            const uint64_t index = ELF64_R_SYM(r.r_info);
            const uint32_t type = static_cast<uint32_t>(ELF64_R_TYPE(r.r_info));
            if (index >= m.symbol_count) return false;
            if (type == R_AARCH64_RELATIVE || type == R_AARCH64_JUMP_SLOT ||
                type == R_AARCH64_GLOB_DAT || type == R_AARCH64_ABS64) {
                if (!memory_range(m, r.r_offset, sizeof(uint64_t))) return false;
                if (type == R_AARCH64_RELATIVE && index) return false;
                if (type != R_AARCH64_RELATIVE && (m.symbols[index].st_info & 0xf) == tls_symbol_type) return false;
            } else if (type != 0) return false; // Only R_AARCH64_NONE is a supported no-op.
        }
        return true;
    };
    if ((have_rela && value(DT_RELAENT) != sizeof(Elf64_Rela)) ||
        (have_plt && value(DT_PLTREL) != DT_RELA) ||
        !relocations(DT_RELA, DT_RELASZ, m.rela) || !relocations(DT_JMPREL, DT_PLTRELSZ, m.jmprel))
        return fail("invalid relocation metadata");
    m.rela_address = value(DT_RELA);
    m.jmprel_address = value(DT_JMPREL);
    m.init = value(DT_INIT);
    m.init_array = value(DT_INIT_ARRAY);
    m.init_arraysz = value(DT_INIT_ARRAYSZ);
    if ((m.init && !memory_range(m, m.init, 4)) ||
        (m.init_arraysz && (!has(DT_INIT_ARRAY) || m.init_arraysz % sizeof(uint64_t) ||
            !memory_range(m, m.init_array, m.init_arraysz))) || m.init_arraysz > SIZE_MAX)
        return fail("invalid constructor metadata");
    out = std::move(m);
    return true;
}

} // namespace elf_metadata_bounds
#endif
