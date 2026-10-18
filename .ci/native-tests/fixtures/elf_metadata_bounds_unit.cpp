// Ordinary host-only unit checks for the production metadata parser.
// The in-memory sample contains data objects only: no executable segment,
// guest instructions, constructor pointers, proprietary bytes or VM execution.
#include "elf_metadata_bounds.h"
#include <cstdio>
#include <cstdlib>
#include <limits>

namespace bounds = elf_metadata_bounds;
static unsigned checks = 0;
static void check(bool value) {
    ++checks;
    if (!value) { std::fprintf(stderr, "unit check %u failed\n", checks); std::exit(1); }
}
template<class T> static void put(std::vector<uint8_t> &data, size_t offset, const T &value) {
    check(bounds::range(data.size(), offset, sizeof(T)));
    std::memcpy(data.data() + offset, &value, sizeof(T));
}
template<class T> static T read(const std::vector<uint8_t> &data, size_t offset) {
    T value{}; check(bounds::file_read(data.data(), data.size(), offset, value)); return value;
}
static constexpr size_t dynamic_at = 0x100, hash_at = 0x200, symbols_at = 0x280;
static constexpr size_t strings_at = 0x300, rela_at = 0x380, object_at = 0x400;

static std::vector<uint8_t> ordinary_data() {
    std::vector<uint8_t> data(0x500, 0);
    Elf64_Ehdr header{};
    std::memcpy(header.e_ident, "\x7f" "ELF\x02\x01\x01", 7);
    header.e_type = 3; header.e_machine = 183; header.e_version = 1;
    header.e_ehsize = sizeof(header); header.e_phoff = sizeof(header);
    header.e_phentsize = sizeof(Elf64_Phdr); header.e_phnum = 2;
    put(data, 0, header);
    Elf64_Phdr load{};
    load.p_type = PT_LOAD; load.p_flags = PF_R | PF_W;
    load.p_filesz = data.size(); load.p_memsz = data.size() + 0x100; load.p_align = 8;
    put(data, sizeof(header), load);
    Elf64_Dyn entries[] = {
        {DT_HASH, {hash_at}}, {DT_SYMTAB, {symbols_at}}, {DT_SYMENT, {sizeof(Elf64_Sym)}},
        {DT_STRTAB, {strings_at}}, {DT_STRSZ, {17}},
        {DT_RELA, {rela_at}}, {DT_RELASZ, {sizeof(Elf64_Rela)}}, {DT_RELAENT, {sizeof(Elf64_Rela)}},
        {DT_NULL, {0}}
    };
    Elf64_Phdr dynamic{};
    dynamic.p_type = PT_DYNAMIC; dynamic.p_flags = PF_R;
    dynamic.p_offset = dynamic.p_vaddr = dynamic_at;
    dynamic.p_filesz = dynamic.p_memsz = sizeof(entries); dynamic.p_align = 8;
    put(data, sizeof(header) + sizeof(load), dynamic);
    for (size_t i = 0; i < sizeof(entries) / sizeof(entries[0]); ++i)
        put(data, dynamic_at + i * sizeof(Elf64_Dyn), entries[i]);
    const uint32_t hash[] = {1, 3, 1, 0, 2, 0};
    for (size_t i = 0; i < 6; ++i) put(data, hash_at + 4 * i, hash[i]);
    Elf64_Sym object{}; object.st_name = 1; object.st_info = 0x11;
    object.st_shndx = 1; object.st_value = object_at; object.st_size = 8;
    Elf64_Sym external{}; external.st_name = 8; external.st_info = 0x11;
    put(data, symbols_at + sizeof(Elf64_Sym), object);
    put(data, symbols_at + 2 * sizeof(Elf64_Sym), external);
    const char names[] = "\0object\0external\0";
    static_assert(sizeof(names) == 18, "sample names include explicit final NUL");
    std::memcpy(data.data() + strings_at, names, 17);
    Elf64_Rela relocation{}; relocation.r_offset = object_at + 8;
    relocation.r_info = (uint64_t(1) << 32) | R_AARCH64_ABS64;
    put(data, rela_at, relocation);
    return data;
}
static bounds::Metadata parse_good(const std::vector<uint8_t> &data) {
    bounds::Metadata metadata; const char *error = nullptr;
    check(bounds::parse(data.data(), data.size(), metadata, error)); check(error == nullptr);
    return metadata;
}
static void rejected(const std::vector<uint8_t> &data) {
    bounds::Metadata output; output.symbol_count = 77; const char *error = nullptr;
    check(!bounds::parse(data.data(), data.size(), output, error));
    check(error != nullptr); check(output.symbol_count == 77);
}
int main() {
    uint64_t out = 99;
    check(bounds::add(4, 5, out) && out == 9);
    check(!bounds::add(UINT64_MAX, 1, out));
    check(bounds::multiply(7, 6, out) && out == 42);
    check(bounds::multiply(UINT64_MAX, 0, out) && out == 0);
    check(!bounds::multiply(UINT64_MAX, 2, out));
    check(bounds::signed_add(4, -4, out) && out == 0);
    check(!bounds::signed_add(4, -5, out));
    check(bounds::signed_add(uint64_t(1) << 63, INT64_MIN, out) && out == 0);
    check(!bounds::signed_add(UINT64_MAX, 1, out));
    for (uint64_t offset = 0; offset <= 17; ++offset)
        for (uint64_t length = 0; length <= 17; ++length)
            check(bounds::range(16, offset, length) == (offset <= 16 && length <= 16 - offset));
    check(!bounds::range(16, UINT64_MAX, 1));
    check(!bounds::range(16, 1, UINT64_MAX));
    check(bounds::allocation_fits(0x1000, 64, 0, 8, 1));
    check(bounds::allocation_fits(0x1000, 64, 56, 8, 8));
    check(!bounds::allocation_fits(0x1000, 64, 56, 8, 9));
    check(bounds::allocation_fits(0x1000, 64, 0, 8, 0));
    check(!bounds::allocation_fits(0x1000, 64, 64, 8, 0));
    check(!bounds::allocation_fits(0x1000, 64, 0, 0, 8));
    check(!bounds::allocation_fits(0x1000, 64, 0, 3, 8));
    check(!bounds::allocation_fits(0x1000, 64, UINT64_MAX, 8, 8));
    check(!bounds::allocation_fits(0x1000, 64, 0, 8, UINT64_MAX));
    check(!bounds::allocation_fits(UINT64_MAX, 64, 0, 8, 8));
    check(!bounds::allocation_fits(UINT64_MAX - 4, 64, 8, 8, 8));
    check(bounds::allocation_fits(0x1000, 64, 48, 16, 16));
    const auto data = ordinary_data();
    auto metadata = parse_good(data);
    check(metadata.symbol_count == 3 && metadata.symbols.size() == 3);
    check(metadata.loads.size() == 1 && !(metadata.loads.front().p_flags & PF_X));
    check(metadata.init == 0 && metadata.init_array == 0 && metadata.init_arraysz == 0);
    check(metadata.rela.size() == 1 && metadata.jmprel.empty());
    std::string name;
    check(bounds::name(metadata, 1, name) && name == "object");
    check(bounds::name(metadata, 8, name) && name == "external");
    check(bounds::name(metadata, 16, name) && name.empty());
    check(!bounds::name(metadata, 17, name));
    check(!bounds::name(metadata, UINT64_MAX, name));
    Elf64_Sym symbol{};
    check(bounds::symbol(metadata, 2, symbol));
    check(!bounds::ordinary_definition(symbol));
    check(!bounds::definition_address(metadata, 0x10000, symbol, out));
    symbol.st_value = object_at;
    check(!bounds::ordinary_definition(symbol));
    check(!bounds::definition_address(metadata, 0x10000, symbol, out));
    check(!bounds::symbol(metadata, 3, symbol));
    check(!bounds::symbol(metadata, UINT64_MAX, symbol));
    check(bounds::symbol(metadata, 1, symbol));
    check(bounds::definition_address(metadata, 0x10000, symbol, out) && out == 0x10400);
    symbol.st_shndx = bounds::absolute_section; symbol.st_value = 7;
    check(bounds::definition_address(metadata, 0x10000, symbol, out) && out == 7);
    symbol.st_shndx = 1; symbol.st_value = 0; symbol.st_size = 1;
    check(bounds::definition_address(metadata, 0x10000, symbol, out) && out == 0x10000);
    symbol.st_info = bounds::tls_symbol_type;
    check(!bounds::definition_address(metadata, 0x10000, symbol, out));
    check(bounds::memory_range(metadata, 0x5ff, 1));
    check(!bounds::memory_range(metadata, 0x5ff, 2));
    check(bounds::file_range(metadata, 0x4ff, 1, out) && out == 0x4ff);
    check(!bounds::file_range(metadata, 0x500, 1, out));
    check(!bounds::guest_address(metadata, UINT64_MAX, 1, 1, out));
    check(bounds::relative_address(metadata, 0x10000, -1, out) && out == 0xffff);
    check(!bounds::relative_address(metadata, 0, -1, out));
    check(!bounds::relative_address(metadata, UINT64_MAX, 1, out));
    {
        auto biased = metadata; biased.min_vaddr = 0x10000;
        check(bounds::relative_address(biased, 0x8000, 0x20000, out) && out == 0x18000);
        check(bounds::relative_address(biased, 0x20000, 0x8000, out) && out == 0x18000);
        check(!bounds::relative_address(biased, 0x8000, 0, out));
    }
    uint64_t value = 123;
    check(!bounds::file_read<uint64_t>(nullptr, 8, 0, value));
    check(!bounds::file_read<uint64_t>(data.data(), data.size(), data.size() - 7, value));
    check(!bounds::file_read<uint64_t>(data.data(), data.size(), UINT64_MAX, value));
    {
        auto names = metadata;
        names.strings.assign(302, 'a'); names.strings.front() = names.strings.back() = 0;
        names.strsz = names.strings.size();
        check(bounds::name(names, 1, name) && name.size() == 300);
        names.strings.back() = 'a';
        check(!bounds::name(names, 1, name));
        names.strsz += 1;
        check(!bounds::name(names, 1, name));
        auto symbols = metadata; symbols.symbols.resize(1);
        check(!bounds::symbol(symbols, 1, symbol));
    }
    for (const size_t length : {size_t(0), size_t(63), size_t(100), data.size() - 1}) {
        auto truncated = data; truncated.resize(length); rejected(truncated);
    }
    {
        auto changed = data; auto header = read<Elf64_Ehdr>(changed, 0);
        header.e_phoff = UINT64_MAX; put(changed, 0, header); rejected(changed);
    }
    {
        auto changed = data; auto header = read<Elf64_Ehdr>(changed, 0);
        header.e_phnum = 0; put(changed, 0, header); rejected(changed);
    }
    {
        auto changed = data; auto load = read<Elf64_Phdr>(changed, sizeof(Elf64_Ehdr));
        load.p_filesz = load.p_memsz + 1; put(changed, sizeof(Elf64_Ehdr), load); rejected(changed);
    }
    {
        auto changed = data; auto entry = read<Elf64_Dyn>(changed, dynamic_at + 2 * sizeof(Elf64_Dyn));
        entry.d_un.d_val = sizeof(Elf64_Sym) - 1;
        put(changed, dynamic_at + 2 * sizeof(Elf64_Dyn), entry); rejected(changed);
    }
    {
        auto changed = data; auto entry = read<Elf64_Dyn>(changed, dynamic_at);
        entry.d_tag = 0x6ffffef5; put(changed, dynamic_at, entry); rejected(changed);
    }
    {
        auto changed = data; put(changed, hash_at + 4, UINT32_MAX); rejected(changed);
    }
    {
        auto changed = data; put(changed, hash_at + 4, uint32_t(0)); rejected(changed);
    }
    {
        auto changed = data; put(changed, hash_at + 8, uint32_t(3)); rejected(changed);
    }
    {
        auto changed = data; changed[strings_at + 16] = 'x'; rejected(changed);
    }
    {
        auto changed = data; auto object = read<Elf64_Sym>(changed, symbols_at + sizeof(Elf64_Sym));
        object.st_name = 17; put(changed, symbols_at + sizeof(Elf64_Sym), object); rejected(changed);
    }
    {
        auto changed = data; auto object = read<Elf64_Sym>(changed, symbols_at + sizeof(Elf64_Sym));
        object.st_value = 0x600; put(changed, symbols_at + sizeof(Elf64_Sym), object); rejected(changed);
    }
    {
        auto changed = data; auto relocation = read<Elf64_Rela>(changed, rela_at);
        relocation.r_info = (uint64_t(3) << 32) | R_AARCH64_ABS64;
        put(changed, rela_at, relocation); rejected(changed);
    }
    {
        auto changed = data; auto relocation = read<Elf64_Rela>(changed, rela_at);
        relocation.r_offset = 0x5f9; put(changed, rela_at, relocation); rejected(changed);
    }
    {
        auto changed = data; auto relocation = read<Elf64_Rela>(changed, rela_at);
        relocation.r_info = (uint64_t(1) << 32) | 9999;
        put(changed, rela_at, relocation); rejected(changed);
    }
    {
        auto changed = data; auto relocation = read<Elf64_Rela>(changed, rela_at);
        relocation.r_info = 0; put(changed, rela_at, relocation);
        const auto no_operation = parse_good(changed);
        check(no_operation.rela.size() == 1 && no_operation.rela.front().r_info == 0);
    }
    {
        auto changed = data; auto entry = read<Elf64_Dyn>(changed, dynamic_at + 6 * sizeof(Elf64_Dyn));
        entry.d_un.d_val = sizeof(Elf64_Rela) - 1;
        put(changed, dynamic_at + 6 * sizeof(Elf64_Dyn), entry); rejected(changed);
    }
    {
        auto changed = data; auto terminal = read<Elf64_Dyn>(changed, dynamic_at + 8 * sizeof(Elf64_Dyn));
        terminal.d_tag = DT_NEEDED; put(changed, dynamic_at + 8 * sizeof(Elf64_Dyn), terminal); rejected(changed);
    }
    // Presence is independent of size: all incomplete recognized table groups
    // must fail, while complete empty groups and entirely absent groups work.
    for (const bool plt : {false, true}) {
        for (const uint64_t bytes : {uint64_t(0), uint64_t(sizeof(Elf64_Rela))}) {
            for (unsigned mask = 0; mask < 8; ++mask) {
                auto changed = data;
                const int64_t tags[] = {plt ? DT_JMPREL : DT_RELA,
                    plt ? DT_PLTRELSZ : DT_RELASZ, plt ? DT_PLTREL : DT_RELAENT};
                const uint64_t values[] = {bytes ? rela_at : 0, bytes,
                    plt ? uint64_t(DT_RELA) : uint64_t(sizeof(Elf64_Rela))};
                for (unsigned member = 0; member < 3; ++member) {
                    Elf64_Dyn entry{};
                    entry.d_tag = (mask & (1u << member)) ? tags[member] : DT_NEEDED;
                    entry.d_un.d_val = values[member];
                    put(changed, dynamic_at + (5 + member) * sizeof(Elf64_Dyn), entry);
                }
                if (mask != 0 && mask != 7) {
                    rejected(changed);
                } else {
                    const auto parsed = parse_good(changed);
                    check(parsed.rela.size() + parsed.jmprel.size() == (mask == 7 && bytes ? 1 : 0));
                    check(plt ? parsed.rela.empty() : parsed.jmprel.empty());
                }
            }
        }
        auto changed = data;
        const Elf64_Dyn empty_group[] = {
            {plt ? DT_JMPREL : DT_RELA, {0}},
            {plt ? DT_PLTRELSZ : DT_RELASZ, {0}},
            {plt ? DT_PLTREL : DT_RELAENT, {0}}
        };
        for (size_t member = 0; member < 3; ++member)
            put(changed, dynamic_at + (5 + member) * sizeof(Elf64_Dyn), empty_group[member]);
        rejected(changed); // Empty tables still require a valid entry format.
    }
    std::printf("{\"schema\":1,\"checks\":%u,\"failures\":0,\"guest_execution\":false,\"proprietary_input\":false}\n", checks);
}
