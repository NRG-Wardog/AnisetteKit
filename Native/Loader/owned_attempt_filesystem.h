#pragma once
#include <string>
#include <vector>
#include <cerrno>
#include <cstdint>
#include <atomic>
#include <sys/stat.h>
#if !defined(_WIN32) && !defined(_MSC_VER)
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#endif

// Descriptor-relative, no-symlink access for an exclusively owned scratch root.
// This bounds admitted object types and sizes, not kernel scheduling latency.
namespace anisette_owned_attempt {
class Filesystem {
public:
    static constexpr uint64_t max_io = 1024 * 1024;
    Filesystem() = default;
    Filesystem(const Filesystem &) = delete;
    Filesystem &operator=(const Filesystem &) = delete;
    ~Filesystem() {
#if !defined(_WIN32) && !defined(_MSC_VER)
        if (scratch_fd_ >= 0) ::close(scratch_fd_);
        if (library_fd_ >= 0) ::close(library_fd_);
#endif
    }
    bool configure(const std::string &scratch, const std::string &library) {
#if !defined(_WIN32) && !defined(_MSC_VER)
        if (scratch_fd_ >= 0 || library_fd_ >= 0) return false;
        scratch_ = scratch; library_ = library;
        scratch_fd_ = ::open(scratch.c_str(), O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
        library_fd_ = ::open(library.c_str(), O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
        struct stat st{};
        return scratch_fd_ >= 0 && library_fd_ >= 0 && ::fstat(scratch_fd_, &st) == 0 &&
            st.st_uid == geteuid() && (st.st_mode & 0077) == 0;
#else
        (void)scratch; (void)library; return false;
#endif
    }
    bool configure_descriptors(const std::string &scratch, const std::string &library, int scratch_fd, int library_fd) {
#if !defined(_WIN32) && !defined(_MSC_VER)
        if (scratch_fd_ >= 0 || library_fd_ >= 0) return false;
        struct stat a{}, b{};
        if (fstat(scratch_fd,&a) || fstat(library_fd,&b) || !S_ISDIR(a.st_mode) || !S_ISDIR(b.st_mode) ||
            a.st_uid!=geteuid() || b.st_uid!=geteuid() || (a.st_mode&0077) || (b.st_mode&0077)) return false;
        scratch_=scratch; library_=library;
        scratch_fd_=fcntl(scratch_fd,F_DUPFD_CLOEXEC,0); library_fd_=fcntl(library_fd,F_DUPFD_CLOEXEC,0);
        return scratch_fd_>=0 && library_fd_>=0;
#else
        (void)scratch; (void)library; (void)scratch_fd; (void)library_fd; return false;
#endif
    }
    int duplicate_scratch() const {
#if !defined(_WIN32) && !defined(_MSC_VER)
        return fcntl(scratch_fd_,F_DUPFD_CLOEXEC,0);
#else
        return -1;
#endif
    }
    int open_file(const std::string &path, int flags, unsigned mode) const {
#if !defined(_WIN32) && !defined(_MSC_VER)
        if (operations_.fetch_add(1, std::memory_order_relaxed) >= 256) { errno = EMFILE; return -1; }
        const bool writable = (flags & O_ACCMODE) != O_RDONLY || (flags & (O_CREAT | O_TRUNC | O_APPEND)) != 0;
        Parent parent = resolve(path, writable);
        if (parent.fd < 0) return -1;
        // No sync/FIFO/device waits and no externally supplied descriptor.
        const int admitted = O_ACCMODE | O_CREAT | O_EXCL | O_TRUNC | O_APPEND;
        int fd = ::openat(parent.fd, parent.leaf.c_str(), (flags & admitted & ~O_TRUNC) | O_NONBLOCK | O_NOFOLLOW | O_CLOEXEC, mode & 0600);
        const int saved = errno; ::close(parent.fd); errno = saved;
        if (fd < 0) return -1;
        struct stat st{};
        if (::fstat(fd, &st) != 0 || !S_ISREG(st.st_mode) || st.st_nlink != 1 || st.st_size < 0 ||
            static_cast<uint64_t>(st.st_size) > (writable ? max_io : 64 * max_io)) {
            ::close(fd); errno = EPERM; return -1;
        }
        if ((flags & O_TRUNC) && ::ftruncate(fd, 0) != 0) { int saved = errno; ::close(fd); errno = saved; return -1; }
        return fd;
#else
        (void)path; (void)flags; (void)mode; errno = EPERM; return -1;
#endif
    }
    int create_directory(const std::string &path) const {
#if !defined(_WIN32) && !defined(_MSC_VER)
        if (operations_.fetch_add(1, std::memory_order_relaxed) >= 256) { errno = EMFILE; return -1; }
        Parent p = resolve(path, true); if (p.fd < 0) return -1;
        int result = ::mkdirat(p.fd, p.leaf.c_str(), 0700);
        if (result != 0 && errno == EEXIST) {
            struct stat st{};
            if (::fstatat(p.fd, p.leaf.c_str(), &st, AT_SYMLINK_NOFOLLOW) == 0 && S_ISDIR(st.st_mode) &&
                st.st_uid == geteuid() && (st.st_mode & 0077) == 0) result = 0;
            else errno = EPERM;
        }
        const int saved = errno; ::close(p.fd); errno = saved; return result;
#else
        (void)path; errno = EPERM; return -1;
#endif
    }
    int stat_path(const std::string &path, struct stat *st) const {
#if !defined(_WIN32) && !defined(_MSC_VER)
        if (operations_.fetch_add(1, std::memory_order_relaxed) >= 256) { errno = EMFILE; return -1; }
        Parent p = resolve(path, false); if (p.fd < 0) return -1;
        int result = ::fstatat(p.fd, p.leaf.c_str(), st, AT_SYMLINK_NOFOLLOW);
        if (result == 0 && !S_ISREG(st->st_mode) && !S_ISDIR(st->st_mode)) { errno = EPERM; result = -1; }
        const int saved = errno; ::close(p.fd); errno = saved; return result;
#else
        (void)path; (void)st; errno = EPERM; return -1;
#endif
    }
private:
    struct Parent { int fd; std::string leaf; };
    Parent resolve(const std::string &path, bool writable) const {
#if !defined(_WIN32) && !defined(_MSC_VER)
        const std::string *root = nullptr; int root_fd = -1;
        if (path.compare(0, scratch_.size() + 1, scratch_ + "/") == 0) { root = &scratch_; root_fd = scratch_fd_; }
        else if (!writable && path.compare(0, library_.size() + 1, library_ + "/") == 0) { root = &library_; root_fd = library_fd_; }
        if (!root || root_fd < 0 || path.size() > 4096 || path.find('\0') != std::string::npos) { errno = EPERM; return {-1,{}}; }
        std::string relative = path.substr(root->size()+1); std::vector<std::string> parts;
        for (size_t begin=0;;) {
            size_t end = relative.find('/', begin); std::string part = relative.substr(begin, end == std::string::npos ? end : end-begin);
            if (part.empty() || part == "." || part == "..") { errno = EPERM; return {-1,{}}; }
            parts.push_back(part); if (end == std::string::npos) break; begin=end+1;
        }
        int fd = ::fcntl(root_fd, F_DUPFD_CLOEXEC, 0); if (fd < 0) return {-1,{}};
        for (size_t i=0; i+1<parts.size(); ++i) {
            int next = ::openat(fd, parts[i].c_str(), O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
            int saved = errno; ::close(fd); errno = saved; if (next < 0) return {-1,{}}; fd=next;
        }
        return {fd, parts.back()};
#else
        (void)path; (void)writable; errno=EPERM; return {-1,{}};
#endif
    }
    mutable std::atomic<uint32_t> operations_{0};
    std::string scratch_, library_;
    int scratch_fd_ = -1, library_fd_ = -1;
};
}
