#pragma once
#if !defined(_WIN32) && !defined(_MSC_VER)
#include <dirent.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#include <cstring>
#include <cerrno>
#include <string>

namespace anisette_owned_attempt {
inline bool same_directory_at(int parent, const char *name, int directory) noexcept {
    struct stat named{}, held{};
    return fstatat(parent,name,&named,AT_SYMLINK_NOFOLLOW)==0 && fstat(directory,&held)==0 &&
        S_ISDIR(named.st_mode) && named.st_uid==geteuid() && (named.st_mode & 0077)==0 &&
        named.st_dev==held.st_dev && named.st_ino==held.st_ino;
}
// No path-based recursion. Caller retains a private parent/root and has drained
// all native writers. A renamed or replaced root is not followed or removed.
inline bool remove_owned_children(int directory, unsigned depth=0) noexcept {
    if (depth>32) return false;
    int copy=fcntl(directory,F_DUPFD_CLOEXEC,0); if(copy<0) return false;
    DIR *stream=fdopendir(copy); if(!stream) { close(copy); return false; }
    bool okay=true; unsigned count=0;
    errno=0;
    while (dirent *entry=readdir(stream)) {
        if(std::strcmp(entry->d_name,".")==0 || std::strcmp(entry->d_name,"..")==0) continue;
        if(++count>1024) { okay=false; break; }
        struct stat st{};
        if(fstatat(directory,entry->d_name,&st,AT_SYMLINK_NOFOLLOW)!=0 || st.st_uid!=geteuid()) { okay=false; break; }
        if(S_ISDIR(st.st_mode)) {
            int child=openat(directory,entry->d_name,O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);
            if(child<0) { okay=false; break; }
            bool removed=same_directory_at(directory,entry->d_name,child) && remove_owned_children(child,depth+1) &&
                same_directory_at(directory,entry->d_name,child) && unlinkat(directory,entry->d_name,AT_REMOVEDIR)==0;
            close(child); if(!removed) { okay=false; break; }
        } else if(S_ISREG(st.st_mode) || S_ISLNK(st.st_mode)) {
            if(unlinkat(directory,entry->d_name,0)!=0) { okay=false; break; }
        } else { okay=false; break; }
        errno=0;
    }
    if(errno!=0) okay=false;
    if(closedir(stream)!=0) okay=false;
    return okay;
}
inline bool remove_owned_root(int parent, const std::string &name, int root) noexcept {
    return same_directory_at(parent,name.c_str(),root) && remove_owned_children(root) &&
        same_directory_at(parent,name.c_str(),root) && unlinkat(parent,name.c_str(),AT_REMOVEDIR)==0;
}
}
#endif
