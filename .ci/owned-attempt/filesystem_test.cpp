#include "owned_attempt_filesystem.h"
#include <cassert>
#include <filesystem>
#include <fstream>
#include <sys/stat.h>
using anisette_owned_attempt::Filesystem;
int main() {
    char temp[] = "/tmp/owned-fs-XXXXXX"; assert(mkdtemp(temp)); std::string root(temp), scratch=root+"/scratch", libs=root+"/libs";
    assert(mkdir(scratch.c_str(),0700)==0); assert(mkdir(libs.c_str(),0700)==0);
    std::ofstream(root+"/outside") << "retain"; std::ofstream(libs+"/fixture") << "asset";
    { Filesystem fs; assert(fs.configure(scratch,libs)); assert(fs.create_directory(scratch+"/id")==0);
      int fd=fs.open_file(scratch+"/id/blob",O_RDWR|O_CREAT,0600); assert(fd>=0); assert(write(fd,"abc",3)==3); close(fd);
      fd=fs.open_file(libs+"/fixture",O_RDONLY,0); assert(fd>=0); close(fd);
      assert(fs.open_file(libs+"/fixture",O_WRONLY|O_TRUNC,0)<0);
      assert(fs.open_file(root+"/outside",O_RDONLY,0)<0); assert(fs.open_file(scratch+"/../outside",O_RDONLY,0)<0);
      assert(symlink((root+"/outside").c_str(),(scratch+"/id/link").c_str())==0); assert(fs.open_file(scratch+"/id/link",O_RDONLY,0)<0); assert(fs.create_directory(scratch+"/id/link")<0); assert(errno==EPERM);
      assert(link((root+"/outside").c_str(),(scratch+"/id/hard").c_str())==0); assert(fs.open_file(scratch+"/id/hard",O_WRONLY|O_TRUNC,0)<0);
      assert(std::filesystem::file_size(root+"/outside")==6); // no truncate before hardlink check
      assert(fs.create_directory(scratch+"/id/blob")<0); assert(errno==EPERM);
      assert(mkfifo((scratch+"/id/fifo").c_str(),0600)==0); assert(fs.open_file(scratch+"/id/fifo",O_RDONLY,0)<0);
      assert(symlink(root.c_str(),(scratch+"/escape").c_str())==0); assert(fs.open_file(scratch+"/escape/outside",O_RDONLY,0)<0);
    }
    std::filesystem::remove_all(root);
}
