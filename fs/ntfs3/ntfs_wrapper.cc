#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "ntfs_fuzzer.hh"

ntfs_fuzzer ntfs_fuzzer;

extern "C" void compress(const char *input_path, void *buffer,
                         const char *meta_path) {
  ntfs_fuzzer.compress(input_path, buffer, meta_path);
}

extern "C" void decompress(const void *mem, void *out_ptr = NULL, size_t len = 0) {
  ntfs_fuzzer.decompress(mem, out_ptr, len);
}

extern "C" void sync_to_file(const char *path) {
  ntfs_fuzzer.sync_to_file(path);
}

extern "C" void overwrite_to_file(const char *path, size_t off, size_t len) {
  ntfs_fuzzer.overwrite_to_file(path, off, len);
}
