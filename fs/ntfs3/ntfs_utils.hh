#ifndef FS_FUZZ_NTFS_UTILS_HH
#define FS_FUZZ_NTFS_UTILS_HH
class ntfs_fuzzer;
void print_boot_sector(ntfs_fuzzer *);
#ifdef DEBUG
#define LOGD(...) printf(__VA_ARGS__)
#else
#define LOGD(...)
#endif
#endif
