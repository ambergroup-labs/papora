#include <stdio.h>
#include "ntfs_fuzzer.hh"

void print_boot_sector(ntfs_fuzzer *fuzzer) {
  printf("bytes / sector: %d\n", fuzzer->bytes_per_sector);
  printf("sectors / cluster: %d\n", fuzzer->sectors_per_cluster);
  printf("bytes / cluster: %d\n", fuzzer->bytes_per_cluster);
  printf("bytes / file rec: %d\n", fuzzer->bytes_per_mft_rec);
  printf("mft offset: %lx\n", fuzzer->mft_offset);
}
