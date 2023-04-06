#ifndef _BTRFS_CRC32C_H_
#define _BTRFS_CRC32C_H_

#include <stddef.h>
#include <stdint.h>

uint32_t crc32c_init(void);

uint32_t crc32c(uint32_t crc, const void *buf, size_t len);

#endif
