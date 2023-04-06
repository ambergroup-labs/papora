#ifndef FS_FUZZ_BTRFS_HH
#define FS_FUZZ_BTRFS_HH

#include <stdint.h>

#define KB 1024ull
#define MB 1024ull * KB
#define GB 1024ull * MB
#define TB 1024ull * GB

/* address translation structure */
struct address_range {
  uint64_t start;
  uint64_t length;

  bool operator<(const address_range &ar) const {
    if (start + length <= ar.start) {
      return true;
    }
    return false;
  }
};
typedef struct address_range address_range;

/* ntfs structure */

#define UUID_LEN 0x10
#define CHECKSUM_LEN 0x20
#define SUPERBLOCK_SIZE 0x1000
#define SECTOR_SIZE 0x200

enum RECORD_NUM {
  MFT_REC_MFT = 0,
  MFT_REC_MIRR = 1,
  MFT_REC_LOG = 2,
  MFT_REC_VOL = 3,
  MFT_REC_ATTR = 4,
  MFT_REC_ROOT = 5,
  MFT_REC_BITMAP = 6,
  MFT_REC_BOOT = 7,
  MFT_REC_BADCLUST = 8,
  // MFT_REC_QUOTA		= 9,
  MFT_REC_SECURE = 9,  // NTFS 3.0
  MFT_REC_UPCASE = 10,
  MFT_REC_EXTEND = 11,  // NTFS 3.0
  MFT_REC_RESERVED = 11,
  MFT_REC_FREE = 16,
  MFT_REC_USER = 24,
  MFT_REC_LAST = 25,  // end
};

struct BootSector {
  uint8_t jump[3];
  char name[8];
  uint16_t bytesPerSector;
  uint8_t sectorsPerCluster;
  uint16_t reservedSectors;
  uint8_t unused0[3];
  uint16_t unused1;
  uint8_t media;
  uint16_t unused2;
  uint16_t sectorsPerTrack;
  uint16_t headsPerCylinder;
  uint32_t hiddenSectors;
  uint32_t unused3;
  uint32_t unused4;
  uint64_t totalSectors;
  uint64_t mftStart;
  uint64_t mftMirrorStart;
  int8_t clustersPerFileRecord;
  int8_t unused5[3];
  int8_t clustersPerIndexBlock;
  int8_t unused6[3];
  uint64_t serialNumber;
  uint32_t checksum;
  uint8_t bootloader[426];
  uint16_t bootSignature;
} __attribute__((packed));

enum NTFS_SIGNATURE {
  NTFS_FILE_SIGNATURE = 0x454C4946,  // 'FILE'
  NTFS_INDX_SIGNATURE = 0x58444E49,  // 'INDX'
  NTFS_CHKD_SIGNATURE = 0x444B4843,  // 'CHKD'
  NTFS_RSTR_SIGNATURE = 0x52545352,  // 'RSTR'
  NTFS_RCRD_SIGNATURE = 0x44524352,  // 'RCRD'
  NTFS_BAAD_SIGNATURE = 0x44414142,  // 'BAAD'
  NTFS_HOLE_SIGNATURE = 0x454C4F48,  // 'HOLE'
  NTFS_FFFF_SIGNATURE = 0xffffffff,
};

struct FileRecordHeader {
  uint32_t magic;
  uint16_t updateSequenceOffset;  // fixup offset
  uint16_t updateSequenceSize;    // fixup number
  uint64_t logSequence;
  uint16_t sequenceNumber;
  uint16_t hardLinkCount;
  uint16_t firstAttributeOffset;
  uint16_t flags;
  uint32_t usedSize;
  uint32_t allocatedSize;
  uint64_t fileReference;
  uint16_t nextAttributeID;
  uint16_t unused;
  uint32_t recordNumber;
} __attribute__((packed));

enum ATTR_TYPE {
  ATTR_ZERO = 0x00,
  ATTR_STD = 0x10,
  ATTR_LIST = 0x20,
  ATTR_NAME = 0x30,
  // ATTR_VOLUME_VERSION on Nt4
  ATTR_ID = 0x40,
  ATTR_SECURE = 0x50,
  ATTR_LABEL = 0x60,
  ATTR_VOL_INFO = 0x70,
  ATTR_DATA = 0x80,
  ATTR_ROOT = 0x90,
  ATTR_ALLOC = 0xA0,
  ATTR_BITMAP = 0xB0,
  // ATTR_SYMLINK on Nt4
  ATTR_REPARSE = 0xC0,
  ATTR_EA_INFO = 0xD0,
  ATTR_EA = 0xE0,
  ATTR_PROPERTYSET = 0xF0,
  ATTR_LOGGED_UTILITY_STREAM = 0x100,
  ATTR_END = 0xFFFFFFFF
};

struct AttributeHeader {
  uint32_t attributeType;
  uint32_t length;
  uint8_t nonResident;
  uint8_t nameLength;
  uint16_t nameOffset;
  uint16_t flags;
  uint16_t attributeID;
} __attribute__((packed));

struct ResidentAttributeHeader : AttributeHeader {
  uint32_t attributeLength;
  uint16_t attributeOffset;
  uint8_t indexed;
  uint8_t unused;
} __attribute__((packed));

struct FileNameAttributeHeader : ResidentAttributeHeader {
  uint64_t parentRecordNumber : 48;
  uint64_t sequenceNumber : 16;
  uint64_t creationTime;
  uint64_t modificationTime;
  uint64_t metadataModificationTime;
  uint64_t readTime;
  uint64_t allocatedSize;
  uint64_t realSize;
  uint32_t flags;
  uint32_t repase;
  uint8_t fileNameLength;
  uint8_t namespaceType;
  wchar_t fileName[1];
} __attribute__((packed));

struct NonResidentAttributeHeader : AttributeHeader {
  uint64_t firstCluster;
  uint64_t lastCluster;
  uint16_t dataRunsOffset;
  uint16_t compressionUnit;
  uint32_t unused;
  uint64_t attributeAllocated;
  uint64_t attributeSize;
  uint64_t streamDataSize;
} __attribute__((packed));

struct RunHeader {
  uint8_t lengthFieldBytes : 4;
  uint8_t offsetFieldBytes : 4;
};

#endif
