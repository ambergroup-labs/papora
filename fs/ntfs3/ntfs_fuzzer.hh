#ifndef FS_FUZZ_NTFS_FUZZER_HH
#define FS_FUZZ_NTFS_FUZZER_HH

#include <map>

#include "fsfuzzer.hh"
#include "ntfs.hh"
#include "ntfs_utils.hh"

class ntfs_fuzzer;

struct Rec_Handler {
  // const char *name;
  void (ntfs_fuzzer::*handler)(uint32_t);
};

enum REC_TYPE { 
  TYPE_BOOT,
  TYPE_MFT,
  TYPE_ATTR,
  TYPE_UNKNOWN
};

struct Meta_Rec {
  REC_TYPE rec_type;
  RECORD_NUM mft_id;
  ATTR_TYPE attr_type;
  uint64_t offset_to_image;
  uint64_t offset_to_meta_file;
  uint64_t length;
};

typedef void (ntfs_fuzzer::*HANDLER)(uint32_t);

class ntfs_fuzzer : public fsfuzzer {
 public:
  ntfs_fuzzer();

  void fix_checksum(Meta_Rec &, const void *, size_t len);

  void compress(const char *in_path, void *buffer,
                const char *meta_path = NULL);

  void decompress(const void *meta_buffer, void *out_ptr = NULL, size_t len = 0, bool checksum = true);

  uint64_t logical_to_physical(uint64_t logical);

 private:
  void ntfs_parse_boot_sector(BootSector *sb);
  void ntfs_parse_mft_rec(RECORD_NUM);
  void save_meta_rec(uint64_t off_to_image, uint64_t len,
                     REC_TYPE rec_type = TYPE_UNKNOWN, RECORD_NUM mft_id = MFT_REC_LAST, 
		     ATTR_TYPE attr_type = ATTR_END) {
    Meta_Rec rec = {rec_type, mft_id, attr_type, off_to_image, cur_off, len};
    metadata_rec.push_back(rec);
    cur_off += len;
  }

  bool save_metadata(int meta_image_fd) {
    if (meta_image_fd <= 0) return false;

    for (auto &rec : metadata_rec) {
      LOGD("rec: type: %d, offset_to_image: %lx, offset_to_meta_file: %lx\n", 
		      rec.type, rec.offset_to_image, rec.offset_to_meta_file);
      if (write(meta_image_fd, (char *)image_buffer_ + rec.offset_to_image,
                rec.length) != rec.length)
        return false;
    }

    return true;
  }

  friend void print_boot_sector(ntfs_fuzzer *);

 protected:
  std::map<address_range, uint64_t> address_map;

 private:
  std::vector<Meta_Rec> metadata_rec;
  BootSector *boot;
  Rec_Handler meta_rec[MFT_REC_LAST];

  // basic information from boot sector
  uint16_t bytes_per_sector;
  uint8_t sectors_per_cluster;
  uint32_t bytes_per_cluster;
  uint32_t bytes_per_mft_rec;

  // MFT information
  uint64_t mft_offset;
  uint64_t mft_addr;

  // some internal information
  uint64_t cur_off;
};

#endif
