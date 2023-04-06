#include <map>
#include <set>
#include <sys/stat.h>

#include "ntfs.hh"
#include "ntfs_fuzzer.hh"
#include "ntfs_utils.hh"
#include "utils.hh"
#include "wchar.h"
extern "C" {
#include "crc32c.h"
}

#define PtrAdd(x, y) ((uint8_t *)x + y)
#define U8P(x) (uint8_t *)(x)
#define U16P(x) (uint16_t *)(x)
void ntfs_fuzzer::ntfs_parse_mft_rec(RECORD_NUM idx) {
  // TODO: remove it for next new fuzz
  //return;
  FileRecordHeader *mft = (FileRecordHeader *)malloc(bytes_per_mft_rec);
  if (mft == NULL)
    FATAL("[-] malloc for mft record failed.");
  uint8_t *end = U8P(mft) + bytes_per_mft_rec;
  // skip parsing if AFL mutation cause OOB read for MFT records
  if (mft_offset + idx * bytes_per_mft_rec > image_size_ - bytes_per_mft_rec)
    return;

  // copy idx record from MFT
  memcpy(mft, U8P(image_buffer_) + mft_offset + idx * bytes_per_mft_rec,
         bytes_per_mft_rec);

  // save the record
  save_meta_rec(mft_offset + idx * bytes_per_mft_rec, bytes_per_mft_rec, 
    TYPE_MFT, idx);

  switch (idx) {
  // case range: GNU C extension
  case MFT_REC_MFT:
  case MFT_REC_LOG:
  case MFT_REC_BOOT:
  case MFT_REC_BADCLUST:
  case MFT_REC_UPCASE:
    // skip these data
    return;
  default:
    break;
  }

  // if (mft->magic != NTFS_FILE_SIGNATURE)	// AFL may mutate the record
  // content, skip sanity check here
  //  FATAL("[-] mft magic not match %x\n", mft->magic);
  LOGD("===== handle %d MFT record =====\n", idx);

  AttributeHeader *attr =
      (AttributeHeader *)(U8P(mft) +
      ((FileRecordHeader *)mft)->firstAttributeOffset);
  NonResidentAttributeHeader *data = NULL;
  while (U8P(attr) <= end - sizeof(AttributeHeader) &&
         attr->attributeType != ATTR_END) {
    ATTR_TYPE attr_type = (ATTR_TYPE)attr->attributeType;
    LOGD("attr %p, type %x, nonResident %d\n", attr, attr_type,
         attr->nonResident);
    if ((attr_type == ATTR_DATA || attr_type == ATTR_SECURE ||
         attr_type == ATTR_ALLOC || attr_type == ATTR_BITMAP) &&
        attr->nonResident)
      data = (NonResidentAttributeHeader *)attr;

    // move to next attr
    attr = (AttributeHeader *)(U8P(attr) + attr->length);
    if (data == NULL)
      continue;
    RunHeader *dataRun = (RunHeader *)(U8P(data) + data->dataRunsOffset);
    uint64_t clusterNumber = 0;

    // TODO: only deal with important MFT records

    // handle data run
    while (U8P(dataRun) - U8P(data) < data->length &&
           dataRun->lengthFieldBytes &&
           U8P(dataRun) + 1 + dataRun->lengthFieldBytes +
                   dataRun->offsetFieldBytes < end) {
      uint64_t length = 0, offset = 0;

      for (int i = 0; i < dataRun->lengthFieldBytes; i++) {
        length |= (uint64_t)((U8P(dataRun))[1 + i]) << (i * 8);
      }

      if (!length) {
	LOGD("dataRun for %d MFT record attr type %x has length 0!!\n", idx, attr_type);
	return;
      }

      for (int i = 0; i < dataRun->offsetFieldBytes; i++) {
        offset |= (uint64_t)((U8P(dataRun))[1 + dataRun->lengthFieldBytes + i])
                  << (i * 8);
      }

      /* offset is signed, if MSB is 1, then it's a negative number*/
      if (offset & ((uint64_t)1 << (dataRun->offsetFieldBytes * 8 - 1))) {
        for (int i = dataRun->offsetFieldBytes; i < 8; i++) {
          offset |= (uint64_t)0xFF << (i * 8);
        }
      }

      clusterNumber += offset;
      LOGD("data @ cluster %ld and length %ld\n", clusterNumber, length);
      // save each data run
      // here we assign REC_TYPE according to idx, e.g.,
      // MFT_REC_MFT ==> 0
      // MFT_REC_MIRR ==> 1
      // each datarun for different idx may store different information
      REC_TYPE rec_type = TYPE_ATTR;

      // sanity check for AFL mutation
      if ((clusterNumber + length) * bytes_per_cluster > image_size_)
        goto next_data_run;

      switch (idx) {
      case MFT_REC_MFT:
        if (attr_type == ATTR_DATA)
          rec_type = TYPE_MFT;
        break;
      }

      // save data runs
      save_meta_rec(clusterNumber * bytes_per_cluster,
                    length * bytes_per_cluster, rec_type, idx, attr_type);
    next_data_run:
      dataRun = (RunHeader *)(U8P(dataRun) + 1 + dataRun->lengthFieldBytes +
                              dataRun->offsetFieldBytes);
    }

    data = NULL;
  }
}

ntfs_fuzzer::ntfs_fuzzer() : fsfuzzer("ntfs") {
  cur_off = 0;
  memset(meta_rec, 0, sizeof(meta_rec));

  // LOGD("[+] sizeof(FileRecordHeader) = %zd\n", sizeof(FileRecordHeader));
  // deal with each records in MFT, 1 by 1, we don't have a better way to do it
  // C++ can't simply loop through enum when their values are specified, e.g.,
  // ONE = 1, THREE = 3, and so on
  // of course we can use switch case, but it's doesn't really have any
  // difference here
  for (int i = MFT_REC_MFT; i <= MFT_REC_RESERVED; i++) {
    meta_rec[i].handler = (HANDLER)&ntfs_fuzzer::ntfs_parse_mft_rec;
  }

  // skip MFT_REC_LOG / MFT_REC_BOOT / MFT_REC_BADCLUST
  //meta_rec[MFT_REC_LOG].handler = meta_rec[MFT_REC_BOOT].handler =
  //    meta_rec[MFT_REC_BADCLUST].handler = NULL;

  // skip MFT_REC_SECURE / MFT_REC_UPCASE
  //meta_rec[MFT_REC_SECURE].handler = meta_rec[MFT_REC_UPCASE].handler = NULL;

  // add MFT_REC_FREE / MFT_REC_USER
  // meta_rec[MFT_REC_FREE].handler = (HANDLER)&ntfs_fuzzer::ntfs_parse_mft_rec;
  // meta_rec[MFT_REC_USER].handler = (HANDLER)&ntfs_fuzzer::ntfs_parse_mft_rec;
}

void ntfs_fuzzer::fix_checksum(Meta_Rec &rec, const void *meta_buffer, size_t meta_len) {
  uint8_t *buf = U8P(meta_buffer) + rec.offset_to_meta_file;
  uint8_t *end = buf + rec.length;
  if (rec.rec_type == TYPE_BOOT) {
    BootSector *boot = (BootSector *)buf;
    // here we'll apply some sanity fixups
    // 1. name must be "NTFS    " (4 spaces)
    memcpy(boot->name, "NTFS    ", 8);
    // 2. boot->bytesPerSector should be multiple of 256 and >= 512
    boot->bytesPerSector &= ~(0xFFL);
    if (boot->bytesPerSector == 0)
      boot->bytesPerSector = 512;
    else
      for (int i = 15; i > 8; i--) {
        if (boot->bytesPerSector & (1 << i)) {
          boot->bytesPerSector = 1 << i;
          break;
        }
      }

    return;
  }

  if (rec.rec_type == TYPE_MFT) {
    #if 1
    // step1. fixup values
    // TODO: smarter way for fix-up values
    // the fuzzer will mutate the metadata, so there are chances that fix-up offset are modified
    // the offset value might be legit or not, and it affects the R/W, so here we leave it to the fuzzer
    
    uint8_t *tmp = buf;
    // last pos
    uint16_t *last = U16P(end - sizeof(uint16_t));
    uint32_t rec_num = rec.length / bytes_per_mft_rec;
    LOGD("we have %d MFT rec\n", rec_num);
    for (int i = 0; i < rec_num; i++) {
      FileRecordHeader *mft = (FileRecordHeader *)(tmp);
      uint16_t *fixup = U16P(tmp + mft->updateSequenceOffset);
      if (fixup > last) {
        LOGD("fixup out of bound: fixup: %p last: %p", fixup, last);
        return;
      }
      LOGD("[fixup] fix offset: %hd\n", mft->updateSequenceOffset);
      //if (mft->updateSequenceSize != 0) LOGD("[checksum] signature is %hx\n", *fixup);
      for (int j = 1; j <= bytes_per_mft_rec / bytes_per_sector; j++) {
        uint16_t *cur = U16P(tmp + bytes_per_sector * j - sizeof(uint16_t));
        //LOGD("cur: %hx, fixup: %hx\n", *cur, *(fixup + j));
        if (cur > last) {
          LOGD("fixup out of bound: cur: %p last: %p", cur, last);
          return;
        }
        // let fixup match
        *cur = *fixup;
      }
    
      tmp += bytes_per_mft_rec;
    }
    
    // step 2. deal with different MFT records
    #if 0
    FileRecordHeader *mft = (FileRecordHeader *)(buf);
    AttributeHeader *attr =
      (AttributeHeader *)(U8P(mft) + mft->firstAttributeOffset);
    switch (rec.mft_id) {
    case MFT_REC_UPCASE:
      while (U8P(attr) <= end - sizeof(NonResidentAttributeHeader) && attr->attributeType != ATTR_END) {
        if (attr->attributeType == ATTR_DATA && attr->nonResident) {
          NonResidentAttributeHeader *nr_attr = (NonResidentAttributeHeader *)attr;
          // the data size is fixed for MFT_REC_UPCASE
          // there is a sanity check for this in ntfs3
          nr_attr->attributeSize = 0x10000 * sizeof(short);
          return;
        }
        
      next_attr:
        attr = (AttributeHeader *)(U8P(attr) + attr->length);
      }
    
    default:
      break;
    }
    #endif
    
    return;
    #endif
  }

  if (rec.rec_type == TYPE_ATTR) {
    switch(rec.mft_id) {
    // TODO: fixup values for ATTR_ALLOC
    case MFT_REC_ROOT:
      break;
    default:
      break;
    }

    return;
  }
}

uint64_t ntfs_fuzzer::logical_to_physical(uint64_t logical) {
  std::map<address_range, uint64_t>::iterator it =
      this->address_map.find({logical, 1});
  if (it == this->address_map.end()) {
    return -1;
  }
  return it->second + (logical - it->first.start);
}

void ntfs_fuzzer::ntfs_parse_boot_sector(BootSector *boot) {
  // Load boot sector
  memcpy(boot, U8P(image_buffer_), SECTOR_SIZE);
  this->boot = boot;

  // save boot sector
  save_meta_rec(0, SECTOR_SIZE, TYPE_BOOT);

  // though ntfs3 implementation will get it from boot sector
  // but only use it for sanity check, e.g., ntfs_init_from_boot()
  // rest code logic use hardcode SECTOR_SIZE (512), so we use it here
  //this->bytes_per_sector = boot->bytesPerSector;
  this->bytes_per_sector = SECTOR_SIZE;
  // sectors per cluster formula
  // 0 to 128 ==> 0-128 sectors
  // 244 to 255 ==>  2^(256-n) sectors
  // (but the ntfs3 implementation not follows)
  // we copy from linux ntfs3 implementation
  this->sectors_per_cluster = boot->sectorsPerCluster <= 0x80
                                  ? boot->sectorsPerCluster
                                  : (1u << (0 - boot->sectorsPerCluster));
  this->bytes_per_cluster = this->bytes_per_sector * this->sectors_per_cluster;
  this->bytes_per_mft_rec =
      boot->clustersPerFileRecord < 0
          ? 1 << (-boot->clustersPerFileRecord)
          : boot->clustersPerFileRecord * this->bytes_per_cluster;
  this->mft_offset = boot->mftStart * this->bytes_per_cluster;
  // print_boot_sector(this);
}

void ntfs_fuzzer::compress(const char *in_path, void *buffer,
                           const char *meta_path) {
  bool generate_meta_image = meta_path != NULL;

  int in_image_fd = open(in_path, O_RDONLY);
  if (in_image_fd < 0) {
    FATAL("[-] image %s compression failed.", in_path);
  }

  struct stat st;
  if (fstat(in_image_fd, &st) != 0) {
    FATAL("[-] image %s compression failed.", in_path);
  }

  image_size_ = st.st_size;
  image_buffer_ = buffer;

  if (read(in_image_fd, image_buffer_, image_size_) != image_size_)
    FATAL("[-] image %s compression failed.", in_path);

  close(in_image_fd);

#if 1
  int meta_image_fd = -1;
  if (generate_meta_image) {
    meta_image_fd = open(meta_path, O_CREAT | O_RDWR | O_TRUNC, 0666);
    if (meta_image_fd < 0) {
      FATAL("[-] image %s compression failed.", in_path);
    }
  }
#endif

  BootSector *boot = (BootSector *)malloc(SECTOR_SIZE);
  ntfs_parse_boot_sector(boot);

  // parse each meta data rec
  for (int i = 0; i < MFT_REC_LAST; i++) {
    if (meta_rec[i].handler != NULL) {
      // special syntax for calling class member function pointer
      (this->*(meta_rec[i].handler))(i);
    }
  }

#if 1
  if (generate_meta_image) {
    if (!save_metadata(meta_image_fd))
      FATAL("[-] image %s compression failed.", in_path);
    close(meta_image_fd);
  }
#endif
  LOGD("compress done\n");
  // print_metadata();
}

void ntfs_fuzzer::decompress(const void *meta_buffer, void *out_ptr, size_t len,
                             bool checksum) {
  // if out_ptr is given, we are decompressing to it other than image_buffer_
  void *ptr = out_ptr ? out_ptr : image_buffer_;
  for (auto &rec : metadata_rec) {
    if (checksum)
      fix_checksum(rec, meta_buffer, len);
    memcpy(U8P(ptr) + rec.offset_to_image,
           U8P(meta_buffer) + rec.offset_to_meta_file, rec.length);
  }
  // if not to image_buffer_, we need to call msync to flush the modifications
  if (out_ptr)
    msync(out_ptr, len, MS_SYNC);
}
