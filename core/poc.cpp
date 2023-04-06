#include <argp.h>
#include <dirent.h>
#include <fcntl.h>
#include <fnmatch.h>
#include <libgen.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/sendfile.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/xattr.h>
#include <time.h>
#include <unistd.h>
#include <dlfcn.h>

#include <vector>

#include "Program.hpp"
#include "executor.hpp"

#define PAGE_SIZE 4096
#define errExit(msg)    \
  do {                  \
    perror(msg);        \
    exit(EXIT_FAILURE); \
  } while (0)

static const char doc_executor[] = "File system fuzzing executor";
static const char args_doc_executor[] = "-t fstype -i fsimage -p program";

static struct argp_option options[] = {
    {"enable-printk", 'v', 0, 0, "show Linux printks"},
    {"filesystem-type", 't', "string", 0, "select filesystem type - mandatory"},
    {"filesystem-image", 'i', "string", 0,
     "path to the filesystem image - mandatory"},
    {"wrapper path", 's', "string", 0, "path to the wrapper so - mandatory"},
    {"serialized-program", 'p', "string", 0, "serialized program - mandatory"},
    {"mutate-image", 'g', "string", 0, "path to store the mutated image"},
    {0},
};

static struct cl_args {
  int printk;
  int part;
  const char *fsimg_type;
  const char *fsimg_path;
  const char *wrapper_path;
  const char *prog_path;
  const char *mutate_path;
} cla;

static error_t parse_opt(int key, char *arg, struct argp_state *state) {
  struct cl_args *cla = (struct cl_args *)state->input;

  switch (key) {
    case 'v':
      cla->printk = 1;
      break;
    case 't':
      cla->fsimg_type = arg;
      break;
    case 'i':
      cla->fsimg_path = arg;
      break;
    case 's':
      cla->wrapper_path = arg;
      break;
    case 'p':
      cla->prog_path = arg;
      break;
    case 'g':
      cla->mutate_path = arg;
      break;
    default:
      return ARGP_ERR_UNKNOWN;
  }

  return 0;
}

static struct argp argp_executor = {
    .options = options,
    .parser = parse_opt,
    .args_doc = args_doc_executor,
    .doc = doc_executor,
};

static void exec_syscall(Program *prog, Syscall *syscall) {
  long params[6];
  long ret;
  int cnt = 0;

  for (Arg *arg : syscall->args) {
    if (!arg->is_variable)
      params[cnt] = arg->value;
    else {
      Variable *v = prog->variables[arg->index];
      if (v->is_pointer() && v->value == 0)
        v->value = static_cast<uint8_t *>(malloc(v->size));
      params[cnt] = reinterpret_cast<long>(v->value);
    }
    cnt++;
  }

  ret = lkl_syscall(lkl_syscall_nr[syscall->nr], params);
  if (syscall->ret_index != -1)
    prog->variables[syscall->ret_index]->value =
        reinterpret_cast<uint8_t *>(ret);

  // show_syscall(prog, syscall);
  // printf("ret: %ld\n", ret);
}

static void close_active_fds(Program *prog) {
  long params[6];

  for (int64_t fd_index : prog->active_fds) {
    params[0] = reinterpret_cast<long>(prog->variables[fd_index]->value);
    lkl_syscall(lkl_syscall_nr[SYS_close], params);
  }
}

extern "C" void __afl_manual_init(void **buffer, size_t *size);
extern uint32_t __afl_in_trace;

void (*wrapper_compress)(char* in_path, char* out_path, char* meta_path);
void (*wrapper_decompress)(void* meta_buffer, void* out_ptr, size_t meta_len);
void (*wrapper_sync_to_file)(char* path);
void (*wrapper_overwrite_to_file)(char* path, size_t off, size_t len);
int setup_wrapper(void) {
  void *wrapper_dh = dlopen(cla.wrapper_path, RTLD_NOW);
  if (!wrapper_dh) {
    fprintf(stderr, "can't open wrapper %s: %s\n", cla.wrapper_path,
    strerror(errno));
    return -1;
  }

  wrapper_compress = dlsym(wrapper_dh, "compress");
  if (!wrapper_compress) {
    fprintf(stderr, "dlsym() failed - you need to define compress()");
    return -1;
  }

  wrapper_decompress = dlsym(wrapper_dh, "decompress");
  if (!wrapper_decompress) {
    fprintf(stderr, "dlsym() failed - you need to define decompress()");
    return -1;
  }

  wrapper_sync_to_file = dlsym(wrapper_dh, "sync_to_file");
  if (!wrapper_sync_to_file) {
    fprintf(stderr, "dlsym() failed - you need to define sync_to_file()");
    return -1;
  }

  wrapper_overwrite_to_file = dlsym(wrapper_dh, "overwrite_to_file");
  if (!wrapper_overwrite_to_file) {
    fprintf(stderr, "dlsym() failed - you need to define overwrite_to_file()");
    return -1;
  }

  return 0;
}

#define POC_META "poc.meta"
size_t image_file_size;
size_t image_meta_size;
uint8_t *mutate_file;
int load_seed_image(void) {
  void* buffer = NULL;

  /* get size */
  struct stat st;
  lstat(cla.fsimg_path, &st);

  /* copy seed_file to mutate_file */
  int sfd = open(cla.fsimg_path, O_RDONLY);
  int ifd = open(cla.mutate_path, O_RDWR | O_CREAT, 0666);

  image_file_size = st.st_size;
  if (sendfile(ifd, sfd, NULL, image_file_size) < 0) {
    fprintf(stderr, "can't sendfile from %s to %s: %s\n", cla.fsimg_path,
    cla.mutate_path, strerror(errno));
    return -1;
  }

  /* mmap for mutate_file */
  mutate_file = (uint8_t *)mmap(NULL, image_file_size, PROT_READ | PROT_WRITE, MAP_SHARED, ifd, 0);
  if (mutate_file == MAP_FAILED) {
    fprintf(stderr, "mmap failed %s\n", strerror(errno));
    return -1;
  }

  close(sfd);
  close(ifd);

  buffer = mmap(NULL, image_file_size, PROT_READ | PROT_WRITE,
                  MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  if (buffer == MAP_FAILED) {
    fprintf(stderr, "mmap failed %s\n", strerror(errno));
    return -1;
  }

  wrapper_compress(cla.fsimg_path, buffer, POC_META);

  lstat(POC_META, &st);
  image_meta_size = st.st_size;
  printf("The meta size is %zd\n", image_meta_size);
  return 0;
}

#define POC_FILE "poc.case"
int write_to_testcase(void) {
  // mmap input test case
  struct stat st;
  lstat(cla.prog_path, &st);
  int fd = open(cla.prog_path, O_RDONLY);
  if (fd < 0) {
    fprintf(stderr, "can't open program file %s: %s\n", cla.prog_path,
    strerror(errno));
    return -1;
  }
  void *mem = mmap(NULL, st.st_size, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);
  if (mem == MAP_FAILED) {
    fprintf(stderr, "mmap for %s failed: %s\n", cla.prog_path,
    strerror(errno));
    return -1;
  }
  close(fd);
  /* first decompress image*/
  wrapper_decompress(mem, mutate_file, image_meta_size);
  /* second flush syscalls to file */
  unlink(POC_FILE);
  fd = open(POC_FILE, O_WRONLY | O_CREAT | O_EXCL, 0600);
  if (fd < 0) {
    fprintf(stderr, "open for %s failed: %s\n", POC_FILE,
    strerror(errno));
    return -1;
  }
  write(fd, (char*)mem + image_meta_size, st.st_size - image_meta_size);
  close(fd);
  munmap(mem, st.st_size);
  return 0;
}

int main(int argc, char **argv) {
  struct lkl_disk disk;
  long ret;
  char mpoint[32];
  unsigned int disk_id;

  if (argp_parse(&argp_executor, argc, argv, 0, 0, &cla) < 0) return -1;

  const char *mount_options = NULL;
  if (!strcmp(cla.fsimg_type, "ntfs3"))
    mount_options = "acl,force";
  else {
    fprintf(stderr, "please specify supported file system type: [ntfs3]\n");
    return -1;
  }

  if (setup_wrapper() < 0) return -1;
  if (load_seed_image() < 0) return -1;
  if (write_to_testcase() < 0) return -1;
  if (!cla.printk) lkl_host_ops.print = NULL;

  __afl_manual_init(NULL, NULL);
  disk.fd = open(cla.mutate_path, O_RDWR);
  if (disk.fd == -1) {
    fprintf(stderr, "can't open mutate image %s: %s\n", cla.mutate_path,
    strerror(errno));
    return -1;
  }
  disk.ops = NULL;

  ret = lkl_disk_add(&disk);
  if (ret < 0) {
    fprintf(stderr, "can't add disk: %s\n", lkl_strerror(ret));
    lkl_sys_halt();
    return -1;
  }
  disk_id = ret;

  lkl_start_kernel(&lkl_host_ops, "mem=128M");

  __afl_in_trace = 1;

  ret = lkl_mount_dev(disk_id, cla.part, cla.fsimg_type, 0, mount_options,
                      mpoint, sizeof(mpoint));
  if (ret) {
    fprintf(stderr, "can't mount disk: %s\n", lkl_strerror(ret));
    lkl_sys_halt();
    return -1;
  }

  ret = lkl_sys_chdir(mpoint);
  if (ret) {
    fprintf(stderr, "can't chdir to %s: %s\n", mpoint, lkl_strerror(ret));
    lkl_umount_dev(disk_id, cla.part, 0, 1000);
    lkl_sys_halt();
    return -1;
  }

  Program *prog = Program::deserialize(POC_FILE, true);
  for (Syscall *syscall : prog->syscalls) {
    exec_syscall(prog, syscall);
  }
  close_active_fds(prog);

  ret = lkl_sys_chdir("/");

  lkl_umount_dev(disk_id, cla.part, 0, 1000);

  __afl_in_trace = 0;

  lkl_disk_remove(disk);
  lkl_sys_halt();
  printf("all done\n");
  return 0;
}
