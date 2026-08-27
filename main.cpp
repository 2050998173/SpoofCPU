#include <android/log.h>
#include <unistd.h>
#include <fcntl.h>
#include <cstring>
#include <cstdio>
#include <cstdarg>
#include <sys/mman.h>
#include <sys/syscall.h>

#include "zygisk.hpp"

#define LOG_TAG "SpoofCPU"

// 手动声明 xhook 函数，避免依赖头文件
extern "C" {
    int xhook_register(const char *pathname, const char *symbol, void *new_func, void **old_func);
    int xhook_refresh(int verbose);
}

static const char* kFakeCpuInfo =
    "Processor: AArch64 Processor rev 0 (aarch64)\n"
    "Features: fp asimd evtstrm aes pmull sha1 sha2 crc32 atomics fphp asimdhp cpuid asimdrdm jscvt fcma lrcpc dcpop sha3 sm3 sm4 asimddp sha512 sve asimdfhm dit ilrcpc flagm ssbs sb pacg dcpodp flagm2 frint svei8mm i8mm bti\n"
    "CPU implementer: 0x48\n"
    "CPU architecture: 8\n"
    "CPU variant: 0x0\n"
    "CPU part: 0xd06\n"
    "CPU revision: 0\n"
    "\n"
    "processor: 0\n"
    "BogoMIPS: 38.40\n"
    "CPU implementer: 0x48\n"
    "CPU architecture: 8\n"
    "CPU variant: 0x0\n"
    "CPU part: 0xd06\n"
    "CPU revision: 0\n"
    "\n"
    "processor: 1\n"
    "BogoMIPS: 38.40\n"
    "CPU implementer: 0x48\n"
    "CPU architecture: 8\n"
    "CPU variant: 0x1\n"
    "CPU part: 0xd47\n"
    "CPU revision: 0\n"
    "\n"
    "processor: 2\n"
    "BogoMIPS: 38.40\n"
    "CPU implementer: 0x48\n"
    "CPU architecture: 8\n"
    "CPU variant: 0x1\n"
    "CPU part: 0xd47\n"
    "CPU revision: 0\n"
    "\n"
    "processor: 3\n"
    "BogoMIPS: 38.40\n"
    "CPU implementer: 0x48\n"
    "CPU architecture: 8\n"
    "CPU variant: 0x1\n"
    "CPU part: 0xd47\n"
    "CPU revision: 0\n"
    "\n"
    "processor: 4\n"
    "BogoMIPS: 38.40\n"
    "CPU implementer: 0x48\n"
    "CPU architecture: 8\n"
    "CPU variant: 0x1\n"
    "CPU part: 0xd47\n"
    "CPU revision: 0\n"
    "\n"
    "processor: 5\n"
    "BogoMIPS: 38.40\n"
    "CPU implementer: 0x41\n"
    "CPU architecture: 8\n"
    "CPU variant: 0x0\n"
    "CPU part: 0xd46\n"
    "CPU revision: 0\n"
    "\n"
    "processor: 6\n"
    "BogoMIPS: 38.40\n"
    "CPU implementer: 0x41\n"
    "CPU architecture: 8\n"
    "CPU variant: 0x0\n"
    "CPU part: 0xd46\n"
    "CPU revision: 0\n"
    "\n"
    "processor: 7\n"
    "BogoMIPS: 38.40\n"
    "CPU implementer: 0x41\n"
    "CPU architecture: 8\n"
    "CPU variant: 0x0\n"
    "CPU part: 0xd46\n"
    "CPU revision: 0\n"
    "\n"
    "processor: 8\n"
    "BogoMIPS: 38.40\n"
    "CPU implementer: 0x41\n"
    "CPU architecture: 8\n"
    "CPU variant: 0x0\n"
    "CPU part: 0xd46\n"
    "CPU revision: 0\n"
    "\n"
    "Hardware: HiSilicon Kirin 9030 Pro\n";

typedef int (*open_t)(const char*, int, ...);
typedef int (*openat_t)(int, const char*, int, ...);

static open_t orig_open = nullptr;
static openat_t orig_openat = nullptr;

static int make_cpuinfo_fd() {
    // 使用 syscall 调用 memfd_create，避免头文件声明问题
    int fd = syscall(SYS_memfd_create, "cpuinfo", 0);
    if (fd < 0) {
        fd = open("/dev/null", O_RDONLY);
        return fd;
    }
    write(fd, kFakeCpuInfo, strlen(kFakeCpuInfo));
    lseek(fd, 0, SEEK_SET);
    return fd;
}

static int fake_open(const char* path, int flags, ...) {
    if (path && strstr(path, "/proc/cpuinfo")) {
        return make_cpuinfo_fd();
    }

    if (flags & O_CREAT) {
        mode_t mode = 0;
        va_list ap;
        va_start(ap, flags);
        mode = va_arg(ap, mode_t);
        va_end(ap);
        return orig_open(path, flags, mode);
    }
    return orig_open(path, flags);
}

static int fake_openat(int dirfd, const char* path, int flags, ...) {
    if (path && strstr(path, "/proc/cpuinfo")) {
        return make_cpuinfo_fd();
    }

    if (flags & O_CREAT) {
        mode_t mode = 0;
        va_list ap;
        va_start(ap, flags);
        mode = va_arg(ap, mode_t);
        va_end(ap);
        return orig_openat(dirfd, path, flags, mode);
    }
    return orig_openat(dirfd, path, flags);
}

static void hook_install() {
    if (orig_open || orig_openat) return;

    xhook_register("libc.so", "open", (void*)fake_open, (void**)&orig_open);
    xhook_register("libc.so", "open64", (void*)fake_open, (void**)&orig_open);
    xhook_register("libc.so", "openat", (void*)fake_openat, (void**)&orig_openat);
    xhook_register("libc.so", "openat64", (void*)fake_openat, (void**)&orig_openat);

    xhook_refresh(0);

    __android_log_print(ANDROID_LOG_INFO, LOG_TAG, "CPU hook installed");
}

class SpoofCPU : public zygisk::ModuleBase {
public:
    void onLoad(zygisk::Api* api) override {}
    void preAppSpecialize(zygisk::AppSpecializeArgs* args) override {}
    void postAppSpecialize(const zygisk::AppSpecializeArgs* args) override {
        hook_install();
    }
};

REGISTER_ZYGISK_MODULE(SpoofCPU)
