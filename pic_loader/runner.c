#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>
#include <fcntl.h>

int main() {
    int sc_fd = open("shellcode.bin", O_RDONLY);
    if (sc_fd < 0) { perror("open shellcode.bin"); return 1; }
    off_t sc_size = lseek(sc_fd, 0, SEEK_END);
    lseek(sc_fd, 0, SEEK_SET);
    unsigned char *sc_buf = malloc(sc_size);
    read(sc_fd, sc_buf, sc_size);
    close(sc_fd);

    int pl_fd = open("payload.b64", O_RDONLY);
    if (pl_fd < 0) { perror("open payload.b64"); return 1; }
    off_t pl_size = lseek(pl_fd, 0, SEEK_END);
    lseek(pl_fd, 0, SEEK_SET);
    char *pl_buf = malloc(pl_size + 1);
    read(pl_fd, pl_buf, pl_size);
    pl_buf[pl_size] = '\0';
    close(pl_fd);

    size_t total_size = sc_size + pl_size + 1;
    void *mem = mmap(NULL, total_size, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (mem == MAP_FAILED) { perror("mmap"); return 1; }

    memcpy(mem, sc_buf, sc_size);
    memcpy(mem + sc_size, pl_buf, pl_size + 1);

    printf("Executing shellcode at %p (size: %zu)...\n", mem, total_size);

    void (*sc)() = (void (*)())mem;
    sc();

    return 0;
}
