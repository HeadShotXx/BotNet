#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <unistd.h>
#include <fcntl.h>

int main() {
    int fd = open("shellcode.bin", O_RDONLY);
    if (fd < 0) {
        perror("open shellcode.bin");
        return 1;
    }

    off_t size = lseek(fd, 0, SEEK_END);
    lseek(fd, 0, SEEK_SET);

    void *mem = mmap(NULL, size, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (mem == MAP_FAILED) {
        perror("mmap");
        return 1;
    }

    if (read(fd, mem, size) != size) {
        perror("read");
        return 1;
    }
    close(fd);

    printf("Executing shellcode at %p (size: %ld)...\n", mem, size);

    void (*sc)() = (void (*)())mem;
    sc();

    return 0;
}
