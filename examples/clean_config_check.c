#define _POSIX_C_SOURCE 200809L
#include <fcntl.h>
#include <unistd.h>

int main(void) {
    for (int i = 0; i < 8; i++) {
        int fd = open("/guest/www/index.html", O_RDONLY);
        if (fd >= 0) {
            char byte;
            if (read(fd, &byte, 1) == 1) {}
            close(fd);
        }
    }
    return 0;
}
