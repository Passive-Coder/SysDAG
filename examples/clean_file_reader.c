#define _POSIX_C_SOURCE 200809L
#include <fcntl.h>
#include <unistd.h>

static void read_file(const char *path) {
    int fd = open(path, O_RDONLY);
    if (fd < 0) return;
    char buffer[4096];
    while (read(fd, buffer, sizeof buffer) > 0) {}
    close(fd);
}

int main(void) {
    read_file("/guest/www/index.html");
    read_file("/guest/www/page.txt");
    return 0;
}
