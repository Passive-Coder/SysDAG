#define _POSIX_C_SOURCE 200809L
#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

int main(void) {
    char buffer[4096] = {0};
    ssize_t length = 0;
    int fd = open("/guest/decoy/secret.txt", O_RDONLY);
    if (fd >= 0) {
        length = read(fd, buffer, sizeof buffer);
        close(fd);
    }
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) return 1;
    struct sockaddr_in destination;
    memset(&destination, 0, sizeof destination);
    destination.sin_family = AF_INET;
    destination.sin_port = htons(9999);
    destination.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (length > 0) {
        sendto(sock, buffer, (size_t)length, 0,
               (struct sockaddr *)&destination, sizeof destination);
    }
    close(sock);
    return 0;
}
