#include <unistd.h>

int main(void) {
    char *arguments[] = {"/bin/sh", "-c", "echo pwned", NULL};
    execve("/bin/sh", arguments, NULL);
    return 1;
}
