#define _GNU_SOURCE
#include <stdio.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <stdarg.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include <errno.h>
#include <sys/un.h>

typedef int64_t (*syscall_hook_fn_t)(int64_t, int64_t, int64_t, int64_t,
    int64_t, int64_t, int64_t);

static syscall_hook_fn_t original_syscall = NULL;

int64_t syscall_hook_fn(int64_t rdi, int64_t rsi, int64_t rdx, int64_t r10, int64_t r8, int64_t r9, int64_t rax) {
    
    int64_t ret;

    if (rax == SYS_openat) {
        // print AT_FDCWD if the DIRFD is -100
        int dirfd = (int)rdi;
        char buf[32];
        if (dirfd == AT_FDCWD) {
            snprintf(buf, sizeof(buf), "AT_FDCWD");
        } else {
            snprintf(buf, sizeof(buf), "%ld", rdi);
        }
        ret = syscall(rax, rdi, rsi, rdx, r10);
        fprintf(stderr, "[logger] openat(%s, \"%s\", 0x%lx, %#lo) = %ld\n", buf, (char *)rsi, rdx, r10, ret);

        return ret;

    } else if (rax == SYS_read) {
        ret = syscall(rax, rdi, rsi, rdx);

        char buf[256] = {0};
        int len;
        // more than 32 bytes: ignore
        if (ret > 32) len = 32;
        else len = ret;

        // escape the string
        int j = 0;
        for (int i = 0; i < len && j < sizeof(buf) -5; ++i) {
            unsigned char c = ((char *)rsi)[i];
            if (c == '\n') { 
                buf[j++] = '\\'; 
                buf[j++] = 'n'; 

            } else if (c == '\r') { 
                buf[j++] = '\\'; 
                buf[j++] = 'r'; 

            } else if (c == '\t') { 
                buf[j++] = '\\'; 
                buf[j++] = 't'; 

            } else if (c >= 32 && c <= 126) { 
                buf[j++] = c; 

            } else { 
                j += snprintf(buf + j, 5, "\\x%02x", c); 

            }
        }

        if (ret > 32) strcpy(buf + j, "...");
        fprintf(stderr, "[logger] read(%ld, \"%s\", %ld) = %ld\n", rdi, buf, rdx, ret);
        return ret;

    } else if (rax == SYS_write) {
        ret = syscall(rax, rdi, rsi, rdx);

        char buf[256] = {0};
        int len;
        // more than 32 bytes: ignore
        if (ret > 32) len = 32;
        else len = ret;

        int j = 0;
        for (int i = 0; i < len && j < sizeof(buf) -5; ++i) {
            unsigned char c = ((char *)rsi)[i];
            if (c == '\n') { 
                buf[j++] = '\\'; 
                buf[j++] = 'n'; 

            } else if (c == '\r') { 
                buf[j++] = '\\'; 
                buf[j++] = 'r'; 

            } else if (c == '\t') { 
                buf[j++] = '\\'; 
                buf[j++] = 't'; 

            } else if (c >= 32 && c <= 126) { 
                buf[j++] = c; 

            } else { 
                j += snprintf(buf + j, 5, "\\x%02x", c); 

            }
        }
        if (ret > 32) strcpy(buf + j, "...");
        fprintf(stderr, "[logger] write(%ld, \"%s\", %ld) = %ld\n", rdi, buf, rdx, ret);

        return ret;

    } else if (rax == SYS_connect){
        ret = syscall(rax, rdi, rsi, rdx);

        char buf[256] = "UNKNOWN";
        struct sockaddr *fd = (struct sockaddr *)rsi;
        // ipv4 and ipv6
        if (fd->sa_family == AF_INET) {
            struct sockaddr_in *client = (struct sockaddr_in *)fd;
            snprintf(buf, sizeof(buf), "\"%s:%d\"", inet_ntoa(client->sin_addr), ntohs(client->sin_port));
        // unix
        } else if (fd->sa_family == AF_UNIX) {
            snprintf(buf, sizeof(buf), "\"UNIX:%s\"", ((struct sockaddr_un *)fd)->sun_path);
        }
        fprintf(stderr, "[logger] connect(%ld, %s, %ld) = %ld\n", rdi, buf, rdx, ret);

        return ret;
    } else if (rax == SYS_execve) {
        fprintf(stderr, "[logger] execve(\"%s\", %p, %p)\n", (char *)rdi, (void *)rsi, (void *)rdx);
        return syscall(rax, rdi, rsi, rdx);

    }

    // fprintf(stderr, "Intercepted syscall: %ld\n", rax);
    return original_syscall(rdi, rsi, rdx, r10, r8, r9, rax);
}

void __hook_init(const syscall_hook_fn_t trigger_syscall, syscall_hook_fn_t *hooked_syscall) {
    original_syscall = trigger_syscall;
    *hooked_syscall = syscall_hook_fn;
}