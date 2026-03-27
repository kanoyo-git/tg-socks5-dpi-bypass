/*
 * SOCKS5 DPI Bypass - LD_PRELOAD library for Linux Telegram/AyuGram
 * 
 * Usage: LD_PRELOAD=/path/to/socks5_dpi_bypass.so telegram-desktop
 * 
 * Intercepts SOCKS5 traffic and applies DPI bypass:
 *   - Fragmented SOCKS5 handshake (byte-by-byte with jitter)
 *   - Fragmented SOCKS5 CONNECT request
 *   - TLS ClientHello split at SNI
 * 
 * No UI, no config - just works with Telegram's native SOCKS5 proxy settings.
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <dlfcn.h>
#include <errno.h>
#include <time.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <poll.h>

/* Configuration */
#define TLS_SPLIT_OFFSET 40
#define JITTER_MIN_US 1000
#define JITTER_MAX_US 7000
#define CHUNK_DELAY_US 2000

#define MAX_FD_TRACK 4096

/* Real function pointers */
static int (*real_connect)(int sockfd, const struct sockaddr *addr, socklen_t addrlen) = NULL;
static ssize_t (*real_send)(int sockfd, const void *buf, size_t len, int flags) = NULL;
static ssize_t (*real_sendto)(int sockfd, const void *buf, size_t len, int flags,
                              const struct sockaddr *dest_addr, socklen_t addrlen) = NULL;
static ssize_t (*real_write)(int fd, const void *buf, size_t count) = NULL;
static ssize_t (*real_recv)(int sockfd, void *buf, size_t len, int flags) = NULL;
static int (*real_close)(int fd) = NULL;

/* Track SOCKS5 state per FD */
typedef enum {
    STATE_NONE = 0,
    STATE_SOCKS5_GREETING,
    STATE_SOCKS5_AUTH,
    STATE_SOCKS5_CONNECT_SENT,
    STATE_TLS_FIRST,
    STATE_PIPE
} socks5_state_t;

typedef struct {
    int active;
    socks5_state_t state;
    int needs_auth;
    char dest_host[256];
    uint16_t dest_port;
} fd_context_t;

static fd_context_t fd_ctx[MAX_FD_TRACK];
static pthread_mutex_t ctx_mutex = PTHREAD_MUTEX_INITIALIZER;

/* Random jitter */
static inline void random_jitter(void) {
    int us = JITTER_MIN_US + (rand() % (JITTER_MAX_US - JITTER_MIN_US));
    usleep((useconds_t)us);
}

/* TLS split jitter */
static inline void chunk_jitter(void) {
    usleep(CHUNK_DELAY_US);
}

/* Get context for FD */
static inline fd_context_t* get_ctx(int fd) {
    if (fd < 0 || fd >= MAX_FD_TRACK) return NULL;
    return &fd_ctx[fd];
}

/* Init real functions */
static void init_real_functions(void) {
    static int initialized = 0;
    if (initialized) return;
    
    real_connect = dlsym(RTLD_NEXT, "connect");
    real_send = dlsym(RTLD_NEXT, "send");
    real_sendto = dlsym(RTLD_NEXT, "sendto");
    real_write = dlsym(RTLD_NEXT, "write");
    real_recv = dlsym(RTLD_NEXT, "recv");
    real_close = dlsym(RTLD_NEXT, "close");
    
    if (!real_connect || !real_send || !real_recv) {
        fprintf(stderr, "[socks5_bypass] Failed to load real functions\n");
        _exit(1);
    }
    
    srand((unsigned int)time(NULL));
    initialized = 1;
}

/* Check if address is localhost */
static int is_localhost(const struct sockaddr *addr) {
    if (addr->sa_family == AF_INET) {
        struct sockaddr_in *in = (struct sockaddr_in *)addr;
        return (ntohl(in->sin_addr.s_addr) == 0x7f000001);
    }
    return 0;
}

/* Send byte-by-byte with jitter */
static ssize_t send_fragmented(int sockfd, const void *buf, size_t len) {
    const unsigned char *data = (const unsigned char *)buf;
    ssize_t total = 0;
    
    for (size_t i = 0; i < len; i++) {
        ssize_t n = real_send(sockfd, &data[i], 1, 0);
        if (n <= 0) {
            return (total > 0) ? total : n;
        }
        total += n;
        if (i < len - 1) {
            random_jitter();
        }
    }
    return total;
}

/* Send with TLS split */
static ssize_t send_with_tls_split(int sockfd, const void *buf, size_t len) {
    const unsigned char *data = (const unsigned char *)buf;
    
    /* Check for TLS handshake */
    if (len > 5 && data[0] == 0x16 && data[1] == 0x03 && 
        (data[2] == 0x01 || data[2] == 0x03)) {
        
        /* Fragment TLS ClientHello at offset */
        if (len > TLS_SPLIT_OFFSET) {
            ssize_t n = real_send(sockfd, data, TLS_SPLIT_OFFSET, 0);
            if (n <= 0) return n;
            
            chunk_jitter();
            
            ssize_t m = real_send(sockfd, data + TLS_SPLIT_OFFSET, len - TLS_SPLIT_OFFSET, 0);
            if (m <= 0) return (ssize_t)((n > 0) ? (size_t)n : (size_t)m);
            
            return n + m;
        }
    }
    
    return real_send(sockfd, buf, len, 0);
}

/* ============== HOOKED FUNCTIONS ============== */

int connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen) {
    (void)addrlen;
    init_real_functions();
    
    int ret = real_connect(sockfd, addr, addrlen);
    if (ret == 0 && addr->sa_family == AF_INET && !is_localhost(addr)) {
        pthread_mutex_lock(&ctx_mutex);
        fd_context_t *ctx = get_ctx(sockfd);
        if (ctx) {
            memset(ctx, 0, sizeof(*ctx));
            ctx->active = 1;
            ctx->state = STATE_NONE;
        }
        pthread_mutex_unlock(&ctx_mutex);
    }
    return ret;
}

ssize_t send(int sockfd, const void *buf, size_t len, int flags) {
    init_real_functions();
    
    pthread_mutex_lock(&ctx_mutex);
    fd_context_t *ctx = get_ctx(sockfd);
    int state = ctx ? ctx->state : STATE_NONE;
    pthread_mutex_unlock(&ctx_mutex);
    
    /* Passthrough for flags like MSG_NOSIGNAL */
    if (flags != 0 && flags != MSG_NOSIGNAL) {
        return real_send(sockfd, buf, len, flags);
    }
    
    /* State machine for SOCKS5 bypass */
    switch (state) {
        case STATE_NONE:
            /* Check if this looks like SOCKS5 greeting */
            if (len >= 3) {
                const unsigned char *data = (const unsigned char *)buf;
                if (data[0] == 0x05 && data[1] > 0) {
                    ssize_t ret = send_fragmented(sockfd, buf, len);
                    pthread_mutex_lock(&ctx_mutex);
                    if (ctx) ctx->state = STATE_SOCKS5_GREETING;
                    pthread_mutex_unlock(&ctx_mutex);
                    return ret;
                }
            }
            break;
            
        case STATE_SOCKS5_GREETING:
            {
                const unsigned char *data = (const unsigned char *)buf;
                if (len >= 2 && data[0] == 0x01) {
                    ssize_t ret = send_fragmented(sockfd, buf, len);
                    pthread_mutex_lock(&ctx_mutex);
                    if (ctx) ctx->state = STATE_SOCKS5_AUTH;
                    pthread_mutex_unlock(&ctx_mutex);
                    return ret;
                } else if (len >= 4 && data[0] == 0x05) {
                    ssize_t ret = send_fragmented(sockfd, buf, len);
                    pthread_mutex_lock(&ctx_mutex);
                    if (ctx) ctx->state = STATE_SOCKS5_CONNECT_SENT;
                    pthread_mutex_unlock(&ctx_mutex);
                    return ret;
                }
            }
            break;
            
        case STATE_SOCKS5_AUTH:
            {
                const unsigned char *data = (const unsigned char *)buf;
                if (len >= 4 && data[0] == 0x05) {
                    ssize_t ret = send_fragmented(sockfd, buf, len);
                    pthread_mutex_lock(&ctx_mutex);
                    if (ctx) ctx->state = STATE_SOCKS5_CONNECT_SENT;
                    pthread_mutex_unlock(&ctx_mutex);
                    return ret;
                }
            }
            break;
            
        case STATE_TLS_FIRST:
            {
                ssize_t ret = send_with_tls_split(sockfd, buf, len);
                pthread_mutex_lock(&ctx_mutex);
                if (ctx) ctx->state = STATE_PIPE;
                pthread_mutex_unlock(&ctx_mutex);
                return ret;
            }
            
        default:
            break;
    }
    return real_send(sockfd, buf, len, flags);
}

ssize_t recv(int sockfd, void *buf, size_t len, int flags) {
    init_real_functions();
    
    ssize_t ret = real_recv(sockfd, buf, len, flags);
    if (ret <= 0) return ret;
    
    pthread_mutex_lock(&ctx_mutex);
    fd_context_t *ctx = get_ctx(sockfd);
    
    if (ctx) {
        unsigned char *data = (unsigned char *)buf;
        int state = ctx->state;
        
        switch (state) {
            case STATE_SOCKS5_GREETING:
                if (ret >= 2 && data[0] == 0x05) {
                    ctx->state = (data[1] == 0x02) ? STATE_SOCKS5_AUTH : STATE_SOCKS5_GREETING;
                }
                break;
                
            case STATE_SOCKS5_AUTH:
                if (ret >= 2 && data[0] == 0x01 && data[1] == 0x00) {
                    ctx->state = STATE_SOCKS5_GREETING;
                }
                break;
                
            case STATE_SOCKS5_CONNECT_SENT:
                if (ret >= 4 && data[0] == 0x05 && data[1] == 0x00) {
                    ctx->state = STATE_TLS_FIRST;
                }
                break;
                
            case STATE_TLS_FIRST:
                ctx->state = STATE_PIPE;
                break;
                
            default:
                break;
        }
    }
    pthread_mutex_unlock(&ctx_mutex);
    
    return ret;
}

ssize_t sendto(int sockfd, const void *buf, size_t len, int flags,
               const struct sockaddr *dest_addr, socklen_t addrlen) {
    (void)dest_addr;
    (void)addrlen;
    init_real_functions();
    return real_sendto(sockfd, buf, len, flags, dest_addr, addrlen);
}

ssize_t write(int fd, const void *buf, size_t count) {
    init_real_functions();
    
    int val = 0;
    socklen_t len = sizeof(val);
    if (getsockopt(fd, SOL_SOCKET, SO_TYPE, &val, &len) == -1) {
        return real_write(fd, buf, count);
    }
    
    return send(fd, buf, count, 0);
}

int close(int fd) {
    init_real_functions();
    
    pthread_mutex_lock(&ctx_mutex);
    fd_context_t *ctx = get_ctx(fd);
    if (ctx) {
        memset(ctx, 0, sizeof(*ctx));
    }
    pthread_mutex_unlock(&ctx_mutex);
    
    return real_close(fd);
}

/* Constructor */
__attribute__((constructor))
static void init(void) {
    init_real_functions();
    memset(fd_ctx, 0, sizeof(fd_ctx));
    fprintf(stderr, "[socks5_bypass] LD_PRELOAD library loaded\n");
}