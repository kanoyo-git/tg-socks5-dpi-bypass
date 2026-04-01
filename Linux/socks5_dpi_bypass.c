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
#define JITTER_MIN_US 1000
#define JITTER_MAX_US 7000
#define INITIAL_SPLIT_DELAY_MIN_US 2000
#define INITIAL_SPLIT_DELAY_MAX_US 6000
#define INITIAL_SPLIT_MIN_GAP 3
#define TLS_RECORD_HEADER_SIZE 5
#define HTTP_METHOD_SPLIT_AT 2
#define GENERIC_SPLIT_EARLY_MIN 16
#define GENERIC_SPLIT_EARLY_MAX 64
#define GENERIC_SPLIT_LATE_MIN 96
#define GENERIC_SPLIT_LATE_MAX 192
#define MAX_SPLIT_POSITIONS 8

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
    STATE_INITIAL_BURST,
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

static inline int random_between(int min_value, int max_value) {
    if (max_value <= min_value) {
        return min_value;
    }
    return min_value + (rand() % (max_value - min_value + 1));
}

/* Random jitter */
static inline void random_jitter(void) {
    usleep((useconds_t) random_between(JITTER_MIN_US, JITTER_MAX_US));
}

/* Adaptive split jitter */
static inline void split_jitter(void) {
    usleep((useconds_t) random_between(INITIAL_SPLIT_DELAY_MIN_US, INITIAL_SPLIT_DELAY_MAX_US));
}

static inline size_t min_size(size_t a, size_t b) {
    return a < b ? a : b;
}

static inline size_t max_size(size_t a, size_t b) {
    return a > b ? a : b;
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

static int read_u16_be(const unsigned char *data, size_t len, size_t offset, unsigned int *value) {
    if (offset + 2 > len) {
        return 0;
    }
    *value = ((unsigned int) data[offset] << 8) | (unsigned int) data[offset + 1];
    return 1;
}

static int read_u24_be(const unsigned char *data, size_t len, size_t offset, unsigned int *value) {
    if (offset + 3 > len) {
        return 0;
    }
    *value = ((unsigned int) data[offset] << 16) |
             ((unsigned int) data[offset + 1] << 8) |
             (unsigned int) data[offset + 2];
    return 1;
}

static int starts_with_ascii(const unsigned char *data, size_t len, const char *value) {
    size_t value_len = strlen(value);
    size_t i;

    if (len < value_len) {
        return 0;
    }
    for (i = 0; i < value_len; i++) {
        if (data[i] != (unsigned char) value[i]) {
            return 0;
        }
    }
    return 1;
}

static unsigned char to_lower_ascii(unsigned char value) {
    if (value >= 'A' && value <= 'Z') {
        return (unsigned char) (value + ('a' - 'A'));
    }
    return value;
}

static int starts_with_ascii_ignore_case(const unsigned char *data, size_t len, const char *value) {
    size_t value_len = strlen(value);
    size_t i;

    if (len < value_len) {
        return 0;
    }
    for (i = 0; i < value_len; i++) {
        if (to_lower_ascii(data[i]) != to_lower_ascii((unsigned char) value[i])) {
            return 0;
        }
    }
    return 1;
}

static int index_of_ascii_ignore_case(const unsigned char *data, size_t len, const char *value) {
    size_t value_len = strlen(value);
    size_t offset;
    size_t i;

    if (value_len == 0 || len < value_len) {
        return -1;
    }
    for (offset = 0; offset <= len - value_len; offset++) {
        for (i = 0; i < value_len; i++) {
            if (to_lower_ascii(data[offset + i]) != to_lower_ascii((unsigned char) value[i])) {
                break;
            }
        }
        if (i == value_len) {
            return (int) offset;
        }
    }
    return -1;
}

static int index_of_byte(const unsigned char *data, size_t start, size_t end, unsigned char value) {
    size_t i;

    for (i = start; i < end; i++) {
        if (data[i] == value) {
            return (int) i;
        }
    }
    return -1;
}

static int looks_like_tls_client_hello(const unsigned char *data, size_t len) {
    return len > 9 && data[0] == 0x16 && data[1] == 0x03 && data[5] == 0x01;
}

static int looks_like_http_request(const unsigned char *data, size_t len) {
    return starts_with_ascii(data, len, "GET ") ||
           starts_with_ascii(data, len, "POST ") ||
           starts_with_ascii(data, len, "HEAD ") ||
           starts_with_ascii(data, len, "PUT ") ||
           starts_with_ascii(data, len, "PATCH ") ||
           starts_with_ascii(data, len, "DELETE ") ||
           starts_with_ascii(data, len, "OPTIONS ") ||
           starts_with_ascii(data, len, "CONNECT ") ||
           starts_with_ascii(data, len, "PRI ");
}

static int find_tls_server_name_range(const unsigned char *data, size_t len, size_t *start, size_t *end) {
    size_t offset = TLS_RECORD_HEADER_SIZE;
    size_t extensions_end;
    unsigned int hello_len;
    unsigned int field_len;

    if (!looks_like_tls_client_hello(data, len) || len < 43) {
        return 0;
    }
    if (!read_u24_be(data, len, offset + 1, &hello_len) || offset + 4 + hello_len > len) {
        return 0;
    }

    offset += 4;  /* Handshake header */
    offset += 2;  /* client_version */
    offset += 32; /* random */
    if (offset >= len) {
        return 0;
    }

    offset += 1 + data[offset];
    if (!read_u16_be(data, len, offset, &field_len)) {
        return 0;
    }
    offset += 2 + field_len;
    if (offset >= len) {
        return 0;
    }

    offset += 1 + data[offset];
    if (!read_u16_be(data, len, offset, &field_len)) {
        return 0;
    }
    offset += 2;
    extensions_end = offset + field_len;
    if (extensions_end > len) {
        return 0;
    }

    while (offset + 4 <= extensions_end) {
        unsigned int ext_type;
        unsigned int ext_len;

        if (!read_u16_be(data, len, offset, &ext_type) ||
            !read_u16_be(data, len, offset + 2, &ext_len)) {
            return 0;
        }
        offset += 4;
        if (offset + ext_len > extensions_end) {
            return 0;
        }

        if (ext_type == 0x0000 && ext_len >= 5) {
            size_t list_end;
            unsigned int list_len;

            if (!read_u16_be(data, len, offset, &list_len)) {
                return 0;
            }
            offset += 2;
            list_end = offset + list_len;
            if (list_end > extensions_end) {
                return 0;
            }

            while (offset + 3 <= list_end) {
                unsigned int name_len;

                if (!read_u16_be(data, len, offset + 1, &name_len) || offset + 3 + name_len > list_end) {
                    return 0;
                }
                if (data[offset] == 0x00 && name_len > 0) {
                    *start = offset + 3;
                    *end = *start + name_len;
                    return 1;
                }
                offset += 3 + name_len;
            }
            return 0;
        }

        offset += ext_len;
    }
    return 0;
}

static int find_http_host_range(const unsigned char *data, size_t len, size_t *start, size_t *end) {
    int host_header_offset = index_of_ascii_ignore_case(data, len, "\r\nHost:");
    size_t prefix_len = 7;
    size_t host_start;
    size_t host_end;
    int separator;

    if (host_header_offset < 0) {
        host_header_offset = index_of_ascii_ignore_case(data, len, "\nHost:");
        prefix_len = 6;
    }
    if (host_header_offset < 0 && starts_with_ascii_ignore_case(data, len, "Host:")) {
        host_header_offset = 0;
        prefix_len = 5;
    }
    if (host_header_offset < 0) {
        return 0;
    }

    host_start = (size_t) host_header_offset + prefix_len;
    while (host_start < len && (data[host_start] == ' ' || data[host_start] == '\t')) {
        host_start++;
    }

    host_end = host_start;
    while (host_end < len && data[host_end] != '\r' && data[host_end] != '\n') {
        host_end++;
    }
    if (host_end <= host_start) {
        return 0;
    }

    if (data[host_start] == '[') {
        separator = index_of_byte(data, host_start, host_end, ']');
        if (separator > (int) host_start) {
            host_end = (size_t) separator + 1;
        }
    } else {
        separator = index_of_byte(data, host_start, host_end, ':');
        if (separator > (int) host_start) {
            host_end = (size_t) separator;
        }
    }

    if (host_end <= host_start) {
        return 0;
    }
    *start = host_start;
    *end = host_end;
    return 1;
}

static int find_second_level_domain_range(const unsigned char *data, size_t start, size_t end, size_t *label_start, size_t *label_end) {
    size_t normalized_end = end;
    int last_dot = -1;
    int second_last_dot = -1;
    int third_last_dot = -1;
    size_t i;

    while (normalized_end > start && data[normalized_end - 1] == '.') {
        normalized_end--;
    }
    if (normalized_end <= start) {
        return 0;
    }

    for (i = start; i < normalized_end; i++) {
        if (data[i] == '.') {
            second_last_dot = last_dot;
            last_dot = (int) i;
        }
    }
    if (last_dot < 0) {
        *label_start = start;
        *label_end = normalized_end;
        return 1;
    }

    *label_start = second_last_dot >= (int) start ? (size_t) second_last_dot + 1 : start;
    *label_end = (size_t) last_dot;

    if (*label_end - *label_start < 3 && second_last_dot >= (int) start) {
        for (i = start; i < (size_t) second_last_dot; i++) {
            if (data[i] == '.') {
                third_last_dot = (int) i;
            }
        }
        if (third_last_dot >= (int) start && (size_t) second_last_dot - ((size_t) third_last_dot + 1) >= 3) {
            *label_start = (size_t) third_last_dot + 1;
            *label_end = (size_t) second_last_dot;
        }
    }

    return *label_end > *label_start;
}

static size_t resolve_hostname_midpoint(const unsigned char *data, size_t start, size_t end) {
    size_t label_start;
    size_t label_end;

    if (find_second_level_domain_range(data, start, end, &label_start, &label_end)) {
        return label_start + ((label_end - label_start) / 2);
    }
    return start + max_size(1, (end - start) / 2);
}

static void add_split_position(size_t *positions, size_t *count, size_t position) {
    if (*count < MAX_SPLIT_POSITIONS) {
        positions[(*count)++] = position;
    }
}

static void add_generic_split(size_t *positions, size_t *count, size_t len, int early_bias) {
    size_t upper_bound;
    size_t lower_bound;

    upper_bound = min_size(len - 1, early_bias ? (GENERIC_SPLIT_EARLY_MAX / 2) : GENERIC_SPLIT_EARLY_MAX);
    lower_bound = min_size(upper_bound, early_bias ? (GENERIC_SPLIT_EARLY_MIN / 2) : GENERIC_SPLIT_EARLY_MIN);

    if (upper_bound <= 1) {
        return;
    }
    lower_bound = max_size(2, lower_bound);
    add_split_position(positions, count, (size_t) random_between((int) lower_bound, (int) upper_bound));
}

static size_t resolve_late_generic_split(size_t len) {
    size_t upper_bound = min_size(len - 1, GENERIC_SPLIT_LATE_MAX);
    size_t lower_bound = min_size(upper_bound, GENERIC_SPLIT_LATE_MIN);

    if (upper_bound <= lower_bound) {
        return upper_bound;
    }
    return (size_t) random_between((int) lower_bound, (int) upper_bound);
}

static void normalize_split_positions(size_t *positions, size_t *count, size_t len) {
    size_t i;
    size_t j;
    size_t output_count = 0;
    size_t previous = 0;

    for (i = 0; i < *count; i++) {
        for (j = i + 1; j < *count; j++) {
            if (positions[j] < positions[i]) {
                size_t temp = positions[i];
                positions[i] = positions[j];
                positions[j] = temp;
            }
        }
    }

    for (i = 0; i < *count; i++) {
        size_t position = positions[i];

        if (position == 0 || position >= len) {
            continue;
        }
        if (output_count > 0 && position - previous < INITIAL_SPLIT_MIN_GAP) {
            continue;
        }
        positions[output_count++] = position;
        previous = position;
    }

    *count = output_count;
}

static void build_initial_split_positions(const unsigned char *data, size_t len, size_t *positions, size_t *count) {
    size_t host_start;
    size_t host_end;

    *count = 0;
    if (len <= 1) {
        return;
    }

    if (looks_like_tls_client_hello(data, len)) {
        add_split_position(positions, count, 1);
        if (len > TLS_RECORD_HEADER_SIZE) {
            add_split_position(positions, count, TLS_RECORD_HEADER_SIZE);
        }
        if (find_tls_server_name_range(data, len, &host_start, &host_end)) {
            add_split_position(positions, count, host_start + 1);
            add_split_position(positions, count, resolve_hostname_midpoint(data, host_start, host_end));
        } else {
            add_generic_split(positions, count, len, 1);
        }
    } else if (looks_like_http_request(data, len)) {
        if (len > HTTP_METHOD_SPLIT_AT) {
            add_split_position(positions, count, HTTP_METHOD_SPLIT_AT);
        }
        if (find_http_host_range(data, len, &host_start, &host_end)) {
            add_split_position(positions, count, host_start + 1);
            add_split_position(positions, count, resolve_hostname_midpoint(data, host_start, host_end));
        } else {
            add_generic_split(positions, count, len, 0);
        }
    } else {
        add_split_position(positions, count, 1);
        add_generic_split(positions, count, len, 0);
        if (len > GENERIC_SPLIT_LATE_MIN) {
            add_split_position(positions, count, resolve_late_generic_split(len));
        }
    }

    normalize_split_positions(positions, count, len);
}

static ssize_t send_segment(int sockfd, const unsigned char *data, size_t len, int flags) {
    size_t total = 0;

    while (total < len) {
        ssize_t n = real_send(sockfd, data + total, len - total, flags);
        if (n <= 0) {
            return total > 0 ? (ssize_t) total : n;
        }
        total += (size_t) n;
    }
    return (ssize_t) total;
}

/* Send byte-by-byte with jitter */
static ssize_t send_fragmented(int sockfd, const void *buf, size_t len, int flags) {
    const unsigned char *data = (const unsigned char *)buf;
    ssize_t total = 0;
    
    for (size_t i = 0; i < len; i++) {
        ssize_t n = real_send(sockfd, &data[i], 1, flags);
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

static ssize_t send_with_split_positions(int sockfd, const unsigned char *data, size_t len,
                                         const size_t *positions, size_t count, int flags) {
    size_t offset = 0;
    ssize_t total = 0;
    size_t i;

    for (i = 0; i < count; i++) {
        size_t split_position = positions[i];
        ssize_t n;

        if (split_position <= offset || split_position >= len) {
            continue;
        }

        n = send_segment(sockfd, data + offset, split_position - offset, flags);
        if (n <= 0) {
            return total > 0 ? total : n;
        }

        total += n;
        offset += (size_t) n;
        if (offset != split_position) {
            return total;
        }
        split_jitter();
    }

    if (offset < len) {
        ssize_t n = send_segment(sockfd, data + offset, len - offset, flags);
        if (n <= 0) {
            return total > 0 ? total : n;
        }
        total += n;
    }

    return total;
}

/* Split the first post-SOCKS payload using protocol-aware DPI evasion */
static ssize_t send_with_adaptive_initial_split(int sockfd, const void *buf, size_t len, int flags) {
    const unsigned char *data = (const unsigned char *)buf;
    size_t positions[MAX_SPLIT_POSITIONS];
    size_t count;

    build_initial_split_positions(data, len, positions, &count);
    if (count == 0) {
        return real_send(sockfd, buf, len, flags);
    }
    return send_with_split_positions(sockfd, data, len, positions, count, flags);
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
                    ssize_t ret = send_fragmented(sockfd, buf, len, flags);
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
                    ssize_t ret = send_fragmented(sockfd, buf, len, flags);
                    pthread_mutex_lock(&ctx_mutex);
                    if (ctx) ctx->state = STATE_SOCKS5_AUTH;
                    pthread_mutex_unlock(&ctx_mutex);
                    return ret;
                } else if (len >= 4 && data[0] == 0x05) {
                    ssize_t ret = send_fragmented(sockfd, buf, len, flags);
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
                    ssize_t ret = send_fragmented(sockfd, buf, len, flags);
                    pthread_mutex_lock(&ctx_mutex);
                    if (ctx) ctx->state = STATE_SOCKS5_CONNECT_SENT;
                    pthread_mutex_unlock(&ctx_mutex);
                    return ret;
                }
            }
            break;
            
        case STATE_INITIAL_BURST:
            {
                ssize_t ret = send_with_adaptive_initial_split(sockfd, buf, len, flags);
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
                    ctx->state = STATE_INITIAL_BURST;
                }
                break;
                
            case STATE_INITIAL_BURST:
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
