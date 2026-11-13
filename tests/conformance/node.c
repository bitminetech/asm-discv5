/*
 * A discv5 node for conformance tests: the event loop of an application,
 * around the assembly core and shell. Test code: the library itself is
 * assembly.
 *
 * Usage: node IP PORT [KEY_HEX] [-v] [-l SECONDS [-t HEX]] [-x SECONDS] [-c COUNT] [-i LIMITS] [-b ENR_TEXT]...
 * Prints the node's ENR text on the first line, then serves until killed.
 * IP 0.0.0.0 binds every interface and leaves the address out of the record.
 * -v prints every action. -l looks up a random node ID every SECONDS, or
 * the node ID given with -t HEX.
 * -b adds a node record (enr:...) to the table. -x stops after SECONDS: it
 * closes the socket and prints "closed".
 * -c prints "peer N ID enr:..." for each new node ID that lookups find, and
 * stops after COUNT of them.
 * -i sets the IP limits of the table: BUCKET,TABLE,SUBNET4,SUBNET6,LAN, the
 * config fields of the same names (for example 2,10,24,24,0 as geth).
 */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if defined(_WIN32) && defined(__x86_64__)
#define DISCV5_ABI __attribute__((sysv_abi))
#else
#define DISCV5_ABI
#endif

DISCV5_ABI uint64_t discv5_init(const void *config, void *state);
DISCV5_ABI uint64_t discv5_step(void *state, const void *tick, const void *events, void *scratch, void *actions);
DISCV5_ABI uint64_t discv5_local_record(const void *state, void *record);
DISCV5_ABI uint64_t discv5_enr_text_decode(const void *text, void *record);
DISCV5_ABI uint64_t discv5_shell_clock(void *tick);
DISCV5_ABI uint64_t discv5_shell_open(const void *endpoint, void *context, void *event);
DISCV5_ABI uint64_t discv5_shell_send(void *context, const void *action, void *event);
DISCV5_ABI uint64_t discv5_shell_receive(void *context, const void *until, void *event);
DISCV5_ABI uint64_t discv5_shell_close(void *context);

/* Values from include/discv5.inc. */
#define STATE_SIZE 245392
#define SCRATCH_SIZE 65536
#define ACTIONS_BASE 32768
#define ACTIONS_PER_EVENT 16384
#define EVENT_MAX 1336
#define MAX_EVENTS 256
#define CONFIG_SIZE 152
#define MAX_BOOT 64
enum { EV_DATAGRAM = 1, EV_ADD_NODE = 2, EV_LOOKUP = 3, EV_OPENED = 6, EV_SENT = 7, EV_IDLE = 8 };
enum { ACT_SEND = 1, ACT_NODE_FOUND = 2, ACT_LOOKUP_DONE = 3, ACT_ENDPOINT = 4, ACT_RECORD = 5, ACT_WAKEUP = 6 };

static uint64_t rd64(const uint8_t *p) {
    uint64_t v;
    memcpy(&v, p, 8);
    return v;
}

static void wr64(uint8_t *p, uint64_t v) { memcpy(p, &v, 8); }

static void *xalloc(size_t n) {
    void *p = calloc(1, n);
    if (!p) {
        fprintf(stderr, "node: out of memory\n");
        exit(1);
    }
    return p;
}

static void hex(const uint8_t *p, size_t n) {
    for (size_t i = 0; i < n; i++)
        printf("%02x", p[i]);
}

static void print_enr(const uint8_t *rec, size_t n) {
    static const char a[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    printf("enr:");
    for (size_t i = 0; i < n; i += 3) {
        uint32_t v = (uint32_t)rec[i] << 16;
        size_t k = n - i;
        if (k > 1)
            v |= (uint32_t)rec[i + 1] << 8;
        if (k > 2)
            v |= rec[i + 2];
        putchar(a[v >> 18 & 63]);
        putchar(a[v >> 12 & 63]);
        if (k > 1)
            putchar(a[v >> 6 & 63]);
        if (k > 2)
            putchar(a[v & 63]);
    }
    printf("\n");
}

static int parse_ip4(const char *s, uint8_t out[4]) {
    for (int i = 0; i < 4; i++) {
        char *end;
        long v = strtol(s, &end, 10);
        if (end == s || v < 0 || v > 255 || (i < 3 && *end != '.') || (i == 3 && *end))
            return 0;
        out[i] = (uint8_t)v;
        s = end + 1;
    }
    return 1;
}

static int parse_hex32(const char *s, uint8_t out[32]) {
    if (strlen(s) != 64)
        return 0;
    for (int i = 0; i < 32; i++) {
        unsigned v;
        if (sscanf(s + 2 * i, "%2x", &v) != 1)
            return 0;
        out[i] = (uint8_t)v;
    }
    return 1;
}

/* The node IDs that lookups found, for -c. */
static uint8_t (*peers)[32];
static size_t npeers;

static int peer_add(const uint8_t id[32]) {
    for (size_t i = 0; i < npeers; i++)
        if (!memcmp(peers[i], id, 32))
            return 0;
    memcpy(peers[npeers++], id, 32);
    return 1;
}

/* The events list for the next step. */
static uint8_t *events;
static size_t events_cap;

static void events_reset(void) {
    wr64(events, events_cap);
    wr64(events + 8, 24);
    wr64(events + 16, 0);
}

static uint8_t *event_room(void) { return events + 24 + rd64(events + 16); }

static void event_add(void) {
    uint8_t *e = event_room();
    wr64(events + 16, rd64(events + 16) + rd64(e));
}

static size_t event_count(void) {
    size_t n = 0;
    for (size_t off = 0; off < rd64(events + 16); off += rd64(events + 24 + off))
        n++;
    return n;
}

int main(int argc, char **argv) {
    int verbose = 0;
    uint64_t every = 0, stop_after = 0, collect = 0, limits[5] = {0};
    uint8_t target[32];
    int fixed_target = 0;
    const char *args[3] = {0};
    int nargs = 0;
    const char *boot[MAX_BOOT];
    int nboot = 0;
    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "-v"))
            verbose = 1;
        else if (!strcmp(argv[i], "-l") && i + 1 < argc)
            every = 1000 * (uint64_t)strtoul(argv[++i], NULL, 10);
        else if (!strcmp(argv[i], "-x") && i + 1 < argc)
            stop_after = 1000 * (uint64_t)strtoul(argv[++i], NULL, 10);
        else if (!strcmp(argv[i], "-t") && i + 1 < argc)
            fixed_target = parse_hex32(argv[++i], target);
        else if (!strcmp(argv[i], "-i") && i + 1 < argc) {
            unsigned long long v[5];
            if (sscanf(argv[++i], "%llu,%llu,%llu,%llu,%llu", &v[0], &v[1], &v[2], &v[3], &v[4]) != 5) {
                fprintf(stderr, "node: -i takes BUCKET,TABLE,SUBNET4,SUBNET6,LAN\n");
                return 2;
            }
            for (int k = 0; k < 5; k++)
                limits[k] = v[k];
        } else if (!strcmp(argv[i], "-c") && i + 1 < argc)
            collect = strtoull(argv[++i], NULL, 10);
        else if (!strcmp(argv[i], "-b") && i + 1 < argc && nboot < MAX_BOOT)
            boot[nboot++] = argv[++i];
        else if (nargs < 3)
            args[nargs++] = argv[i];
    }
    uint8_t ip[4];
    if (nargs < 2 || !parse_ip4(args[0], ip)) {
        fprintf(stderr, "usage: node IP PORT [KEY_HEX] [-v] [-l SECONDS [-t HEX]] [-x SECONDS] [-c COUNT] [-i LIMITS] [-b ENR_TEXT]...\n");
        return 2;
    }
    long port = strtol(args[1], NULL, 10);
    int any = !ip[0] && !ip[1] && !ip[2] && !ip[3];
    if (collect)
        peers = xalloc(collect * 32);

    uint8_t *state = xalloc(STATE_SIZE);
    uint8_t *scratch = xalloc(SCRATCH_SIZE);
    uint8_t tick[40], config[CONFIG_SIZE], endpoint[32], context[64];
    uint8_t *event = xalloc(EVENT_MAX);
    events_cap = 24 + MAX_EVENTS * 64 + 2 * EVENT_MAX;
    events = xalloc(events_cap);
    size_t actions_cap = 24 + ACTIONS_BASE + (size_t)MAX_EVENTS * ACTIONS_PER_EVENT;
    uint8_t *actions = xalloc(actions_cap);

    /* Start: the key, the config, the socket. */
    for (int tries = 0;; tries++) {
        if (discv5_shell_clock(tick)) {
            fprintf(stderr, "node: no clock or random bytes\n");
            return 1;
        }
        memset(config, 0, sizeof config);
        if (nargs >= 3) {
            if (!parse_hex32(args[2], config)) {
                fprintf(stderr, "node: KEY_HEX must be 64 hex digits\n");
                return 2;
            }
        } else {
            memcpy(config, tick + 8, 32);
            if (discv5_shell_clock(tick))
                return 1;
        }
        wr64(config + 32, 1);
        memcpy(config + 40, tick + 8, 32);
        wr64(config + 72, rd64(tick));
        if (!any) {
            wr64(config + 80, (uint64_t)port);
            wr64(config + 88, 4);
            memcpy(config + 96, ip, 4);
        }
        for (int k = 0; k < 5; k++)
            wr64(config + 112 + 8 * k, limits[k]);
        uint64_t st = discv5_init(config, state);
        if (st == 0)
            break;
        if (nargs >= 3 || tries > 8) {
            fprintf(stderr, "node: discv5_init status %llu\n", (unsigned long long)st);
            return 1;
        }
    }
    memset(endpoint, 0, sizeof endpoint);
    wr64(endpoint, (uint64_t)port);
    wr64(endpoint + 8, 4);
    memcpy(endpoint + 16, ip, 4);
    discv5_shell_open(endpoint, context, event);
    if (rd64(event + 16)) {
        fprintf(stderr, "node: open failed, OS error %llu\n", (unsigned long long)rd64(event + 16));
        return 1;
    }
    uint8_t record[24 + 304];
    wr64(record, sizeof record);
    discv5_local_record(state, record);
    print_enr(record + 24, rd64(record + 16));
    fflush(stdout);

    events_reset();
    memcpy(event_room(), event, rd64(event));
    event_add();
    for (int i = 0; i < nboot; i++) {
        uint8_t text[24 + 512], rec[24 + 512];
        size_t n = strlen(boot[i]);
        if (n > 512)
            continue;
        wr64(text, sizeof text);
        wr64(text + 8, 24);
        wr64(text + 16, n);
        memcpy(text + 24, boot[i], n);
        wr64(rec, sizeof rec);
        if (discv5_enr_text_decode(text, rec)) {
            fprintf(stderr, "node: bad record %s\n", boot[i]);
            continue;
        }
        uint8_t *e = event_room();
        uint64_t len = rd64(rec + 16);
        wr64(e, (24 + len + 7) & ~(uint64_t)7);
        wr64(e + 8, EV_ADD_NODE);
        wr64(e + 16, len);
        memcpy(e + 24, rec + 24, len);
        event_add();
    }

    /* The loop: step, perform the actions, wait for a datagram or the wakeup time. */
    uint64_t until = 0, next_lookup = 0, stop_at = stop_after ? rd64(tick) + stop_after : 0, started = rd64(tick);
    for (;;) {
        if (discv5_shell_clock(tick)) {
            fprintf(stderr, "node: no clock or random bytes\n");
            return 1;
        }
        if (stop_at && rd64(tick) >= stop_at) {
            uint64_t st = discv5_shell_close(context);
            uint8_t closed[8];
            memset(closed, 0xFF, 8);
            if (st || memcmp(context, closed, 8)) {
                fprintf(stderr, "node: close failed\n");
                return 1;
            }
            printf("closed\n");
            return 0;
        }
        if (every && rd64(tick) >= next_lookup) {
            if (next_lookup) {
                uint8_t *e = event_room();
                wr64(e, 48);
                wr64(e + 8, EV_LOOKUP);
                memcpy(e + 16, fixed_target ? target : tick + 8, 32);
                event_add();
            }
            next_lookup = rd64(tick) + every;
        }
        wr64(scratch, SCRATCH_SIZE);
        wr64(actions, 24 + ACTIONS_BASE + event_count() * ACTIONS_PER_EVENT);
        uint64_t st = discv5_step(state, tick, events, scratch, actions);
        if (st) {
            fprintf(stderr, "node: discv5_step status %llu\n", (unsigned long long)st);
            return 1;
        }
        events_reset();
        uint8_t *a = actions + rd64(actions + 8);
        uint8_t *end = a + rd64(actions + 16);
        for (; a < end; a += rd64(a)) {
            uint64_t kind = rd64(a + 8);
            if (kind == ACT_SEND) {
                if (verbose)
                    printf("send %llu bytes to port %llu\n", (unsigned long long)rd64(a + 48),
                           (unsigned long long)rd64(a + 16));
                discv5_shell_send(context, a, event_room());
                if (rd64(event_room() + 16))
                    fprintf(stderr, "node: send failed, OS error %llu\n", (unsigned long long)rd64(event_room() + 16));
                event_add();
            } else if (kind == ACT_WAKEUP) {
                until = rd64(a + 16);
            } else if (collect && kind == ACT_NODE_FOUND) {
                if (peer_add(a + 16)) {
                    printf("peer %llu ", (unsigned long long)npeers);
                    hex(a + 16, 32);
                    printf(" ");
                    print_enr(a + 56, rd64(a + 48));
                }
                if (npeers >= collect) {
                    printf("collected %llu peers in %llu ms\n", (unsigned long long)npeers,
                           (unsigned long long)(rd64(tick) - started));
                    discv5_shell_close(context);
                    return 0;
                }
            } else if (verbose && kind == ACT_NODE_FOUND) {
                printf("found ");
                hex(a + 16, 32);
                printf("\n");
            } else if (verbose && kind == ACT_LOOKUP_DONE) {
                printf("lookup done, %llu found\n", (unsigned long long)rd64(a + 48));
            } else if (verbose && kind == ACT_ENDPOINT) {
                printf("endpoint seen: port %llu\n", (unsigned long long)rd64(a + 16));
            } else if (kind == ACT_RECORD) {
                print_enr(a + 24, rd64(a + 16));
            }
            fflush(stdout);
        }
        if (every && until > next_lookup)
            until = next_lookup;
        if (stop_at && until > stop_at)
            until = stop_at;
        if (event_count() >= MAX_EVENTS - 1)
            continue;
        discv5_shell_receive(context, &until, event_room());
        if (verbose && rd64(event_room() + 8) == EV_DATAGRAM)
            printf("receive %llu bytes from port %llu\n", (unsigned long long)rd64(event_room() + 48),
                   (unsigned long long)rd64(event_room() + 16));
        event_add();
        fflush(stdout);
    }
}
