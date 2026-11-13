/*
 * C view of the asm-discv5 interface for the test code, and the helpers the
 * runner files share. Test code: the library itself is assembly. The values
 * mirror include/discv5.inc.
 */
#ifndef DISCV5_TEST_H
#define DISCV5_TEST_H

#include <stddef.h>
#include <stdint.h>

#if defined(_WIN32) && defined(__x86_64__)
#define DISCV5_ABI __attribute__((sysv_abi))
#else
#define DISCV5_ABI
#endif

enum {
    DISCV5_OK = 0,
    DISCV5_BUFFER_TOO_SMALL = 1,
    DISCV5_INVALID_KEY = 2,
    DISCV5_INVALID_EVENT = 3,
    DISCV5_INVALID_RECORD = 4,
    DISCV5_INVALID_TEXT = 5,
    DISCV5_INVALID_PACKET = 6,
    DISCV5_DECRYPT_FAIL = 7,
    DISCV5_OS_ERROR = 8,
};

/* Sizes. */
#define DISCV5_ENR_SCRATCH 10240
#define DISCV5_ENR_SIZE 3208
#define DISCV5_HDR_SIZE 1064
#define DISCV5_CFG_SIZE 112
#define DISCV5_TICK_SIZE 40
#define DISCV5_SCRATCH_SIZE 65536
#define DISCV5_ACTIONS_BASE 32768
#define DISCV5_ACTIONS_PER_EVENT 16384
#define DISCV5_NODE_SLOTS 442
#define DISCV5_N_SIZE 448
#define DISCV5_SESSION_SLOTS 256
#define DISCV5_S_SIZE 112
#define DISCV5_CHALLENGE_SLOTS 32
#define DISCV5_C_SIZE 136
#define DISCV5_REQUEST_SLOTS 32
#define DISCV5_R_SIZE 152
#define DISCV5_LOOKUP_SLOTS 4
#define DISCV5_L_SIZE (56 + 16 * 112)
#define DISCV5_ST_NODES 2056
#define DISCV5_STATE_SIZE                                                                                         \
    (DISCV5_ST_NODES + DISCV5_NODE_SLOTS * DISCV5_N_SIZE + DISCV5_SESSION_SLOTS * DISCV5_S_SIZE +                 \
     DISCV5_CHALLENGE_SLOTS * DISCV5_C_SIZE + DISCV5_REQUEST_SLOTS * DISCV5_R_SIZE + DISCV5_LOOKUP_SLOTS * DISCV5_L_SIZE)

/* Event and action kinds. */
enum { EV_DATAGRAM = 1, EV_ADD_NODE = 2, EV_LOOKUP = 3, EV_SET_ENDPOINT = 4, EV_SET_ENTRY = 5 };
enum { ACT_SEND = 1, ACT_NODE_FOUND = 2, ACT_LOOKUP_DONE = 3, ACT_ENDPOINT = 4, ACT_RECORD = 5, ACT_WAKEUP = 6 };

/* Core functions. */
DISCV5_ABI uint64_t discv5_init(const void *config, void *state);
DISCV5_ABI uint64_t discv5_step(void *state, const void *tick, const void *events, void *scratch, void *actions);
DISCV5_ABI uint64_t discv5_local_record(const void *state, void *record);
DISCV5_ABI uint64_t discv5_enr_decode(const void *record, void *scratch, void *enr);
DISCV5_ABI uint64_t discv5_enr_text_decode(const void *text, void *record);
DISCV5_ABI uint64_t discv5_packet_decode(const void *packet, const void *local_id, void *header);
DISCV5_ABI uint64_t discv5_message_decrypt(const void *header, const void *key, const void *packet, void *message);
DISCV5_ABI uint64_t discv5_packet_encode(void *header, const void *dest_id, const void *key, const void *message,
                                         void *packet);
DISCV5_ABI uint64_t discv5_derive_keys(const void *private_key, const void *public_key, const void *challenge,
                                       const void *ids, void *keys);
DISCV5_ABI uint64_t discv5_id_sign(const void *private_key, const void *challenge, const void *ephemeral_key,
                                   const void *dest_id, void *signature);
DISCV5_ABI uint64_t discv5_id_verify(const void *public_key, const void *challenge, const void *header,
                                     const void *dest_id, void *valid);

enum {
    F_INIT,
    F_STEP,
    F_LOCAL_RECORD,
    F_ENR_DECODE,
    F_ENR_TEXT,
    F_PACKET_DECODE,
    F_DECRYPT,
    F_PACKET_ENCODE,
    F_DERIVE,
    F_ID_SIGN,
    F_ID_VERIFY,
    F_COUNT
};

static const char *const fn_name[F_COUNT] = {
    "discv5_init",          "discv5_step",           "discv5_local_record",    "discv5_enr_decode",
    "discv5_enr_text_decode", "discv5_packet_decode", "discv5_message_decrypt", "discv5_packet_encode",
    "discv5_derive_keys",   "discv5_id_sign",        "discv5_id_verify",
};

static const void *const fn_address[F_COUNT] = {
    (const void *)discv5_init,          (const void *)discv5_step,           (const void *)discv5_local_record,
    (const void *)discv5_enr_decode,    (const void *)discv5_enr_text_decode, (const void *)discv5_packet_decode,
    (const void *)discv5_message_decrypt, (const void *)discv5_packet_encode, (const void *)discv5_derive_keys,
    (const void *)discv5_id_sign,       (const void *)discv5_id_verify,
};

/* Call function fn through abi_call (runner.c). */
uint64_t checked_call(int fn, const void *const *args, size_t n);
#define CALL(fn, ...)                                                                                              \
    checked_call(fn, (const void *const[]){__VA_ARGS__}, sizeof((const void *const[]){__VA_ARGS__}) / sizeof(void *))

/* Buffers. */
#define GUARD 16
#define FILL 0x5A

typedef struct {
    uint8_t *p, *copy;
    size_t n;
} input;

typedef struct {
    uint8_t *base, *p;
    size_t n;
} output;

typedef struct {
    const uint8_t *p, *end;
    const char *name;
} cursor;

typedef struct {
    const uint8_t *p;
    uint64_t n;
} blob;

uint64_t rd64(const uint8_t *p);
void wr64(uint8_t *p, uint64_t v);
void *xmalloc(size_t n);
input in_bytes(const uint8_t *b, size_t n, size_t room);
input in_list(const uint8_t *b, uint64_t len);
int in_done(input *r);
output out_new(size_t n);
output out_sized(size_t n);
int out_guards(output *r);
int out_list_is(output *r, const uint8_t *want, uint64_t n);
void out_free(output *r);
const uint8_t *take(cursor *c, uint64_t n);
uint64_t take64(cursor *c);
blob take_blob(cursor *c);
int note(int fn, int ok, const char *file, const char *name);

/* step.c */
int case_step(cursor *c, const char *name);

#endif
