/*
 * discv5_step cases. Test code: the library itself is assembly.
 *
 * record:    local record changes, against records geth signs.
 * nodes:     three nodes on a simulated network discover each other.
 * errors:    calls that must fail leave the state unchanged.
 * challenge: WHOAREYOU for packets without a session, sent again unchanged.
 *
 * Every step goes through CALL, so the stack cap and ABI checks cover it, and
 * every action list it returns must be well formed and end with WAKEUP.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "discv5.h"

#define ST_NODE_ID 72
#define ST_SEQ 104
#define ST_NOW 152

enum { SUB_RECORD = 1, SUB_NODES = 2, SUB_ERRORS = 3, SUB_CHALLENGE = 4 };

static const char *FILE_NAME = "step.bin";

/* ---------------------------------------------------------------- Steps */

typedef struct {
    uint8_t *p;
    size_t n;
} buf;

/* An events list being built. */
typedef struct {
    uint8_t *p;
    size_t cap, used, count;
} evlist;

static evlist ev_new(size_t cap) {
    evlist e = {xmalloc(cap + 24), cap + 24, 0, 0};
    return e;
}

static uint8_t *ev_add(evlist *e, uint64_t kind, size_t size) {
    if (24 + e->used + size > e->cap) {
        size_t cap = 2 * e->cap + size;
        uint8_t *p = xmalloc(cap);
        memcpy(p, e->p, e->cap);
        free(e->p);
        e->p = p;
        e->cap = cap;
    }
    uint8_t *v = e->p + 24 + e->used;
    memset(v, 0, size);
    wr64(v, size);
    wr64(v + 8, kind);
    e->used += size;
    e->count++;
    return v;
}

static void ev_clear(evlist *e) {
    e->used = 0;
    e->count = 0;
}

/* The events as an input: a list with its exact size. */
static input ev_input(evlist *e) {
    wr64(e->p, 24 + e->used);
    wr64(e->p + 8, 24);
    wr64(e->p + 16, e->used);
    return in_bytes(e->p, 24 + e->used, 0);
}

static void tick_of(uint8_t tick[DISCV5_TICK_SIZE], uint64_t now, uint64_t salt) {
    wr64(tick, now);
    for (int i = 0; i < 32; i++)
        tick[8 + i] = (uint8_t)(salt * 131 + (uint64_t)i * 17 + (now >> (i % 8)));
}

/* The actions of the last good step. */
static uint8_t *last_actions;
static size_t last_actions_n;

/* Well formed: offset 24, sizes multiples of 8 that sum to the count, known kinds, WAKEUP last and only there. */
static int actions_ok(const uint8_t *a, size_t cap) {
    if (rd64(a + 8) != 24 || rd64(a + 16) > cap - 24)
        return 0;
    size_t off = 0, n = rd64(a + 16);
    int wakeups = 0;
    uint64_t last = 0;
    while (off < n) {
        const uint8_t *v = a + 24 + off;
        uint64_t size = rd64(v), kind = rd64(v + 8);
        if (size < 16 || size % 8 || size > n - off || kind < 1 || kind > 6)
            return 0;
        if (kind == ACT_SEND && (rd64(v + 48) > 1280 || 56 + rd64(v + 48) > size))
            return 0;
        wakeups += kind == ACT_WAKEUP;
        last = kind;
        off += size;
    }
    return off == n && wakeups == 1 && last == ACT_WAKEUP;
}

/*
 * One step: events as an exact input, scratch of its exact size, actions of
 * exactly the room the README asks for. Returns the status; on 0 the actions
 * are in last_actions.
 */
static uint64_t step(uint8_t *state, uint64_t now, uint64_t salt, evlist *e, int *ok) {
    uint8_t tickv[DISCV5_TICK_SIZE];
    tick_of(tickv, now, salt);
    input t = in_bytes(tickv, sizeof tickv, 0);
    input ev = ev_input(e);
    output sc = out_sized(DISCV5_SCRATCH_SIZE);
    size_t cap = 24 + DISCV5_ACTIONS_BASE + e->count * DISCV5_ACTIONS_PER_EVENT;
    output act = out_sized(cap);
    uint64_t status = CALL(F_STEP, state, t.p, ev.p, sc.p, act.p);
    *ok &= in_done(&t) && in_done(&ev) && out_guards(&sc) && out_guards(&act);
    if (status == DISCV5_OK) {
        *ok &= actions_ok(act.p, cap);
        free(last_actions);
        last_actions_n = 24 + rd64(act.p + 16);
        last_actions = xmalloc(last_actions_n);
        memcpy(last_actions, act.p, last_actions_n);
    }
    out_free(&sc);
    out_free(&act);
    return status;
}

/* The next action of a kind after *at in last_actions, or NULL. */
static const uint8_t *next_action(uint64_t kind, size_t *at) {
    while (*at < last_actions_n - 24) {
        const uint8_t *v = last_actions + 24 + *at;
        *at += rd64(v);
        if (rd64(v + 8) == kind)
            return v;
    }
    return NULL;
}

static int count_actions(uint64_t kind) {
    size_t at = 0;
    int n = 0;
    while (next_action(kind, &at))
        n++;
    return n;
}

static uint64_t wakeup_at(void) {
    size_t at = 0;
    const uint8_t *w = next_action(ACT_WAKEUP, &at);
    return w ? rd64(w + 16) : 0;
}

/* A node from a config: key, seq, now, endpoint. Returns the init status. */
static uint64_t node_init(uint8_t *state, const uint8_t *key, uint64_t seq, uint64_t now, uint64_t port,
                          uint64_t family, const uint8_t *addr) {
    uint8_t cfg[DISCV5_CFG_SIZE];
    memset(cfg, 0, sizeof cfg);
    memcpy(cfg, key, 32);
    wr64(cfg + 32, seq);
    for (int i = 0; i < 32; i++)
        cfg[40 + i] = (uint8_t)(key[i] ^ (i * 29));
    wr64(cfg + 72, now);
    wr64(cfg + 80, port);
    wr64(cfg + 88, family);
    if (addr)
        memcpy(cfg + 96, addr, 16);
    return CALL(F_INIT, cfg, state);
}

static size_t local_record(const uint8_t *state, uint8_t *out) {
    uint8_t r[24 + 304];
    wr64(r, sizeof r);
    if (CALL(F_LOCAL_RECORD, state, r))
        return 0;
    memcpy(out, r + 24, rd64(r + 16));
    return rd64(r + 16);
}

/* ---------------------------------------------------------------- record */

static int case_record(cursor *c, const char *name) {
    const uint8_t *key = take(c, 32);
    uint64_t seq = take64(c), port = take64(c), family = take64(c);
    const uint8_t *addr = take(c, 16);
    uint64_t n = take64(c);
    uint8_t *state = xmalloc(DISCV5_STATE_SIZE), *copy = xmalloc(DISCV5_STATE_SIZE);
    int ok = node_init(state, key, seq, 1000, port, family, addr) == DISCV5_OK;
    evlist e = ev_new(256);
    for (uint64_t i = 0; i < n; i++) {
        blob ev = take_blob(c);
        uint64_t want = take64(c);
        blob rec = take_blob(c);
        ev_clear(&e);
        uint8_t *v = ev_add(&e, rd64(ev.p + 8), (size_t)ev.n);
        memcpy(v, ev.p, (size_t)ev.n);
        memcpy(copy, state, DISCV5_STATE_SIZE);
        uint64_t status = step(state, 2000 + 10 * i, i, &e, &ok);
        ok &= status == want;
        if (status != DISCV5_OK) {
            ok &= memcmp(copy, state, DISCV5_STATE_SIZE) == 0;
            continue;
        }
        size_t at = 0;
        const uint8_t *r = next_action(ACT_RECORD, &at);
        if (rec.n == 0) {
            ok &= r == NULL && rd64(state + ST_SEQ) == rd64(copy + ST_SEQ);
        } else {
            ok &= r && rd64(r + 16) == rec.n && memcmp(r + 24, rec.p, (size_t)rec.n) == 0 &&
                  rd64(r) == ((24 + rec.n + 7) & ~(uint64_t)7);
            uint8_t now[304];
            ok &= local_record(state, now) == rec.n && memcmp(now, rec.p, (size_t)rec.n) == 0;
        }
    }
    free(e.p);
    free(state);
    free(copy);
    return note(F_STEP, ok, FILE_NAME, name);
}

/* ---------------------------------------------------------------- nodes */

#define NODES 3

typedef struct {
    uint8_t *state;
    uint8_t ep[32];
    uint8_t id[32];
    uint8_t rec[304];
    size_t rec_n;
    evlist in;
    uint64_t wake;
} sim_node;

static void add_record_event(evlist *e, const uint8_t *rec, size_t n) {
    uint8_t *v = ev_add(e, EV_ADD_NODE, (24 + n + 7) & ~(size_t)7);
    wr64(v + 16, n);
    memcpy(v + 24, rec, n);
}

/*
 * A and C know only B. B learns A and C from their handshakes and checks
 * them. Then C looks up A's node ID: B must give C A's record. A must also
 * hear from B, in a PONG, the endpoint B saw.
 */
static int case_nodes(cursor *c, const char *name) {
    sim_node nd[NODES];
    int ok = 1;
    for (int i = 0; i < NODES; i++) {
        const uint8_t *key = take(c, 32);
        uint8_t addr[16] = {10, 0, 0, (uint8_t)(1 + i)};
        sim_node *s = &nd[i];
        s->state = xmalloc(DISCV5_STATE_SIZE);
        ok &= node_init(s->state, key, 1, 1000, 30001 + i, 4, addr) == DISCV5_OK;
        memset(s->ep, 0, 32);
        wr64(s->ep, 30001 + i);
        wr64(s->ep + 8, 4);
        memcpy(s->ep + 16, addr, 4);
        memcpy(s->id, s->state + ST_NODE_ID, 32);
        s->rec_n = local_record(s->state, s->rec);
        ok &= s->rec_n > 0;
        s->in = ev_new(4096);
        s->wake = 0;
    }
    add_record_event(&nd[0].in, nd[1].rec, nd[1].rec_n);
    add_record_event(&nd[2].in, nd[1].rec, nd[1].rec_n);
    int found = 0, done = 0, endpoint = 0, lookup_sent = 0;
    for (uint64_t now = 1000; now <= 30000 && ok; now += 10) {
        if (now >= 6000 && !lookup_sent) {
            uint8_t *v = ev_add(&nd[2].in, EV_LOOKUP, 48);
            memcpy(v + 16, nd[0].id, 32);
            lookup_sent = 1;
        }
        for (int i = 0; i < NODES && ok; i++) {
            sim_node *s = &nd[i];
            if (s->in.count == 0 && now < s->wake)
                continue;
            ok &= step(s->state, now, (uint64_t)i * 1000003 + now, &s->in, &ok) == DISCV5_OK;
            if (!ok)
                break;
            ev_clear(&s->in);
            s->wake = wakeup_at();
            ok &= s->wake > now;
            size_t at = 0;
            const uint8_t *v;
            while ((v = next_action(ACT_SEND, &at))) {
                for (int j = 0; j < NODES; j++) {
                    if (memcmp(v + 16, nd[j].ep, 32))
                        continue;
                    uint64_t len = rd64(v + 48);
                    uint8_t *d = ev_add(&nd[j].in, EV_DATAGRAM, (56 + len + 7) & ~(uint64_t)7);
                    memcpy(d + 16, s->ep, 32);
                    wr64(d + 48, len);
                    memcpy(d + 56, v + 56, (size_t)len);
                }
            }
            at = 0;
            while ((v = next_action(ACT_NODE_FOUND, &at)))
                if (i == 2 && memcmp(v + 16, nd[0].id, 32) == 0)
                    found |= rd64(v + 48) == nd[0].rec_n && memcmp(v + 56, nd[0].rec, nd[0].rec_n) == 0;
            at = 0;
            while ((v = next_action(ACT_LOOKUP_DONE, &at)))
                if (i == 2 && memcmp(v + 16, nd[0].id, 32) == 0)
                    done = rd64(v + 48) >= 1 ? 1 : -1;
            at = 0;
            while ((v = next_action(ACT_ENDPOINT, &at)))
                if (i == 0 && memcmp(v + 16, nd[0].ep, 32) == 0 && memcmp(v + 48, nd[1].id, 32) == 0)
                    endpoint = 1;
        }
    }
    if (ok && !(found && done == 1 && endpoint))
        fprintf(stderr, "%s: %s: found %d, done %d, endpoint %d\n", FILE_NAME, name, found, done, endpoint);
    ok &= found && done == 1 && endpoint;
    for (int i = 0; i < NODES; i++) {
        free(nd[i].state);
        free(nd[i].in.p);
    }
    return note(F_STEP, ok, FILE_NAME, name);
}

/* ---------------------------------------------------------------- errors */

/* The step fails with want and leaves the state unchanged. */
static int fails(uint8_t *state, evlist *e, uint64_t want, const char *what) {
    uint8_t *copy = xmalloc(DISCV5_STATE_SIZE);
    memcpy(copy, state, DISCV5_STATE_SIZE);
    int ok = 1;
    uint64_t status = step(state, rd64(state + ST_NOW) + 100, 7, e, &ok);
    ok &= status == want && memcmp(copy, state, DISCV5_STATE_SIZE) == 0;
    if (!ok)
        fprintf(stderr, "%s: errors: %s: status %llu\n", FILE_NAME, what, (unsigned long long)status);
    free(copy);
    return ok;
}

/* A step with scratch or action room one byte short. */
static int short_buffers(uint8_t *state, evlist *e) {
    int ok = 1;
    uint8_t *copy = xmalloc(DISCV5_STATE_SIZE);
    for (int which = 0; which < 2; which++) {
        memcpy(copy, state, DISCV5_STATE_SIZE);
        uint8_t tickv[DISCV5_TICK_SIZE];
        tick_of(tickv, rd64(state + ST_NOW) + 100, 3);
        input ev = ev_input(e);
        output sc = out_sized(DISCV5_SCRATCH_SIZE - (which == 0));
        output act = out_sized(24 + DISCV5_ACTIONS_BASE + e->count * DISCV5_ACTIONS_PER_EVENT - (which == 1));
        uint64_t status = CALL(F_STEP, state, tickv, ev.p, sc.p, act.p);
        ok &= status == DISCV5_BUFFER_TOO_SMALL && memcmp(copy, state, DISCV5_STATE_SIZE) == 0;
        ok &= in_done(&ev) && out_guards(&sc) && out_guards(&act);
        out_free(&sc);
        out_free(&act);
    }
    free(copy);
    return ok;
}

static int case_errors(cursor *c, const char *name) {
    const uint8_t *key = take(c, 32);
    uint8_t addr[16] = {10, 0, 0, 9};
    uint8_t *state = xmalloc(DISCV5_STATE_SIZE);
    int ok = node_init(state, key, 1, 1000, 30009, 4, addr) == DISCV5_OK;
    evlist e = ev_new(4096);
    ok &= step(state, 1500, 1, &e, &ok) == DISCV5_OK && count_actions(ACT_WAKEUP) == 1 && last_actions_n == 24 + 24 &&
          wakeup_at() == 2000;

    /* Scratch and action room. */
    ok &= short_buffers(state, &e);
    uint8_t *v = ev_add(&e, EV_LOOKUP, 48);
    memset(v + 16, 7, 32);
    ok &= short_buffers(state, &e);

    /* Events that break the rules. */
    struct {
        uint64_t kind, size, at, value;
        const char *what;
    } bad[] = {
        {0, 48, 0, 0, "kind 0"},
        {9, 48, 0, 0, "kind 9"},
        {EV_LOOKUP, 40, 0, 0, "LOOKUP too small"},
        {EV_LOOKUP, 52, 0, 0, "size not a multiple of 8"},
        {EV_DATAGRAM, 56 + 1288, 48, 1281, "DATAGRAM over 1280 bytes"},
        {EV_DATAGRAM, 64, 48, 9, "DATAGRAM longer than its event"},
        {EV_DATAGRAM, 64, 24, 5, "DATAGRAM family 5"},
        {EV_ADD_NODE, 32, 16, 9, "ADD_NODE longer than its event"},
        {EV_SET_ENDPOINT, 48, 16, 65536, "SET_ENDPOINT port 65536"},
        {EV_SET_ENDPOINT, 48, 24, 0, "SET_ENDPOINT family 0"},
        {EV_SET_ENTRY, 56, 16, 0, "SET_ENTRY key length 0"},
        {EV_SET_ENTRY, 56, 16, 17, "SET_ENTRY key length 17"},
        {EV_SET_ENTRY, 120, 40, 65, "SET_ENTRY value length 65"},
        {EV_SET_ENTRY, 56, 40, 9, "SET_ENTRY value longer than its event"},
        {6, 48, 0, 0, "OPENED too small"},
        {8, 16, 0, 0, "IDLE too small"},
    };
    for (size_t i = 0; i < sizeof bad / sizeof bad[0]; i++) {
        for (int after_good = 0; after_good < 2; after_good++) {
            ev_clear(&e);
            if (after_good) {
                uint8_t *g = ev_add(&e, EV_LOOKUP, 48);
                memset(g + 16, 1, 32);
            }
            v = ev_add(&e, bad[i].kind, bad[i].size);
            if (bad[i].kind == EV_DATAGRAM || bad[i].kind == EV_SET_ENDPOINT)
                wr64(v + 24, 4), wr64(v + 16, 30000);
            if (bad[i].kind == EV_SET_ENTRY)
                wr64(v + 16, 3), memcpy(v + 24, "abc", 3);
            if (bad[i].at)
                wr64(v + bad[i].at, bad[i].value);
            ok &= fails(state, &e, DISCV5_INVALID_EVENT, bad[i].what);
        }
    }
    const char *owned[] = {"id", "secp256k1", "ip", "udp", "ip6", "udp6"};
    for (size_t i = 0; i < 6; i++) {
        ev_clear(&e);
        v = ev_add(&e, EV_SET_ENTRY, 56);
        wr64(v + 16, strlen(owned[i]));
        memcpy(v + 24, owned[i], strlen(owned[i]));
        wr64(v + 40, 1);
        ok &= fails(state, &e, DISCV5_INVALID_EVENT, owned[i]);
    }
    ev_clear(&e);
    v = ev_add(&e, EV_LOOKUP, 48);
    wr64(e.p + 24, 56); /* the event passes the end of the list */
    ok &= fails(state, &e, DISCV5_INVALID_EVENT, "event past the list");
    ev_clear(&e);
    ev_add(&e, EV_LOOKUP, 48);
    e.used -= 8; /* a list that ends inside the event */
    ok &= fails(state, &e, DISCV5_INVALID_EVENT, "list ends inside an event");

    /* Well formed but useless: nothing to do but WAKEUP. */
    ev_clear(&e);
    uint64_t lens[] = {0, 10, 62, 63, 100, 1280};
    for (size_t i = 0; i < 6; i++) {
        v = ev_add(&e, EV_DATAGRAM, (56 + lens[i] + 7) & ~(uint64_t)7);
        wr64(v + 16, 40000);
        wr64(v + 24, 4);
        wr64(v + 48, lens[i]);
        for (uint64_t k = 0; k < lens[i]; k++)
            v[56 + k] = (uint8_t)(k * 13 + i);
    }
    v = ev_add(&e, 6, 56);
    v = ev_add(&e, 7, 24);
    v = ev_add(&e, 8, 24);
    wr64(v + 16, 4);
    v = ev_add(&e, EV_ADD_NODE, 32);
    wr64(v + 16, 3);
    ok &= step(state, 1600, 2, &e, &ok) == DISCV5_OK && last_actions_n == 24 + 24 && wakeup_at() == 2000;

    /* The time never goes back. */
    ev_clear(&e);
    ok &= step(state, 1200, 3, &e, &ok) == DISCV5_OK && rd64(state + ST_NOW) == 1600;
    free(e.p);
    free(state);
    return note(F_STEP, ok, FILE_NAME, name);
}

/* ---------------------------------------------------------------- challenge */

/* A packet from node x (ID xid) to the node with a random nonce and a 20-byte message under a random key. */
static size_t random_packet(const uint8_t *xid, const uint8_t *dest, uint64_t salt, uint8_t nonce[12], uint8_t *out) {
    uint8_t *h = xmalloc(DISCV5_HDR_SIZE);
    for (int i = 0; i < 16; i++)
        h[i] = (uint8_t)(salt * 3 + i);
    for (int i = 0; i < 12; i++)
        nonce[i] = h[16 + i] = (uint8_t)(salt * 7 + i * 11);
    wr64(h + 32, 0);
    memcpy(h + 40, xid, 32);
    uint8_t key[16], msg[24 + 8], pkt[24 + 1280];
    for (int i = 0; i < 16; i++)
        key[i] = (uint8_t)(salt + i);
    wr64(msg, sizeof msg);
    wr64(msg + 8, 24);
    wr64(msg + 16, 4);
    memcpy(msg + 24, "\x01\x02\x03\x04", 4);
    wr64(pkt, sizeof pkt);
    size_t n = 0;
    if (CALL(F_PACKET_ENCODE, h, dest, key, msg, pkt) == DISCV5_OK) {
        n = rd64(pkt + 16);
        memcpy(out, pkt + 24, n);
    }
    free(h);
    return n;
}

/* The WHOAREYOU sent to x in last_actions: checks it and copies its 63 bytes. */
static int whoareyou_to(const uint8_t *xep, const uint8_t *xid, const uint8_t nonce[12], uint8_t out[63]) {
    size_t at = 0;
    const uint8_t *v = next_action(ACT_SEND, &at);
    if (!v || next_action(ACT_SEND, &at) || memcmp(v + 16, xep, 32) || rd64(v + 48) != 63)
        return 0;
    memcpy(out, v + 56, 63);
    uint8_t pkt[24 + 64], *h = xmalloc(DISCV5_HDR_SIZE);
    wr64(pkt, sizeof pkt);
    wr64(pkt + 8, 24);
    wr64(pkt + 16, 63);
    memcpy(pkt + 24, out, 63);
    int ok = CALL(F_PACKET_DECODE, pkt, xid, h) == DISCV5_OK && rd64(h + 32) == 1 && memcmp(h + 16, nonce, 12) == 0;
    free(h);
    return ok;
}

static int case_challenge(cursor *c, const char *name) {
    const uint8_t *key = take(c, 32), *xkey = take(c, 32);
    uint8_t addr[16] = {10, 0, 0, 7};
    uint8_t *state = xmalloc(DISCV5_STATE_SIZE), *xstate = xmalloc(DISCV5_STATE_SIZE);
    int ok = node_init(state, key, 1, 1000, 30007, 4, addr) == DISCV5_OK;
    ok &= node_init(xstate, xkey, 1, 1000, 0, 0, NULL) == DISCV5_OK;
    const uint8_t *id = state + ST_NODE_ID, *xid = xstate + ST_NODE_ID;
    uint8_t xep[32] = {0};
    wr64(xep, 41000);
    wr64(xep + 8, 4);
    memcpy(xep + 16, "\x0a\x00\x00\x08", 4);
    evlist e = ev_new(4096);
    uint8_t pkt[1280], nonce[12], first_nonce[12], w1[63], w2[63];
    uint64_t times[] = {1100, 1500, 2200};
    for (int k = 0; k < 3; k++) {
        size_t n = random_packet(xid, id, (uint64_t)k + 1, nonce, pkt);
        ok &= n == 16 + 23 + 32 + 20;
        if (k == 0)
            memcpy(first_nonce, nonce, 12);
        ev_clear(&e);
        uint8_t *v = ev_add(&e, EV_DATAGRAM, (56 + n + 7) & ~(size_t)7);
        memcpy(v + 16, xep, 32);
        wr64(v + 48, n);
        memcpy(v + 56, pkt, n);
        ok &= step(state, times[k], (uint64_t)k, &e, &ok) == DISCV5_OK;
        if (k == 0) {
            ok &= whoareyou_to(xep, xid, nonce, w1);
        } else if (k == 1) {
            /* Within 1 s: the same WHOAREYOU, for the first packet's nonce. */
            ok &= whoareyou_to(xep, xid, first_nonce, w2) && memcmp(w1, w2, 63) == 0;
        } else {
            /* After 1 s: a new one for this packet. */
            ok &= whoareyou_to(xep, xid, nonce, w2) && memcmp(w1, w2, 63) != 0;
        }
    }
    free(e.p);
    free(state);
    free(xstate);
    return note(F_STEP, ok, FILE_NAME, name);
}

/* ---------------------------------------------------------------- Dispatch */

int case_step(cursor *c, const char *name) {
    switch (take64(c)) {
    case SUB_RECORD: return case_record(c, name);
    case SUB_NODES: return case_nodes(c, name);
    case SUB_ERRORS: return case_errors(c, name);
    case SUB_CHALLENGE: return case_challenge(c, name);
    default: fprintf(stderr, "%s: %s: unknown step case\n", FILE_NAME, name); exit(2);
    }
}
