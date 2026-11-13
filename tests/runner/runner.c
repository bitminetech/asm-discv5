/*
 * Vector runner for asm-discv5. Test code: the library itself is assembly.
 *
 * Usage: runner VECTOR_DIR [FILE ...]
 *
 * Reads the case files that tests/generator/ writes (format in its README),
 * calls the library for every case and compares the results. With no FILE
 * arguments it runs every file. It exits with status 0 only when every case
 * of every file it ran passes.
 *
 * Inputs sit in buffers of their exact size and must stay unchanged. Outputs
 * have guard bytes on both sides. ByteList outputs and scratch buffers get
 * exactly the size the function needs; one byte less must give
 * DISCV5_BUFFER_TOO_SMALL.
 *
 * Every call goes through abi_call (tests/runner/abi_<ISA>.s). The runner
 * prints the most stack each function used, and fails when a call uses more
 * than the README cap or changes state that the ABI says it must keep.
 */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "discv5.h"

#define STACK_CAP 16384 /* README: stack per call */
#define PAINT_BYTES (STACK_CAP + 4096)

typedef struct {
    uint64_t fn, arg[5], paint, status, fault, stack, scratch[4];
} abi_ctx;
DISCV5_ABI void abi_call(abi_ctx *ctx);

static uint64_t stack_peak[F_COUNT], abi_fault[F_COUNT], fn_cases[F_COUNT], fn_bad[F_COUNT];

uint64_t checked_call(int fn, const void *const *args, size_t n) {
    abi_ctx c;
    memset(&c, 0, sizeof c);
    c.fn = (uint64_t)(uintptr_t)fn_address[fn];
    for (size_t i = 0; i < n; i++) c.arg[i] = (uint64_t)(uintptr_t)args[i];
    c.paint = PAINT_BYTES;
    abi_call(&c);
    if (c.stack > stack_peak[fn]) stack_peak[fn] = c.stack;
    abi_fault[fn] |= c.fault;
    return c.status;
}

/* ---------------------------------------------------------------- Buffers */

uint64_t rd64(const uint8_t *p) {
    uint64_t v = 0;
    for (int i = 7; i >= 0; i--) v = (v << 8) | p[i];
    return v;
}

void wr64(uint8_t *p, uint64_t v) {
    for (int i = 0; i < 8; i++) p[i] = (uint8_t)(v >> (8 * i));
}

void *xmalloc(size_t n) {
    void *p = calloc(1, n ? n : 1);
    if (!p) {
        fprintf(stderr, "out of memory\n");
        exit(2);
    }
    return p;
}

input in_bytes(const uint8_t *b, size_t n, size_t room) {
    input r = {xmalloc(n + room), xmalloc(n + room), n + room};
    memset(r.p, 0xA5, n + room);
    memcpy(r.p, b, n);
    memcpy(r.copy, r.p, n + room);
    return r;
}

input in_list(const uint8_t *b, uint64_t len) {
    size_t size = (size_t)(32 + len + 7);
    input r = {xmalloc(size), xmalloc(size), size};
    memset(r.p, 0xA5, size);
    wr64(r.p, size);
    wr64(r.p + 8, 32);
    wr64(r.p + 16, len);
    if (len) memcpy(r.p + 32, b, (size_t)len);
    memcpy(r.copy, r.p, size);
    return r;
}

int in_done(input *r) {
    int ok = memcmp(r->p, r->copy, r->n) == 0;
    free(r->p);
    free(r->copy);
    return ok;
}

output out_new(size_t n) {
    output r;
    r.base = xmalloc(n + 2 * GUARD);
    r.p = r.base + GUARD;
    r.n = n;
    memset(r.base, FILL, n + 2 * GUARD);
    return r;
}

output out_sized(size_t n) {
    output r = out_new(n);
    wr64(r.p, n);
    return r;
}

int out_guards(output *r) {
    int ok = 1;
    for (int i = 0; i < GUARD; i++) ok &= r->base[i] == FILL && r->p[r->n + i] == FILL;
    return ok;
}

int out_list_is(output *r, const uint8_t *want, uint64_t n) {
    return out_guards(r) && rd64(r->p) == r->n && rd64(r->p + 8) == 24 && rd64(r->p + 16) == n &&
           (n == 0 || memcmp(r->p + 24, want, (size_t)n) == 0);
}

void out_free(output *r) { free(r->base); }

const uint8_t *take(cursor *c, uint64_t n) {
    if ((uint64_t)(c->end - c->p) < n) {
        fprintf(stderr, "%s: file ends early\n", c->name);
        exit(2);
    }
    const uint8_t *r = c->p;
    c->p += n;
    return r;
}

uint64_t take64(cursor *c) { return rd64(take(c, 8)); }

blob take_blob(cursor *c) {
    blob b;
    b.n = take64(c);
    b.p = take(c, b.n);
    return b;
}

int note(int fn, int ok, const char *file, const char *name) {
    fn_cases[fn]++;
    if (!ok) {
        if (fn_bad[fn] < 8) fprintf(stderr, "%s: %s: %s fails\n", file, name, fn_name[fn]);
        fn_bad[fn]++;
    }
    return ok;
}

/* ---------------------------------------------------------------- Codec cases */

static int case_enr(cursor *c, const char *name) {
    blob rec = take_blob(c);
    uint64_t want = take64(c);
    const uint8_t *fields = NULL;
    blob pairs = {0, 0};
    if (want == DISCV5_OK) {
        fields = take(c, 136);
        pairs = take_blob(c);
    }
    int ok = 1;
    for (int small = 0; small < 2; small++) {
        input r = in_list(rec.p, rec.n);
        output s = out_sized(DISCV5_ENR_SCRATCH - small), e = out_new(DISCV5_ENR_SIZE);
        uint64_t status = CALL(F_ENR_DECODE, r.p, s.p, e.p);
        if (small)
            ok &= status == DISCV5_BUFFER_TOO_SMALL;
        else {
            ok &= status == want && out_guards(&e) && out_guards(&s);
            if (status == DISCV5_OK && want == DISCV5_OK)
                ok &= memcmp(e.p, fields, 136) == 0 && memcmp(e.p + 136, pairs.p, (size_t)pairs.n) == 0;
        }
        ok &= in_done(&r);
        out_free(&s);
        out_free(&e);
    }
    return note(F_ENR_DECODE, ok, c->name, name);
}

static int case_text(cursor *c, const char *name) {
    blob text = take_blob(c);
    uint64_t want = take64(c);
    blob rec = take_blob(c);
    int ok = 1;
    for (int small = 0; small < 2; small++) {
        if (small && (want != DISCV5_OK)) break;
        input t = in_list(text.p, text.n);
        output r = out_sized((size_t)(24 + rec.n - small));
        uint64_t status = CALL(F_ENR_TEXT, t.p, r.p);
        if (small)
            ok &= status == DISCV5_BUFFER_TOO_SMALL && out_guards(&r);
        else if (want != DISCV5_OK)
            ok &= status == want && out_guards(&r);
        else
            ok &= status == DISCV5_OK && out_list_is(&r, rec.p, rec.n);
        ok &= in_done(&t);
        out_free(&r);
    }
    return note(F_ENR_TEXT, ok, c->name, name);
}

/* Fill a Header value from the vector fields. */
static void header_fill(uint8_t *h, uint64_t flag, const uint8_t *iv, const uint8_t *nonce, const uint8_t *src,
                        const uint8_t *idn, uint64_t seq, const uint8_t *sig, const uint8_t *eph, blob record) {
    memset(h, 0, DISCV5_HDR_SIZE);
    memcpy(h + 0, iv, 16);
    memcpy(h + 16, nonce, 12);
    wr64(h + 32, flag);
    memcpy(h + 40, src, 32);
    memcpy(h + 72, idn, 16);
    wr64(h + 88, seq);
    memcpy(h + 96, sig, 64);
    memcpy(h + 160, eph, 33);
    wr64(h + 200, 324);
    wr64(h + 208, 24);
    wr64(h + 216, record.n);
    memcpy(h + 224, record.p, (size_t)record.n);
}

static int case_packet(cursor *c, const char *name) {
    blob pkt = take_blob(c);
    const uint8_t *local = take(c, 32);
    uint64_t want = take64(c);
    uint64_t flag = take64(c);
    const uint8_t *iv = take(c, 16), *nonce = take(c, 12), *src = take(c, 32), *idn = take(c, 16);
    uint64_t seq = take64(c);
    const uint8_t *sig = take(c, 64), *eph = take(c, 40);
    blob record = take_blob(c), raw = take_blob(c);
    const uint8_t *key = take(c, 16);
    uint64_t dwant = take64(c);
    blob pt = take_blob(c);
    uint64_t encode = take64(c);

    /* Decode. */
    input p = in_list(pkt.p, pkt.n), id = in_bytes(local, 32, 0);
    output h = out_new(DISCV5_HDR_SIZE);
    uint64_t status = CALL(F_PACKET_DECODE, p.p, id.p, h.p);
    int ok = status == want && out_guards(&h);
    if (ok && want == DISCV5_OK) {
        ok &= rd64(h.p + 32) == flag && memcmp(h.p, iv, 16) == 0 && memcmp(h.p + 16, nonce, 12) == 0;
        if (flag != 1) ok &= memcmp(h.p + 40, src, 32) == 0;
        if (flag == 1) ok &= memcmp(h.p + 72, idn, 16) == 0 && rd64(h.p + 88) == seq;
        if (flag == 2)
            ok &= memcmp(h.p + 96, sig, 64) == 0 && memcmp(h.p + 160, eph, 33) == 0 && rd64(h.p + 216) == record.n &&
                  memcmp(h.p + 224, record.p, (size_t)record.n) == 0;
        ok &= rd64(h.p + 544) == raw.n && memcmp(h.p + 552, raw.p, (size_t)raw.n) == 0;
    }
    note(F_PACKET_DECODE, ok, c->name, name);

    /* Decrypt with the header just decoded. */
    if (want == DISCV5_OK && flag != 1) {
        input k = in_bytes(key, 16, 0), hd = in_bytes(h.p, DISCV5_HDR_SIZE, 0);
        output m = out_sized(24 + 1280);
        status = CALL(F_DECRYPT, hd.p, k.p, p.p, m.p);
        int dok = status == dwant && out_guards(&m);
        if (dok && dwant == DISCV5_OK) dok &= out_list_is(&m, pt.p, pt.n);
        dok &= in_done(&k) & in_done(&hd);
        out_free(&m);
        note(F_DECRYPT, dok, c->name, name);
    }
    ok = in_done(&p) & in_done(&id);
    out_free(&h);

    /* Encode from the fields. */
    if (encode) {
        int eok = ok;
        for (int small = 0; small < 2; small++) {
            output hh = out_new(DISCV5_HDR_SIZE);
            header_fill(hh.p, flag, iv, nonce, src, idn, seq, sig, eph, record);
            input d = in_bytes(local, 32, 0), k = in_bytes(key, 16, 0), m = in_list(pt.p, pt.n);
            output o = out_sized((size_t)(24 + pkt.n - small));
            status = CALL(F_PACKET_ENCODE, hh.p, d.p, k.p, m.p, o.p);
            if (small)
                eok &= status == DISCV5_BUFFER_TOO_SMALL && out_guards(&o);
            else
                eok &= status == DISCV5_OK && out_list_is(&o, pkt.p, pkt.n) && out_guards(&hh) &&
                       rd64(hh.p + 544) == raw.n && memcmp(hh.p + 552, raw.p, (size_t)raw.n) == 0;
            eok &= in_done(&d) & in_done(&k) & in_done(&m);
            out_free(&hh);
            out_free(&o);
        }
        note(F_PACKET_ENCODE, eok, c->name, name);
    }
    return 1;
}

static int case_derive(cursor *c, const char *name) {
    const uint8_t *priv = take(c, 32), *pub = take(c, 40), *ch = take(c, 64), *ids = take(c, 64);
    uint64_t want = take64(c);
    const uint8_t *keys = take(c, 32);
    input a = in_bytes(priv, 32, 0), b = in_bytes(pub, 33, 7), d = in_bytes(ch, 63, 1), e = in_bytes(ids, 64, 0);
    output o = out_new(32);
    uint64_t status = CALL(F_DERIVE, a.p, b.p, d.p, e.p, o.p);
    int ok = status == want && out_guards(&o) && (want != DISCV5_OK || memcmp(o.p, keys, 32) == 0);
    ok &= in_done(&a) & in_done(&b) & in_done(&d) & in_done(&e);
    out_free(&o);
    return note(F_DERIVE, ok, c->name, name);
}

static int case_sign(cursor *c, const char *name) {
    const uint8_t *priv = take(c, 32), *ch = take(c, 64), *eph = take(c, 40), *dest = take(c, 32);
    uint64_t want = take64(c);
    const uint8_t *sig = take(c, 64);
    input a = in_bytes(priv, 32, 0), b = in_bytes(ch, 63, 1), d = in_bytes(eph, 33, 7), e = in_bytes(dest, 32, 0);
    output o = out_new(64);
    uint64_t status = CALL(F_ID_SIGN, a.p, b.p, d.p, e.p, o.p);
    int ok = status == want && out_guards(&o) && (want != DISCV5_OK || memcmp(o.p, sig, 64) == 0);
    ok &= in_done(&a) & in_done(&b) & in_done(&d) & in_done(&e);
    out_free(&o);
    return note(F_ID_SIGN, ok, c->name, name);
}

static int case_verify(cursor *c, const char *name) {
    const uint8_t *pub = take(c, 40), *ch = take(c, 64), *eph = take(c, 40), *dest = take(c, 32), *sig = take(c, 64);
    uint64_t want = take64(c), valid = take64(c);
    uint8_t *hdr = xmalloc(DISCV5_HDR_SIZE);
    memcpy(hdr + 96, sig, 64);
    memcpy(hdr + 160, eph, 33);
    input a = in_bytes(pub, 33, 7), b = in_bytes(ch, 63, 1), h = in_bytes(hdr, DISCV5_HDR_SIZE, 0),
          e = in_bytes(dest, 32, 0);
    free(hdr);
    output o = out_new(8);
    uint64_t status = CALL(F_ID_VERIFY, a.p, b.p, h.p, e.p, o.p);
    int ok = status == want && out_guards(&o) && (want != DISCV5_OK || rd64(o.p) == valid);
    ok &= in_done(&a) & in_done(&b) & in_done(&h) & in_done(&e);
    out_free(&o);
    return note(F_ID_VERIFY, ok, c->name, name);
}

static int case_init(cursor *c, const char *name) {
    const uint8_t *key = take(c, 32);
    uint64_t seq = take64(c), port = take64(c), family = take64(c);
    const uint8_t *addr = take(c, 16);
    uint64_t want = take64(c);
    blob rec = take_blob(c);
    uint8_t cfg[DISCV5_CFG_SIZE];
    memset(cfg, 0, sizeof cfg);
    memcpy(cfg, key, 32);
    wr64(cfg + 32, seq);
    for (int i = 0; i < 32; i++) cfg[40 + i] = (uint8_t)(i * 7 + 1);
    wr64(cfg + 72, 1000);
    wr64(cfg + 80, port);
    wr64(cfg + 88, family);
    memcpy(cfg + 96, addr, 16);
    input k = in_bytes(cfg, sizeof cfg, 0);
    output st = out_new(DISCV5_STATE_SIZE);
    uint64_t status = CALL(F_INIT, k.p, st.p);
    int ok = status == want && out_guards(&st);
    if (ok && want == DISCV5_OK) {
        for (int small = 0; small < 2; small++) {
            input s = in_bytes(st.p, DISCV5_STATE_SIZE, 0);
            output r = out_sized((size_t)(24 + rec.n - small));
            status = CALL(F_LOCAL_RECORD, s.p, r.p);
            if (small)
                ok &= status == DISCV5_BUFFER_TOO_SMALL && out_guards(&r);
            else
                ok &= status == DISCV5_OK && out_list_is(&r, rec.p, rec.n);
            ok &= in_done(&s);
            out_free(&r);
        }
        note(F_LOCAL_RECORD, ok, c->name, name);
    }
    ok &= in_done(&k);
    out_free(&st);
    return note(F_INIT, ok, c->name, name);
}

/* ---------------------------------------------------------------- Files */

static uint8_t *read_file(const char *path, size_t *len) {
    FILE *f = fopen(path, "rb");
    if (!f) return NULL;
    fseek(f, 0, SEEK_END);
    long n = ftell(f);
    fseek(f, 0, SEEK_SET);
    uint8_t *data = malloc(n > 0 ? (size_t)n : 1);
    if (!data || fread(data, 1, (size_t)n, f) != (size_t)n) {
        fclose(f);
        free(data);
        return NULL;
    }
    fclose(f);
    *len = (size_t)n;
    return data;
}

static const char *ALL_FILES[] = {"enr.bin", "enr-text.bin", "packet.bin", "handshake.bin", "init.bin", "step.bin"};

static int run_file(const char *dir, const char *name) {
    char path[4096];
    snprintf(path, sizeof path, "%s/%s", dir, name);
    size_t len = 0;
    uint8_t *data = read_file(path, &len);
    if (!data) {
        fprintf(stderr, "%s: cannot read\n", path);
        return 1;
    }
    cursor c = {data, data + len, name};
    if (memcmp(take(&c, 8), "DISCV5V1", 8) != 0) {
        fprintf(stderr, "%s: wrong magic\n", name);
        exit(2);
    }
    uint64_t n = take64(&c);
    uint64_t before = 0;
    for (int f = 0; f < F_COUNT; f++) before += fn_bad[f];
    for (uint64_t k = 0; k < n; k++) {
        uint64_t kind = take64(&c);
        blob nm = take_blob(&c);
        char cname[256];
        snprintf(cname, sizeof cname, "%.*s", (int)(nm.n < 255 ? nm.n : 255), (const char *)nm.p);
        switch (kind) {
        case 1: case_enr(&c, cname); break;
        case 2: case_text(&c, cname); break;
        case 3: case_packet(&c, cname); break;
        case 4: case_derive(&c, cname); break;
        case 5: case_sign(&c, cname); break;
        case 6: case_verify(&c, cname); break;
        case 7: case_init(&c, cname); break;
        case 8: case_step(&c, cname); break;
        default:
            fprintf(stderr, "%s: unknown kind %llu\n", name, (unsigned long long)kind);
            exit(2);
        }
    }
    if (c.p != c.end) {
        fprintf(stderr, "%s: bytes left after the last case\n", name);
        exit(2);
    }
    uint64_t after = 0;
    for (int f = 0; f < F_COUNT; f++) after += fn_bad[f];
    printf("%s %s: %llu cases\n", after > before ? "FAIL" : "PASS", name, (unsigned long long)n);
    free(data);
    return after > before;
}

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "usage: runner VECTOR_DIR [FILE ...]\n");
        return 2;
    }
    int failed = 0;
    if (argc == 2) {
        for (size_t i = 0; i < sizeof ALL_FILES / sizeof ALL_FILES[0]; i++) failed |= run_file(argv[1], ALL_FILES[i]);
    } else {
        for (int i = 2; i < argc; i++) failed |= run_file(argv[1], argv[i]);
    }
    for (int f = 0; f < F_COUNT; f++) {
        if (!fn_cases[f]) continue;
        int over = stack_peak[f] > STACK_CAP;
        printf("%s stack %s: %llu bytes, cap %d\n", over ? "FAIL" : "PASS", fn_name[f],
               (unsigned long long)stack_peak[f], STACK_CAP);
        if (abi_fault[f])
            printf("FAIL abi %s: kept state changed, mask 0x%016llx\n", fn_name[f], (unsigned long long)abi_fault[f]);
        else
            printf("PASS abi %s: kept registers, stack pointer and flags\n", fn_name[f]);
        int bad = over || abi_fault[f] || fn_bad[f];
        failed |= bad;
        if (argc == 2) printf("FUNCTION %s %s\n", fn_name[f], bad ? "FAIL" : "PASS");
    }
    return failed;
}
