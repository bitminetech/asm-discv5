// Command generator writes the asm-discv5 vector files.
//
// Usage: go run . OUT_DIR SOURCES_DIR
//
// Expected results come from go-ethereum v1.17.10 (p2p/enr, p2p/enode,
// p2p/discover/v5wire and crypto), and from the official devp2p test
// vectors at commit 88f1c80. SOURCES_DIR holds the pinned devp2p files,
// which run.sh downloads and checks. The file format is in README.md.
package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math/big"
	"math/rand"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/ethereum/go-ethereum/common/math"
	"github.com/ethereum/go-ethereum/common/mclock"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/p2p/discover/v5wire"
	"github.com/ethereum/go-ethereum/p2p/enode"
	"github.com/ethereum/go-ethereum/p2p/enr"
	"github.com/ethereum/go-ethereum/rlp"
	"golang.org/x/crypto/hkdf"
)

// Status codes of include/discv5.inc.
const (
	OK            = 0
	InvalidKey    = 2
	InvalidRecord = 4
	InvalidText   = 5
	InvalidPacket = 6
	DecryptFail   = 7
)

// Case kinds.
const (
	KEnrDecode = 1
	KEnrText   = 2
	KPacket    = 3
	KDerive    = 4
	KIDSign    = 5
	KIDVerify  = 6
	KInit      = 7
	KStep      = 8
)

// Step case sub-kinds.
const (
	StepRecord    = 1 // local record changes
	StepNodes     = 2 // three nodes discover each other
	StepErrors    = 3 // calls that must fail and change nothing
	StepChallenge = 4 // WHOAREYOU for a packet without a session
)

// Event kinds and the status of an event list that breaks the rules.
const (
	EvSetEndpoint = 4
	EvSetEntry    = 5
	InvalidEvent  = 3
)

var rng = rand.New(rand.NewSource(5))

func fail(f string, a ...interface{}) {
	fmt.Fprintf(os.Stderr, "generator: "+f+"\n", a...)
	os.Exit(1)
}

func must(err error) {
	if err != nil {
		fail("%v", err)
	}
}

func u64(v uint64) []byte {
	b := make([]byte, 8)
	binary.LittleEndian.PutUint64(b, v)
	return b
}

func blob(b []byte) []byte { return append(u64(uint64(len(b))), b...) }

func randBytes(n int) []byte {
	b := make([]byte, n)
	rng.Read(b)
	return b
}

func fixed(b []byte, n int) []byte {
	if len(b) > n {
		fail("value of %d bytes for a %d byte field", len(b), n)
	}
	return append(append([]byte{}, b...), make([]byte, n-len(b))...)
}

func unhex(s string) []byte {
	b, err := hex.DecodeString(strings.TrimPrefix(s, "0x"))
	must(err)
	return b
}

// A vector file: "DISCV5V1", the number of cases, then the cases.
type file struct {
	name  string
	cases [][]byte
}

func (f *file) add(kind uint64, name string, body ...[]byte) {
	c := append(u64(kind), blob([]byte(name))...)
	for _, b := range body {
		c = append(c, b...)
	}
	f.cases = append(f.cases, c)
}

func (f *file) write(dir string) {
	var out bytes.Buffer
	out.WriteString("DISCV5V1")
	out.Write(u64(uint64(len(f.cases))))
	for _, c := range f.cases {
		out.Write(c)
	}
	must(os.WriteFile(filepath.Join(dir, f.name), out.Bytes(), 0o644))
	fmt.Printf("%s: %d cases\n", f.name, len(f.cases))
}

func randomKey() *ecdsa.PrivateKey {
	for {
		k, err := crypto.ToECDSA(randBytes(32))
		if err == nil {
			return k
		}
	}
}

// ---------------------------------------------------------------- Records

// element is one RLP element of a list: where it starts, where its payload is, where it ends.
type element struct {
	kind                      rlp.Kind
	start, payload, size, end int
}

func elements(raw []byte, list []byte, base int) []element {
	var out []element
	pos := base
	rest := list
	for len(rest) > 0 {
		kind, content, next, err := rlp.Split(rest)
		must(err)
		total := len(rest) - len(next)
		hdr := total - len(content)
		out = append(out, element{kind, pos, pos + hdr, len(content), pos + total})
		pos += total
		rest = next
	}
	return out
}

func canonicalUint(b []byte, max int) bool {
	return len(b) <= max && (len(b) == 0 || b[0] != 0)
}

// enrExpect gives the status and fields that discv5_enr_decode must write.
func enrExpect(raw []byte) []byte {
	var r enr.Record
	if err := rlp.DecodeBytes(raw, &r); err != nil {
		return u64(InvalidRecord)
	}
	n, err := enode.New(enode.ValidSchemes, &r)
	if err != nil || n.Record().IdentityScheme() != "v4" {
		return u64(InvalidRecord)
	}
	_, content, _, err := rlp.Split(raw)
	must(err)
	els := elements(raw, content, len(raw)-len(content))
	var pk enode.Secp256k1
	must(r.Load(&pk))
	pub := crypto.CompressPubkey((*ecdsa.PublicKey)(&pk))
	var ip4, ip6 []byte
	var udp4, udp6, has uint64
	var pairs []byte
	for i := 2; i+1 < len(els); i += 2 {
		k, v := els[i], els[i+1]
		key := string(raw[k.payload : k.payload+k.size])
		val := raw[v.payload : v.payload+v.size]
		kind := uint32(1)
		off, size := v.payload, v.size
		if v.kind == rlp.List {
			kind, off, size = 2, v.start, v.end-v.start
		} else {
			switch key {
			case "ip":
				if len(val) == 4 {
					ip4, has = val, has|1
				}
			case "udp":
				if canonicalUint(val, 2) {
					udp4, has = new(big.Int).SetBytes(val).Uint64(), has|2
				}
			case "ip6":
				if len(val) == 16 {
					ip6, has = val, has|4
				}
			case "udp6":
				if canonicalUint(val, 2) {
					udp6, has = new(big.Int).SetBytes(val).Uint64(), has|8
				}
			}
		}
		p := make([]byte, 24)
		binary.LittleEndian.PutUint32(p[0:], uint32(k.payload))
		binary.LittleEndian.PutUint32(p[4:], uint32(k.size))
		binary.LittleEndian.PutUint32(p[8:], uint32(off))
		binary.LittleEndian.PutUint32(p[12:], uint32(size))
		binary.LittleEndian.PutUint32(p[16:], kind)
		pairs = append(pairs, p...)
	}
	id := n.ID()
	out := u64(OK)
	out = append(out, id[:]...)
	out = append(out, fixed(pub, 40)...)
	out = append(out, u64(r.Seq())...)
	out = append(out, fixed(ip4, 8)...)
	out = append(out, u64(udp4)...)
	out = append(out, fixed(ip6, 16)...)
	out = append(out, u64(udp6)...)
	out = append(out, u64(has)...)
	out = append(out, u64(uint64(len(pairs)/24))...)
	return append(out, blob(pairs)...)
}

func addRecord(f *file, name string, raw []byte) {
	f.add(KEnrDecode, name, blob(raw), enrExpect(raw))
}

// signContent builds [sig, seq, k, v, ...] from content elements, signed over keccak256 of [seq, k, v, ...].
func signContent(key *ecdsa.PrivateKey, content []interface{}) []byte {
	enc, err := rlp.EncodeToBytes(content)
	must(err)
	sig, err := crypto.Sign(crypto.Keccak256(enc), key)
	must(err)
	raw, err := rlp.EncodeToBytes(append([]interface{}{sig[:64]}, content...))
	must(err)
	return raw
}

func randomRecord(key *ecdsa.PrivateKey) *enr.Record {
	var r enr.Record
	r.SetSeq(rng.Uint64() >> uint(rng.Intn(64)))
	if rng.Intn(4) > 0 {
		r.Set(enr.IPv4(randBytes(4)))
		r.Set(enr.UDP(uint16(rng.Intn(65536))))
	}
	if rng.Intn(3) == 0 {
		r.Set(enr.IPv6(randBytes(16)))
		r.Set(enr.UDP6(uint16(rng.Intn(65536))))
	}
	if rng.Intn(2) == 0 {
		r.Set(enr.TCP(uint16(rng.Intn(65536))))
	}
	if rng.Intn(2) == 0 {
		r.Set(enr.WithEntry("eth2", randBytes(16)))
		r.Set(enr.WithEntry("attnets", randBytes(8)))
		r.Set(enr.WithEntry("syncnets", randBytes(1)))
	}
	if rng.Intn(3) == 0 {
		r.Set(enr.WithEntry("eth", []interface{}{[]interface{}{randBytes(4), uint64(rng.Intn(1 << 20))}}))
	}
	for i := rng.Intn(4); i > 0; i-- {
		k := strings.Repeat(string(rune('a'+rng.Intn(26))), 1+rng.Intn(6))
		r.Set(enr.WithEntry(k, randBytes(rng.Intn(24))))
	}
	return &r
}

func records(dir string, enrText string, enrKey []byte) [][]byte {
	f := &file{name: "enr.bin"}
	var valid [][]byte

	// The devp2p example.
	example := unhex(regexp.MustCompile(`(?m)^\s*([0-9a-f]{64})\s*$`).FindStringSubmatch(enrText)[1])
	txt := regexp.MustCompile(`(enr:[-_A-Za-z0-9]+)`).FindString(enrText)
	raw, err := base64.RawURLEncoding.DecodeString(txt[4:])
	must(err)
	if !bytes.Equal(example, enrKey) {
		fail("enr.md private key mismatch")
	}
	addRecord(f, "devp2p/enr.md", raw)
	valid = append(valid, raw)

	for i := 0; i < 300; i++ {
		key := randomKey()
		r := randomRecord(key)
		if enode.SignV4(r, key) != nil {
			continue
		}
		raw, err := rlp.EncodeToBytes(r)
		must(err)
		addRecord(f, fmt.Sprintf("valid/%d", i), raw)
		valid = append(valid, raw)
	}

	// Broken records.
	key := randomKey()
	pub := crypto.CompressPubkey(&key.PublicKey)
	base := []interface{}{uint64(7), "id", "v4", "ip", []byte{127, 0, 0, 1}, "secp256k1", pub, "udp", uint16(30303)}
	broken := map[string][]byte{
		"empty":         {},
		"not-a-list":    {0x83, 1, 2, 3},
		"no-seq":        mustEnc([]interface{}{make([]byte, 64)}),
		"odd-pairs":     signContent(key, []interface{}{uint64(1), "id", "v4", "secp256k1"}),
		"unsorted":      signContent(key, []interface{}{uint64(1), "secp256k1", pub, "id", "v4"}),
		"duplicate":     signContent(key, []interface{}{uint64(1), "id", "v4", "id", "v4", "secp256k1", pub}),
		"no-key":        signContent(key, []interface{}{uint64(1), "id", "v4", "ip", []byte{1, 2, 3, 4}}),
		"no-id":         signContent(key, []interface{}{uint64(1), "ip", []byte{1, 2, 3, 4}, "secp256k1", pub}),
		"id-v5":         signContent(key, []interface{}{uint64(1), "id", "v5", "secp256k1", pub}),
		"key-32":        signContent(key, []interface{}{uint64(1), "id", "v4", "secp256k1", pub[1:]}),
		"key-list":      signContent(key, []interface{}{uint64(1), "id", "v4", "secp256k1", []interface{}{pub}}),
		"key-off-curve": signContent(key, []interface{}{uint64(1), "id", "v4", "secp256k1", append([]byte{2}, bytes.Repeat([]byte{0xff}, 32)...)}),
		"too-big":       signContent(key, append(append([]interface{}{}, base...), "zz", make([]byte, 200))),
		"seq-leading-zero": func() []byte {
			raw := signContent(key, base)
			// seq 7 is the byte 0x07 after the signature; make it 0x82 0x00 0x07 is too long, so rebuild.
			c, _ := rlp.EncodeToBytes(append([]interface{}{make([]byte, 64), rlp.RawValue{0x82, 0x00, 0x07}}, base[1:]...))
			_ = raw
			return c
		}(),
	}
	good := signContent(key, base)
	flip := append([]byte{}, good...)
	flip[10] ^= 1
	broken["bad-signature"] = flip
	flip2 := append([]byte{}, good...)
	flip2[len(flip2)-1] ^= 1
	broken["changed-value"] = flip2
	broken["trailing-byte"] = append(append([]byte{}, good...), 0)
	addRecord(f, "valid/manual", good)
	valid = append(valid, good)

	// High s: the signature with s replaced by n - s still verifies by plain ECDSA.
	n := crypto.S256().Params().N
	_, content, _, _ := rlp.Split(good)
	sigContent, _, _ := rlp.SplitString(content)
	s := new(big.Int).SetBytes(sigContent[32:])
	hs := append(append([]byte{}, sigContent[:32]...), math.PaddedBigBytes(new(big.Int).Sub(n, s), 32)...)
	high, _ := rlp.EncodeToBytes(append([]interface{}{hs}, base...))
	broken["high-s"] = high

	names := make([]string, 0, len(broken))
	for k := range broken {
		names = append(names, k)
	}
	sort.Strings(names)
	for _, k := range names {
		addRecord(f, "broken/"+k, broken[k])
	}
	f.write(dir)
	return valid
}

func mustEnc(v interface{}) []byte {
	b, err := rlp.EncodeToBytes(v)
	must(err)
	return b
}

// ---------------------------------------------------------------- Text form

func texts(dir string, valid [][]byte) {
	f := &file{name: "enr-text.bin"}
	add := func(name, text string) {
		var out []byte
		status := uint64(OK)
		if !strings.HasPrefix(text, "enr:") {
			status = InvalidText
		} else if b, err := base64.RawURLEncoding.DecodeString(text[4:]); err != nil {
			status = InvalidText
		} else {
			out = b
		}
		f.add(KEnrText, name, blob([]byte(text)), u64(status), blob(out))
	}
	for i, raw := range valid {
		t := "enr:" + base64.RawURLEncoding.EncodeToString(raw)
		add(fmt.Sprintf("valid/%d", i), t)
		if i < 40 {
			bad := []byte(t)
			bad[4+rng.Intn(len(bad)-4)] = "*+/= !"[rng.Intn(6)]
			add(fmt.Sprintf("bad-char/%d", i), string(bad))
			add(fmt.Sprintf("prefix/%d", i), "enx:"+t[4:])
			add(fmt.Sprintf("padded/%d", i), t+"=")
		}
	}
	add("empty", "enr:")
	add("short", "enr")
	add("one-char", "enr:A")
	add("five-chars", "enr:AAAAA")
	add("two-chars", "enr:AA")
	add("three-chars", "enr:AAA")
	f.write(dir)
}

// ---------------------------------------------------------------- Packets

// header fields in the order of the vector format.
type header struct {
	flag     byte
	iv       [16]byte
	nonce    [12]byte
	src      enode.ID
	idNonce  [16]byte
	enrSeq   uint64
	sig      []byte
	eph      []byte
	record   []byte
	authdata []byte
	raw      []byte // IV, static header, authdata
}

func (h *header) build() {
	var auth bytes.Buffer
	switch h.flag {
	case 0:
		auth.Write(h.src[:])
	case 1:
		auth.Write(h.idNonce[:])
		binary.Write(&auth, binary.BigEndian, h.enrSeq)
	case 2:
		auth.Write(h.src[:])
		auth.WriteByte(byte(len(h.sig)))
		auth.WriteByte(byte(len(h.eph)))
		auth.Write(h.sig)
		auth.Write(h.eph)
		auth.Write(h.record)
	}
	h.authdata = auth.Bytes()
	var raw bytes.Buffer
	raw.Write(h.iv[:])
	raw.WriteString("discv5")
	binary.Write(&raw, binary.BigEndian, uint16(1))
	raw.WriteByte(h.flag)
	raw.Write(h.nonce[:])
	binary.Write(&raw, binary.BigEndian, uint16(len(h.authdata)))
	raw.Write(h.authdata)
	h.raw = raw.Bytes()
}

func (h *header) fields() []byte {
	var out []byte
	out = append(out, u64(uint64(h.flag))...)
	out = append(out, h.iv[:]...)
	out = append(out, h.nonce[:]...)
	out = append(out, h.src[:]...)
	out = append(out, h.idNonce[:]...)
	out = append(out, u64(h.enrSeq)...)
	out = append(out, fixed(h.sig, 64)...)
	out = append(out, fixed(h.eph, 40)...)
	out = append(out, blob(h.record)...)
	return append(out, blob(h.raw)...)
}

func seal(key, nonce, pt, ad []byte) []byte {
	block, err := aes.NewCipher(key)
	must(err)
	gcm, err := cipher.NewGCMWithNonceSize(block, 12)
	must(err)
	return gcm.Seal(nil, nonce, pt, ad)
}

var codec = func() *v5wire.Codec {
	key := randomKey()
	db, err := enode.OpenDB("")
	must(err)
	return v5wire.NewCodec(enode.NewLocalNode(db, key), key, mclock.System{}, nil)
}()

// packet encodes with geth's EncodeRaw: the header masked with dest, then the message bytes.
func packet(dest enode.ID, h *header, msg []byte) []byte {
	var head v5wire.Header
	head.IV = h.iv
	copy(head.ProtocolID[:], "discv5")
	head.Version = 1
	head.Flag = h.flag
	head.Nonce = h.nonce
	head.AuthSize = uint16(len(h.authdata))
	head.AuthData = h.authdata
	enc, err := codec.EncodeRaw(dest, head, msg)
	must(err)
	return append([]byte{}, enc...)
}

// A packet case: the packet, the local ID, the decode status, the header,
// the key, the decrypt status, the plaintext, and 1 when encode must give the packet.
func addPacket(f *file, name string, pkt []byte, local enode.ID, status uint64, h *header, key []byte, dstatus uint64, pt []byte, encode bool) {
	if h == nil {
		h = &header{}
	}
	e := uint64(0)
	if encode {
		e = 1
	}
	f.add(KPacket, name, blob(pkt), local[:], u64(status), h.fields(), fixed(key, 16), u64(dstatus), blob(pt), u64(e))
}

func randomHeader(flag byte) *header {
	h := &header{flag: flag}
	copy(h.iv[:], randBytes(16))
	copy(h.nonce[:], randBytes(12))
	copy(h.src[:], randBytes(32))
	switch flag {
	case 1:
		copy(h.idNonce[:], randBytes(16))
		h.enrSeq = rng.Uint64() >> uint(rng.Intn(64))
	case 2:
		h.sig = randBytes(64)
		h.eph = randBytes(33)
		h.record = randBytes([]int{0, 1, 120, 300}[rng.Intn(4)])
	}
	h.build()
	return h
}

func packets(dir string, vec map[string]string) {
	f := &file{name: "packet.bin"}
	for i := 0; i < 400; i++ {
		flag := byte(i % 3)
		h := randomHeader(flag)
		var dest enode.ID
		copy(dest[:], randBytes(32))
		key := randBytes(16)
		var pt, msg []byte
		if flag != 1 {
			pt = randBytes(1 + rng.Intn(900-len(h.raw)))
			msg = seal(key, h.nonce[:], pt, h.raw)
		}
		pkt := packet(dest, h, msg)
		addPacket(f, fmt.Sprintf("valid/%d", i), pkt, dest, OK, h, key, OK, pt, true)
		if flag != 1 {
			wrong := randBytes(16)
			addPacket(f, fmt.Sprintf("wrong-key/%d", i), pkt, dest, OK, h, wrong, DecryptFail, nil, false)
			bad := append([]byte{}, pkt...)
			bad[len(bad)-1-rng.Intn(len(msg))] ^= 1
			addPacket(f, fmt.Sprintf("changed/%d", i), bad, dest, OK, h, key, DecryptFail, nil, false)
		}
	}

	// Broken headers.
	var dest enode.ID
	copy(dest[:], randBytes(32))
	key := randBytes(16)
	brokenHeader := func(name string, edit func(*header) []byte) {
		h := randomHeader(0)
		pt := []byte{1, 0xc2, 0x80, 0x80}
		raw := edit(h)
		if raw == nil {
			raw = packet(dest, h, seal(key, h.nonce[:], pt, h.raw))
		}
		addPacket(f, "broken/"+name, raw, dest, InvalidPacket, nil, nil, 0, nil, false)
	}
	encodeWith := func(h *header, proto string, version uint16, msg []byte) []byte {
		var head v5wire.Header
		head.IV = h.iv
		copy(head.ProtocolID[:], proto)
		head.Version = version
		head.Flag = h.flag
		head.Nonce = h.nonce
		head.AuthSize = uint16(len(h.authdata))
		head.AuthData = h.authdata
		enc, err := codec.EncodeRaw(dest, head, msg)
		must(err)
		return append([]byte{}, enc...)
	}
	msg48 := randBytes(48)
	brokenHeader("too-short", func(h *header) []byte { return randBytes(62) })
	brokenHeader("too-long", func(h *header) []byte {
		return encodeWith(h, "discv5", 1, randBytes(1281-len(h.raw)))
	})
	brokenHeader("protocol", func(h *header) []byte { return encodeWith(h, "discv4", 1, msg48) })
	brokenHeader("version-0", func(h *header) []byte { return encodeWith(h, "discv5", 0, msg48) })
	brokenHeader("flag-3", func(h *header) []byte { h.flag = 3; return encodeWith(h, "discv5", 1, msg48) })
	brokenHeader("message-short", func(h *header) []byte { return encodeWith(h, "discv5", 1, randBytes(15)) })
	brokenHeader("auth-31", func(h *header) []byte { h.authdata = h.authdata[:31]; return encodeWith(h, "discv5", 1, msg48) })
	brokenHeader("auth-beyond", func(h *header) []byte {
		h.authdata = append(h.authdata, randBytes(60)...)
		enc := encodeWith(h, "discv5", 1, nil)
		return enc[:len(enc)-30]
	})
	brokenHeader("whoareyou-23", func(h *header) []byte {
		w := randomHeader(1)
		w.authdata = w.authdata[:23]
		return encodeWith(w, "discv5", 1, nil)
	})
	brokenHeader("handshake-sig-65", func(h *header) []byte {
		w := randomHeader(2)
		w.authdata[32] = 65
		w.authdata = append(w.authdata, 0)
		return encodeWith(w, "discv5", 1, msg48)
	})
	brokenHeader("handshake-key-32", func(h *header) []byte {
		w := randomHeader(2)
		w.authdata[33] = 32
		return encodeWith(w, "discv5", 1, msg48)
	})
	brokenHeader("handshake-short", func(h *header) []byte {
		w := randomHeader(2)
		w.authdata = w.authdata[:130]
		return encodeWith(w, "discv5", 1, msg48)
	})
	brokenHeader("handshake-record-301", func(h *header) []byte {
		w := randomHeader(2)
		w.authdata = append(w.authdata[:131], randBytes(301)...)
		return encodeWith(w, "discv5", 1, msg48)
	})

	// The devp2p packet vectors: node B decodes them.
	bkey, _ := crypto.ToECDSA(unhex(vec["node-b-key"]))
	akey, _ := crypto.ToECDSA(unhex(vec["node-a-key"]))
	bid, aid := enode.PubkeyToIDV4(&bkey.PublicKey), enode.PubkeyToIDV4(&akey.PublicKey)
	ping := func(seq uint64) []byte {
		b, err := rlp.EncodeToBytes([]interface{}{[]byte{0, 0, 0, 1}, seq})
		must(err)
		return append([]byte{1}, b...)
	}
	for _, p := range []struct {
		name, packet, readKey string
		flag                  byte
		seq                   uint64
	}{
		{"devp2p/ping", "ping-packet", "0x00000000000000000000000000000000", 0, 2},
		{"devp2p/whoareyou", "whoareyou-packet", "", 1, 0},
		{"devp2p/handshake", "handshake-packet", "0x4f9fac6de7567d1e3b1241dffe90f662", 2, 1},
		{"devp2p/handshake-enr", "handshake-enr-packet", "0x53b1c075f41876423154e157470c2f48", 2, 1},
	} {
		pkt := unhex(vec[p.packet])
		h := &header{flag: p.flag}
		copy(h.iv[:], pkt[:16])
		switch p.flag {
		case 0:
			copy(h.nonce[:], unhex("0xffffffffffffffffffffffff"))
			h.src = aid
		case 1:
			copy(h.nonce[:], unhex("0x0102030405060708090a0b0c"))
			copy(h.idNonce[:], unhex("0x0102030405060708090a0b0c0d0e0f10"))
		case 2:
			copy(h.nonce[:], unhex("0xffffffffffffffffffffffff"))
			h.src = aid
			h.eph = unhex("0x039a003ba6517b473fa0cd74aefe99dadfdb34627f90fec6362df85803908f53a5")
		}
		// The signature and record come from the packet itself: take them from geth's view
		// of the unmasked header.
		raw := unmask(bid, pkt)
		if p.flag == 2 {
			auth := raw[39:]
			h.sig = auth[34 : 34+64]
			h.record = auth[131:]
		}
		h.build()
		if !bytes.Equal(h.raw, raw) {
			fail("%s: header fields do not rebuild the packet header", p.name)
		}
		var pt []byte
		dstatus := uint64(OK)
		if p.flag != 1 {
			pt = ping(p.seq)
			if !bytes.Equal(seal(unhex(p.readKey), h.nonce[:], pt, h.raw), pkt[len(h.raw):]) {
				fail("%s: the message does not seal to the vector", p.name)
			}
		}
		addPacket(f, p.name, pkt, bid, OK, h, unhex(p.readKey), dstatus, pt, true)
	}
	f.write(dir)
}

// unmask undoes the header masking with the destination ID.
func unmask(dest enode.ID, pkt []byte) []byte {
	block, err := aes.NewCipher(dest[:16])
	must(err)
	out := append([]byte{}, pkt...)
	cipher.NewCTR(block, pkt[:16]).XORKeyStream(out[16:], out[16:])
	size := int(binary.BigEndian.Uint16(out[37:39]))
	return out[:39+size]
}

// ---------------------------------------------------------------- Handshake crypto

func ecdhSecret(priv *ecdsa.PrivateKey, pub *ecdsa.PublicKey) []byte {
	x, y := pub.Curve.ScalarMult(pub.X, pub.Y, priv.D.Bytes())
	sec := make([]byte, 33)
	sec[0] = 0x02 | byte(y.Bit(0))
	math.ReadBits(x, sec[1:])
	return sec
}

func deriveKeys(priv *ecdsa.PrivateKey, pub *ecdsa.PublicKey, challenge, ids []byte) []byte {
	info := append([]byte("discovery v5 key agreement"), ids...)
	kdf := hkdf.New(sha256.New, ecdhSecret(priv, pub), challenge, info)
	keys := make([]byte, 32)
	kdf.Read(keys)
	return keys
}

func idHash(challenge, eph, dest []byte) []byte {
	h := sha256.New()
	h.Write([]byte("discovery v5 identity proof"))
	h.Write(challenge)
	h.Write(eph)
	h.Write(dest)
	return h.Sum(nil)
}

func handshake(dir string, vec map[string]string) {
	f := &file{name: "handshake.bin"}
	addDerive := func(name string, priv *ecdsa.PrivateKey, pub, challenge, ids []byte, want []byte) {
		pk, err := crypto.DecompressPubkey(pub)
		status, keys := uint64(OK), make([]byte, 32)
		if err != nil {
			status = InvalidKey
		} else {
			keys = deriveKeys(priv, pk, challenge, ids)
		}
		if want != nil && !bytes.Equal(keys, want) {
			fail("%s: keys differ from the vector", name)
		}
		f.add(KDerive, name, crypto.FromECDSA(priv), fixed(pub, 40), fixed(challenge, 64), ids, u64(status), keys)
	}
	addSign := func(name string, priv *ecdsa.PrivateKey, challenge, eph, dest []byte, want []byte) []byte {
		sig, err := crypto.Sign(idHash(challenge, eph, dest), priv)
		must(err)
		sig = sig[:64]
		if want != nil && !bytes.Equal(sig, want) {
			fail("%s: signature differs from the vector", name)
		}
		f.add(KIDSign, name, crypto.FromECDSA(priv), fixed(challenge, 64), fixed(eph, 40), dest, u64(OK), sig)
		return sig
	}
	addVerify := func(name string, pub, challenge, eph, dest, sig []byte) {
		status, valid := uint64(OK), uint64(0)
		if _, err := crypto.DecompressPubkey(pub); err != nil {
			status = InvalidKey
		} else if crypto.VerifySignature(pub, idHash(challenge, eph, dest), sig) {
			valid = 1
		}
		f.add(KIDVerify, name, fixed(pub, 40), fixed(challenge, 64), fixed(eph, 40), dest, sig, u64(status), u64(valid))
	}

	// The devp2p crypto vectors.
	ephKey, _ := crypto.ToECDSA(unhex(vec["ephemeral-key"]))
	ids := append(unhex(vec["node-id-a"]), unhex(vec["node-id-b"])...)
	addDerive("devp2p/key-derivation", ephKey, unhex(vec["dest-pubkey"]), unhex(vec["challenge-data"]), ids,
		append(unhex(vec["initiator-key"]), unhex(vec["recipient-key"])...))
	static, _ := crypto.ToECDSA(unhex(vec["static-key"]))
	sig := addSign("devp2p/id-signature", static, unhex(vec["challenge-data"]), unhex(vec["ephemeral-pubkey"]),
		unhex(vec["node-id-B"]), unhex(vec["id-signature"]))
	addVerify("devp2p/id-signature", crypto.CompressPubkey(&static.PublicKey), unhex(vec["challenge-data"]),
		unhex(vec["ephemeral-pubkey"]), unhex(vec["node-id-B"]), sig)

	for i := 0; i < 100; i++ {
		a, b, eph := randomKey(), randomKey(), randomKey()
		challenge := randBytes(63)
		ids := randBytes(64)
		addDerive(fmt.Sprintf("derive/%d", i), eph, crypto.CompressPubkey(&b.PublicKey), challenge, ids, nil)
		ephPub := crypto.CompressPubkey(&eph.PublicKey)
		dest := randBytes(32)
		sig := addSign(fmt.Sprintf("sign/%d", i), a, challenge, ephPub, dest, nil)
		apub := crypto.CompressPubkey(&a.PublicKey)
		addVerify(fmt.Sprintf("verify/%d", i), apub, challenge, ephPub, dest, sig)
		bad := append([]byte{}, sig...)
		bad[rng.Intn(64)] ^= 1
		addVerify(fmt.Sprintf("verify-changed/%d", i), apub, challenge, ephPub, dest, bad)
		addVerify(fmt.Sprintf("verify-other-dest/%d", i), apub, challenge, ephPub, randBytes(32), sig)
	}
	offCurve := append([]byte{2}, bytes.Repeat([]byte{0xff}, 32)...)
	addDerive("derive/bad-public-key", randomKey(), offCurve, randBytes(63), randBytes(64), nil)
	addVerify("verify/bad-public-key", offCurve, randBytes(63), randBytes(33), randBytes(32), randBytes(64))
	f.write(dir)
}

// ---------------------------------------------------------------- Local records

func inits(dir string) {
	f := &file{name: "init.bin"}
	for i := 0; i < 100; i++ {
		key := randomKey()
		seq := 1 + rng.Uint64()>>uint(rng.Intn(64))
		if seq == 0 {
			seq = 1
		}
		var r enr.Record
		r.SetSeq(seq)
		family, port := uint64(0), uint64(0)
		addr := make([]byte, 16)
		switch i % 3 {
		case 1:
			family, port = 4, uint64(rng.Intn(65536))
			copy(addr, randBytes(4))
			r.Set(enr.IPv4(net.IP(addr[:4])))
			if port != 0 {
				r.Set(enr.UDP(uint16(port)))
			}
		case 2:
			family, port = 6, uint64(1+rng.Intn(65535))
			copy(addr, randBytes(16))
			r.Set(enr.IPv6(net.IP(addr)))
			r.Set(enr.UDP6(uint16(port)))
		}
		must(enode.SignV4(&r, key))
		raw, err := rlp.EncodeToBytes(&r)
		must(err)
		f.add(KInit, fmt.Sprintf("init/%d", i), crypto.FromECDSA(key), u64(seq), u64(port), u64(family), addr, u64(OK), blob(raw))
	}
	for _, k := range [][]byte{make([]byte, 32), crypto.S256().Params().N.Bytes(), bytes.Repeat([]byte{0xff}, 32)} {
		f.add(KInit, "init/bad-key", k, u64(1), u64(0), u64(0), make([]byte, 16), u64(InvalidKey), blob(nil))
	}
	f.write(dir)
}

// ---------------------------------------------------------------- Steps

// recordOf signs the entries (ip, udp, ip6, udp6 and others, as byte strings)
// at seq with the v4 scheme, as geth does; nil when it passes 300 bytes.
func recordOf(key *ecdsa.PrivateKey, seq uint64, entries map[string][]byte) []byte {
	var r enr.Record
	r.SetSeq(seq)
	for k, v := range entries {
		r.Set(enr.WithEntry(k, v))
	}
	if err := enode.SignV4(&r, key); err != nil {
		return nil
	}
	raw, err := rlp.EncodeToBytes(&r)
	must(err)
	return raw
}

func portBytes(port uint64) []byte {
	if port < 256 {
		return []byte{byte(port)}
	}
	return []byte{byte(port >> 8), byte(port)}
}

func setEndpointEvent(family, port uint64, addr []byte) []byte {
	return append(append(append(u64(48), u64(EvSetEndpoint)...), append(u64(port), u64(family)...)...), fixed(addr, 16)...)
}

func setEntryEvent(key, value []byte) []byte {
	size := (48 + len(value) + 7) &^ 7
	e := append(append(u64(uint64(size)), u64(EvSetEntry)...), u64(uint64(len(key)))...)
	e = append(append(e, fixed(key, 16)...), u64(uint64(len(value)))...)
	return append(e, fixed(value, size-48)...)
}

var ownedKeys = []string{"id", "secp256k1", "ip", "udp", "ip6", "udp6"}

func isOwned(k string) bool {
	for _, o := range ownedKeys {
		if k == o {
			return true
		}
	}
	return false
}

// steps writes step.bin. A record case starts a node like init.bin, then
// gives one SET_ENDPOINT or SET_ENTRY event per step: the step status, and
// the record geth signs for the new entries at the next sequence number, or
// no record when the change cannot be made (more than 16 entries, or more
// than 300 bytes).
func steps(dir string) {
	f := &file{name: "step.bin"}
	letters := []byte("abcdefghijklmnopqrstuvwxyz0123456789")
	for i := 0; i < 60; i++ {
		key := randomKey()
		seq := uint64(1 + rng.Intn(1000))
		start := seq
		entries := map[string][]byte{}
		family, port := uint64(0), uint64(0)
		addr := make([]byte, 16)
		if i%2 == 1 {
			family, port = 4, uint64(1+rng.Intn(65535))
			copy(addr, randBytes(4))
			entries["ip"] = append([]byte{}, addr[:4]...)
			entries["udp"] = portBytes(port)
		}
		var changes []byte
		n := 1 + rng.Intn(24)
		for c := 0; c < n; c++ {
			var ev []byte
			status := uint64(OK)
			next := map[string][]byte{}
			for k, v := range entries {
				next[k] = v
			}
			switch r := rng.Intn(20); {
			case r < 3:
				fam, p, a := uint64(4), uint64(rng.Intn(65536)), randBytes(4)
				ipKey, udpKey := "ip", "udp"
				if rng.Intn(2) == 0 {
					fam, a, ipKey, udpKey = 6, randBytes(16), "ip6", "udp6"
				}
				ev = setEndpointEvent(fam, p, a)
				next[ipKey] = a
				if p != 0 {
					next[udpKey] = portBytes(p)
				}
			case r < 5:
				switch rng.Intn(4) {
				case 0:
					ev = setEntryEvent([]byte(ownedKeys[rng.Intn(len(ownedKeys))]), randBytes(rng.Intn(8)))
				case 1:
					ev = setEntryEvent(nil, randBytes(4))
				case 2:
					ev = setEndpointEvent(4, 65536, randBytes(4))
				default:
					ev = setEndpointEvent(5, 1, randBytes(4))
				}
				status = InvalidEvent
			default:
				k := make([]byte, 1+rng.Intn(16))
				for j := range k {
					k[j] = letters[rng.Intn(len(letters))]
				}
				var mine []string
				for old := range entries {
					if !isOwned(old) {
						mine = append(mine, old)
					}
				}
				sort.Strings(mine)
				if len(mine) > 0 && rng.Intn(4) == 0 {
					k = []byte(mine[rng.Intn(len(mine))])
				}
				v := randBytes(rng.Intn(65))
				ev = setEntryEvent(k, v)
				next[string(k)] = v
			}
			var rec []byte
			if status == OK && len(next)+2 <= 16 {
				rec = recordOf(key, seq+1, next)
			}
			if rec != nil {
				entries, seq = next, seq+1
			}
			changes = append(changes, blob(ev)...)
			changes = append(changes, u64(status)...)
			changes = append(changes, blob(rec)...)
		}
		f.add(KStep, fmt.Sprintf("record/%d", i), u64(StepRecord), crypto.FromECDSA(key), u64(start), u64(port), u64(family), addr, u64(uint64(n)), changes)
	}
	for i := 0; i < 4; i++ {
		f.add(KStep, fmt.Sprintf("nodes/%d", i), u64(StepNodes), crypto.FromECDSA(randomKey()), crypto.FromECDSA(randomKey()), crypto.FromECDSA(randomKey()))
	}
	f.add(KStep, "errors", u64(StepErrors), crypto.FromECDSA(randomKey()))
	for i := 0; i < 4; i++ {
		f.add(KStep, fmt.Sprintf("challenge/%d", i), u64(StepChallenge), crypto.FromECDSA(randomKey()), crypto.FromECDSA(randomKey()))
	}
	f.write(dir)
}

// ---------------------------------------------------------------- Main

// devp2pValues reads "name = 0x..." and "name: 0x..." lines, not the "# name = ..."
// comments of the packet section, and the packet hex blocks.
func devp2pValues(text string) map[string]string {
	v := map[string]string{}
	for _, m := range regexp.MustCompile(`(?m)^\s+([\w.-]+)\s*[:=]\s*(0x[0-9a-fA-F]+)\s*$`).FindAllStringSubmatch(text, -1) {
		if _, ok := v[m[1]]; !ok {
			v[m[1]] = m[2]
		}
	}
	blocks := regexp.MustCompile(`(?s)\n\n((?:    [0-9a-f]+\n)+)`).FindAllStringSubmatch(text, -1)
	names := []string{"ping-packet", "whoareyou-packet", "handshake-packet", "handshake-enr-packet"}
	if len(blocks) < len(names) {
		fail("found %d packet blocks", len(blocks))
	}
	for i, n := range names {
		v[n] = "0x" + strings.Join(strings.Fields(blocks[i][1]), "")
	}
	return v
}

func main() {
	if len(os.Args) != 3 {
		fail("usage: generator OUT_DIR SOURCES_DIR")
	}
	out, src := os.Args[1], os.Args[2]
	read := func(name string) string {
		b, err := os.ReadFile(filepath.Join(src, name))
		must(err)
		return string(b)
	}
	vec := devp2pValues(read("discv5-wire-test-vectors.md"))
	enrText := read("enr.md")
	valid := records(out, enrText, unhex("b71c71a67e1177ad4e901695e1b4b9ee17ae16c6668d313eac2f96dbcda3f291"))
	texts(out, valid)
	packets(out, vec)
	handshake(out, vec)
	inits(out)
	steps(out)
}
