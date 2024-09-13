module main

import os
import sync.pool
import encoding.hex
import crypto.ed25519

const vexe = os.getenv('VEXE')

const vroot = os.dir(vexe)

const testdata = os.join_path(os.dir(@FILE), 'testdata')

const contents = os.read_lines(os.join_path(testdata, 'sign.input')) or { panic(err) }

fn test_sign_verify() {
	// mut zero := ZeroReader{}
	public, private := ed25519.generate_key()!

	message := 'test message'.bytes()
	sig := ed25519.sign(private, message)!
	res := ed25519.verify(public, message, sig) or { false }
	assert res == true

	wrongmessage := 'wrong message'.bytes()
	res2 := ed25519.verify(public, wrongmessage, sig)!
	assert res2 == false
}

fn test_equal() {
	public, private := ed25519.generate_key()!

	assert public.equal(public) == true

	// This is not AVAILABLE
	/*
	if !public.Equal(crypto.Signer(private).Public()) {
		t.Errorf("private.Public() is not Equal to public: %q", public)
	}*/
	assert private.equal(private) == true

	otherpub, otherpriv := ed25519.generate_key()!
	assert public.equal(otherpub) == false

	assert private.equal(otherpriv) == false
}

fn test_malleability() {
	// https://tools.ietf.org/html/rfc8032#section-5.1.7 adds an additional test
	// that s be in [0, order). This prevents someone from adding a multiple of
	// order to s and obtaining a second valid signature for the same message.
	msg := [u8(0x54), 0x65, 0x73, 0x74]
	sig := [u8(0x7c), 0x38, 0xe0, 0x26, 0xf2, 0x9e, 0x14, 0xaa, 0xbd, 0x05, 0x9a, 0x0f, 0x2d, 0xb8,
		0xb0, 0xcd, 0x78, 0x30, 0x40, 0x60, 0x9a, 0x8b, 0xe6, 0x84, 0xdb, 0x12, 0xf8, 0x2a, 0x27,
		0x77, 0x4a, 0xb0, 0x67, 0x65, 0x4b, 0xce, 0x38, 0x32, 0xc2, 0xd7, 0x6f, 0x8f, 0x6f, 0x5d,
		0xaf, 0xc0, 0x8d, 0x93, 0x39, 0xd4, 0xee, 0xf6, 0x76, 0x57, 0x33, 0x36, 0xa5, 0xc5, 0x1e,
		0xb6, 0xf9, 0x46, 0xb3, 0x1d]
	publickey := [u8(0x7d), 0x4d, 0x0e, 0x7f, 0x61, 0x53, 0xa6, 0x9b, 0x62, 0x42, 0xb5, 0x22, 0xab,
		0xbe, 0xe6, 0x85, 0xfd, 0xa4, 0x42, 0x0f, 0x88, 0x34, 0xb1, 0x08, 0xc3, 0xbd, 0xae, 0x36,
		0x9e, 0xf5, 0x49, 0xfa]
	// verify should fail on provided bytes
	res := ed25519.verify(publickey, msg, sig) or { false }
	assert res == false
}

fn works_check_on_sign_input_string(item string) !bool {
	// this is core part of the tests sign input
	parts := item.split(':') // []string

	if parts.len != 5 {
		return false
	}
	// assert parts.len == 5
	privbytes := hex.decode(parts[0])!
	pubkey := hex.decode(parts[1])!
	msg := hex.decode(parts[2])!
	mut sig := hex.decode(parts[3])!

	if pubkey.len != ed25519.public_key_size {
		return false
	}
	// assert pubkey.len == public_key_size

	sig = unsafe { sig[..ed25519.signature_size] }
	mut priv := []u8{len: ed25519.private_key_size}
	copy(mut priv[..], privbytes)
	copy(mut priv[32..], pubkey)

	sig2 := ed25519.sign(priv[..], msg)!
	if sig != sig2[..] {
		return false
	}

	res := ed25519.verify(pubkey, msg, sig2)!
	// assert res == true
	if !res {
		return false
	}

	priv2 := ed25519.new_key_from_seed(priv[..32])
	if ed25519.PrivateKey(priv[..]) != priv2 {
		return false
	}

	pubkey2 := priv2.public_key()
	if ed25519.PublicKey(pubkey) != pubkey2 {
		return false
	}

	seed2 := priv2.seed()
	if priv[0..32] != seed2 {
		return false
	}

	return true
}

fn worker_for_string_content(mut p pool.PoolProcessor, idx int, worker_id int) &SignResult {
	item := p.get_item[string](idx)
	// println('worker_s worker_id: $worker_id | idx: $idx ')
	res := works_check_on_sign_input_string(item) or { panic(err) }
	mut sr := &SignResult{
		item:   item
		result: res
	}
	return sr
}

pub struct SignResult {
mut:
	item   string
	result bool
}

// This test read a lot of entries in `testdata/sign.input` so, it may need a long time to finish.
fn test_input_from_djb_ed25519_crypto_sign_input_with_syncpool() {
	mut pool_s := pool.new_pool_processor(
		callback: worker_for_string_content
		maxjobs:  4
	)
	pool_s.work_on_items[string](contents)
	for i, x in pool_s.get_results[SignResult]() {
		// println("i: $i = $x.result")
		assert x.result == true
	}
}