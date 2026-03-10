import x.crypto.mldsa { Kind, PrivateKey, PublicKey }

struct SignVerifyCase {
	label string
	kind  Kind
}

const sign_verify_cases = [
	SignVerifyCase{
		label: 'ML-DSA-44'
		kind:  .ml_dsa_44
	},
	SignVerifyCase{
		label: 'ML-DSA-65'
		kind:  .ml_dsa_65
	},
	SignVerifyCase{
		label: 'ML-DSA-87'
		kind:  .ml_dsa_87
	},
]

fn test_keygen_sign_verify() {
	seeds := [u8(42), 0, 99]
	for i, c in sign_verify_cases {
		seed := []u8{len: 32, init: u8(index + seeds[i])}
		priv_key := PrivateKey.from_seed(seed, c.kind) or { panic('${c.label}: ${err}') }
		pub_key := priv_key.public_key()

		msg := 'hello ${c.label}'.bytes()
		sig := priv_key.sign(msg, deterministic: true) or { panic('${c.label}: ${err}') }
		valid := pub_key.verify(msg, sig) or { panic('${c.label}: ${err}') }
		assert valid, '${c.label} signature verification failed'

		wrong_msg := 'wrong message'.bytes()
		valid2 := pub_key.verify(wrong_msg, sig) or { panic('${c.label}: ${err}') }
		assert !valid2, '${c.label} verification should fail with wrong message'
	}
}

struct PkRoundtripCase {
	label    string
	kind     Kind
	pk_size  int
	sig_size int
}

const pk_roundtrip_cases = [
	PkRoundtripCase{
		label:    'ML-DSA-44'
		kind:     .ml_dsa_44
		pk_size:  mldsa.public_key_size_44
		sig_size: mldsa.signature_size_44
	},
	PkRoundtripCase{
		label:    'ML-DSA-65'
		kind:     .ml_dsa_65
		pk_size:  mldsa.public_key_size_65
		sig_size: mldsa.signature_size_65
	},
	PkRoundtripCase{
		label:    'ML-DSA-87'
		kind:     .ml_dsa_87
		pk_size:  mldsa.public_key_size_87
		sig_size: mldsa.signature_size_87
	},
]

fn test_public_key_encode_decode() {
	for c in pk_roundtrip_cases {
		seed := []u8{len: 32, init: u8(index + 7)}
		sk := PrivateKey.from_seed(seed, c.kind) or { panic('${c.label}: ${err}') }
		pk := sk.public_key()

		pk_bytes := pk.bytes()
		assert pk_bytes.len == c.pk_size, '${c.label}: pk size mismatch'

		pk2 := PublicKey.from_bytes(pk_bytes, c.kind) or { panic('${c.label}: ${err}') }
		assert pk.equal(&pk2), '${c.label}: pk roundtrip mismatch'
	}
}

fn test_signature_sizes() {
	for c in pk_roundtrip_cases {
		seed := []u8{len: 32, init: u8(index + 13)}
		sk := PrivateKey.from_seed(seed, c.kind) or { panic('${c.label}: ${err}') }
		msg := 'size test'.bytes()
		sig := sk.sign(msg, deterministic: true) or { panic('${c.label}: ${err}') }
		assert sig.len == c.sig_size, '${c.label}: expected sig size ${c.sig_size}, got ${sig.len}'
	}
}

fn test_context_string() {
	seed := []u8{len: 32, init: u8(index)}
	sk := PrivateKey.from_seed(seed, .ml_dsa_65) or { panic(err) }
	pk := sk.public_key()

	msg := 'context test'.bytes()
	sig := sk.sign(msg, context: 'my-context', deterministic: true) or { panic(err) }

	valid := pk.verify(msg, sig, context: 'my-context') or { panic(err) }
	assert valid

	valid2 := pk.verify(msg, sig, context: 'wrong-context') or { panic(err) }
	assert !valid2
}

fn test_randomized_sign() {
	seed := []u8{len: 32, init: u8(index + 1)}
	sk := PrivateKey.from_seed(seed, .ml_dsa_44) or { panic(err) }
	pk := sk.public_key()
	msg := 'randomized'.bytes()

	sig := sk.sign(msg) or { panic(err) }
	valid := pk.verify(msg, sig) or { panic(err) }
	assert valid

	// two randomized signatures should differ
	sig2 := sk.sign(msg) or { panic(err) }
	assert sig != sig2
}

fn test_generate_key() {
	sk44 := PrivateKey.generate(.ml_dsa_44) or { panic(err) }
	pk44 := sk44.public_key()
	sig := sk44.sign('gen'.bytes(), deterministic: true) or { panic(err) }
	assert pk44.verify('gen'.bytes(), sig) or { panic(err) }

	sk65 := PrivateKey.generate(.ml_dsa_65) or { panic(err) }
	assert sk65.public_key().bytes().len == mldsa.public_key_size_65

	sk87 := PrivateKey.generate(.ml_dsa_87) or { panic(err) }
	assert sk87.public_key().bytes().len == mldsa.public_key_size_87
}

fn test_private_key_equal() {
	seed := []u8{len: 32, init: u8(index)}
	sk1 := PrivateKey.from_seed(seed, .ml_dsa_44) or { panic(err) }
	sk2 := PrivateKey.from_seed(seed, .ml_dsa_44) or { panic(err) }
	assert sk1.equal(&sk2)

	seed2 := []u8{len: 32, init: u8(index + 1)}
	sk3 := PrivateKey.from_seed(seed2, .ml_dsa_44) or { panic(err) }
	assert !sk1.equal(&sk3)
}

fn test_private_key_seed_roundtrip() {
	seed := []u8{len: 32, init: u8(index + 3)}
	sk := PrivateKey.from_seed(seed, .ml_dsa_65) or { panic(err) }
	seed_out := sk.seed()
	sk2 := PrivateKey.from_seed(seed_out, .ml_dsa_65) or { panic(err) }
	assert sk.equal(&sk2)
}

fn test_private_key_bytes_roundtrip() {
	for c in sign_verify_cases {
		seed := []u8{len: 32, init: u8(index + 50)}
		sk := PrivateKey.from_seed(seed, c.kind) or { panic('${c.label}: ${err}') }
		pk := sk.public_key()

		sk_bytes := sk.bytes()
		assert sk_bytes.len == c.kind.private_key_size(), '${c.label}: sk size mismatch'

		sk2 := PrivateKey.from_bytes(sk_bytes, c.kind) or { panic('${c.label}: ${err}') }
		pk2 := sk2.public_key()

		assert pk.equal(pk2), '${c.label}: pk mismatch after sk roundtrip'

		msg := 'roundtrip ${c.label}'.bytes()
		sig := sk2.sign(msg, deterministic: true) or { panic('${c.label}: ${err}') }
		valid := pk.verify(msg, sig) or { panic('${c.label}: ${err}') }
		assert valid, '${c.label}: sig from deserialized sk failed verification'
	}
}

fn test_error_invalid_private_key() {
	bad := []u8{len: 10}
	if _ := PrivateKey.from_bytes(bad, .ml_dsa_44) {
		assert false, 'should reject invalid sk'
	}
}

fn test_error_invalid_seed_length() {
	short := []u8{len: 16}
	if _ := PrivateKey.from_seed(short, .ml_dsa_44) {
		assert false, 'should reject short seed'
	}
	long := []u8{len: 64}
	if _ := PrivateKey.from_seed(long, .ml_dsa_65) {
		assert false, 'should reject long seed'
	}
}

fn test_error_invalid_public_key() {
	bad := []u8{len: 10}
	if _ := PublicKey.from_bytes(bad, .ml_dsa_44) {
		assert false, 'should reject invalid pk'
	}
}

fn test_error_context_too_long() {
	seed := []u8{len: 32, init: u8(index)}
	sk := PrivateKey.from_seed(seed, .ml_dsa_44) or { panic(err) }
	pk := sk.public_key()
	long_ctx := 'x'.repeat(256)

	if _ := sk.sign('msg'.bytes(), context: long_ctx) {
		assert false, 'sign should reject long context'
	}
	if _ := sk.sign('msg'.bytes(), context: long_ctx, deterministic: true) {
		assert false, 'sign_deterministic should reject long context'
	}
	if _ := pk.verify('msg'.bytes(), []u8{}, context: long_ctx) {
		assert false, 'verify should reject long context'
	}
}

fn test_verify_corrupted_signature() {
	seed := []u8{len: 32, init: u8(index + 2)}
	sk := PrivateKey.from_seed(seed, .ml_dsa_44) or { panic(err) }
	pk := sk.public_key()
	msg := 'corrupt'.bytes()
	sig := sk.sign(msg, deterministic: true) or { panic(err) }

	// flip a byte in the sig
	mut bad_sig := sig.clone()
	bad_sig[sig.len / 2] ^= 0xff
	valid := pk.verify(msg, bad_sig) or { false }
	assert !valid
}
