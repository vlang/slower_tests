module mldsa

// Wycheproof ML-DSA verification test vectors from C2SP/wycheproof.
import encoding.hex
import json
import os

struct WpTestCase {
	tc_id   int      @[json: 'tcId']
	comment string
	msg     string
	ctx     string
	sig     string
	result  string
	flags   []string
}

struct WpTestGroup {
	type_      string       @[json: 'type']
	public_key string       @[json: 'publicKey']
	tests      []WpTestCase
}

struct WpTestFile {
	algorithm       string
	number_of_tests int          @[json: 'numberOfTests']
	test_groups     []WpTestGroup @[json: 'testGroups']
}

fn load_wycheproof(filename string) !WpTestFile {
	dir := os.dir(@FILE)
	raw := os.read_file(os.join_path(dir, 'testdata', 'wycheproof', filename))!
	return json.decode(WpTestFile, raw)
}

fn run_wycheproof(filename string, kind Kind) ! {
	tf := load_wycheproof(filename)!
	mut passed := 0
	mut total := 0

	for g in tf.test_groups {
		pk_bytes := hex.decode(g.public_key) or {
			// invalid pk is expected for some test cases
			for tc in g.tests {
				total++
				assert tc.result == 'invalid', 'tc ${tc.tc_id}: pk decode failed but expected ${tc.result}'
				passed++
			}
			continue
		}
		pk := PublicKey.from_bytes(pk_bytes, kind) or {
			for tc in g.tests {
				total++
				assert tc.result == 'invalid', 'tc ${tc.tc_id}: pk parse failed but expected ${tc.result}'
				passed++
			}
			continue
		}

		for tc in g.tests {
			total++
			msg := hex.decode(tc.msg) or {
				assert tc.result == 'invalid', 'tc ${tc.tc_id}: msg decode failed but expected ${tc.result}'
				passed++
				continue
			}
			sig := hex.decode(tc.sig) or {
				assert tc.result == 'invalid', 'tc ${tc.tc_id}: sig decode failed but expected ${tc.result}'
				passed++
				continue
			}

			ctx := (hex.decode(tc.ctx) or { []u8{} }).bytestr()
			verified := pk.verify(msg, sig, context: ctx) or { false }

			match tc.result {
				'valid' {
					assert verified, 'tc ${tc.tc_id} (${tc.comment}): expected valid, got invalid'
				}
				'invalid' {
					assert !verified, 'tc ${tc.tc_id} (${tc.comment}): expected invalid, got valid'
				}
				'acceptable' {}
				else {
					assert false, 'tc ${tc.tc_id}: unknown result ${tc.result}'
				}
			}
			passed++
		}
	}
	assert total == tf.number_of_tests, 'expected ${tf.number_of_tests} tests, ran ${total}'
	println('${filename}: ${passed}/${total} passed')
}

fn test_wycheproof_mldsa_44() {
	run_wycheproof('mldsa_44_verify_test.json', .ml_dsa_44)!
}

fn test_wycheproof_mldsa_65() {
	run_wycheproof('mldsa_65_verify_test.json', .ml_dsa_65)!
}

fn test_wycheproof_mldsa_87() {
	run_wycheproof('mldsa_87_verify_test.json', .ml_dsa_87)!
}
