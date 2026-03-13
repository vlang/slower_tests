// NIST ACVP test vectors for SHAKE-128, SHAKE-256.
// tests: AFT (Algorithm Functional Test) and VOT (Variable Output Test)
// vectors from: https://github.com/usnistgov/ACVP-Server/tree/master/gen-val/json-files

// only byte-aligned messages (len % 8 == 0) are tested
import encoding.hex
import json
import os
import crypto.sha3

struct ShakeTest {
	tc_id   int @[json: 'tcId']
	msg     string
	msg_len int @[json: 'len']
	out_len int @[json: 'outLen']
}

struct ShakeGroup {
	tg_id     int    @[json: 'tgId']
	test_type string @[json: 'testType']
	tests     []ShakeTest
}

struct ShakePrompt {
	algorithm   string
	test_groups []ShakeGroup @[json: 'testGroups']
}

struct ShakeResult {
	tc_id   int @[json: 'tcId']
	md      string
	out_len int @[json: 'outLen']
}

struct ShakeResultGroup {
	tg_id int @[json: 'tgId']
	tests []ShakeResult
}

struct ShakeExpected {
	test_groups []ShakeResultGroup @[json: 'testGroups']
}

fn load_shake_vectors(name string) !(ShakePrompt, map[int]ShakeResult) {
	dir := os.dir(@FILE)
	prompt_raw := os.read_file(os.join_path(dir, 'testdata', '${name}_prompt.json'))!
	expected_raw := os.read_file(os.join_path(dir, 'testdata', '${name}_expected.json'))!
	prompt := json.decode(ShakePrompt, prompt_raw)!
	expected := json.decode(ShakeExpected, expected_raw)!

	mut results := map[int]ShakeResult{}
	for g in expected.test_groups {
		for t in g.tests {
			results[t.tc_id] = t
		}
	}
	return prompt, results
}

fn shake_hash(algorithm string, data []u8, output_len int) []u8 {
	return match algorithm {
		'SHAKE-128' { sha3.shake128(data, output_len) }
		'SHAKE-256' { sha3.shake256(data, output_len) }
		else { panic('unknown algorithm: ${algorithm}') }
	}
}

// run_shake_aft runs AFT and VOT tests (same structure).
fn run_shake_aft(prompt ShakePrompt, results map[int]ShakeResult, test_type string) {
	mut total := 0
	for g in prompt.test_groups {
		if g.test_type != test_type {
			continue
		}
		for t in g.tests {
			if t.msg_len % 8 != 0 || t.out_len % 8 != 0 {
				continue
			}
			byte_len := t.msg_len / 8
			out_byte_len := t.out_len / 8

			msg_bytes := if byte_len == 0 {
				[]u8{}
			} else {
				hex.decode(t.msg) or { panic('tcId ${t.tc_id}: bad msg hex: ${err}') }
			}
			input := if msg_bytes.len > byte_len {
				msg_bytes[..byte_len]
			} else {
				msg_bytes
			}

			got := shake_hash(prompt.algorithm, input, out_byte_len)
			want_result := results[t.tc_id]
			want := hex.decode(want_result.md) or {
				panic('tcId ${t.tc_id}: bad expected md hex: ${err}')
			}

			assert got == want, 'NIST ACVP ${prompt.algorithm} ${test_type} tcId ${t.tc_id}: output mismatch'
			total++
		}
	}
	assert total > 0, 'no ${prompt.algorithm} ${test_type} tests were run'
}

fn test_nist_acvp_shake_128_aft() {
	prompt, results := load_shake_vectors('shake_128') or { panic(err) }
	run_shake_aft(prompt, results, 'AFT')
}

fn test_nist_acvp_shake_128_vot() {
	prompt, results := load_shake_vectors('shake_128') or { panic(err) }
	run_shake_aft(prompt, results, 'VOT')
}

fn test_nist_acvp_shake_256_aft() {
	prompt, results := load_shake_vectors('shake_256') or { panic(err) }
	run_shake_aft(prompt, results, 'AFT')
}

fn test_nist_acvp_shake_256_vot() {
	prompt, results := load_shake_vectors('shake_256') or { panic(err) }
	run_shake_aft(prompt, results, 'VOT')
}
