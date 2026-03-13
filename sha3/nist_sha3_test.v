// NIST ACVP test vectors for SHA3-224, SHA3-256, SHA3-384, SHA3-512.
// tests: AFT (Algorithm Functional Test) and MCT (Monte Carlo Test).
// vectors from: https://github.com/usnistgov/ACVP-Server/tree/master/gen-val/json-files

// only byte-aligned messages (len % 8 == 0) are tested
import encoding.hex
import json
import os
import crypto.sha3

struct Sha3Test {
	tc_id   int @[json: 'tcId']
	msg     string
	msg_len int @[json: 'len']
}

struct Sha3Group {
	tg_id     int    @[json: 'tgId']
	test_type string @[json: 'testType']
	tests     []Sha3Test
}

struct Sha3Prompt {
	algorithm   string
	test_groups []Sha3Group @[json: 'testGroups']
}

struct MdEntry {
	md string
}

struct Sha3Result {
	tc_id         int @[json: 'tcId']
	md            string
	results_array []MdEntry @[json: 'resultsArray']
}

struct Sha3ResultGroup {
	tg_id int @[json: 'tgId']
	tests []Sha3Result
}

struct Sha3Expected {
	test_groups []Sha3ResultGroup @[json: 'testGroups']
}

fn load_sha3_vectors(name string) !(Sha3Prompt, map[int]Sha3Result) {
	dir := os.dir(@FILE)
	prompt_raw := os.read_file(os.join_path(dir, 'testdata', '${name}_prompt.json'))!
	expected_raw := os.read_file(os.join_path(dir, 'testdata', '${name}_expected.json'))!
	prompt := json.decode(Sha3Prompt, prompt_raw)!
	expected := json.decode(Sha3Expected, expected_raw)!

	mut results := map[int]Sha3Result{}
	for g in expected.test_groups {
		for t in g.tests {
			results[t.tc_id] = t
		}
	}
	return prompt, results
}

fn sha3_hash(algorithm string, data []u8) []u8 {
	return match algorithm {
		'SHA3-224' { sha3.sum224(data) }
		'SHA3-256' { sha3.sum256(data) }
		'SHA3-384' { sha3.sum384(data) }
		'SHA3-512' { sha3.sum512(data) }
		else { panic('unknown algorithm: ${algorithm}') }
	}
}

fn run_sha3_aft(prompt Sha3Prompt, results map[int]Sha3Result) {
	mut total := 0
	for g in prompt.test_groups {
		if g.test_type != 'AFT' {
			continue
		}
		for t in g.tests {
			if t.msg_len % 8 != 0 {
				continue
			}
			byte_len := t.msg_len / 8
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

			got := sha3_hash(prompt.algorithm, input)
			want_result := results[t.tc_id]
			want := hex.decode(want_result.md) or {
				panic('tcId ${t.tc_id}: bad expected md hex: ${err}')
			}

			assert got == want, 'NIST ACVP ${prompt.algorithm} AFT tcId ${t.tc_id}: digest mismatch'
			total++
		}
	}
	assert total > 0, 'no ${prompt.algorithm} AFT tests were run'
}

// 100 outer iters + each with 1000 inner
fn run_sha3_mct(prompt Sha3Prompt, results map[int]Sha3Result) {
	for g in prompt.test_groups {
		if g.test_type != 'MCT' {
			continue
		}
		for t in g.tests {
			expected := results[t.tc_id]
			mut md := hex.decode(t.msg) or { panic('MCT tcId ${t.tc_id}: bad seed hex: ${err}') }

			for i, want_entry in expected.results_array {
				for _ in 0 .. 1000 {
					md = sha3_hash(prompt.algorithm, md)
				}
				want := hex.decode(want_entry.md) or {
					panic('MCT tcId ${t.tc_id} iter ${i}: bad md hex: ${err}')
				}
				assert md == want, 'NIST ACVP ${prompt.algorithm} MCT tcId ${t.tc_id} iteration ${i}: mismatch'
			}
		}
	}
}

fn test_nist_acvp_sha3_224_aft() {
	prompt, results := load_sha3_vectors('sha3_224') or { panic(err) }
	run_sha3_aft(prompt, results)
}

fn test_nist_acvp_sha3_224_mct() {
	prompt, results := load_sha3_vectors('sha3_224') or { panic(err) }
	run_sha3_mct(prompt, results)
}

fn test_nist_acvp_sha3_256_aft() {
	prompt, results := load_sha3_vectors('sha3_256') or { panic(err) }
	run_sha3_aft(prompt, results)
}

fn test_nist_acvp_sha3_256_mct() {
	prompt, results := load_sha3_vectors('sha3_256') or { panic(err) }
	run_sha3_mct(prompt, results)
}

fn test_nist_acvp_sha3_384_aft() {
	prompt, results := load_sha3_vectors('sha3_384') or { panic(err) }
	run_sha3_aft(prompt, results)
}

fn test_nist_acvp_sha3_384_mct() {
	prompt, results := load_sha3_vectors('sha3_384') or { panic(err) }
	run_sha3_mct(prompt, results)
}

fn test_nist_acvp_sha3_512_aft() {
	prompt, results := load_sha3_vectors('sha3_512') or { panic(err) }
	run_sha3_aft(prompt, results)
}

fn test_nist_acvp_sha3_512_mct() {
	prompt, results := load_sha3_vectors('sha3_512') or { panic(err) }
	run_sha3_mct(prompt, results)
}
