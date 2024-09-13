// These tests are derived from the Secure Hash Algorithm Validation System
// test vectors contained in:
// https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/shs/shabytetestvectors.zip
//
// For SHA512_256, the test vectors come from:
//     SHA512_256LongMsg.rsp
import crypto.sha512
import encoding.hex
import os

fn test_long_messages() {
	long_case_files := os.walk_ext('${os.dir(@FILE)}/testdata/sha512_256_long_msg_tests/',
		'.txt')

	for file_name in long_case_files {
		lines := os.read_lines(file_name)!
		message := hex.decode(lines[0])!
		expected_result := hex.decode(lines[1])!

		actual_result := sha512.sum512_256(message)

		assert actual_result == expected_result, 'failed ${os.file_name(file_name)}'
	}
}