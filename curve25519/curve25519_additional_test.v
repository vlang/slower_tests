// The additional test for `x.crypto.curve25519` module.
//
// These tests contains two additional test
// The first was vector tests taken and adapted from
// https://github.com/LoupVaillant/Monocypher/blob/master/tests/gen/vectors/x25519
// The second test was the slow version of the type 2 of RFC 7748 test vector,
// that was included in the main test module, but slightly modified by reducing
// iteration number.
module main

import encoding.hex
import x.crypto.curve25519

// Random tests
//
fn test_random_vectors_ones() ! {
	for mut item in random_normal_vectors {
		shared_sec := curve25519.x25519(mut item.pvkey, item.pbkey)!
		assert shared_sec == item.expected_shared
	}
}

struct RandomTestOne {
mut:
	pvkey           []u8
	pbkey           []u8
	expected_shared []u8
}

const random_normal_vectors = [
	RandomTestOne{
		pvkey:           hex.decode('a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4')!
		pbkey:           hex.decode('e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c')!
		expected_shared: hex.decode('c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552')!
	},
	RandomTestOne{
		pvkey:           hex.decode('4b66e9d4d1b4673c5ad22691957d6af5c11b6421e0ea01d42ca4169e7918ba0d')!
		pbkey:           hex.decode('e5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a493')!
		expected_shared: hex.decode('95cbde9476e8907d7aade45cb4b873f88b595a68799fa152e6f8f7647aac7957')!
	},
	RandomTestOne{
		pvkey:           hex.decode('77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a')!
		pbkey:           hex.decode('de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f')!
		expected_shared: hex.decode('4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742')!
	},
	RandomTestOne{
		pvkey:           hex.decode('5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb')!
		pbkey:           hex.decode('8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a')!
		expected_shared: hex.decode('4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742')!
	},
]

// First iteration of the iterated scalarmult test
//
fn test_first_iteration() ! {
	pvkey := hex.decode('0900000000000000000000000000000000000000000000000000000000000000')!
	pbkey := hex.decode('0900000000000000000000000000000000000000000000000000000000000000')!
	expected_shared := hex.decode('422c8e7a6227d7bca1350b3e2bb7279f7897b87bb6854b783c60e80311ae3079')!

	mut pvk := curve25519.PrivateKey.new_from_seed(pvkey)!

	shared_sec := pvk.x25519(pbkey)!
	assert shared_sec == expected_shared
}

// Daniel Bleichenbacher test vectors from Wycheproof:
// https://github.com/google/wycheproof/blob/master/testvectors/x25519_test.json
//
fn test_wycheproof_vector_data_normal_and_on_twist() ! {
	for mut item in wycheproof_vector_tests {
		shared_sec := curve25519.x25519(mut item.pvkey, item.pbkey)!
		assert shared_sec == item.expected_shared
	}
}

struct NormalAndlTwisted {
	title  string
	status string
mut:
	pvkey           []u8
	pbkey           []u8
	expected_shared []u8
	err             IError
}

const wycheproof_vector_tests = [
	NormalAndlTwisted{
		title:           '# normal case'
		status:          '# valid'
		pvkey:           hex.decode('c8a9d5a91091ad851c668b0736c1c9a02936c0d3ad62670858088047ba057475')!
		pbkey:           hex.decode('504a36999f489cd2fdbc08baff3d88fa00569ba986cba22548ffde80f9806829')!
		expected_shared: hex.decode('436a2c040cf45fea9b29a0cb81b1f41458f863d0d61b453d0a982720d6d61320')!
		err:             none
	},
	NormalAndlTwisted{
		title:           '# public key on twist'
		status:          '# acceptable: Twist'
		pvkey:           hex.decode('d85d8c061a50804ac488ad774ac716c3f5ba714b2712e048491379a500211958')!
		pbkey:           hex.decode('63aa40c6e38346c5caf23a6df0a5e6c80889a08647e551b3563449befcfc9733')!
		expected_shared: hex.decode('279df67a7c4611db4708a0e8282b195e5ac0ed6f4b2f292c6fbd0acac30d1332')!
		err:             none
	},
	NormalAndlTwisted{
		title:           '# public key on twist'
		status:          '# acceptable: Twist'
		pvkey:           hex.decode('c8b45bfd32e55325d9fd648cb302848039000b390e44d521e58aab3b29a6964b')!
		pbkey:           hex.decode('0f83c36fded9d32fadf4efa3ae93a90bb5cfa66893bc412c43fa7287dbb99779')!
		expected_shared: hex.decode('4bc7e01e7d83d6cf67632bf90033487a5fc29eba5328890ea7b1026d23b9a45f')!
		err:             none
	},
	NormalAndlTwisted{
		title:           '# public key on twist'
		status:          '# acceptable: Twist'
		pvkey:           hex.decode('f876e34bcbe1f47fbc0fddfd7c1e1aa53d57bfe0f66d243067b424bb6210be51')!
		pbkey:           hex.decode('0b8211a2b6049097f6871c6c052d3c5fc1ba17da9e32ae458403b05bb283092a')!
		expected_shared: hex.decode('119d37ed4b109cbd6418b1f28dea83c836c844715cdf98a3a8c362191debd514')!
		err:             none
	},
	NormalAndlTwisted{
		title:           '# public key on twist'
		status:          '# acceptable: Twist'
		pvkey:           hex.decode('006ac1f3a653a4cdb1d37bba94738f8b957a57beb24d646e994dc29a276aad45')!
		pbkey:           hex.decode('343ac20a3b9c6a27b1008176509ad30735856ec1c8d8fcae13912d08d152f46c')!
		expected_shared: hex.decode('cc4873aed3fcee4b3aaea7f0d20716b4276359081f634b7bea4b705bfc8a4d3e')!
		err:             none
	},
	NormalAndlTwisted{
		title:           '# public key on twist'
		status:          '# acceptable: Twist'
		pvkey:           hex.decode('08da77b26d06dff9d9f7fd4c5b3769f8cdd5b30516a5ab806be324ff3eb69e60')!
		pbkey:           hex.decode('fa695fc7be8d1be5bf704898f388c452bafdd3b8eae805f8681a8d15c2d4e142')!
		expected_shared: hex.decode('b6f8e2fcb1affc79e2ff798319b2701139b95ad6dd07f05cbac78bd83edfd92e')!
		err:             none
	},
	NormalAndlTwisted{
		title:           '# public key on twist'
		status:          '# acceptable: Twist'
		pvkey:           hex.decode('d03edde9f3e7b799045f9ac3793d4a9277dadeadc41bec0290f81f744f73775f')!
		pbkey:           hex.decode('0200000000000000000000000000000000000000000000000000000000000000')!
		expected_shared: hex.decode('b87a1722cc6c1e2feecb54e97abd5a22acc27616f78f6e315fd2b73d9f221e57')!
		err:             none
	},
	NormalAndlTwisted{
		title:           '# public key on twist'
		status:          '# acceptable: Twist'
		pvkey:           hex.decode('e09d57a914e3c29036fd9a442ba526b5cdcdf28216153e636c10677acab6bd6a')!
		pbkey:           hex.decode('0300000000000000000000000000000000000000000000000000000000000000')!
		expected_shared: hex.decode('a29d8dad28d590cd3017aa97a4761f851bf1d3672b042a4256a45881e2ad9035')!
		err:             none
	},
	NormalAndlTwisted{
		title:           '# public key on twist'
		status:          '# acceptable: Twist'
		pvkey:           hex.decode('e0ed78e6ee02f08bec1c15d66fbbe5b83ffc37ea14e1512cc1bd4b2ea6d8066f')!
		pbkey:           hex.decode('ff00000000000000000000000000000000000000000000000000000000000000')!
		expected_shared: hex.decode('e703bc8aa94b7d87ba34e2678353d12cdaaa1a97b5ca3e1b8c060c4636087f07')!
		err:             none
	},
	NormalAndlTwisted{
		title:           '# public key on twist'
		status:          '# acceptable: Twist'
		pvkey:           hex.decode('a8a1a2ec9fa9915ae7aace6a37c68591d39e15995c4ef5ebd3561c02f72dda41')!
		pbkey:           hex.decode('ffff000000000000000000000000000000000000000000000000000000000000')!
		expected_shared: hex.decode('ff5cf041e924dbe1a64ac9bdba96bdcdfaf7d59d91c7e33e76ed0e4c8c836446')!
		err:             none
	},
	NormalAndlTwisted{
		title:           '# public key on twist'
		status:          '# acceptable: Twist'
		pvkey:           hex.decode('a8c9df5820eb399d471dfa3215d96055b3c7d0f4ea49f8ab028d6a6e3194517b')!
		pbkey:           hex.decode('0000010000000000000000000000000000000000000000000000000000000000')!
		expected_shared: hex.decode('a92a96fa029960f9530e6fe37e2429cd113be4d8f3f4431f8546e6c76351475d')!
		err:             none
	},
	NormalAndlTwisted{
		title:           '# public key on twist'
		status:          '# acceptable: Twist'
		pvkey:           hex.decode('d0d31c491cbd39271859b4a63a316826507b1db8c701709fd0ffe3eb21c4467c')!
		pbkey:           hex.decode('ffffff0f00000000000000000000000000000000000000000000000000000000')!
		expected_shared: hex.decode('9f8954868158ec62b6b586b8cae1d67d1b9f4c03d5b3ca0393cee71accc9ab65')!
		err:             none
	},
	NormalAndlTwisted{
		title:           '# public key on twist'
		status:          '# acceptable: Twist'
		pvkey:           hex.decode('d053e7bf1902619cd61c9c739e09d54c4147f46d190720966f7de1d9cffbbd4e')!
		pbkey:           hex.decode('ffffffff00000000000000000000000000000000000000000000000000000000')!
		expected_shared: hex.decode('6cbf1dc9af97bc148513a18be4a257de1a3b065584df94e8b43c1ab89720b110')!
		err:             none
	},
	NormalAndlTwisted{
		title:           '# public key on twist'
		status:          '# acceptable: Twist'
		pvkey:           hex.decode('a021d75009a4596e5a33f12921c10f3670933bc80dde3bba22881b6120582144')!
		pbkey:           hex.decode('0000000000001000000000000000000000000000000000000000000000000000')!
		expected_shared: hex.decode('38284b7086095a9406028c1f800c071ea106039ad7a1d7f82fe00906fd90594b')!
		err:             none
	},
	NormalAndlTwisted{
		title:           '# public key on twist'
		status:          '# acceptable: Twist'
		pvkey:           hex.decode('a89c6687f99bd569a01fd8bd438236160d15ce2c57c1d71ebaa3f2da88233863')!
		pbkey:           hex.decode('0000000000000001000000000000000000000000000000000000000000000000')!
		expected_shared: hex.decode('c721041df0244071794a8db06b9f7eaeec690c257265343666f4416f4166840f')!
		err:             none
	},
	NormalAndlTwisted{
		title:           '# public key on twist'
		status:          '# acceptable: Twist'
		pvkey:           hex.decode('68964bca51465bf0f5ba524b1482ceff0e960a1ed9f48dcc30f1608d0e501a50')!
		pbkey:           hex.decode('ffffffffffffffff000000000000000000000000000000000000000000000000')!
		expected_shared: hex.decode('25ff9a6631b143dbdbdc207b38e38f832ae079a52a618c534322e77345fd9049')!
		err:             none
	},
	NormalAndlTwisted{
		title:           '# public key on twist'
		status:          '# acceptable: Twist'
		pvkey:           hex.decode('a8e56bb13a9f2b33b8e6750b4a6e6621dc26ae8c5c624a0992c8f0d5b910f170')!
		pbkey:           hex.decode('0000000000000000000000000000000000000000000000000100000000000000')!
		expected_shared: hex.decode('f294e7922c6cea587aefe72911630d50f2456a2ba7f21207d57f1ecce04f6213')!
		err:             none
	},
	NormalAndlTwisted{
		title:           '# public key on twist'
		status:          '# acceptable: Twist'
		pvkey:           hex.decode('e045f55c159451e97814d747050fd7769bd478434a01876a56e553f66384a74c')!
		pbkey:           hex.decode('ffffffffffffffffffffffffffffffffffffffffffffffffffffffff00000000')!
		expected_shared: hex.decode('ff4715bd8cf847b77c244ce2d9b008b19efaa8e845feb85ce4889b5b2c6a4b4d')!
		err:             none
	},
	NormalAndlTwisted{
		title:           '# public key on twist'
		status:          '# acceptable: Twist'
		pvkey:           hex.decode('105d621e1ef339c3d99245cfb77cd3a5bd0c4427a0e4d8752c3b51f045889b4f')!
		pbkey:           hex.decode('ffffff030000f8ffff1f0000c0ffffff000000feffff070000f0ffff3f000000')!
		expected_shared: hex.decode('61eace52da5f5ecefafa4f199b077ff64f2e3d2a6ece6f8ec0497826b212ef5f')!
		err:             none
	},
	NormalAndlTwisted{
		title:           '# public key on twist'
		status:          '# acceptable: Twist'
		pvkey:           hex.decode('d88a441e706f606ae7f630f8b21f3c2554739e3e549f804118c03771f608017b')!
		pbkey:           hex.decode('ffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f0000')!
		expected_shared: hex.decode('ff1b509a0a1a54726086f1e1c0acf040ab463a2a542e5d54e92c6df8126cf636')!
		err:             none
	},
	NormalAndlTwisted{
		title:           '# public key on twist'
		status:          '# acceptable: Twist'
		pvkey:           hex.decode('80bbad168222276200aafd36f7f25fdc025632d8bf9f6354bb762e06fb63e250')!
		pbkey:           hex.decode('0000000000000000000000000000000000000000000000000000000000800000')!
		expected_shared: hex.decode('f134e6267bf93903085117b99932cc0c7ba26f25fca12102a26d7533d9c4272a')!
		err:             none
	},
	NormalAndlTwisted{
		title:           '# public key on twist'
		status:          '# acceptable: Twist'
		pvkey:           hex.decode('68e134092e94e622c8a0cd18aff55be23dabd994ebdee982d90601f6f0f4b369')!
		pbkey:           hex.decode('ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff1f')!
		expected_shared: hex.decode('74bfc15e5597e9f5193f941e10a5c008fc89f051392723886a4a8fe5093a7354')!
		err:             none
	},
	NormalAndlTwisted{
		title:           '# public key on twist'
		status:          '# acceptable: Twist'
		pvkey:           hex.decode('e8e43fc1ebac0bbc9b99c8035ee1ac59b90f19a16c42c0b90f96adfcc5fdee78')!
		pbkey:           hex.decode('0000000000000000000000000000000000000000000000000000000000000020')!
		expected_shared: hex.decode('0d41a5b3af770bf2fcd34ff7972243a0e2cf4d34f2046a144581ae1ec68df03b')!
		err:             none
	},
	NormalAndlTwisted{
		title:           '# public key on twist'
		status:          '# acceptable: Twist'
		pvkey:           hex.decode('18bffb16f92680a9e267473e43c464476d5372ddd1f664f3d0678efe7c98bc79')!
		pbkey:           hex.decode('000000fcffff070000e0ffff3f000000ffffff010000f8ffff0f0000c0ffff7f')!
		expected_shared: hex.decode('5894e0963583ae14a0b80420894167f4b759c8d2eb9b69cb675543f66510f646')!
		err:             none
	},
	NormalAndlTwisted{
		title:           '# public key on twist'
		status:          '# acceptable: Twist'
		pvkey:           hex.decode('300305eb002bf86c71fe9c0b311993727b9dc618d0ce7251d0dfd8552d17905d')!
		pbkey:           hex.decode('ffffffffffffff00000000000000ffffffffffffff00000000000000ffffff7f')!
		expected_shared: hex.decode('f8624d6e35e6c548ac47832f2e5d151a8e53b9290363b28d2ab8d84ab7cb6a72')!
		err:             none
	},
	NormalAndlTwisted{
		title:           '# public key on twist'
		status:          '# acceptable: Twist'
		pvkey:           hex.decode('80da9f02842247d4ade5ddbac51dbce55ea7dca2844e7f97ab8987ce7fd8bc71')!
		pbkey:           hex.decode('00000000ffffffff00000000ffffffff00000000ffffffff00000000ffffff7f')!
		expected_shared: hex.decode('bfe183ba3d4157a7b53ef178613db619e27800f85359c0b39a9fd6e32152c208')!
		err:             none
	},
	NormalAndlTwisted{
		title:           '# public key on twist'
		status:          '# acceptable: Twist'
		pvkey:           hex.decode('806e7f26ca3246de8182946cbed09f52b95da626c823c7b50450001a47b7b252')!
		pbkey:           hex.decode('edfffffffffffffffffffffffffffeffffffffffffffffffffffffffffffff7f')!
		expected_shared: hex.decode('bca4a0724f5c1feb184078448c898c8620e7caf81f64cca746f557dff2498859')!
		err:             none
	},
	NormalAndlTwisted{
		title:           '# public key on twist'
		status:          '# acceptable: Twist'
		pvkey:           hex.decode('58354fd64bc022cba3a71b2ae64281e4ea7bf6d65fdbaead1440eeb18604fe62')!
		pbkey:           hex.decode('edfffffffffffffeffffffffffffffffffffffffffffffffffffffffffffff7f')!
		expected_shared: hex.decode('b3418a52464c15ab0cacbbd43887a1199206d59229ced49202300638d7a40f04')!
		err:             none
	},
	NormalAndlTwisted{
		title:           '# public key on twist'
		status:          '# acceptable: Twist'
		pvkey:           hex.decode('f0019cf05159794cc8052b00c2e75b7f46fb6693c4b38c02b12a4fe272e8556a')!
		pbkey:           hex.decode('edffffffffffefffffffffffffffffffffffffffffffffffffffffffffffff7f')!
		expected_shared: hex.decode('fcde6e0a3d5fd5b63f10c2d3aad4efa05196f26bc0cb26fd6d9d3bd015eaa74f')!
		err:             none
	},
	NormalAndlTwisted{
		title:           '# public key on twist'
		status:          '# acceptable: Twist'
		pvkey:           hex.decode('d0fca64cc5f3a0c8e75c824e8b09d1615aa79aeba139bb7302e2bb2fcbe54b40')!
		pbkey:           hex.decode('edfeffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f')!
		expected_shared: hex.decode('7d62f189444c6231a48afab10a0af2eee4a52e431ea05ff781d616af2114672f')!
		err:             none
	},
	NormalAndlTwisted{
		title:           '# public key on twist'
		status:          '# acceptable: Twist'
		pvkey:           hex.decode('d02456e456911d3c6cd054933199807732dfdc958642ad1aebe900c793bef24a')!
		pbkey:           hex.decode('eaffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f')!
		expected_shared: hex.decode('07ba5fcbda21a9a17845c401492b10e6de0a168d5c94b606694c11bac39bea41')!
		err:             none
	},
]

// SmallPublicKey, LowOrderPublic, ZeroSharedSecret test
//
struct SmallLowOrderPKZeros {
	title  string
	status string
mut:
	pvkey           []u8
	pbkey           []u8
	expected_shared []u8
	err             IError
}

const smallloworderpk_zeroshared = [
	SmallLowOrderPKZeros{
		title:  '# public key = 0'
		status: '# acceptable: SmallPublicKey, LowOrderPublic, ZeroSharedSecret'
		pvkey:  hex.decode('88227494038f2bb811d47805bcdf04a2ac585ada7f2f23389bfd4658f9ddd45e')!
		// this zeros public key was early rejected on latest module updates
		pbkey:           hex.decode('0000000000000000000000000000000000000000000000000000000000000000')!
		expected_shared: hex.decode('0000000000000000000000000000000000000000000000000000000000000000')!
		err:             error('x25519: unallowed zeros/scalar point')
	},
	SmallLowOrderPKZeros{
		title:  '# public key = 1'
		status: '# acceptable: SmallPublicKey, LowOrderPublic, ZeroSharedSecret'
		pvkey:  hex.decode('48232e8972b61c7e61930eb9450b5070eae1c670475685541f0476217e48184f')!
		// TODO: should this ones be rejected ?
		pbkey:           hex.decode('0100000000000000000000000000000000000000000000000000000000000000')!
		expected_shared: hex.decode('0000000000000000000000000000000000000000000000000000000000000000')!
		err:             error('bad input point: low order point')
	},
	SmallLowOrderPKZeros{
		title:           '# public key with low order'
		status:          '# acceptable: LowOrderPublic, ZeroSharedSecret'
		pvkey:           hex.decode('e0f978dfcd3a8f1a5093418de54136a584c20b7b349afdf6c0520886f95b1272')!
		pbkey:           hex.decode('e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800')!
		expected_shared: hex.decode('0000000000000000000000000000000000000000000000000000000000000000')!
		err:             error('bad input point: low order point')
	},
	SmallLowOrderPKZeros{
		title:           '# public key with low order'
		status:          '# acceptable: LowOrderPublic, ZeroSharedSecret'
		pvkey:           hex.decode('387355d995616090503aafad49da01fb3dc3eda962704eaee6b86f9e20c92579')!
		pbkey:           hex.decode('5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f1157')!
		expected_shared: hex.decode('0000000000000000000000000000000000000000000000000000000000000000')!
		err:             error('bad input point: low order point')
	},
	SmallLowOrderPKZeros{
		title:           '# public key with low order'
		status:          '# acceptable: LowOrderPublic, Twist, ZeroSharedSecret'
		pvkey:           hex.decode('c8fe0df92ae68a03023fc0c9adb9557d31be7feed0d3ab36c558143daf4dbb40')!
		pbkey:           hex.decode('ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f')!
		expected_shared: hex.decode('0000000000000000000000000000000000000000000000000000000000000000')!
		err:             error('bad input point: low order point')
	},
	SmallLowOrderPKZeros{
		title:           '# public key with low order'
		status:          '# acceptable: LowOrderPublic, NonCanonicalPublic, Twist, ZeroSharedSecret'
		pvkey:           hex.decode('c8d74acde5934e64b9895d5ff7afbffd7f704f7dfccff7ac28fa62a1e6410347')!
		pbkey:           hex.decode('e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b880')!
		expected_shared: hex.decode('0000000000000000000000000000000000000000000000000000000000000000')!
		err:             error('bad input point: low order point')
	},
	SmallLowOrderPKZeros{
		title:           'public key = 57896044618658097711785492504343953926634992332820282019728792003956564819949'
		status:          '# acceptable: SmallPublicKey, LowOrderPublic, ZeroSharedSecret'
		pvkey:           hex.decode('40ff586e73d61f0960dc2d763ac19e98225f1194f6fe43d5dd97ad55b3d35961')!
		pbkey:           hex.decode('edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f')!
		expected_shared: hex.decode('0000000000000000000000000000000000000000000000000000000000000000')!
		err:             error('bad input point: low order point')
	},
	SmallLowOrderPKZeros{
		title:           'public key = 57896044618658097711785492504343953926634992332820282019728792003956564819950'
		status:          '# acceptable: SmallPublicKey, LowOrderPublic, NonCanonicalPublic, ZeroSharedSecret'
		pvkey:           hex.decode('584fceaebae944bfe93b2e0d0a575f706ce5ada1da2b1311c3b421f9186c7a6f')!
		pbkey:           hex.decode('eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f')!
		expected_shared: hex.decode('0000000000000000000000000000000000000000000000000000000000000000')!
		err:             error('bad input point: low order point')
	},
]

// We dont allow low order point, or zero point
//
fn test_wycheproof_small_loworder_zeroshared() ! {
	for mut item in smallloworderpk_zeroshared {
		shared_sec := curve25519.x25519(mut item.pvkey, item.pbkey) or {
			assert err == item.err
			continue
		}
		assert shared_sec == item.expected_shared
	}
}

// Non canonical public key
//
fn test_wycheproof_noncanonical_pubkey() ! {
	for mut item in noncanonical_pubkey_vectors {
		shared_sec := curve25519.x25519(mut item.pvkey, item.pbkey) or {
			assert err == item.err
			continue
		}
		assert shared_sec == item.expected_shared
	}
}

struct NonCanonicalPk {
	title  string
	status string
mut:
	pvkey           []u8
	pbkey           []u8
	expected_shared []u8
	err             IError
}

const noncanonical_pubkey_vectors = [
	NonCanonicalPk{
		title:           '# non-canonical public key'
		status:          '# acceptable: NonCanonicalPublic, Twist'
		pvkey:           hex.decode('0016b62af5cabde8c40938ebf2108e05d27fa0533ed85d70015ad4ad39762d54')!
		pbkey:           hex.decode('efffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f')!
		expected_shared: hex.decode('b4d10e832714972f96bd3382e4d082a21a8333a16315b3ffb536061d2482360d')!
		err:             none
	},
	NonCanonicalPk{
		title:           '# non-canonical public key'
		status:          '# acceptable: NonCanonicalPublic, Twist'
		pvkey:           hex.decode('d83650ba7cec115881916255e3fa5fa0d6b8dcf968731bd2c9d2aec3f561f649')!
		pbkey:           hex.decode('f0ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f')!
		expected_shared: hex.decode('515eac8f1ed0b00c70762322c3ef86716cd2c51fe77cec3d31b6388bc6eea336')!
		err:             none
	},
	NonCanonicalPk{
		title:           '# non-canonical public key'
		status:          '# acceptable: NonCanonicalPublic'
		pvkey:           hex.decode('88dd14e2711ebd0b0026c651264ca965e7e3da5082789fbab7e24425e7b4377e')!
		pbkey:           hex.decode('f1ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f')!
		expected_shared: hex.decode('6919992d6a591e77b3f2bacbd74caf3aea4be4802b18b2bc07eb09ade3ad6662')!
		err:             none
	},
	NonCanonicalPk{
		title:           '# non-canonical public key'
		status:          '# acceptable: NonCanonicalPublic'
		pvkey:           hex.decode('98c2b08cbac14e15953154e3b558d42bb1268a365b0ef2f22725129d8ac5cb7f')!
		pbkey:           hex.decode('ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f')!
		expected_shared: hex.decode('9c034fcd8d3bf69964958c0105161fcb5d1ea5b8f8abb371491e42a7684c2322')!
		err:             none
	},
	NonCanonicalPk{
		title:           '# non-canonical public key'
		status:          '# acceptable: NonCanonicalPublic, Twist'
		pvkey:           hex.decode('c0697b6f05e0f3433b44ea352f20508eb0623098a7770853af5ca09727340c4e')!
		pbkey:           hex.decode('0200000000000000000000000000000000000000000000000000000000000080')!
		expected_shared: hex.decode('ed18b06da512cab63f22d2d51d77d99facd3c4502e4abf4e97b094c20a9ddf10')!
		err:             none
	},
	NonCanonicalPk{
		title:           '# non-canonical public key'
		status:          '# acceptable: NonCanonicalPublic, Twist'
		pvkey:           hex.decode('18422b58a18e0f4519b7a887b8cfb649e0bfe4b34d75963350a9944e5b7f5b7e')!
		pbkey:           hex.decode('0300000000000000000000000000000000000000000000000000000000000080')!
		expected_shared: hex.decode('448ce410fffc7e6149c5abec0ad5f3607dfde8a34e2ac3243c3009176168b432')!
		err:             none
	},
	NonCanonicalPk{
		title:           '# non-canonical public key'
		status:          '# acceptable: NonCanonicalPublic'
		pvkey:           hex.decode('20620d82487707bedf9ee3549e95cb9390d2618f50cf6acba47ffaa103224a6f')!
		pbkey:           hex.decode('0400000000000000000000000000000000000000000000000000000000000080')!
		expected_shared: hex.decode('03a633df01480d0d5048d92f51b20dc1d11f73e9515c699429b90a4f6903122a')!
		err:             none
	},
	NonCanonicalPk{
		title:           '# non-canonical public key'
		status:          '# acceptable: NonCanonicalPublic'
		pvkey:           hex.decode('285a6a7ceeb7122f2c78d99c53b2a902b490892f7dff326f89d12673c3101b53')!
		pbkey:           hex.decode('daffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff')!
		expected_shared: hex.decode('9b01287717d72f4cfb583ec85f8f936849b17d978dbae7b837db56a62f100a68')!
		err:             none
	},
	NonCanonicalPk{
		title:           '# non-canonical public key'
		status:          '# acceptable: NonCanonicalPublic'
		pvkey:           hex.decode('c8e0330ae9dceeff887fba761225879a4bd2e0db08799244136e4721b2c88970')!
		pbkey:           hex.decode('dbffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff')!
		expected_shared: hex.decode('dfe60831c9f4f96c816e51048804dbdc27795d760eced75ef575cbe3b464054b')!
		err:             none
	},
	NonCanonicalPk{
		title:           '# non-canonical public key'
		status:          '# acceptable: NonCanonicalPublic, Twist'
		pvkey:           hex.decode('10db6210fc1fb13382472fa1787b004b5d11868ab3a79510e0cee30f4a6df26b')!
		pbkey:           hex.decode('dcffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff')!
		expected_shared: hex.decode('50bfa826ca77036dd2bbfd092c3f78e2e4a1f980d7c8e78f2f14dca3cce5cc3c')!
		err:             none
	},
	NonCanonicalPk{
		title:           '# non-canonical public key'
		status:          '# acceptable: NonCanonicalPublic'
		pvkey:           hex.decode('9041c6e044a277df8466275ca8b5ee0da7bc028648054ade5c592add3057474e')!
		pbkey:           hex.decode('eaffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff')!
		expected_shared: hex.decode('13da5695a4c206115409b5277a934782fe985fa050bc902cba5616f9156fe277')!
		err:             none
	},
	NonCanonicalPk{
		title:           '# non-canonical public key'
		status:          '# acceptable: NonCanonicalPublic'
		pvkey:           hex.decode('b8d499041a6713c0f6f876db7406587fdb44582f9542356ae89cfa958a34d266')!
		pbkey:           hex.decode('ebffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff')!
		expected_shared: hex.decode('63483b5d69236c63cddbed33d8e22baecc2b0ccf886598e863c844d2bf256704')!
		err:             none
	},
	NonCanonicalPk{
		title:           '# non-canonical public key'
		status:          '# acceptable: NonCanonicalPublic'
		pvkey:           hex.decode('c85f08e60c845f82099141a66dc4583d2b1040462c544d33d0453b20b1a6377e')!
		pbkey:           hex.decode('ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff')!
		expected_shared: hex.decode('e9db74bc88d0d9bf046ddd13f943bccbe6dbb47d49323f8dfeedc4a694991a3c')!
		err:             none
	},
]

// edge case public key testing
//
fn test_wycheproof_edge_cases_public_key() ! {
	for mut item in edge_case_pubkey_vectors {
		shared_sec := curve25519.x25519(mut item.pvkey, item.pbkey)!
		assert shared_sec == item.expected_shared
	}
}

struct EdgeCasePubkey {
	title  string
	status string
mut:
	pvkey           []u8
	pbkey           []u8
	expected_shared []u8
	err             IError
}

const edge_case_pubkey_vectors = [
	EdgeCasePubkey{
		title:           '# edge case public key'
		status:          '# valid'
		pvkey:           hex.decode('a8386f7f16c50731d64f82e6a170b142a4e34f31fd7768fcb8902925e7d1e25a')!
		pbkey:           hex.decode('0400000000000000000000000000000000000000000000000000000000000000')!
		expected_shared: hex.decode('34b7e4fa53264420d9f943d15513902342b386b172a0b0b7c8b8f2dd3d669f59')!
		err:             none
	},
	EdgeCasePubkey{
		title:           '# edge case public key'
		status:          '# valid'
		pvkey:           hex.decode('d05abd08bf5e62538cb9a5ed105dbedd6de38d07940085072b4311c2678ed77d')!
		pbkey:           hex.decode('0001000000000000000000000000000000000000000000000000000000000000')!
		expected_shared: hex.decode('3aa227a30781ed746bd4b3365e5f61461b844d09410c70570abd0d75574dfc77')!
		err:             none
	},
	EdgeCasePubkey{
		title:           '# edge case public key'
		status:          '# valid'
		pvkey:           hex.decode('f0b8b0998c8394364d7dcb25a3885e571374f91615275440db0645ee7c0a6f6b')!
		pbkey:           hex.decode('0000001000000000000000000000000000000000000000000000000000000000')!
		expected_shared: hex.decode('97755e7e775789184e176847ffbc2f8ef98799d46a709c6a1c0ffd29081d7039')!
		err:             none
	},
	EdgeCasePubkey{
		title:           '# edge case public key'
		status:          '# valid'
		pvkey:           hex.decode('d00c35dc17460f360bfae7b94647bc4e9a7ad9ce82abeadb50a2f1a0736e2175')!
		pbkey:           hex.decode('0000000001000000000000000000000000000000000000000000000000000000')!
		expected_shared: hex.decode('c212bfceb91f8588d46cd94684c2c9ee0734087796dc0a9f3404ff534012123d')!
		err:             none
	},
	EdgeCasePubkey{
		title:           '# edge case public key'
		status:          '# valid'
		pvkey:           hex.decode('385fc8058900a85021dd92425d2fb39a62d4e23aef1d5104c4c2d88712d39e4d')!
		pbkey:           hex.decode('ffffffffffff0f00000000000000000000000000000000000000000000000000')!
		expected_shared: hex.decode('388faffb4a85d06702ba3e479c6b216a8f33efce0542979bf129d860f93b9f02')!
		err:             none
	},
	EdgeCasePubkey{
		title:           '# edge case public key'
		status:          '# valid'
		pvkey:           hex.decode('e0614b0c408af24d9d24c0a72f9137fbd6b16f02ccc94797ea3971ab16073a7f')!
		pbkey:           hex.decode('ffffffffffffff00000000000000000000000000000000000000000000000000')!
		expected_shared: hex.decode('877fec0669d8c1a5c866641420eea9f6bd1dfd38d36a5d55a8c0ab2bf3105c68')!
		err:             none
	},
	EdgeCasePubkey{
		title:           '# edge case public key'
		status:          '# valid'
		pvkey:           hex.decode('f004b8fd05d9fffd853cdc6d2266389b737e8dfc296ad00b5a69b2a9dcf72956')!
		pbkey:           hex.decode('0000000000000000010000000000000000000000000000000000000000000000')!
		expected_shared: hex.decode('180373ea0f23ea73447e5a90398a97d490b541c69320719d7dd733fb80d5480f')!
		err:             none
	},
	EdgeCasePubkey{
		title:           '# edge case public key'
		status:          '# valid'
		pvkey:           hex.decode('e80bf0e609bf3b035b552f9db7e9ecbc44a04b7910b1493661a524f46c3c2277')!
		pbkey:           hex.decode('ffffffffffffffffffffffffffff000000000000000000000000000000000000')!
		expected_shared: hex.decode('208142350af938aba52a156dce19d3c27ab1628729683cf4ef2667c3dc60cf38')!
		err:             none
	},
	EdgeCasePubkey{
		title:           '# edge case public key'
		status:          '# valid'
		pvkey:           hex.decode('48890e95d1b03e603bcb51fdf6f296f1f1d10f5df10e00b8a25c9809f9aa1a54')!
		pbkey:           hex.decode('0000000000000000000000000000010000000000000000000000000000000000')!
		expected_shared: hex.decode('1c3263890f7a081cefe50cb92abd496582d90dcc2b9cb858bd286854aa6b0a7e')!
		err:             none
	},
	EdgeCasePubkey{
		title:           '# edge case public key'
		status:          '# valid'
		pvkey:           hex.decode('a806f1e39b742615a7dde3b29415ed827c68f07d4a47a4d9595c40c7fccb9263')!
		pbkey:           hex.decode('ffffffffffffffffffffffffffffffff00000000000000000000000000000000')!
		expected_shared: hex.decode('56128e78d7c66f48e863e7e6f2caa9c0988fd439deac11d4aac9664083087f7a')!
		err:             none
	},
	EdgeCasePubkey{
		title:           '# edge case public key'
		status:          '# valid'
		pvkey:           hex.decode('9899d5e265e1fc7c32345227d6699a6d6b5517cf33b43ab156ee20df4878794e')!
		pbkey:           hex.decode('0000000000000000000000000000000001000000000000000000000000000000')!
		expected_shared: hex.decode('30eca56f1f1c2e8ff780134e0e9382c5927d305d86b53477e9aeca79fc9ced05')!
		err:             none
	},
	EdgeCasePubkey{
		title:           '# edge case public key'
		status:          '# valid'
		pvkey:           hex.decode('d842316e5476aeaee838204258a06f15de011ba40b9962705e7f6e889fe71f40')!
		pbkey:           hex.decode('ffffffffffffffffffffffffffffffffffffffffffffffff0000000000000000')!
		expected_shared: hex.decode('cb21b7aa3f992ecfc92954849154b3af6b96a01f17bf21c612da748db38eb364')!
		err:             none
	},
	EdgeCasePubkey{
		title:           '# edge case public key'
		status:          '# valid'
		pvkey:           hex.decode('a0933ee30512b25ee4e900aaa07f73e507a8ec53b53a44626e0f589af4e0356c')!
		pbkey:           hex.decode('ffffffff00000000ffffffff00000000ffffffff00000000ffffffff00000000')!
		expected_shared: hex.decode('c5caf8cabc36f086deaf1ab226434098c222abdf8acd3ce75c75e9debb271524')!
		err:             none
	},
	EdgeCasePubkey{
		title:           '# edge case public key'
		status:          '# valid'
		pvkey:           hex.decode('38d6403e1377734cdce98285e820f256ad6b769d6b5612bcf42cf2b97945c073')!
		pbkey:           hex.decode('0000000000000000000000000000000000000000000000000000000001000000')!
		expected_shared: hex.decode('4d46052c7eabba215df8d91327e0c4610421d2d9129b1486d914c766cf104c27')!
		err:             none
	},
	EdgeCasePubkey{
		title:           '# edge case public key'
		status:          '# valid'
		pvkey:           hex.decode('182191b7052e9cd630ef08007fc6b43bc7652913be6774e2fd271b71b962a641')!
		pbkey:           hex.decode('ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff03')!
		expected_shared: hex.decode('a0e0315175788362d4ebe05e6ac76d52d40187bd687492af05abc7ba7c70197d')!
		err:             none
	},
	EdgeCasePubkey{
		title:           '# edge case public key'
		status:          '# valid'
		pvkey:           hex.decode('106221fe5694a710d6e147696c5d5b93d6887d584f24f228182ebe1b1d2db85d')!
		pbkey:           hex.decode('ffffff0f000000ffffff0f000000ffffff0f000000ffffff0f000000ffffff0f')!
		expected_shared: hex.decode('5e64924b91873b499a5402fa64337c65d4b2ed54beeb3fa5d7347809e43aef1c')!
		err:             none
	},
	EdgeCasePubkey{
		title:           '# edge case public key'
		status:          '# valid'
		pvkey:           hex.decode('d035de9456080d85a912083b2e3c7ddd7971f786f25a96c5e782cf6f4376e362')!
		pbkey:           hex.decode('000000fcffff030000e0ffff1f000000ffffff000000f8ffff070000c0ffff3f')!
		expected_shared: hex.decode('c052466f9712d9ec4ef40f276bb7e6441c5434a83efd8e41d20ce83f2dbf5952')!
		err:             none
	},
	EdgeCasePubkey{
		title:           '# edge case public key'
		status:          '# valid'
		pvkey:           hex.decode('a8f37318a4c760f3cb2d894822918735683cb1edacf3e666e15694154978fd6d')!
		pbkey:           hex.decode('ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff3f')!
		expected_shared: hex.decode('d151b97cba9c25d48e6d576338b97d53dd8b25e84f65f7a2091a17016317c553')!
		err:             none
	},
	EdgeCasePubkey{
		title:           '# edge case public key'
		status:          '# valid'
		pvkey:           hex.decode('20d4d624cf732f826f09e8088017742f13f2da98f4dcf4b40519adb790cebf64')!
		pbkey:           hex.decode('edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff5f')!
		expected_shared: hex.decode('5716296baf2b1a6b9cd15b23ba86829743d60b0396569be1d5b40014c06b477d')!
		err:             none
	},
	EdgeCasePubkey{
		title:           '# edge case public key'
		status:          '# valid'
		pvkey:           hex.decode('d806a735d138efb3b404683c9d84485ab4af540d0af253b574323d8913003c66')!
		pbkey:           hex.decode('edffffffffffffffffffffffffffffffffffffffffffffffffffffffff7fff7f')!
		expected_shared: hex.decode('ddbd56d0454b794c1d1d4923f023a51f6f34ef3f4868e3d6659307c683c74126')!
		err:             none
	},
	EdgeCasePubkey{
		title:           '# edge case public key'
		status:          '# valid'
		pvkey:           hex.decode('184198c6228177f3ef41dc9a341258f8181ae365fe9ec98d93639b0bbee1467d')!
		pbkey:           hex.decode('fffffffffeffff7ffffffffffeffff7ffffffffffeffff7ffffffffffeffff7f')!
		expected_shared: hex.decode('8039eebed1a4f3b811ea92102a6267d4da412370f3f0d6b70f1faaa2e8d5236d')!
		err:             none
	},
	EdgeCasePubkey{
		title:           '# edge case public key'
		status:          '# valid'
		pvkey:           hex.decode('f0a46a7f4b989fe515edc441109346ba746ec1516896ec5b7e4f4d903064b463')!
		pbkey:           hex.decode('edfffffffffffffffffffffffffffffffffffffffffffffffffffffffeffff7f')!
		expected_shared: hex.decode('b69524e3955da23df6ad1a7cd38540047f50860f1c8fded9b1fdfcc9e812a035')!
		err:             none
	},
	EdgeCasePubkey{
		title:           '# edge case public key'
		status:          '# valid'
		pvkey:           hex.decode('881874fda3a99c0f0216e1172fbd07ab1c7df78602cc6b11264e57aab5f23a49')!
		pbkey:           hex.decode('edfffffffffffffffffffffffffffffffffffffffffffffffeffffffffffff7f')!
		expected_shared: hex.decode('e417bb8854f3b4f70ecea557454c5c4e5f3804ae537960a8097b9f338410d757')!
		err:             none
	},
	EdgeCasePubkey{
		title:           '# edge case public key'
		status:          '# valid'
		pvkey:           hex.decode('b8d0f1ae05a5072831443150e202ac6db00322cdf341f467e9f296588b04db72')!
		pbkey:           hex.decode('edfffffffffffffffffffffffffffffffeffffffffffffffffffffffffffff7f')!
		expected_shared: hex.decode('afca72bb8ef727b60c530c937a2f7d06bb39c39b903a7f4435b3f5d8fc1ca810')!
		err:             none
	},
	EdgeCasePubkey{
		title:           '# edge case public key'
		status:          '# valid'
		pvkey:           hex.decode('c8619ba988859db7d6f20fbf3ffb8b113418cc278065b4e8bb6d4e5b3e7cb569')!
		pbkey:           hex.decode('edfffffffffffffffeffffffffffffffffffffffffffffffffffffffffffff7f')!
		expected_shared: hex.decode('7e41c2886fed4af04c1641a59af93802f25af0f9cba7a29ae72e2a92f35a1e5a')!
		err:             none
	},
	EdgeCasePubkey{
		title:           '# edge case public key'
		status:          '# valid'
		pvkey:           hex.decode('f8d4ca1f37a30ec9acd6dbe5a6e150e5bc447d22b355d80ba002c5b05c26935d')!
		pbkey:           hex.decode('edfffffffeffffffffffffffffffffffffffffffffffffffffffffffffffff7f')!
		expected_shared: hex.decode('dd3abd4746bf4f2a0d93c02a7d19f76d921c090d07e6ea5abae7f28848355947')!
		err:             none
	},
	EdgeCasePubkey{
		title:           '# edge case public key'
		status:          '# valid'
		pvkey:           hex.decode('88037ac8e33c72c2c51037c7c8c5288bba9265c82fd8c31796dd7ea5df9aaa4a')!
		pbkey:           hex.decode('edffffefffffffffffffffffffffffffffffffffffffffffffffffffffffff7f')!
		expected_shared: hex.decode('8c27b3bff8d3c1f6daf2d3b7b3479cf9ad2056e2002be247992a3b29de13a625')!
		err:             none
	},
	EdgeCasePubkey{
		title:           '# edge case public key'
		status:          '# valid'
		pvkey:           hex.decode('5034ee7bf83a13d9167df86b0640294f3620f4f4d9030e5e293f9190824ae562')!
		pbkey:           hex.decode('edfffeffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f')!
		expected_shared: hex.decode('8e1d2207b47432f881677448b9d426a30de1a1f3fd38cad6f4b23dbdfe8a2901')!
		err:             none
	},
	EdgeCasePubkey{
		title:           '# edge case public key'
		status:          '# valid'
		pvkey:           hex.decode('40bd4e1caf39d9def7663823502dad3e7d30eb6eb01e9b89516d4f2f45b7cd7f')!
		pbkey:           hex.decode('ebffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f')!
		expected_shared: hex.decode('2cf6974b0c070e3707bf92e721d3ea9de3db6f61ed810e0a23d72d433365f631')!
		err:             none
	},
]

// Special private keys test
//

fn test_wycheproof_special_cases_private_key() ! {
	for mut item in special_privkey_vectors {
		shared_sec := curve25519.x25519(mut item.pvkey, item.pbkey) or {
			assert err == item.err
			continue
		}
		assert shared_sec == item.expected_shared
	}
}

struct SpecialPrivKey {
	title  string
	status string
mut:
	pvkey           []u8
	pbkey           []u8
	expected_shared []u8
	err             IError
}

const special_privkey_vectors = [
	// TODO: should this be disallowed ?
	SpecialPrivKey{
		title:           '# private key == -1 (mod order)'
		status:          '# valid'
		pvkey:           hex.decode('a023cdd083ef5bb82f10d62e59e15a6800000000000000000000000000000050')!
		pbkey:           hex.decode('6c05871352a451dbe182ed5e6ba554f2034456ffe041a054ff9cc56b8e946376')!
		expected_shared: hex.decode('6c05871352a451dbe182ed5e6ba554f2034456ffe041a054ff9cc56b8e946376')!
		err:             none
	},
	// TODO: should this be disallowed ?
	SpecialPrivKey{
		title:           'private key == 1 (mod order) on twist'
		status:          'acceptable: Twist'
		pvkey:           hex.decode('58083dd261ad91eff952322ec824c682ffffffffffffffffffffffffffffff5f')!
		pbkey:           hex.decode('2eae5ec3dd494e9f2d37d258f873a8e6e9d0dbd1e383ef64d98bb91b3e0be035')!
		expected_shared: hex.decode('2eae5ec3dd494e9f2d37d258f873a8e6e9d0dbd1e383ef64d98bb91b3e0be035')!
		err:             none
	},
	SpecialPrivKey{
		title:           'special case private key'
		status:          'valid'
		pvkey:           hex.decode('4855555555555555555555555555555555555555555555555555555555555555')!
		pbkey:           hex.decode('3e3e7708ef72a6dd78d858025089765b1c30a19715ac19e8d917067d208e0666')!
		expected_shared: hex.decode('63ef7d1c586476ec78bb7f747e321e01102166bf967a9ea9ba9741f49d439510')!
		err:             none
	},
	SpecialPrivKey{
		title:           'special case private key'
		status:          'valid'
		pvkey:           hex.decode('4855555555555555555555555555555555555555555555555555555555555555')!
		pbkey:           hex.decode('9f40bb30f68ab67b1c4b8b664982fdab04ff385cd850deac732f7fb705e6013a')!
		expected_shared: hex.decode('8b98ef4d6bf30df7f88e58d51505d37ed6845a969fe598747c033dcd08014065')!
		err:             none
	},
	SpecialPrivKey{
		title:           'special case private key'
		status:          'valid'
		pvkey:           hex.decode('4855555555555555555555555555555555555555555555555555555555555555')!
		pbkey:           hex.decode('be3b3edeffaf83c54ae526379b23dd79f1cb41446e3687fef347eb9b5f0dc308')!
		expected_shared: hex.decode('cfa83e098829fe82fd4c14355f70829015219942c01e2b85bdd9ac4889ec2921')!
		err:             none
	},
	SpecialPrivKey{
		title:           'special case private key'
		status:          'valid'
		pvkey:           hex.decode('b8aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa6a')!
		pbkey:           hex.decode('3e3e7708ef72a6dd78d858025089765b1c30a19715ac19e8d917067d208e0666')!
		expected_shared: hex.decode('4782036d6b136ca44a2fd7674d8afb0169943230ac8eab5160a212376c06d778')!
		err:             none
	},
	SpecialPrivKey{
		title:           'special case private key'
		status:          'valid'
		pvkey:           hex.decode('b8aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa6a')!
		pbkey:           hex.decode('9f40bb30f68ab67b1c4b8b664982fdab04ff385cd850deac732f7fb705e6013a')!
		expected_shared: hex.decode('65fc1e7453a3f8c7ebcd577ade4b8efe1035efc181ab3bdb2fcc7484cbcf1e4e')!
		err:             none
	},
	SpecialPrivKey{
		title:           'special case private key'
		status:          'valid'
		pvkey:           hex.decode('b8aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa6a')!
		pbkey:           hex.decode('be3b3edeffaf83c54ae526379b23dd79f1cb41446e3687fef347eb9b5f0dc308')!
		expected_shared: hex.decode('e3c649beae7cc4a0698d519a0a61932ee5493cbb590dbe14db0274cc8611f914')!
		err:             none
	},
]

// Special cases test
//

fn test_wycheproof_other_special_cases() ! {
	for mut item in special_cases_vectors {
		shared_sec := curve25519.x25519(mut item.pvkey, item.pbkey) or {
			assert err == item.err
			continue
		}
		assert shared_sec == item.expected_shared
	}
}

struct SpecialCases {
	title  string
	status string
mut:
	pvkey           []u8
	pbkey           []u8
	expected_shared []u8
	err             IError
}

const special_cases_vectors = [
	// TODO: should this be disallowed ?
	SpecialCases{
		title:           '# special case for E in multiplication by 2'
		status:          '# acceptable: Twist'
		pvkey:           hex.decode('581ecbda5a4a228044fefd6e03df234558c3c79152c6e2c5e60b142c4f26a851')!
		pbkey:           hex.decode('0000000000000000000008000000000000000000000000000000000000000000')!
		expected_shared: hex.decode('59e7b1e6f47065a48bd34913d910176b6792a1372aad22e73cd7df45fcf91a0e')!
		err:             none
	},
	SpecialCases{
		title:           '# special case for E in multiplication by 2'
		status:          '# valid'
		pvkey:           hex.decode('b0561a38000795b7cb537b55e975ea452c2118506295d5eb15fd9c83b67f7a50')!
		pbkey:           hex.decode('77af0d3897a715dfe25df5d538cf133bc9ab7ad52df6bd922a2fb75621d59901')!
		expected_shared: hex.decode('179f6b020748acba349133eaa4518f1bd8bab7bfc4fb05fd4c24e7553da1e960')!
		err:             none
	},
	SpecialCases{
		title:           '# special case for E in multiplication by 2'
		status:          '# valid'
		pvkey:           hex.decode('b00f7df2d47128441c7270b9a87eee45b6056fc64236a57bdf81dbcccf5f5d42')!
		pbkey:           hex.decode('4e39866127b6a12a54914e106aab86464af55631f3cb61766d5999aa8d2e070e')!
		expected_shared: hex.decode('43c5ee1451f213ef7624729e595a0fee7c9af7ee5d27eb03278ee9f94c202352')!
		err:             none
	},
	SpecialCases{
		title:           '# special case for E in multiplication by 2'
		status:          '# valid'
		pvkey:           hex.decode('c8f7a0c0bfb1e9c72576c534f86854fbe4af521d4fa807f67e2440e100ec8852')!
		pbkey:           hex.decode('adc6799ed8495ed5ab6eb1ef955479b9b50aa9ce0c349e8992a6665572d1f811')!
		expected_shared: hex.decode('2f350bcf0b40784d1d756c9ca3e38ec9dd68ba80faf1f9847de50779c0d4902a')!
		err:             none
	},
	SpecialCases{
		title:           '# special case for E in multiplication by 2'
		status:          '# acceptable: Twist'
		pvkey:           hex.decode('58181f581aa37022ff71c56c6e68e6175d967c5c995a249885f66565074ded4d')!
		pbkey:           hex.decode('770f4218ef234f5e185466e32442c302bbec21bbb6cd28c979e783fe5013333f')!
		expected_shared: hex.decode('d5d650dc621072eca952e4344efc7320b2b1459aba48f5e2480db881c50cc650')!
		err:             none
	},
	SpecialCases{
		title:           '# special case for E in multiplication by 2'
		status:          '# acceptable: Twist'
		pvkey:           hex.decode('301c935cae4357070b0adaf9cd6192830b2c989c153729eed99f589eb45f884b')!
		pbkey:           hex.decode('5c6118c4c74cfb842d9a87449f9d8db8b992d46c5a9093ce2fcb7a49b535c451')!
		expected_shared: hex.decode('909cc57275d54f20c67b45f9af9484fd67581afb7d887bee1db5461f303ef257')!
		err:             none
	},
	SpecialCases{
		title:           '# special case for E in multiplication by 2'
		status:          '# valid'
		pvkey:           hex.decode('d002292d4359a3d42bc8767f1380009332e7a0df2f3379011ab78f789f6baa54')!
		pbkey:           hex.decode('4039866127b6a12a54914e106aab86464af55631f3cb61766d5999aa8d2e076e')!
		expected_shared: hex.decode('4a7e2c5caf1d8180eb1c4f22692f29a14b4cdc9b193bd1d16e2f27438eef1448')!
		err:             none
	},
	SpecialCases{
		title:           '# special case for E in multiplication by 2'
		status:          '# acceptable: Twist'
		pvkey:           hex.decode('d0c2c49e644ab738270707ff9917065942687e2f12886d961161db46c05b565f')!
		pbkey:           hex.decode('078fa523498fb51cba1112d83b20af448b8009d8eea14368564d01b8f9b6086f')!
		expected_shared: hex.decode('c0ee59d3685fc2c3c803608b5ee39a7f8da30b48e4293ae011f0ea1e5aeb7173')!
		err:             none
	},
	SpecialCases{
		title:           '# special case for E in multiplication by 2'
		status:          '# valid'
		pvkey:           hex.decode('f087d38b274c1dad1bce6eaa36b48e2190b90b9bf8ca59669cc5e00464534342')!
		pbkey:           hex.decode('9fc6799ed8495ed5ab6eb1ef955479b9b50aa9ce0c349e8992a6665572d1f871')!
		expected_shared: hex.decode('b252bc8eabfaa68c56e54d61b99061a35d11e3a7b9bda417d90f69b1119bcf45')!
		err:             none
	},
	SpecialCases{
		title:           '# special case for E in multiplication by 2'
		status:          '# valid'
		pvkey:           hex.decode('48dbcc5a695f1514bbbaa6ad00842b69d9ae5216b1963add07fb2947c97b8447')!
		pbkey:           hex.decode('7650f2c76858ea201da2022ac730ecc43654852ad209426dd5d048a9de2a667e')!
		expected_shared: hex.decode('fbda33bc930c08df837208e19afdc1cfe3fd0f8f0e3976be34775e58a4a7771f')!
		err:             none
	},
	// This produces zeros secret, gives an error
	SpecialCases{
		title:           '# D = 0 in multiplication by 2'
		status:          '# acceptable: LowOrderPublic, ZeroSharedSecret'
		pvkey:           hex.decode('48dbcc5a695f1514bbbaa6ad00842b69d9ae5216b1963add07fb2947c97b8447')!
		pbkey:           hex.decode('e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800')!
		expected_shared: hex.decode('0000000000000000000000000000000000000000000000000000000000000000')!
		err:             error('bad input point: low order point')
	},
	// This produces zeros secret, gives an error
	SpecialCases{
		title:           '# D = 0 in multiplication by 2'
		status:          '# acceptable: LowOrderPublic, ZeroSharedSecret'
		pvkey:           hex.decode('c0f9c60aea73731d92ab5ed9f4cea122f9a6eb2577bda72f94948fea4d4cc65d')!
		pbkey:           hex.decode('5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f1157')!
		expected_shared: hex.decode('0000000000000000000000000000000000000000000000000000000000000000')!
		err:             error('bad input point: low order point')
	},
	SpecialCases{
		title:           '# special case for DA - CB in multiplication by 2'
		status:          '# acceptable: Twist'
		pvkey:           hex.decode('0066dd7674fe51f9326c1e239b875f8ac0701aae69a804c25fe43595e8660b45')!
		pbkey:           hex.decode('b0224e7134cf92d40a31515f2f0e89c2a2777e8ac2fe741db0dc39399fdf2702')!
		expected_shared: hex.decode('8dacfe7beaaa62b94bf6e50ee5214d99ad7cda5a431ea0c62f2b20a89d73c62e')!
		err:             none
	},
	SpecialCases{
		title:           '# special case for DA - CB in multiplication by 2'
		status:          '# valid'
		pvkey:           hex.decode('80067f30f40d61318b420c859fce128c9017ab81b47b76028a57bc30d5856846')!
		pbkey:           hex.decode('601e3febb848ec3e57fce64588aad82afc9c2af99bbcdffcc4cd58d4b3d15c07')!
		expected_shared: hex.decode('20f1d3fe90e08bc6f152bf5dacc3ed35899785333f1470e6a62c3b8cbe28d260')!
		err:             none
	},
	SpecialCases{
		title:           '# special case for DA - CB in multiplication by 2'
		status:          '# acceptable: Twist'
		pvkey:           hex.decode('584577669d21ce0ae3e30b02c9783ffe97709cbfe396889aa31e8ee43352dc52')!
		pbkey:           hex.decode('82a3807bbdec2fa9938fb4141e27dc57456606301f78ff7133cf24f3d13ee117')!
		expected_shared: hex.decode('2b28cc5140b816add5ad3a77a81b1c073d67bf51bf95bda2064a14eb12d5f766')!
		err:             none
	},
	SpecialCases{
		title:           '# special case for DA - CB in multiplication by 2'
		status:          '# valid'
		pvkey:           hex.decode('18e597a4e2ccdb5e8052d57c9009938c2d4c43d6d8c9f93c98727b7311035953')!
		pbkey:           hex.decode('f329ab2376462e5f3128a2682086253c19222ac1e2bca45692f0c3b528f4c428')!
		expected_shared: hex.decode('8392160083b9af9e0ef44fcfce53ba8ff7282ee7a6c71ab66f8843a55d09cd68')!
		err:             none
	},
	SpecialCases{
		title:           '# special case for DA in multiplication by 2'
		status:          '# valid'
		pvkey:           hex.decode('88281cc51d5512d8814ea5249b879dcbad0323d38512dafbdc7ba85bba8c8d5d')!
		pbkey:           hex.decode('4fce3bb6c8aaf022dbd100e3cde3941b37d543f00401dba7da9bc143dfc55709')!
		expected_shared: hex.decode('42184e22c535530c457bd3b4f1084cbf5e297f502fe136b8d1daecf5334cc96c')!
		err:             none
	},
	SpecialCases{
		title:           '# special case for DA in multiplication by 2'
		status:          '# valid'
		pvkey:           hex.decode('d0e795450df0a813c6573496ec5793ca02e1bdbad10ed08df83fdaed68b3385f')!
		pbkey:           hex.decode('15c68851c1db844b5a1ef3456a659f188854b1a75fbdb2f68f514c9289ce711f')!
		expected_shared: hex.decode('f654d78e5945b24bc63e3e6d790e0ae986e53937764068b1bce920e1d79b756f')!
		err:             none
	},
	SpecialCases{
		title:           '# special case for DA in multiplication by 2'
		status:          '# valid'
		pvkey:           hex.decode('30b69a1cc1eb2d0b83ea213846e90a2c922088bdf294a6995bf6e6e77c646c41')!
		pbkey:           hex.decode('4200a242434337b8914f49345301ed782b13594f9ede089c41fb1e7ea82c9053')!
		expected_shared: hex.decode('cd8a09b04795edcc7061867373981aa748651ebdce5ec218a335b878cefe4872')!
		err:             none
	},
	SpecialCases{
		title:           '# special case for DA in multiplication by 2'
		status:          '# valid'
		pvkey:           hex.decode('78b30bb63cd8ade71b7a77d426f4419d05f199ffef349e89faa9d9a5f21f6654')!
		pbkey:           hex.decode('baabf0174aaaea4de48cc83adfb0401461a741903ea6fb130d7d64b7bf03a966')!
		expected_shared: hex.decode('c9f8258f237db1c80702c5c4d9048dfba9dfe259da4aeee90dc2945526961275')!
		err:             none
	},
	SpecialCases{
		title:           '# special case for x_2 in multiplication by 2'
		status:          '# valid'
		pvkey:           hex.decode('c0b386f4ef0d4698686404977e7b60cb6c1f8b6012a22e29d6224c5947439041')!
		pbkey:           hex.decode('f12f18bd59c126348f6a7a9f4a5fdd9fcaf581345073a851fba098e5d64b4a0c')!
		expected_shared: hex.decode('6600cbe900616a770a126b8b19156d5e27e1174bd538d0944eb3c0be4899c758')!
		err:             none
	},
	SpecialCases{
		title:           '# special case for x_2 in multiplication by 2'
		status:          '# acceptable: Twist'
		pvkey:           hex.decode('9886602e719bacafea092bb75b51ae7258abe1a364c176857f3dc188c03e6759')!
		pbkey:           hex.decode('bee386527b772490aeb96fc4d23b9304037cb4430f64b228f3d8b3b498319f22')!
		expected_shared: hex.decode('3fe710d6344ff0cb342e52349e1c5b57b7a271f2a133bb5249bbe40dc86e1b40')!
		err:             none
	},
	SpecialCases{
		title:           '# special case for x_2 in multiplication by 2'
		status:          '# valid'
		pvkey:           hex.decode('b83960f5d0613cdaac6dda690351666e9f277bba6bd406b0e27a1886bb2d3e46')!
		pbkey:           hex.decode('cf911ac91b0d944049cec66ae5ef0c4549d1e612e107c68e87263a2fbcf8323f')!
		expected_shared: hex.decode('71373ebe67f39a2c230027c7db4b3b74bab80ed212b232679785ee10f47c304e')!
		err:             none
	},
	SpecialCases{
		title:           '# special case for x_2 in multiplication by 2'
		status:          '# valid'
		pvkey:           hex.decode('d03b75f09ac807dfd2ee352c04a1f25984720f785ffaa0af88bc5db6ff9c3453')!
		pbkey:           hex.decode('1e6ee536e4f26bbfb63139951a10f3bab62e19ed1ef8397178d9c5d04307cd40')!
		expected_shared: hex.decode('238eef43c589822e1d3de41c1cc46dcfec7a93febf37c8546b6625e1a123815d')!
		err:             none
	},
	SpecialCases{
		title:           '# special case for x_2 in multiplication by 2'
		status:          '# valid'
		pvkey:           hex.decode('d036948c0ec223f0ee577e390dbf87222358ed199f2823345ad154bbc4cbcc47')!
		pbkey:           hex.decode('2f1c79ad8488db6f5146903b2dc46cfbfc834bbcf09b4dd70c274c4b67ce605d')!
		expected_shared: hex.decode('87a79c9c231d3b9526b49bf3d683bf38c3c319af7c7c5d1456487398da535010')!
		err:             none
	},
	SpecialCases{
		title:           '# special case for x_2 in multiplication by 2'
		status:          '# valid'
		pvkey:           hex.decode('d054ded613febf2950ac5c927fcb120c387de0ba61b331cd33024c8b6e737048')!
		pbkey:           hex.decode('fccfe742a63ed9cb70958560b5a02260350a7ecbaf8c57ae045f671a29b4b573')!
		expected_shared: hex.decode('d683ca6194452d878c12d7da35f22833f99728bba89931a51274f61210336a5f')!
		err:             none
	},
	SpecialCases{
		title:           '# special case for AA in multiplication by 2'
		status:          '# acceptable: Twist'
		pvkey:           hex.decode('e82c480631fb153ba2211fe603032b3e71b162dbd3c11bec03208ffcd510655f')!
		pbkey:           hex.decode('cb3d4a90f86b3011da3369d9988597c7fff1499273b4a04f84d0e26ed1683c0d')!
		expected_shared: hex.decode('dbf6203516635840cf69a02db87cf0d95dae315da7fc1ec7ce2b29e1f2db6666')!
		err:             none
	},
	SpecialCases{
		title:           '# special case for AA in multiplication by 2'
		status:          '# acceptable: Twist'
		pvkey:           hex.decode('c0c01d28c1cab01f59700aca5f18d2697658b37fdd54a339ff391c0a1a1b1645')!
		pbkey:           hex.decode('101e13f7bc0570fa2638caa20a67c6e0c21dab132f4b456191590264c493d018')!
		expected_shared: hex.decode('1fe314744390d525278b1f5fbf108101b8ded587081375ed4ac4ac690d92414f')!
		err:             none
	},
	SpecialCases{
		title:           '# special case for AA in multiplication by 2'
		status:          '# acceptable: Twist'
		pvkey:           hex.decode('c82bde72df36479688c485a8bf442f4a34412e429c02db97704f03daf4dfd542')!
		pbkey:           hex.decode('dce1ec0843fa8f05d9c7355df598391f3de254ecd0b4ba9e6ea6fd9b3b6c2f67')!
		expected_shared: hex.decode('ad454395ee392be677be7b9cb914038d57d2d87ec56cc98678dd84f19920912b')!
		err:             none
	},
	SpecialCases{
		title:           '# special case for AA in multiplication by 2'
		status:          '# valid'
		pvkey:           hex.decode('503f697617fb02a7b8ef00ba34e7fc8ce93f9ec3e1cbfe4bf2c05bcee0cb9757')!
		pbkey:           hex.decode('21c2b56f0794cfee25cc9626677a6838000eb66d8c4b5fb07b2f1d912e97c372')!
		expected_shared: hex.decode('c6d6499255133398f9dd7f32525db977a538118800bfaf3aad8bcd26f02c3863')!
		err:             none
	},
	SpecialCases{
		title:           '# special case for BB in multiplication by 2'
		status:          '# valid'
		pvkey:           hex.decode('58cd4ca1e4331188de2b2889419ce20ec5ef88a0e93af092099065551b904e41')!
		pbkey:           hex.decode('cc3d4a90f86b3011da3369d9988597c7fff1499273b4a04f84d0e26ed1683c0d')!
		expected_shared: hex.decode('0d74214da1344b111d59dfad3713eb56effe7c560c59cbbb99ec313962dbba58')!
		err:             none
	},
	SpecialCases{
		title:           '# special case for BB in multiplication by 2'
		status:          '# acceptable: Twist'
		pvkey:           hex.decode('004ea3448b84ca509efec5fcc24c63ee984def63b29deb9037894709709c0957')!
		pbkey:           hex.decode('111e13f7bc0570fa2638caa20a67c6e0c21dab132f4b456191590264c493d018')!
		expected_shared: hex.decode('7b9dbf8d6c6d65898b518167bf4011d54ddc265d953c0743d7868e22d9909e67')!
		err:             none
	},
	SpecialCases{
		title:           '# special case for BB in multiplication by 2'
		status:          '# valid'
		pvkey:           hex.decode('c8a6eb00a4d74bbdff239522c3c891ed7ce1904be2a329cd0ae0061a253c9542')!
		pbkey:           hex.decode('dde1ec0843fa8f05d9c7355df598391f3de254ecd0b4ba9e6ea6fd9b3b6c2f67')!
		expected_shared: hex.decode('fb0e0209c5b9d51b401183d7e56a59081d37a62ab1e05753a0667eebd377fd39')!
		err:             none
	},
	SpecialCases{
		title:           '# special case for BB in multiplication by 2'
		status:          '# valid'
		pvkey:           hex.decode('50322ff0d0dcdd6b14f307c04dfecefe5b7cdeaf92bffb919e9d62ed27079040')!
		pbkey:           hex.decode('22c2b56f0794cfee25cc9626677a6838000eb66d8c4b5fb07b2f1d912e97c372')!
		expected_shared: hex.decode('dbe7a1fe3b337c9720123e6fcc02cf96953a17dc9b395a2206cb1bf91d41756e')!
		err:             none
	},
	SpecialCases{
		title:           '# special case for D in multiplication by 2'
		status:          '# valid'
		pvkey:           hex.decode('e0328c7d188d98faf2ac72d728b7d14f2bbbd7a94d0fbd8e8f79abe0b1fe1055')!
		pbkey:           hex.decode('e58baccede32bcf33b3b6e3d69c02af8284a9631de74b6af3f046a9369df040f')!
		expected_shared: hex.decode('97bd42093e0d48f973f059dd7ab9f97d13d5b0d5eedffdf6da3c3c432872c549')!
		err:             none
	},
	SpecialCases{
		title:           '# special case for D in multiplication by 2'
		status:          '# valid'
		pvkey:           hex.decode('5017679a17bd23adf95ad47e310fc6526f4ba9ca3b0839b53bd0d92839eb5b4f')!
		pbkey:           hex.decode('c6d5c693fc0a4e2df6b290026860566a166b6d7aebe3c98828d492745c8df936')!
		expected_shared: hex.decode('99bcbc7b9aa5e25580f92bf589e95dae874b83e420225d8a93e18e96dac00b63')!
		err:             none
	},
	SpecialCases{
		title:           '# special case for D in multiplication by 2'
		status:          '# valid'
		pvkey:           hex.decode('2864aaf61c146df06cc256b065f66b34985cc015da5b1d647a6ed4e2c76bfc43')!
		pbkey:           hex.decode('d15f4bf2ef5c7bda4ee95196f3c0df710df5d3d206360fc3174ea75c3aa3a743')!
		expected_shared: hex.decode('afa2adb52a670aa9c3ec3020d5fda285474ede5c4f4c30e9238b884a77969443')!
		err:             none
	},
	SpecialCases{
		title:           '# special case for D in multiplication by 2'
		status:          '# acceptable: Twist'
		pvkey:           hex.decode('184a6cfbabcbd1507a2ea41f52796583dbdb851b88a85781ee8e3c28782c3349')!
		pbkey:           hex.decode('6dffb0a25888bf23cf1ac701bfbdede8a18e323b9d4d3d31e516a05fce7ce872')!
		expected_shared: hex.decode('e6a2fc8ed93ce3530178fef94bb0056f43118e5be3a6eabee7d2ed384a73800c')!
		err:             none
	},
	SpecialCases{
		title:           '# special case for D in multiplication by 2'
		status:          '# acceptable: Twist'
		pvkey:           hex.decode('c85f954b85bc102aca799671793452176538d077862ee45e0b253619767dff42')!
		pbkey:           hex.decode('21f86d123c923a92aaf2563df94b5b5c93874f5b7ab9954aaa53e3d72f0ff67e')!
		expected_shared: hex.decode('7fc28781631410c5a6f25c9cfd91ec0a848adb7a9eb40bc5b495d0f4753f2260')!
		err:             none
	},
	SpecialCases{
		title:           '# special case for D in multiplication by 2'
		status:          '# valid'
		pvkey:           hex.decode('50e3e5a9a19be2ee3548b0964672fb5e3134cb0d2f7adf000e4556d0ffa37643')!
		pbkey:           hex.decode('587c347c8cb249564ab77383de358cc2a19fe7370a8476d43091123598941c7f')!
		expected_shared: hex.decode('314d8a2b5c76cc7ee1217df2283b7e6724436e273aeb80628dce0600ab478a63')!
		err:             none
	},
	SpecialCases{
		title:           '# special case for DA + CB in multiplication by 2'
		status:          '# valid'
		pvkey:           hex.decode('08ece580bb6ddf96559b81d7a97dd4531def6cc78d448a70cebabdd26caab146')!
		pbkey:           hex.decode('f5c6311a1dd1b9e0f8cfd034ac6d01bf28d9d0f962a1934ae2cb97cb173dd810')!
		expected_shared: hex.decode('2bfd8e5308c34498eb2b4daf9ed51cf623da3beaeb0efd3d687f2b8becbf3101')!
		err:             none
	},
	SpecialCases{
		title:           '# special case for DA + CB in multiplication by 2'
		status:          '# acceptable: Twist'
		pvkey:           hex.decode('a886033e9dc2b6a913fffbc2bd402e8c11ec34d49c0dc0fa1429329b694a285f')!
		pbkey:           hex.decode('9316c06d27b24abc673ffb5105c5b9a89bdfaa79e81cdbb89556074377c70320')!
		expected_shared: hex.decode('d53c3d6f538c126b9336785d1d4e6935dc8b21f3d7e9c25bc240a03e39023363')!
		err:             none
	},
	SpecialCases{
		title:           '# special case for DA + CB in multiplication by 2'
		status:          '# acceptable: Twist'
		pvkey:           hex.decode('98b1cc2020a8ec575d5c46c76024cf7c7ad7628eb909730bc4f460aaf0e6da4b')!
		pbkey:           hex.decode('8a4179807b07649e04f711bf9473a79993f84293e4a8b9afee44a22ef1000b21')!
		expected_shared: hex.decode('4531881ad9cf011693ddf02842fbdab86d71e27680e9b4b3f93b4cf15e737e50')!
		err:             none
	},
	SpecialCases{
		title:           '# special case for DA + CB in multiplication by 2'
		status:          '# acceptable: Twist'
		pvkey:           hex.decode('c8e193de162aa349a3432c7a0c0521d92cbc5e3bf82615e42955dd67ec12345f')!
		pbkey:           hex.decode('a773277ae1029f854749137b0f3a02b5b3560b9c4ca4dbdeb3125ec896b81841')!
		expected_shared: hex.decode('7ba4d3de697aa11addf3911e93c94b7e943beff3e3b1b56b7de4461f9e48be6b')!
		err:             none
	},
	SpecialCases{
		title:           '# special case for DA + CB in multiplication by 2'
		status:          '# acceptable: Twist'
		pvkey:           hex.decode('88e01237b336014075676082afbde51d595d47e1fa5214b51a351abbf6491442')!
		pbkey:           hex.decode('1eceb2b3763231bc3c99dc62266a09ab5d3661c756524cddc5aabcedee92da61')!
		expected_shared: hex.decode('bcf0884052f912a63bbab8c5c674b91c4989ae051fa07fcf30cb5317fb1f2e72')!
		err:             none
	},
	SpecialCases{
		title:           '# special case for DA + CB in multiplication by 2'
		status:          '# acceptable: Twist'
		pvkey:           hex.decode('e82313e451a198dce4ae95c6832a8281d847fc87b28db00fe43757c16cc49c4a')!
		pbkey:           hex.decode('9a2acbb3b5a386a6102e3728be3a97de03981d5c71fd2d954604bee3d3d0ce62')!
		expected_shared: hex.decode('e5772a92b103ee696a999705cf07110c460f0545682db3fac5d875d69648bc68')!
		err:             none
	},
	SpecialCases{
		title:           '# special case for DA + CB in multiplication by 2'
		status:          '# acceptable: Twist'
		pvkey:           hex.decode('2828594d16768e586df39601ecc86d3fad6389d872b53fca3edcaf6fb958f653')!
		pbkey:           hex.decode('27430e1c2d3089708bca56d7a5ad03792828d47685b6131e023dd0808716b863')!
		expected_shared: hex.decode('378c29e3be97a21b9f81afca0d0f5c242fd4f896114f77a77155d06ce5fbfa5e')!
		err:             none
	},
	SpecialCases{
		title:           '# special case for z_2 in multiplication by 2'
		status:          '# valid'
		pvkey:           hex.decode('a84f488e193139f986b0e5b249635b137d385e420342aef1f194fcde1fe5e850')!
		pbkey:           hex.decode('4ef367901aac8ba90a50e0cf86ca4e4a3ff164fb121605be346e2e48d04ac912')!
		expected_shared: hex.decode('7eb48a60b14fb9ea5728f6410aef627d1522fad481b934af64e2c483b64d585f')!
		err:             none
	},
	SpecialCases{
		title:           '# special case for z_2 in multiplication by 2'
		status:          '# valid'
		pvkey:           hex.decode('30fd2a781e095c34a483907b3dd2d8bd2736e279617bfa6b8b4e0e1cf90fbd46')!
		pbkey:           hex.decode('d1de303c4ddd05d57c29df92ad172dd8c8f424e63ec93445beaea44f9d124b17')!
		expected_shared: hex.decode('b71bdbed78023a06deed1c182e14c98f7cf46bc627a4a2c102ad23c41cf32454')!
		err:             none
	},
	SpecialCases{
		title:           '# special case for z_2 in multiplication by 2'
		status:          '# valid'
		pvkey:           hex.decode('28312e17b47dd32d90561168245187963c7469a31c881e4a5c94384262b71959')!
		pbkey:           hex.decode('5bccd739fd7517d9344bf6b2b0f19a1e0c38d9349a25ad1f94af4a2cdcf5e837')!
		expected_shared: hex.decode('5bb56877caf2cdac98611b60367fbb74265984614e5e73996e8ea1bd6f749f1a')!
		err:             none
	},
	SpecialCases{
		title:           '# special case for z_2 in multiplication by 2'
		status:          '# acceptable: Twist'
		pvkey:           hex.decode('a87640cf8237b473c638b3e9df08644e8607e563b5964363ccc42133b2996742')!
		pbkey:           hex.decode('8a7a939310df7ea768454df51bcd0dfbd7be4fcbb2ffc98429d913ec6911f337')!
		expected_shared: hex.decode('b568ed46d04f6291f8c176dca8aff6d221de4c9cce4b404d5401fbe70a324501')!
		err:             none
	},
	SpecialCases{
		title:           '# special case for z_2 in multiplication by 2'
		status:          '# acceptable: Twist'
		pvkey:           hex.decode('780c5b882720d85e5ddfaf1033e9a1385df9e21689eeda4dcc7444ad28330a50')!
		pbkey:           hex.decode('fe3590fc382da7a82e28d07fafe40d4afc91183a4536e3e6b550fee84a4b7b4b')!
		expected_shared: hex.decode('11fb44e810bce8536a957eaa56e02d04dd866700298f13b04ebeb48e20d93647')!
		err:             none
	},
	SpecialCases{
		title:           '# special case for z_2 in multiplication by 2'
		status:          '# acceptable: Twist'
		pvkey:           hex.decode('209e5e0ae1994bd859ce8992b62ec3a66df2eb50232bcc3a3d27b6614f6b014d')!
		pbkey:           hex.decode('fad9ab3e803b49fc81b27ee69db6fc9fdb82e35453b59ef8fab2a3beb5e1134c')!
		expected_shared: hex.decode('85d9db8f182bc68db67de3471f786b45b1619aec0f32b108ace30ee7b2624305')!
		err:             none
	},
	SpecialCases{
		title:           '# special case for z_2 in multiplication by 2'
		status:          '# valid'
		pvkey:           hex.decode('806d1dee5ff6aea84a848916991a89ef3625583e1bd4ae0b3dd25c2524a4ff46')!
		pbkey:           hex.decode('98bed955f1516c7a442751ac590046d7d52ca64f76df82be09d32e5d33b49073')!
		expected_shared: hex.decode('61d4ef71cbe7be3128be829ab26ed3463eb4ab25937c309788e876b23412aa7c')!
		err:             none
	},
	SpecialCases{
		title:           '# special case for z_2 in multiplication by 2'
		status:          '# valid'
		pvkey:           hex.decode('00f98b02ae0df5274cc899f526eb1b877289e0963440a57dd97e414cdd2f7c51')!
		pbkey:           hex.decode('e59be4917b3f05b6fc8748c9b90f1b910273c9c6e17ff96ef415ff3d927d987e')!
		expected_shared: hex.decode('5ba4394ed1a664811b01557944becf7585652a8acbdbf806742911207bd79346')!
		err:             none
	},
	SpecialCases{
		title:           '# special case for A in multiplication by 2'
		status:          '# acceptable: Twist'
		pvkey:           hex.decode('d86c18f2be396b3bb72f22e6ece22e273af6e1506a1c09ad4d01bdd2f439f843')!
		pbkey:           hex.decode('8c9885a26cb334054700a270f7a5f4aac06bad8263b651ebf0712eca1ebb6416')!
		expected_shared: hex.decode('a5952588613eb7a5cd49dd526f1f20a4f0ffe9423e82cea302c2dd90ce559955')!
		err:             none
	},
	SpecialCases{
		title:           '# special case for A in multiplication by 2'
		status:          '# acceptable: Twist'
		pvkey:           hex.decode('f81aadb9053eb698996d0f781d9cda67f82ddefa3987d276ff5a94ffdf5d255f')!
		pbkey:           hex.decode('f6135fe9741c2c9de7dcf7627ef08832f351cb325dbb3a26f93a2b48620e1727')!
		expected_shared: hex.decode('cb6fb623084b6197443ec9ba1050c0923332e5e829ae0194269cfaf920a43601')!
		err:             none
	},
	SpecialCases{
		title:           '# special case for A in multiplication by 2'
		status:          '# acceptable: Twist'
		pvkey:           hex.decode('305b4db4321b4923fc559bf91df677d0e12c3a31b16ec655cb708b759d7c114d')!
		pbkey:           hex.decode('f6ffffffffffffffffffffffffffffbfffffffffffffffffffffffffffffff3f')!
		expected_shared: hex.decode('9e526079c2fcf12426ae6c2a54b5ffb70f2ec662e29ea5ce0c8385c3b21cd162')!
		err:             none
	},
	SpecialCases{
		title:           '# special case for A in multiplication by 2'
		status:          '# acceptable: Twist'
		pvkey:           hex.decode('e88bd02c7016547a24f428bc2a9dcccad6c6f880c17bffcf66fc68459627af4e')!
		pbkey:           hex.decode('60677a5d934ccbfab8ff5d8f085a0b553f94527d9c49ae140f8ed135e1449b69')!
		expected_shared: hex.decode('834bbad5470e1498c4b0148782dfe630e8bfadff1997de802ac8ce302a1bda28')!
		err:             none
	},
	SpecialCases{
		title:           '# special case for A in multiplication by 2'
		status:          '# valid'
		pvkey:           hex.decode('900638d1979802db9b52e4dd84fa19579f61cd7bef3c0b62fcccaeaa15fa484d')!
		pbkey:           hex.decode('f6ffffffffffffffffffffffffffff3f00000000000000000000000000000040')!
		expected_shared: hex.decode('6329c7dc2318ec36153ef4f6f91bc6e7d1e008f5293065d9586ab88abb58f241')!
		err:             none
	},
	SpecialCases{
		title:           '# special case for A in multiplication by 2'
		status:          '# valid'
		pvkey:           hex.decode('38575cf7c8691ecc79cd5f8d7d4703aa48592ff6e7f64731c2d98a19aeae514f')!
		pbkey:           hex.decode('f6eba0168be3d3621823089d810f77cd0cae34cda244c5d906c5d4b79df1e858')!
		expected_shared: hex.decode('603f4fc410081f880944e0e13d56fc542a430eec813fad302b7c5ac380576f1c')!
		err:             none
	},
	SpecialCases{
		title:           '# special case for B in multiplication by 2'
		status:          '# valid'
		pvkey:           hex.decode('a021ba2fd4e3ad57bcbf204d6f6c3e8018d8978552633b6dff1b7447bf529459')!
		pbkey:           hex.decode('f7ffffffffffffffffffffffffffffbfffffffffffffffffffffffffffffff3f')!
		expected_shared: hex.decode('1b174b189981d81bc6887932083e8488df8bbbed57f9214c9cfa59d59b572359')!
		err:             none
	},
	SpecialCases{
		title:           '# special case for B in multiplication by 2'
		status:          '# valid'
		pvkey:           hex.decode('3035083e984837587f6b7346af871bf3fc9581c50eb55c83aefabeed68cee349')!
		pbkey:           hex.decode('f7ffffffffffffffffffffffffffff3f00000000000000000000000000000040')!
		expected_shared: hex.decode('15a052148abaad1b0f2e7481a34edb61403589439b5bd5e5646cecebe2a1be2b')!
		err:             none
	},
	SpecialCases{
		title:           '# special case for B in multiplication by 2'
		status:          '# valid'
		pvkey:           hex.decode('30435ce187f2723f9a3bdea0eef892207e152e4cee8985fa72d2db4147bd2a53')!
		pbkey:           hex.decode('f7eba0168be3d3621823089d810f77cd0cae34cda244c5d906c5d4b79df1e858')!
		expected_shared: hex.decode('1d048cbe2f8df07c233a8f93706f307d17130c2497fb752eeaa31fe3edfc725a')!
		err:             none
	},
	SpecialCases{
		title:           '# special case for B in multiplication by 2'
		status:          '# acceptable: Twist'
		pvkey:           hex.decode('9036ed7d68f7448ac440dc51216b49840dcabd3d5e32e3b4ffc32a5fe9e96742')!
		pbkey:           hex.decode('8d9885a26cb334054700a270f7a5f4aac06bad8263b651ebf0712eca1ebb6416')!
		expected_shared: hex.decode('ec9070ad3491a5ff50d7d0db6c9c844783dde1c6fbd4fe163e9ade1ce9cd041d')!
		err:             none
	},
	SpecialCases{
		title:           '# special case for B in multiplication by 2'
		status:          '# acceptable: Twist'
		pvkey:           hex.decode('90c55e77aa0fe4afb1287109fd010f526364dea18d88e2fd870ac01b66e3fa4e')!
		pbkey:           hex.decode('f7135fe9741c2c9de7dcf7627ef08832f351cb325dbb3a26f93a2b48620e1727')!
		expected_shared: hex.decode('dc6d05b92edcdb5dc334b1fc3dff58fe5b24a5c5f0b2d4311555d0fc945d7759')!
		err:             none
	},
	SpecialCases{
		title:           '# special case for B in multiplication by 2'
		status:          '# acceptable: Twist'
		pvkey:           hex.decode('580f0a9bba7281a30fb033490e0f429f22e3f267852caeacefa3e5291f0e614e')!
		pbkey:           hex.decode('61677a5d934ccbfab8ff5d8f085a0b553f94527d9c49ae140f8ed135e1449b69')!
		expected_shared: hex.decode('cb92a98b6aa99ac9e3c5750cea6f0846b0181faa5992845b798923d419e82756')!
		err:             none
	},
	SpecialCases{
		title:           '# special case for C in multiplication by 2'
		status:          '# acceptable: Twist'
		pvkey:           hex.decode('709098feb2e25c67b4bfd3be0a01af409adb6da52b3fbe3d970642dd2c983856')!
		pbkey:           hex.decode('c8239b710136fe431fb4d98436157e47c9e78a10f09ff92e98baff159926061c')!
		expected_shared: hex.decode('f1bd12d9d32c6f4c5b2dcb3a5c52d9fd454d52ca704c2c137956ec8ad9aef107')!
		err:             none
	},
	SpecialCases{
		title:           '# special case for C in multiplication by 2'
		status:          '# valid'
		pvkey:           hex.decode('185ac62e729f88528950926c0de7c481c924bf9cf26a122f443b861e8b6af640')!
		pbkey:           hex.decode('b7a2f79e0de9b58147691b5546d9ec463da8325e1440e58bb20aa129d1b97327')!
		expected_shared: hex.decode('e6f1c494c9e4bd2325c17183e82d31ab0bbee6c847d4b0e4a99c7c6891117c3f')!
		err:             none
	},
	SpecialCases{
		title:           '# special case for C in multiplication by 2'
		status:          '# valid'
		pvkey:           hex.decode('f03743eead7c2f7719794324f271072817d1a04cbda42b232f3bee43f397cc40')!
		pbkey:           hex.decode('2dc624e1663f42a7b9336350f277541b50b8ddc7ee0d86133ad53273aed4e62e')!
		expected_shared: hex.decode('aa2a12edf752d279bdb000fb1405a5df8c5f1d41309b4f2bd41aed7ac1ed0149')!
		err:             none
	},
	SpecialCases{
		title:           '# special case for C in multiplication by 2'
		status:          '# valid'
		pvkey:           hex.decode('a8fbb4f90da45794981405d59ef310621e3c3b6b7760b5e30308c7822c88ae5f')!
		pbkey:           hex.decode('0e5eceee9104a64f82c9093b9bf7b4076ee5bc70815af7ee9f942ef015756176')!
		expected_shared: hex.decode('74d5606ba0b6ad1d8ba36ae6f264d6315f479b3984de573e9b001e0555247c32')!
		err:             none
	},
	SpecialCases{
		title:           '# special case for CB in multiplication by 2'
		status:          '# acceptable: Twist'
		pvkey:           hex.decode('c887886fd07107c7221f6d9dd36c305ec779ceca132ac933ff77dab2beac6345')!
		pbkey:           hex.decode('737d45477e2beb77a6c38b98e2a19b05c395df7da998cb91f6dfab5819614f27')!
		expected_shared: hex.decode('8cf4538ae5f445cc6d273df4ad300a45d7bb2f6e373a562440f1b37773904e32')!
		err:             none
	},
	SpecialCases{
		title:           '# special case for CB in multiplication by 2'
		status:          '# valid'
		pvkey:           hex.decode('58096ee29361978f630ad1fb00c1267c5a901f99c502f9569b933ad0dcce0f50')!
		pbkey:           hex.decode('873f8b260ea9d9ddac08b7b030727bf0072315ab54075ecc393a37a975882b7e')!
		expected_shared: hex.decode('d5766753211d9968de4ac2559998f22ef44e8aa879f3328cbc46aa858dcb433c')!
		err:             none
	},
	SpecialCases{
		title:           '# special case for CB in multiplication by 2'
		status:          '# valid'
		pvkey:           hex.decode('0829a49046dce2c07ab28440dbad146453e128960e85dd2e6a69a1512873dd44')!
		pbkey:           hex.decode('75e1587c5eefc83715d71020aa6be5347bb9ec9d91ce5b28a9bbb74c92ef407e')!
		expected_shared: hex.decode('761d8cecf13f93b379a772e5fac5b9ffe996cad9af06152580afe87ff9651c71')!
		err:             none
	},
	SpecialCases{
		title:           '# special case for x_2 in multiplication by 3'
		status:          '# acceptable: Twist'
		pvkey:           hex.decode('587ac36b9a23594632679adea1a826f2f62d79738220fb487464039f36ca2372')!
		pbkey:           hex.decode('f85a06065ea2527238fc5ec1b75ead9262e6b1aed61feff83b91230aeb4b7d01')!
		expected_shared: hex.decode('f12acd36f6299a4d192c03aa4efeea7df51e2d15d763172e68accf7bc6f5c230')!
		err:             none
	},
	SpecialCases{
		title:           '# special case for x_2 in multiplication by 3'
		status:          '# acceptable: Twist'
		pvkey:           hex.decode('d8f7233e9612c00c9dca2c751ec1d3f5f67bad77c2e714a20e71eb3f220a6671')!
		pbkey:           hex.decode('696757ced3097fa960c8390a09e8bd6d390dbde8d1fa170261f3422edc192929')!
		expected_shared: hex.decode('45ecfa275f1daa25d3fadf33cdf89a152afea25eae37e68e00b30c367789887a')!
		err:             none
	},
	SpecialCases{
		title:           '# special case for x_2 in multiplication by 3'
		status:          '# acceptable: Twist'
		pvkey:           hex.decode('d80c7c7557c9907e1b11e844bf1369cba669bc38e9b7b253e51f239bda322374')!
		pbkey:           hex.decode('fd84b3f2fbfa16aebf40c27f46e18d77bafa0c7971bedde4909212e771bd3c35')!
		expected_shared: hex.decode('595e144e07bbe65b38e0e4163d02ad75a65e422e74067db35c90dfa6e055d456')!
		err:             none
	},
	SpecialCases{
		title:           '# special case for x_2 in multiplication by 3'
		status:          '# acceptable: Twist'
		pvkey:           hex.decode('8002a85115ad7b41c50f84f35fac750ee8e19734807102830ff6a306beed4464')!
		pbkey:           hex.decode('805485703ccfc4a221ef281267f52b61cebc879f0f13b1e5f521c17352a0784f')!
		expected_shared: hex.decode('226e16a279ac81e268437eb3e09e07406324cb72a9d4ee58e4cf009147497201')!
		err:             none
	},
	SpecialCases{
		title:           '# special case for x_2 in multiplication by 3'
		status:          '# acceptable: Twist'
		pvkey:           hex.decode('782db0c8e3e68f106fe0c56415e0bd13d812dea0e94cbd18bdf6761295613a6d')!
		pbkey:           hex.decode('80642a3279da6bf5fc13db14a569c7089db014225cfcae7dff5a0d25ecc9235b')!
		expected_shared: hex.decode('790d09b1726d210957ce8f65869ca1ec8fa0b2b06b6bcf9483b3eb55e49e9272')!
		err:             none
	},
	SpecialCases{
		title:           '# special case for x_2 in multiplication by 3'
		status:          '# valid'
		pvkey:           hex.decode('a8a442b7c0a99227b4cb5c75fb9e5a72cea25eba8a0bdf07271bb4a93c2b6665')!
		pbkey:           hex.decode('6e0f1d00b1099d2a71f7be86655feb8988bba5577b02f964043a49f00c749613')!
		expected_shared: hex.decode('b2bbbd173f41d952d329251da973a9500300628177ad0fb79d01e2e263905b38')!
		err:             none
	},
	SpecialCases{
		title:           '# special case for z_2 in multiplication by 3'
		status:          '# valid'
		pvkey:           hex.decode('909fb0bdbf53a69a2fe39c8b2497abd4fa57d2d54e046b5f514595e2c0f33d63')!
		pbkey:           hex.decode('84e827f78cae0cf063e4340198f788c284e07430b3a94a3873df38b1f872ce02')!
		expected_shared: hex.decode('684cc83af806bcd9cd251e1858f3c10f0166e0a0cd2be154339a886b13e7c76f')!
		err:             none
	},
	SpecialCases{
		title:           '# special case for z_2 in multiplication by 3'
		status:          '# acceptable: Twist'
		pvkey:           hex.decode('286a302d5b076d2aba7c2a4daf9e7cc9d8539b7c0391307db65a2f4220d30f70')!
		pbkey:           hex.decode('f26aa6151a4b22390176f6233e742f40f2ecd5137166fb2e1ec9b2f2454ac277')!
		expected_shared: hex.decode('862df92e25277bd94f9af2e1dda51f905a6e2a3f6068a92fabfc6c53da21ec11')!
		err:             none
	},
	SpecialCases{
		title:           '# special case for DA - CB in multiplication by 3'
		status:          '# valid'
		pvkey:           hex.decode('a838b70d17161cb38222f7bc69a3c8576032d580275b3b7d63fba08908cb4879')!
		pbkey:           hex.decode('2b02db3c82477fe21aa7a94d85df379f571c8449b43cbd0605d0acc53c472f05')!
		expected_shared: hex.decode('3f438dbf03947995c99fd4cb366ca7e00e8cfbce64c3039c26d9fad00fa49c70')!
		err:             none
	},
	SpecialCases{
		title:           '# special case for DA - CB in multiplication by 3'
		status:          '# acceptable: Twist'
		pvkey:           hex.decode('b0733b4203267ab3c94c506acadb949a76cc600486fcd601478fcdef79c29d6c')!
		pbkey:           hex.decode('d71dd7db122330c9bbaab5da6cf1f6e1c25345ee6a66b17512b1804ace287359')!
		expected_shared: hex.decode('95f3f1849b0a070184e6077c92ae36ba3324bf1441168b89bb4b9167edd67308')!
		err:             none
	},
	SpecialCases{
		title:           '# special case for BB in multiplication by 3'
		status:          '# acceptable: Twist'
		pvkey:           hex.decode('d844a36b58aefdb08b981796029a2766101884b348f70eed947c2541064caf6a')!
		pbkey:           hex.decode('737bc07de0729bbcfbee3a08e696f97f3770577e4b01ec108f59caf46406d205')!
		expected_shared: hex.decode('6a969af6d236aba08fa83160f699e9ed76fb6355f0662f03dbc5915a3c23063e')!
		err:             none
	},
	SpecialCases{
		title:           '# special case for BB in multiplication by 3'
		status:          '# valid'
		pvkey:           hex.decode('a0b7d312d9b832e124d1bc8cb21db545440e3cf14e7473ee9ccbe9b682f2156c')!
		pbkey:           hex.decode('9758061a7b3e2c02fb5c20875ae6b55b11fb6795990a0f4fdcd1147be5521607')!
		expected_shared: hex.decode('ab39db4aa29ac4017c7446f1ad0c7daa9a37f1b6b4f2e9d2902ccefb84839d28')!
		err:             none
	},
	SpecialCases{
		title:           '# special case for E in multiplication by 3'
		status:          '# valid'
		pvkey:           hex.decode('08f9f4a4fac4db413315f74a59818b2452fc7b7685592e26556775f9b86d907f')!
		pbkey:           hex.decode('fd1a2cd17a93f850deb8c45a2d34539232dfd8a558304209781c6cb58229870e')!
		expected_shared: hex.decode('010218bd67b1b92fee3e7fa4578c13617d73195de10279747e53ba01a254525a')!
		err:             none
	},
	SpecialCases{
		title:           '# special case for E in multiplication by 3'
		status:          '# acceptable: Twist'
		pvkey:           hex.decode('00022b43775ab2f4b91bc1cb54c97f78026289eaaf02abeed04ca84f736c686c')!
		pbkey:           hex.decode('2a209e2ace0e3d6973ffbf7403f9857ff97a5fdcd27f2c7098b444fc3c166738')!
		expected_shared: hex.decode('9f66848681d534e52b659946ea2c92d2fabed43fe6e69032c11153db43dca75b')!
		err:             none
	},
	SpecialCases{
		title:           '# special case for AA in multiplication by 3'
		status:          '# acceptable: Twist'
		pvkey:           hex.decode('d8815bd144518fa526befdd373f5f9cff254d5d3c4660e8a90ef2a22c6876a74')!
		pbkey:           hex.decode('c3ba28057728d0533965ec34979fe7bd93cf6cb644e8da038baa87997b8dc20e')!
		expected_shared: hex.decode('74f95b4700f0185f33c5b5528ed5012a3363f8bbd6f6a840aa1f0f3bdb7c9650')!
		err:             none
	},
	SpecialCases{
		title:           '# special case for AA in multiplication by 3'
		status:          '# valid'
		pvkey:           hex.decode('a82d996093eefdaf283f4049bba4f5af6ecc2e64894f325ee1f9ca1e156d0567')!
		pbkey:           hex.decode('4eb095a86d1e781bb182233075ebf1db109d57135bf91d54fdb18eb371427640')!
		expected_shared: hex.decode('e9677b854851c41cc489e03981ae78690be6cbf0054ea9834759de3e27bcf03e')!
		err:             none
	},
	SpecialCases{
		title:           '# special case for D in multiplication by 4'
		status:          '# acceptable: Twist'
		pvkey:           hex.decode('906a9bfcfd71014d18967680d4509eaa41c666424af98bf9ff7ff49eb1baba41')!
		pbkey:           hex.decode('b9bd793624d6a7e808486110058853edb25e136bd4d6a795d6d2ef53b25e3804')!
		expected_shared: hex.decode('7c6148134c9e8b2ba5daeca41e6a1f3a82d8f75d0b292b23c40fe7f5ce0a2b7a')!
		err:             none
	},
	SpecialCases{
		title:           '# special case for D in multiplication by 4'
		status:          '# valid'
		pvkey:           hex.decode('08ecf76e31a23039ea8a15ee474b6251a9d725bff1a5751eb5ecde9d7d4e2f49')!
		pbkey:           hex.decode('a625a5b7a04cea462d123b485c39ea44a8079aa223c59e9ca97abcd30b500e4b')!
		expected_shared: hex.decode('c941369b085c7465d50d23ceaf6717ab06e24638f217a7b8055ce8ebd3ca1225')!
		err:             none
	},
	SpecialCases{
		title:           '# special case for E in multiplication by 4'
		status:          '# valid'
		pvkey:           hex.decode('3806b036c92d7bc0771998d24dbda2945b601d42449bd3ec4bbf3757d01b894d')!
		pbkey:           hex.decode('0ee3bee8cb3a0afcec22fa2233706e8ec29ccf1af212c0a674745ebba34f9d08')!
		expected_shared: hex.decode('20322dd024fb5a40f327cf7c00da203734c2a279b9666a9ff7d8527c927b675e')!
		err:             none
	},
	SpecialCases{
		title:           '# special case for B in multiplication by 4'
		status:          '# valid'
		pvkey:           hex.decode('700679e8c24df828f2e5212a3263d5e93ea61679988298bab3b480f46f961a48')!
		pbkey:           hex.decode('d05656aa014d476022dfc55e8d3b4884ed0bdf85209be8b55351394d52be684b')!
		expected_shared: hex.decode('20f1fc613874495f20562c10b7a8be47bfc12c168d829d6321aa2de17060e40d')!
		err:             none
	},
	SpecialCases{
		title:           '# special case for B in multiplication by 4'
		status:          '# acceptable: Twist'
		pvkey:           hex.decode('98452ad7df4e26bc4b3d403f9ebf72bb2d7b6b7d5860dbf6fb9a4f78dc02704a')!
		pbkey:           hex.decode('e559c417da7fd5851352f508b90031d49b5d2d0aac88a9c8b5fb6e80165ac10b')!
		expected_shared: hex.decode('c7c6f6d7ce1e4f54c727e5900686c34e6a6953254bd470bbbf0c7c18bbddad73')!
		err:             none
	},
	SpecialCases{
		title:           '# special case for BB in multiplication by 4'
		status:          '# valid'
		pvkey:           hex.decode('e8fef5c9b60f84984e8836d535acb372096ba8159824a0b49a17eccda843bd41')!
		pbkey:           hex.decode('fc6b718ba8b47d24b1cfd6b5d0dd8b20fd920960fabc302dbe4f93bd2a06e933')!
		expected_shared: hex.decode('06f1b495b04a0010845c9d39b13bf2784ade860d9632c8847618c0b34297c249')!
		err:             none
	},
	SpecialCases{
		title:           '# special case for BB in multiplication by 4'
		status:          '# acceptable: Twist'
		pvkey:           hex.decode('90c3cfedd919a2ccd51fb455649e3ad2da1ef0ff619b59a7f9c55a68a8219645')!
		pbkey:           hex.decode('1df3dfdab74ff38177dac294b2da2f49a348bc3b3bc6ce9312bea5ef3ecdd30b')!
		expected_shared: hex.decode('bcc95fb4890ed311f3fb4f44c2b60866cdddec97db820a7f79f475337e16284a')!
		err:             none
	},
	SpecialCases{
		title:           '# special case for x_2 in multiplication by 4'
		status:          '# valid'
		pvkey:           hex.decode('984256b12ef154ff6c2e1d030826164cba3614e3df7688d82b59e16201c9114d')!
		pbkey:           hex.decode('4f03849c24d584534d74302220cfdc90e1bc360bb5e297c0fd0fd5f8d799e416')!
		expected_shared: hex.decode('24acb4afa63919621df795206c3929b599ec9d253693895d51a0555072e89a34')!
		err:             none
	},
	SpecialCases{
		title:           '# special case for x_2 in multiplication by 4'
		status:          '# acceptable: Twist'
		pvkey:           hex.decode('b0a4fe63515169bd82639b515ff7e5c4ac85bba0a53bbaca80477eb3b4250d44')!
		pbkey:           hex.decode('c08f72760d9cb4a542aad6e2af777920c44563bd90356168c3608c6b9af2ef0f')!
		expected_shared: hex.decode('72566a91ccd2bcf38cf639e4a5fcb296f0b67de192c6091242a62fae467fb635')!
		err:             none
	},
	SpecialCases{
		title:           '# special case for DA + CB in multiplication by 4'
		status:          '# valid'
		pvkey:           hex.decode('183f28ec867624ef5eca4827ed0714a5525ef21d5e35038b24d307a3391a2846')!
		pbkey:           hex.decode('03b8ca5efd1777d6d625a945db52b81f11214daf015d09fdc9df7d47b9850e31')!
		expected_shared: hex.decode('35e9289234bd5e531da65d161a065a14f785076088d741c9a2d886efd7d17921')!
		err:             none
	},
	SpecialCases{
		title:           '# special case for DA + CB in multiplication by 4'
		status:          '# acceptable: Twist'
		pvkey:           hex.decode('888c6444ff5eb482b2b10bd4e8a01bdccb65f32934d8026106f16a91349f484c')!
		pbkey:           hex.decode('4eca5f8731b0fa0c106acf578b83a350fa8173a290f1eba803956de34eeb7671')!
		expected_shared: hex.decode('833afb867054b8b9ac70d6013c163e8b7676fd45ae49a1325f3acb75975d8c13')!
		err:             none
	},
	SpecialCases{
		title:           '# special case for A in multiplication by 4'
		status:          '# valid'
		pvkey:           hex.decode('c8a85d140ba150f5c6a8d3cb363bcbcb75365e51c61640e974a0725b5e9d5940')!
		pbkey:           hex.decode('a5562b4ba86b464dff4c2cfae85b384be211771efe8a9697e51d84de47f1eb14')!
		expected_shared: hex.decode('8a914760129575c8ab3270d04b0465fc2f327acaf1676463113803bbb2ec8021')!
		err:             none
	},
	SpecialCases{
		title:           '# special case for A in multiplication by 4'
		status:          '# acceptable: Twist'
		pvkey:           hex.decode('90a3aeb1417c3d61c1efef1ac052218fb55d3a59c4fe930b5a33cc5183b48547')!
		pbkey:           hex.decode('88ae1631cd08ab54c24a31e1fec860391fe29bc50db23eb66709362ec4264929')!
		expected_shared: hex.decode('c1988b6e1f020151ec913b4fb2695bae2c21cc553d0f91cf0c668623a3e5a43d')!
		err:             none
	},
	SpecialCases{
		title:           '# special case for DA - CB in multiplication by 4'
		status:          '# valid'
		pvkey:           hex.decode('b0a710b470e324bb56a7d8ff8788d05eb327616129b84972482425ea4ad4f34b')!
		pbkey:           hex.decode('de0fed2fab6e01492675bc75cbe45d7b45b0306cec8dc67611699811c9aaef16')!
		expected_shared: hex.decode('471ba91a99634f9acf34fd7fd58f72682be97ee1c821486d62ba4e448cbc0417')!
		err:             none
	},
	SpecialCases{
		title:           '# special case for DA - CB in multiplication by 4'
		status:          '# acceptable: Twist'
		pvkey:           hex.decode('b898f0329794747d33269a3989b67e43a7ab5a55fa1210b0e5dba193f4fa094e')!
		pbkey:           hex.decode('6418d49fe440a755c9ff1a3582d35dc9b44c818498f15782c95284fe868a914c')!
		expected_shared: hex.decode('cdb3ca02d5fdb536dbc7395bab12bdcfd55b1ae771a4176dedb55eb4d755c752')!
		err:             none
	},
	SpecialCases{
		title:           '# special case for C in multiplication by 4'
		status:          '# valid'
		pvkey:           hex.decode('7082fc53299a4d30e5d0c383c035935b1eeebd9408fe4d04b93eec24be52eb47')!
		pbkey:           hex.decode('4a474249af8f771f0cfb1116f24fda4c42f4136d2afb766d1b291c73c6668d5a')!
		expected_shared: hex.decode('80dfae7a28bb13d9e51ff199267cec2a19dfc8b6f4974e3446b2f62fe9b62470')!
		err:             none
	},
	SpecialCases{
		title:           '# special case for C in multiplication by 4'
		status:          '# acceptable: Twist'
		pvkey:           hex.decode('702a7448c0ed58e1f4e0e332d096a36360beca2f6955c815bc120b3a691d7742')!
		pbkey:           hex.decode('4d19e156e084fe582a0eb79b2f12b61d0b03f3f229227e798a933eea5a1b6129')!
		expected_shared: hex.decode('c46057fcf63088b3a80e0be5ce24c8026dfadd341b5d8215b8afcb2a5a02bb2b')!
		err:             none
	},
	SpecialCases{
		title:           '# special case for z_2 in multiplication by 4'
		status:          '# valid'
		pvkey:           hex.decode('b080f4ac1e758bbfbfa888a78cb8d624d97b8688002b2017e35f52f3d7c79649')!
		pbkey:           hex.decode('2fe11d723dba63559e1b96147893cb7ec862711806316daa86cd4da769d4b22d')!
		expected_shared: hex.decode('c5edcc5d447071c08dfa8281414ae6a02de753e2f7bb80af5f6253e56db43422')!
		err:             none
	},
	SpecialCases{
		title:           '# special case for CB in multiplication by 4'
		status:          '# valid'
		pvkey:           hex.decode('c0d861a6d5ff91f91e3bd05934161ff0ab0f3ce7e4a2b5b4fcb31ae34b46664f')!
		pbkey:           hex.decode('ae8cf2fcdde710c2c1184524bc32430874dfa08c125f61d6919daf8e66db415a')!
		expected_shared: hex.decode('deaae6c9952844a3a1d01688e7105b0bbeadc160763c2002b6d0bcf35c22d123')!
		err:             none
	},
	SpecialCases{
		title:           '# special case for CB in multiplication by 4'
		status:          '# acceptable: Twist'
		pvkey:           hex.decode('98c092363184e58ad6ce510bd32b309c9d5a46f8d9ee6f64a69d8180bbc6cb45')!
		pbkey:           hex.decode('340b9f613550d14e3c6256caf029b31cad3fe6db588294e2d3af37605a68d837')!
		expected_shared: hex.decode('9efe5cd71102d899a333a45ea6d2c089604b926db8c2645ce5ff21492f27a314')!
		err:             none
	},
	SpecialCases{
		title:           '# special case for AA in multiplication by 4'
		status:          '# valid'
		pvkey:           hex.decode('70785cad160972b711318659b47b574f6941ef6da1ea06508b2650f57ec9e54a')!
		pbkey:           hex.decode('2a59f478402d2829cd3b62e9f7cc01445e8e73a42cb11af00b6b9a9f0e44cb3b')!
		expected_shared: hex.decode('c204bd15f01a11a2efdabe2e902b7cd0aa079316f60e911b3ee5d46262e98631')!
		err:             none
	},
	SpecialCases{
		title:           '# special case for AA in multiplication by 4'
		status:          '# acceptable: Twist'
		pvkey:           hex.decode('60afc8eb1f87df4b55287f3c4698c5f8b997b28a73c573fc273e9c467fb7e44c')!
		pbkey:           hex.decode('836c8e45dd890e658c33e69b6f578a5a774c48b435bc3b91ac693df94a055857')!
		expected_shared: hex.decode('c5457487e90932f57b94af2e8750403e09c9ac727e2bd213590462b6937b0753')!
		err:             none
	},
	SpecialCases{
		title:           '# special case for DA in multiplication by 4'
		status:          '# valid'
		pvkey:           hex.decode('901b20f0cda74076c3d4bf4e02653cd406ed480c355159e22ca44b984f10764f')!
		pbkey:           hex.decode('772e31e776e8d4f23b7af2037af28a37e68f61e740b3904f4ec4c90157be1478')!
		expected_shared: hex.decode('91a9bec28cf18c7094e2d80d2764df59ada0cb1946be422864bd7ad0e533b663')!
		err:             none
	},
	SpecialCases{
		title:           '# special case for z_2 in multiplication by 5'
		status:          '# acceptable: Twist'
		pvkey:           hex.decode('989eee317b9c254dc023f9e35eff0224bc2e0bc871996b946a96970e7506a85e')!
		pbkey:           hex.decode('33c94be58b0f0e6cf363e1b12a2ebfb93040715be91518f21df2953eeab5fb01')!
		expected_shared: hex.decode('d4c3b3467714f2d105904a84cc7e81d7f291304e908041682d8906a683c12125')!
		err:             none
	},
	SpecialCases{
		title:           '# special case for z_2 in multiplication by 5'
		status:          '# valid'
		pvkey:           hex.decode('d83eb7affd1bcc1ec0b4823cee5cf0b15b5f57085aa2708ed437a2925329b550')!
		pbkey:           hex.decode('a8d55d5c1137e9bb626557f9d6eea8d3120e9364f8bcd9b67934260b1a091801')!
		expected_shared: hex.decode('6c1b8e240edfa5db2abb3dc12bcf9e8ac9ca10dd3507083746f6f36dc035d755')!
		err:             none
	},
	SpecialCases{
		title:           '# special case for E in multiplication by 5'
		status:          '# acceptable: Twist'
		pvkey:           hex.decode('c0e19634dbf6460e1486930c46e8556b3c16d6de959904600549bb3e08603455')!
		pbkey:           hex.decode('832a46aec02240d716fe22dea94ad566a3fafbeedcce35c83e41e58076c99749')!
		expected_shared: hex.decode('cd0686b32ea4cddb8e13ff20a78d380749a5d4f6a3dc55d72f4813d949a0ea57')!
		err:             none
	},
	SpecialCases{
		title:           '# special case for E in multiplication by 5'
		status:          '# valid'
		pvkey:           hex.decode('68a1a7ccc50bab4b01e55e18cbd464aff43131fb0741e68d53cdebfc54f33051')!
		pbkey:           hex.decode('dfb1ffc176aff84db30182d2378f83728f83dd1b33d79856f3da5459cf9df907')!
		expected_shared: hex.decode('7b535fc31c6c2a3803d8bd45410a1781bd90a09205da28c9df120df23a9fa32d')!
		err:             none
	},
	SpecialCases{
		title:           '# special case for AA in multiplication by 5'
		status:          '# acceptable: Twist'
		pvkey:           hex.decode('88f9a0d2354adfcbab2d12a0e09b3c7719c944384edfbaa27fe0731cb9c6fc5a')!
		pbkey:           hex.decode('73bdeef8cc044f5ad8d6a241273e1995e0007dc9e6579046df86aa6cd97f5d2a')!
		expected_shared: hex.decode('5aa750de4207869ec7fddab34c639559b1eb27ef244aaf2a702c84963b6d6e7c')!
		err:             none
	},
	SpecialCases{
		title:           '# special case for AA in multiplication by 5'
		status:          '# valid'
		pvkey:           hex.decode('a01f0cad98cf2905b812d3530531bb3ac899391abd1eaf4a3ebed96ac6126f58')!
		pbkey:           hex.decode('0c8090e1cfe7f761cfdf08d944d4aeb7a509a07a6101645b9a4c7c9e9c3d4609')!
		expected_shared: hex.decode('2d49b09f81f3f6fab2c67e32f1bcead2ad09ac9e0d642b0873becfb64de2ab23')!
		err:             none
	},
	SpecialCases{
		title:           '# special case for DA - CB in multiplication by 5'
		status:          '# acceptable: Twist'
		pvkey:           hex.decode('88f9a0d2354adfcbab2d12a0e09b3c7719c944384edfbaa27fe0731cb9c6fc5a')!
		pbkey:           hex.decode('73bdeef8cc044f5ad8d6a241273e1995e0007dc9e6579046df86aa6cd97f5d2a')!
		expected_shared: hex.decode('5aa750de4207869ec7fddab34c639559b1eb27ef244aaf2a702c84963b6d6e7c')!
		err:             none
	},
	SpecialCases{
		title:           '# special case for BB in multiplication by 5'
		status:          '# valid'
		pvkey:           hex.decode('d07babed90b27c4eacafdc871703bd036b720a82b5c094dceb4749eeaeb81052')!
		pbkey:           hex.decode('5b40777e80ff6efe378b5e81959ccdcbb4ca04b9d77edc6b3006deb99926fa22')!
		expected_shared: hex.decode('f482531e523d058d6e3fe3a427fc40dbce6dd6f18defbc097bfd7d0cdd2f710d')!
		err:             none
	},
	SpecialCases{
		title:           '# special case for BB in multiplication by 5'
		status:          '# acceptable: Twist'
		pvkey:           hex.decode('68a3049aef8c069b906cf743286d3952a888bf2b9b93bc8775fb5adde06e9f53')!
		pbkey:           hex.decode('48d952a2924ff167f037707469ec715da72bb65f49aaf4dce7ec5a17039ddb42')!
		expected_shared: hex.decode('de88af905d37417d8331105345dabaab9fd2d3cb1ee902911c1c8eae2991d911')!
		err:             none
	},
	SpecialCases{
		title:           '# special case for x_2 in multiplication by 5'
		status:          '# valid'
		pvkey:           hex.decode('28ec7c693e222c72ac0815f1fd36661357e0a8da7bc996daeeeafcd21c013451')!
		pbkey:           hex.decode('419adb8b1f2f87de016b0c78d1029a210492eb8cadd164b12cd65b1d57bf3634')!
		expected_shared: hex.decode('379f9221abebf3582681a0e857f3da578a1b0121982b96f14b94de5dc8b24528')!
		err:             none
	},
	SpecialCases{
		title:           '# special case for x_2 in multiplication by 5'
		status:          '# acceptable: Twist'
		pvkey:           hex.decode('18efcd5fe345be4985316695391d2c952eee13b0e1ee7584721fbe8b19d4fc5f')!
		pbkey:           hex.decode('9051e55a4050ef4dce0b0c40811f16371e8b16932541da37f069406d848ea424')!
		expected_shared: hex.decode('212dbf9bc89b6873a60dfc8731a10be11ab2dca4b172142e6c9f06614cd72852')!
		err:             none
	},
	SpecialCases{
		title:           '# special case for C in multiplication by 6'
		status:          '# valid'
		pvkey:           hex.decode('f0de9c5f8a9372f30c41ca47a55743ce697d46e32e7a9ae26d32503fd5222767')!
		pbkey:           hex.decode('441c487a48f0a4989d931cd77a6142a0a13d1aabad82623ba8d94b5c374f4f08')!
		expected_shared: hex.decode('d47c46b4329bedcbc1986b3c6d2aa9bcd027d6b68925175d35bbb536b3440801')!
		err:             none
	},
	SpecialCases{
		title:           '# special case for C in multiplication by 6'
		status:          '# acceptable: Twist'
		pvkey:           hex.decode('686be5a12b310420f9bfb209381fd459a5ccd55c752b88337ebe89e1921ae765')!
		pbkey:           hex.decode('0e67ee5c6b65aa802259810b2605f8d7accf9b49bf14cb4a536928e883172915')!
		expected_shared: hex.decode('1d730158da880533dbf1e6c64a8e99f9169611660969b0a84fb42dd8dc2efa3d')!
		err:             none
	},
	SpecialCases{
		title:           '# special case for CB in multiplication by 6'
		status:          '# valid'
		pvkey:           hex.decode('30ce71f856ceb874fe580039ca67e896e6d08207a73cd55db7059127c1342b67')!
		pbkey:           hex.decode('505e7851e2352e311ca9536a1fe6c0d95d648197374ce08e4b8a0fbddf62910b')!
		expected_shared: hex.decode('ea62b0eda2d7b249a42417675a2b82b1e6c0d69a4e7cef336448844d2f432251')!
		err:             none
	},
	SpecialCases{
		title:           '# special case for CB in multiplication by 6'
		status:          '# acceptable: Twist'
		pvkey:           hex.decode('e879752683cd73a834251c65749135e06eb9064d3ae35095d88cde14a02ba366')!
		pbkey:           hex.decode('0e9c4431999ef1ce177e900d37ec6ae665e387e2d4fa27cba8e7baebc65c6520')!
		expected_shared: hex.decode('8ff2ac65c85ee2fe9452fce460f8c87f9570d769cadddc87fe93ef8b7657c726')!
		err:             none
	},
	SpecialCases{
		title:           '# special case for x_2 in multiplication by 6'
		status:          '# valid'
		pvkey:           hex.decode('40cb1fe06b08f068f7080ba07c695eda91a2bebeadd4db95c97dd7c91af2566d')!
		pbkey:           hex.decode('ec3c8b0c10b1fa65dbbd17cf1ba5f86381284765709b07c5f0428e3d5bcd3920')!
		expected_shared: hex.decode('384f2221618e71d456b1551651efdb708a161d7f89f5604b27eb872d4aa93276')!
		err:             none
	},
	SpecialCases{
		title:           '# special case for x_2 in multiplication by 6'
		status:          '# acceptable: Twist'
		pvkey:           hex.decode('d805a7014755dd656f98d2b331f2d2d4912725ef3d03752f26f74dc1ad61666a')!
		pbkey:           hex.decode('a244413ddc3a205d038d64266833eea1efba51ba62c9c6cdcdbe943be52bb00c')!
		expected_shared: hex.decode('66484a4120e0eb0c7e0505e1d2c5d15de9b52b72e094c9bac88634200c557267')!
		err:             none
	},
	SpecialCases{
		title:           '# special case for DA - CB in multiplication by 6'
		status:          '# valid'
		pvkey:           hex.decode('c0ea97e442e5dc1c8142bfab7089ecb9bb9c5ae372f9907c2825e678defae567')!
		pbkey:           hex.decode('dad981552c57541c57ef395ed770ce5edc48f8015461b2ba7aa831ec593ceb15')!
		expected_shared: hex.decode('9093bfa3ed3491d0891f02ae466e5e13c980df229db7404c5b9d34e4ed21c653')!
		err:             none
	},
	SpecialCases{
		title:           '# special case for DA - CB in multiplication by 6'
		status:          '# acceptable: Twist'
		pvkey:           hex.decode('b0333f09ac1eaacd3cd617eb8832e9de488b458b735cb4b5345f517130c25d6b')!
		pbkey:           hex.decode('c588dfe6e733d90581cbe112079749d8eb30ab8631134ec29abfb98b32e76522')!
		expected_shared: hex.decode('6e88bb6bf75596bbe5f1fbe91e365a527a156f4f1b57c13ac1e3e6db93191239')!
		err:             none
	},
	SpecialCases{
		title:           '# special case for DA + CB in multiplication by 6'
		status:          '# valid'
		pvkey:           hex.decode('109697f400210f9a92de80a8bed264097199bc240e22767b54d8bb22050b7a61')!
		pbkey:           hex.decode('aa34d772e9ace43c4d92f4f85596ab9ccd8c36c4f4cbddc819afe2a33cb8b216')!
		expected_shared: hex.decode('2533b845bb83e3d48cffa8dbd1edd5d601778662d5da03759152a5e0a84b357d')!
		err:             none
	},
	SpecialCases{
		title:           '# special case for DA + CB in multiplication by 6'
		status:          '# acceptable: Twist'
		pvkey:           hex.decode('d036308a53c11bebcb02e83688ad74fec43f8462ef4d806272676637d99b3765')!
		pbkey:           hex.decode('1f06cfe464ccc0e27a5ec5f9edd9bc7bc822ad2ff5068ca5c963d20edd1a2d22')!
		expected_shared: hex.decode('eb40a3974b1b0310b1597d1f1f4101c08dca727455a9d8224cd061a7aa3cb628')!
		err:             none
	},
	SpecialCases{
		title:           '# special case for z_2 in multiplication by 6'
		status:          '# valid'
		pvkey:           hex.decode('00e099eb23125dab5ec35a419d455d0ba8c01da160f9354e9fb21e6a55d55c64')!
		pbkey:           hex.decode('8dfee48ad8b367488ea4dafcf7086e305356a80901f87c720149a5f522337453')!
		expected_shared: hex.decode('45dc39831f3471d7466bbe29c8142b1a6d6b00c47fea021be2ffc452d9046806')!
		err:             none
	},
	SpecialCases{
		title:           '# special case for z_2 in multiplication by 6'
		status:          '# acceptable: Twist'
		pvkey:           hex.decode('685c0784aa6d194c1b859bda44c4e27cd1dfdf34776e498dd03d09f87ae68a65')!
		pbkey:           hex.decode('b775e016b32a97f49971121906763f3a0b41689092b9583b6710cf7dee03a61c')!
		expected_shared: hex.decode('11393bb548813e04fb54133edbe0626458e80981885e1fe5f3377e8ebe9afa52')!
		err:             none
	},
	SpecialCases{
		title:           '# special case for D in multiplication by 6'
		status:          '# valid'
		pvkey:           hex.decode('a8b64b8ed397773b8290425ca5c2f7c3e50fac7a4781bd4a54c133781c9a1360')!
		pbkey:           hex.decode('ff0f15adeab334afeda3916785ddd38d252dce9876c2357b643b5dc2c06a3b1d')!
		expected_shared: hex.decode('9f04e42c1b2f311d87e1470a4708bba25ac6ffd3f7b486f9b6b502ecbb2c004e')!
		err:             none
	},
	SpecialCases{
		title:           '# special case for D in multiplication by 6'
		status:          '# acceptable: Twist'
		pvkey:           hex.decode('204a3b5652854ff48e25cd385cabe6360f64ce44fea5621db1fa2f6e219f3063')!
		pbkey:           hex.decode('ed1c82082b74cc2aaebf3dc772ba09557c0fc14139a8814fc5f9370bb8e98858')!
		expected_shared: hex.decode('e0a82f313046024b3cea93b98e2f8ecf228cbfab8ae10b10292c32feccff1603')!
		err:             none
	},
	SpecialCases{
		title:           '# special case for DA in multiplication by 6'
		status:          '# valid'
		pvkey:           hex.decode('5082e497c42979cdbfdd1b3b0653cfea6f2ceb7d07639ebf3541866bb60edb62')!
		pbkey:           hex.decode('151f54a8a899711757b3b118fc5501779d621d25227af53d0af00b7583ba8824')!
		expected_shared: hex.decode('fac30a74f4ca99f6cf233065e9acd826690cab364bf69320b58095783ed76e11')!
		err:             none
	},
	SpecialCases{
		title:           '# special case for DA in multiplication by 6'
		status:          '# acceptable: Twist'
		pvkey:           hex.decode('f85a8db44f9e56b11729f51682a9769fc504f93597cbe39444616b224532106e')!
		pbkey:           hex.decode('a819c667ed466bd9a69ea0b38642ee8e53f40a50377b051eb590142dd27e3431')!
		expected_shared: hex.decode('17f6543c4727e7f129ee82477655577635c125a20c3dc8ba206ca3cc4854ca6c')!
		err:             none
	},
	SpecialCases{
		title:           '# special case for z_2 in multiplication by 7'
		status:          '# valid'
		pvkey:           hex.decode('c006ab1762720882017d106b9a4675fdd47005657155c90ca61d4cbf7cc4f973')!
		pbkey:           hex.decode('1ee1b9a74604ac31c3db83280170e3811504fcc78c7626b5b2c07a99d80daa0a')!
		expected_shared: hex.decode('a1b30418436ba1908804ffcce1be2cdcf50c61a8e3938d95c790abdb786b8022')!
		err:             none
	},
	SpecialCases{
		title:           '# special case for z_2 in multiplication by 7'
		status:          '# acceptable: Twist'
		pvkey:           hex.decode('d071807d607953da432d8574d5f3f420676dafdbc6a285a36e1d737624d77c75')!
		pbkey:           hex.decode('f226c2d6bd7831eda1b51ee5aec29443a507ef9f7a04e2340f349dbf14933844')!
		expected_shared: hex.decode('a5976fda89954a81e442107f9e416a2b4b481bbd4654ebc0c7b57a78b45b4979')!
		err:             none
	},
	SpecialCases{
		title:           '# special case for BB in multiplication by 7'
		status:          '# valid'
		pvkey:           hex.decode('c86fc76650cf3b58837aa0f0633560415241c6c4f8f293ba0222b7d6a3875773')!
		pbkey:           hex.decode('010850a0974d3e89c029d252b46f739548294c0f9a23183863f9455b9559c211')!
		expected_shared: hex.decode('63788190b10d7451f5fc2b82c421151db4f3e22782e392da6d8d3aba2c344306')!
		err:             none
	},
	SpecialCases{
		title:           '# special case for E in multiplication by 7'
		status:          '# acceptable: Twist'
		pvkey:           hex.decode('98ff2856ef44b4fa14d86782ea793828bdf6f1ef9b669cac1aae338a7bb69376')!
		pbkey:           hex.decode('0f460100d88a1d316dff02d1b22ffb2e42d99d0b92474fc3ec7d62567d0cf112')!
		expected_shared: hex.decode('ed83e810ce5ff0868f8589623bb13478dec1c22326c92765ae5e48c84bbabb24')!
		err:             none
	},
	SpecialCases{
		title:           '# special case for E in multiplication by 7'
		status:          '# valid'
		pvkey:           hex.decode('b0cdbfdd98bd988d7c6a530455c51c57dd33fd2c7aee3961971bd3a31388fc71')!
		pbkey:           hex.decode('13756a411ff3ae0c39222dde0810f08c432463162d81ef061071249a48439e15')!
		expected_shared: hex.decode('ff94862117d3c6edc9dd5f4852fa8a589452b924ca8a75cb23b3d68dfed88c4b')!
		err:             none
	},
	SpecialCases{
		title:           '# special case for AA in multiplication by 7'
		status:          '# acceptable: Twist'
		pvkey:           hex.decode('00615e4697014fc12484ef53a1440206410a8df78caa0bfff82161db83fea574')!
		pbkey:           hex.decode('102e95eadca7c3c28e5d52336c857bad99ea246f299b06334f401276f49ca814')!
		expected_shared: hex.decode('3952efb93573ae9ce2162d10e4b8c46435859f3f2778db89f72bc579e695cb51')!
		err:             none
	},
	SpecialCases{
		title:           '# special case for AA in multiplication by 7'
		status:          '# valid'
		pvkey:           hex.decode('009738e1e6efef9e2cad8b416fe90a098eb5cb0199f2df5218166c7b181ea079')!
		pbkey:           hex.decode('ba74e766d44855ec93bd441aa41058a4c4ad2be63c639a3f9a87bde51eeaba20')!
		expected_shared: hex.decode('fec3e94cb5f316625b090c2c820828ce0f3ee431e8d6e12abccc7ef2bd0be81a')!
		err:             none
	},
	SpecialCases{
		title:           '# special case for x_2 in multiplication by 7'
		status:          '# valid'
		pvkey:           hex.decode('f0c9c3984854d5bd599d3819738a023eb795e93586dc0e5e29b1c870c612d178')!
		pbkey:           hex.decode('cc275a2cdd9125e52f20ce2abad41f920afa5a643fb7f276ef416f761d689f1e')!
		expected_shared: hex.decode('b210e368729501d9f9b6ebefbebae38f195f91eaf2a5a3a49288bb615ff2216c')!
		err:             none
	},
	SpecialCases{
		title:           '# special case for x_2 in multiplication by 7'
		status:          '# acceptable: Twist'
		pvkey:           hex.decode('b0fe7b06b9950600b3a7ce1d7bb2a1d984194cc9d6c8964504c364dd5c875b74')!
		pbkey:           hex.decode('2743ba408d5f68c65324a485086a004b6bbf784cc9e8b1a7dbeb8c4b9414b018')!
		expected_shared: hex.decode('a6b97da989dccf730f122d455152328051c8ed9abc1815c19eec6501d6cfc77c')!
		err:             none
	},
	SpecialCases{
		title:           '# special case for DA - CB in multiplication by 7'
		status:          '# valid'
		pvkey:           hex.decode('40e300cb1ff260574f85b3f04aac478464a86e6203b3d4656418f4305157877b')!
		pbkey:           hex.decode('ac9fd80a45da109fa2329390e5a951cfc03065d7bb4a7855826ccb22c3bfeb3d')!
		expected_shared: hex.decode('67b88774f19bd1081d6f23656a135803e34ae1cdcae10818124a78569c299f42')!
		err:             none
	},
	SpecialCases{
		title:           '# special case for DA - CB in multiplication by 7'
		status:          '# acceptable: Twist'
		pvkey:           hex.decode('706cee5f9b357c03b2f1913294f6e4f0ca5a190a87d30268327d0cb6bdd5bc79')!
		pbkey:           hex.decode('238de7fcc8a3f194c3554c328efb1215d0640ac674b61a98ef934ec004cfd73b')!
		expected_shared: hex.decode('0681036a0d27583ba6f2be7630613171a33fb8a6c8991c53b379999f0f15923b')!
		err:             none
	},
	SpecialCases{
		title:           '# special case for D in multiplication by 8'
		status:          '# acceptable: Twist'
		pvkey:           hex.decode('a8edec59ae6ba23813ec54d66df152e0626762b97d4b0c20e0dd8a5695d86e47')!
		pbkey:           hex.decode('dc99ad0031463e4537c01e16629966d1b962c0b4e4872f067ca3c26ccc957001')!
		expected_shared: hex.decode('6cfa935f24b031ff261a7cd3526660fd6b396c5c30e299575f6a322281191e03')!
		err:             none
	},
	SpecialCases{
		title:           '# special case for D in multiplication by 8'
		status:          '# valid'
		pvkey:           hex.decode('1098723ffe567ea6dcc8d04ecc01efafeea0aee44e1c733be8b1e5d97c8b8041')!
		pbkey:           hex.decode('b32750fd80d2d7c62c6b8e39670654baea5719a3e072e99507fd5bcb23898264')!
		expected_shared: hex.decode('c623e2d2083f18110a525f2b66d89ed82d313b6a2dd082f6b7a6e733134f5a06')!
		err:             none
	},
	SpecialCases{
		title:           '# special case for DA + CB in multiplication by 8'
		status:          '# acceptable: Twist'
		pvkey:           hex.decode('882f5578ae4a13d8f5af473bdde1709bf2e059df809ee05b505f34de857c3447')!
		pbkey:           hex.decode('8abb8cfd60c6f8a4d84d0750d3b40a4f846b30edf2052fef7df84142cd0d9e47')!
		expected_shared: hex.decode('5faba645fc21f9421ebd35c69bdb1d85b46f95e3746ff7f4886bc280a9ab2522')!
		err:             none
	},
	SpecialCases{
		title:           '# special case for DA + CB in multiplication by 8'
		status:          '# valid'
		pvkey:           hex.decode('30473a77a98374f67d5bd43df231ce142916aea0d271e72333fa47dc441a0247')!
		pbkey:           hex.decode('21cc338d7869e5863349cc739c8a6946cfc797cb82fbf62dcd2154844b106003')!
		expected_shared: hex.decode('b9e5728b37435b1d339988f93267d59f3bd1c517851c5a258e74cb64aea73d2d')!
		err:             none
	},
	SpecialCases{
		title:           '# special case for AA in multiplication by 8'
		status:          '# acceptable: Twist'
		pvkey:           hex.decode('401539703ca4980db4ba42c59fc29e83b4189f2ddea53ba54ca966c06898a640')!
		pbkey:           hex.decode('eebd858850b56febb707f27a7aad5ff5ab4b0e0c73b9c86ec4ca0f42e7f38e75')!
		expected_shared: hex.decode('581e4b12b0f39a7cc42dee4513ecfdd20b595f905f17ad8c1fbf1b5cb2068b31')!
		err:             none
	},
	SpecialCases{
		title:           '# special case for AA in multiplication by 8'
		status:          '# valid'
		pvkey:           hex.decode('60c9af7f4d03136a6034ae52deadfd9d4f274ad8122812eb92a53169c8354141')!
		pbkey:           hex.decode('a26a722f7ba71ccfc96ed8e108d7c9f842d17f92051ee7d429ea7fa7908ab907')!
		expected_shared: hex.decode('f5cb3a1b76185a29a6360b2142feebb11f3d08f4fd8d73df3a5228624a521c02')!
		err:             none
	},
	SpecialCases{
		title:           '# special case for z_2 in multiplication by 8'
		status:          '# acceptable: Twist'
		pvkey:           hex.decode('487882956c49c69fd0e2d7277a24fb1dbe4b0365b36a13f63440248bca2fbb42')!
		pbkey:           hex.decode('7bbc504e04d134eedc13f06dfdfc69c518257a3f374040a49a8d21dac109110c')!
		expected_shared: hex.decode('690305c9e192cd8a513f705b3f101ecdf3db1ea15a09c4a1bce3a8cdc3a1a93f')!
		err:             none
	},
	SpecialCases{
		title:           '# special case for z_2 in multiplication by 8'
		status:          '# valid'
		pvkey:           hex.decode('c8eb056286e098e6b2c79e42f007ebc6ab3705346cdbdace949b5de1e8c36743')!
		pbkey:           hex.decode('c800bf799783275eb93312b43dc032ccdfb00a4b77c8b3772cd2fec8db7e4a09')!
		expected_shared: hex.decode('6bf264532fc70a6a7e459f4579eca6b84f8f76ab85c3264b20bca725a6eb6c40')!
		err:             none
	},
	SpecialCases{
		title:           '# special case for B in multiplication by 8'
		status:          '# acceptable: Twist'
		pvkey:           hex.decode('f83e4647e82c560aa082c59641e13bf366be8f24dc01d14801e67841160bed47')!
		pbkey:           hex.decode('66a09767a0d83bb18d404e1200375a745d1f1f749d5dc6f84a205efa6a11bc65')!
		expected_shared: hex.decode('1401829aac4e64bcfa297a7effc60477090d3627a64a35b872ae055d2091785f')!
		err:             none
	},
	SpecialCases{
		title:           '# special case for B in multiplication by 8'
		status:          '# valid'
		pvkey:           hex.decode('a8a5d4f7894a519537babfac736de36054f508dae434b4fe63cd5633846a2647')!
		pbkey:           hex.decode('ceb90c56508cf330c7f25bab42b05b5612a8310690107ac63a404c0ade788009')!
		expected_shared: hex.decode('3d145851b6ff2b92b5807ed1df21eb50c9f24c4474d4721db3abb7356df7b764')!
		err:             none
	},
	SpecialCases{
		title:           '# special case for C in multiplication by 8'
		status:          '# acceptable: Twist'
		pvkey:           hex.decode('786a97207adbd4b0d6bfc9f49b18660ad3606c12e325044b8690b4fa07874641')!
		pbkey:           hex.decode('84c92d8ecf3d0cb22dde7d721f04140c2d9c179cc813ce6cf8db2dce6168880d')!
		expected_shared: hex.decode('07538f1b6583041c4949fafae3349d62f9dd302d3d86857af0dedc0d5ad6741f')!
		err:             none
	},
	SpecialCases{
		title:           '# special case for x_2 in multiplication by 8'
		status:          '# valid'
		pvkey:           hex.decode('20596e1dc56596823d37698dfa699c79874aaefde797f863ef92135980fb2043')!
		pbkey:           hex.decode('6d3cd623f26a7453fa05a01ae758ba84d3c58d93d60ce32735a15e0d053d5b12')!
		expected_shared: hex.decode('7c3219b3c1fae1f95590ac843efd2084a1f4bd3efa2f592f022032db64ebcd77')!
		err:             none
	},
	SpecialCases{
		title:           '# special case for x_2 in multiplication by 8'
		status:          '# acceptable: Twist'
		pvkey:           hex.decode('38141518e8e5efa1d031c6c4d95480239f6c30b8ccd8c751a9e04bd3aec17342')!
		pbkey:           hex.decode('8f195547346b3d53b7ea4f742b22f1ef7b3cc01a7d3dcd19aa7c5b03f31bd214')!
		expected_shared: hex.decode('a31f6b249d64a87c4aed329c6c05c3f2240b3ca938ccdc920ba8016c1aeaeb45')!
		err:             none
	},
	SpecialCases{
		title:           '# special case for E in multiplication by 8'
		status:          '# valid'
		pvkey:           hex.decode('7012852211f6536fca79937e7e316c9149b0e20ea03f951e1bb072895ca0e044')!
		pbkey:           hex.decode('c6b9e6288737ad40452cec1022871d90af1642d10bd0a97792b1a9c8998e2220')!
		expected_shared: hex.decode('db990d979f4f22f766e7826d93554e771b361de461274d6c37baadeb8ef7be4e')!
		err:             none
	},
	SpecialCases{
		title:           '# special case for E in multiplication by 8'
		status:          '# acceptable: Twist'
		pvkey:           hex.decode('8815052344dcad97efd1341e9072a808cf999e46e52cf04e0cfbcd9901e18d43')!
		pbkey:           hex.decode('e3655448339e4850806eb58abba0c89185511ea72c37c49e9583ee6dd235d213')!
		expected_shared: hex.decode('5e10dfbff4443efcae2ccc78c289a41460d5a82f79df726b8824ccbef7146d40')!
		err:             none
	},
	SpecialCases{
		title:           '# special case for DA - CB in multiplication by 8'
		status:          '# valid'
		pvkey:           hex.decode('f04f87f4e623af4c31ceca0bb87fac2d5b12517b5a7284902ad75838e65f1e41')!
		pbkey:           hex.decode('8842317357bde825ef438a1c53906fb8b04ea360f7ef338c78e668586047936a')!
		expected_shared: hex.decode('488b8341c9cb1bbf124510b9f8dae4faf2e0dca9b84e00e952a63b5aa328a860')!
		err:             none
	},
	SpecialCases{
		title:           '# special case for DA - CB in multiplication by 8'
		status:          '# acceptable: Twist'
		pvkey:           hex.decode('101b990bd83d684126ff047d930c27d086a588dd19683d2629f0e34f4374ab41')!
		pbkey:           hex.decode('42e5a6b8e9654bb4ad624af3f491877977513cc8775c8fb312ad19dbf3903a28')!
		expected_shared: hex.decode('223f1eb552308373026d11c954684ce6db870b638b190b9443e50aae219f4e3e')!
		err:             none
	},
	SpecialCases{
		title:           '# special case for CB in multiplication by 8'
		status:          '# valid'
		pvkey:           hex.decode('f8e161d69297e017d7c51b1b1ff3ba703d4c4cf8fc2b8ff47f74c3ff8c7d3541')!
		pbkey:           hex.decode('65922a06e9be4e8a5e8aceb1a4e08fe90f01e10ef2dd27315427cedfcf95ec32')!
		expected_shared: hex.decode('038de7fdb9cc0030f5c11dda00589f0a95f65658815b06ed013553a02b6c5017')!
		err:             none
	},
	SpecialCases{
		title:           '# special case for CB in multiplication by 8'
		status:          '# acceptable: Twist'
		pvkey:           hex.decode('b0ffa5f4922bb117ad75ff43acac62331efaa45536fe88306e4a4cb58db73a47')!
		pbkey:           hex.decode('d128ea3e13325ed6ebd6533a9fd3045a55f25ad8b67def30912843504c1aab29')!
		expected_shared: hex.decode('30512142d3e3a4cad6726d9d35f2e043fca9dfb750884ae22b2547c840f3587b')!
		err:             none
	},
	SpecialCases{
		title:           '# special case for BB in multiplication by 8'
		status:          '# valid'
		pvkey:           hex.decode('105d7589f8abef0acf0940da84a69e8f2f306fa73c9afd27342287c1dba80044')!
		pbkey:           hex.decode('d36a240e972dc16e9b97a997ada337f02760d05c46d7f8d7b4e9ea9a635c7c64')!
		expected_shared: hex.decode('22b0dea3b3b7ca55eceeaae6443426548c7c15cc7ddf31780318d1c23879c16a')!
		err:             none
	},
	SpecialCases{
		title:           '# special case for BB in multiplication by 8'
		status:          '# acceptable: Twist'
		pvkey:           hex.decode('1893d4388b0e90f0b50208aa8f0cc24f576d03641baf1c3eddb2a3efa69c9d40')!
		pbkey:           hex.decode('4f5b8b9892b8a46df08d76a4745b1c58d4e7a394905435875688ca11f1e9d86a')!
		expected_shared: hex.decode('a25e1306684ad7870a31f0404566e8d28f2d83d4b9497822c57f8781b18fec20')!
		err:             none
	},
	SpecialCases{
		title:           '# special case for A in multiplication by 8'
		status:          '# valid'
		pvkey:           hex.decode('10c81a4e78d82145b266e1d74b3869bf1c27427803ebb11c92ff8073d1e4cc46')!
		pbkey:           hex.decode('d995cb287e9a9c5791f3cae3d494a5b516a1e26cbc930f43e73c8b70b69d783b')!
		expected_shared: hex.decode('330f5d0b5bccc90f7694dfdd9c6449a62d93af8840eaf571e3e0610e0198b03f')!
		err:             none
	},
	SpecialCases{
		title:           '# special case for A in multiplication by 8'
		status:          '# acceptable: Twist'
		pvkey:           hex.decode('48b98b4a99eadd73012c07fe5c4a0b9590ac55e821353b41d5f665e17188bc41')!
		pbkey:           hex.decode('479afb1e73dc77c3743e51e9ec0bcc61ce66ed084dc10bfa2794b4c3e4953769')!
		expected_shared: hex.decode('bdef00caa514b2f8ab1fb2241e83787a02601ecdff6cf166c4210f8c1ade4211')!
		err:             none
	},
	SpecialCases{
		title:           '# special case for DA in multiplication by 8'
		status:          '# valid'
		pvkey:           hex.decode('a898af8138e11ae45bbcefa737182a571885f92d515c32056c7cb0d7deac4741')!
		pbkey:           hex.decode('0cad7545ade2fd93fcae007c97648348f26d85829bdb7223a63eccb84e56d475')!
		expected_shared: hex.decode('c8085877800c175e949cdd88e196eb9c4841da2ac446dfed9085bda5bbec265d')!
		err:             none
	},
	SpecialCases{
		title:           '# special case for DA in multiplication by 8'
		status:          '# acceptable: Twist'
		pvkey:           hex.decode('1897678e38222a61fe105dc6643c1eb5940e8dbc73ed6c00f25a34328f43a641')!
		pbkey:           hex.decode('378eda41470b0f238a200f80809ad562ca41e62411a61feb7f7e9b752b554642')!
		expected_shared: hex.decode('bfd5b5acd2d89f213a26caf54062f9a24e6f6fd8ddd0cd2e5e47b7fea4a9c537')!
		err:             none
	},
	SpecialCases{
		title:           '# special case for A in multiplication by 9'
		status:          '# valid'
		pvkey:           hex.decode('b0bfef6ec095b5a1f93917d32f16a21d0462c1fde17446f5a590232d9c895f4a')!
		pbkey:           hex.decode('60f27ed0a27804ced237cf3c1cc776650fb320bae6d5acb564e97b56cba25210')!
		expected_shared: hex.decode('4c300895827382a9d1079028bd6f694a7a12ddac9c76abac6fdf5d29457a3310')!
		err:             none
	},
	SpecialCases{
		title:           '# special case for A in multiplication by 9'
		status:          '# acceptable: Twist'
		pvkey:           hex.decode('60497d4464ed8823c50fbc6b68620826c4f629c1d9193058df6bf857c6aecc4b')!
		pbkey:           hex.decode('f93a73270ac19194b8e4ffd02be4b1438525f84a76224688ea89a9dd6a1bd623')!
		expected_shared: hex.decode('7285fbb3f76340a979ab6e288727a2113332cf933809b018b8739a796a09d00b')!
		err:             none
	},
	SpecialCases{
		title:           '# special case for DA - CB in multiplication by 9'
		status:          '# acceptable: Twist'
		pvkey:           hex.decode('608c84d2b76fccda579e974db3d3b2ce39a6bc0dad440599db22411b60467849')!
		pbkey:           hex.decode('557b825012d98f065bb95a2ab9b2d2d8b83fd2037912508c263f86d7e36c4f24')!
		expected_shared: hex.decode('5ce84842dbae8b795b3d545343558045508f271383bfb3dd3943f4101398c864')!
		err:             none
	},
	SpecialCases{
		title:           '# special case for z_2 in multiplication by 9'
		status:          '# valid'
		pvkey:           hex.decode('80f233936a8821936d39114c84d929e79760b27680779e5009e1709410dd8e4f')!
		pbkey:           hex.decode('ae98296d4a2fbcbb40b472f4063231608bb1465c226c8a4a2dff29afd915882a')!
		expected_shared: hex.decode('4f11aa0c313195f96f25cadcbf49f06a932d8b051879ea537d1c6dfee7f36d35')!
		err:             none
	},
	SpecialCases{
		title:           '# special case for z_2 in multiplication by 9'
		status:          '# acceptable: Twist'
		pvkey:           hex.decode('6079dae04c40a59ea4e0c8c17092e4c85ea9133d143307363487836df4e30349')!
		pbkey:           hex.decode('ccc1dc186229dba9a9360a0f7ff00247a3732625acaacd18ea13a9a8b40fac4f')!
		expected_shared: hex.decode('4f678b64fd1f85cbbd5f7e7f3c8ac95ec7500e102e9006d6d42f48fb2473ab02')!
		err:             none
	},
	SpecialCases{
		title:           '# special case for E in multiplication by 9'
		status:          '# valid'
		pvkey:           hex.decode('f0a34d6d76896e17cb8f66feda23115ffb96f246b823bb63dec08335787de74c')!
		pbkey:           hex.decode('362eb92dab9fb29f7ed0e03843dcc15797928c2b4e51ec260204179c1c12945f')!
		expected_shared: hex.decode('d7f4583ee4fe86af3a3f1dfcb295ba3a3e37bced7b9c6f000a95336530318902')!
		err:             none
	},
	SpecialCases{
		title:           '# special case for E in multiplication by 9'
		status:          '# acceptable: Twist'
		pvkey:           hex.decode('10230bd0721f4c8c4b921881dd88c603af501ee80e2102f8acc30cf8b2acd349')!
		pbkey:           hex.decode('e853062b2d6f38d021d645163ea208d0e193a479f11f99971b98e21188fd0b2c')!
		expected_shared: hex.decode('64bdfa0207a174ca17eeba8df74d79b25f54510e6174923034a4d6ee0c167e7b')!
		err:             none
	},
	SpecialCases{
		title:           '# special case for x_2 in multiplication by 9'
		status:          '# valid'
		pvkey:           hex.decode('b0c1822566e016c12ae35ec035edd09af3cb7a48f55c9028e05e1178a8c3824e')!
		pbkey:           hex.decode('90ef70844ead1613f69df7d78c057813f866c0d95e6d22caee4a012b9c1c4b33')!
		expected_shared: hex.decode('9369ebb3d2b744341cba77302719a4b2d63aff612872f86d9877a76bc919ca1c')!
		err:             none
	},
	SpecialCases{
		title:           '# special case for x_2 in multiplication by 9'
		status:          '# acceptable: Twist'
		pvkey:           hex.decode('e06fe64e2117796f997bbcd3bcad3067cf1291640a3a643fb359809a4016834d')!
		pbkey:           hex.decode('88c1ae575ad073dda66c6eacb7b7f436e1f8ad72a0db5c04e5660b7b719e4c4b')!
		expected_shared: hex.decode('335394be9c154901c0b4063300001804b1cd01b27fa562e44f3302168837166e')!
		err:             none
	},
	SpecialCases{
		title:           '# special case for BB in multiplication by 9'
		status:          '# valid'
		pvkey:           hex.decode('7089654baacbb65bd00cd8cb9de4680e748075e8842ca69d448fb50fea85e74e')!
		pbkey:           hex.decode('6c0044cd10578c5aff1ff4917b041b76c9a9ae23664eb8cf978bd7aa192cf249')!
		expected_shared: hex.decode('0d8c21fa800ee63ce5e473d4c2975495062d8afa655091122cb41799d374594f')!
		err:             none
	},
]

// RFC 7748 Type 2 vector test
//
// Please be aware, this is long running times test, its loop until 1.000.000 times.
// so, please be patient. See the detail of the type 2 test from rfc
// see at https://datatracker.ietf.org/doc/html/rfc7748#section-5.2
//
// Currently, this test was disabled due to its takes long time to complete,
// please uncomment it if you need run the test.
// On my test machine, its pass successfully in 2225590.282 ms
// ```v
// ... (previous line)
// ...
// start i: 999995
// start i: 999996
// start i: 999997
// start i: 999998
// start i: 999999
//
//     OK   2225590.282 ms     3 asserts | curve25519.test_x25519_after_iteration_from_rfc_vector_type2()
//     Summary for running V tests in "curve25519_test.v": 3 passed, 3 total. Elapsed time: 2225590 ms.
// ```
// Its slightly modified to iterate only 1.000 iterations.
fn test_x25519_after_iteration_from_rfc_vector_type2() ! {
	iteration1 := hex.decode('422c8e7a6227d7bca1350b3e2bb7279f7897b87bb6854b783c60e80311ae3079')!
	iteration1000 := hex.decode('684cf59ba83309552800ef566f2f4d3c1c3887c49360e3875f2eb94d99532c51')!

	// Disabled this one, to reduces needed time to complete
	// iteration1000000 := hex.decode('7c3911e0ab2586fd864497297e575e6f3bc601c0883c30df5f4dd2d24f665424') !
	num_of_iterations := 1000

	// Initially, set k and u to be the following values
	key := '0900000000000000000000000000000000000000000000000000000000000000'
	mut k := hex.decode(key)!
	mut u := k.clone()
	mut r := []u8{len: 32}

	// For each iteration, set k to be the result of calling the function and u
	// to be the old value of k.  The final result is the value left in k.
	//
	for i in 0 .. num_of_iterations {
		// println('start i: ${i}')
		tmp_k := k.clone()
		r = curve25519.x25519(mut k, u)!
		unsafe {
			u = tmp_k
		}
		unsafe {
			k = r
		}
		if i == 0 {
			assert k == iteration1
		} else if i == 999 {
			assert k == iteration1000
		}
		// Disabled this one
		//
		// else if i == 999999 {
		// assert k == iteration1000000
		// }
	}
}
