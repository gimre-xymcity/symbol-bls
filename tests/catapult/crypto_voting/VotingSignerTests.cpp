/**
*** Copyright (c) 2016-2019, Jaguar0625, gimre, BloodyRookie, Tech Bureau, Corp.
*** Copyright (c) 2020-present, Jaguar0625, gimre, BloodyRookie.
*** All rights reserved.
***
*** This file is part of Catapult.
***
*** Catapult is free software: you can redistribute it and/or modify
*** it under the terms of the GNU Lesser General Public License as published by
*** the Free Software Foundation, either version 3 of the License, or
*** (at your option) any later version.
***
*** Catapult is distributed in the hope that it will be useful,
*** but WITHOUT ANY WARRANTY; without even the implied warranty of
*** MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
*** GNU Lesser General Public License for more details.
***
*** You should have received a copy of the GNU Lesser General Public License
*** along with Catapult. If not, see <http://www.gnu.org/licenses/>.
**/

#include "catapult/crypto_voting/VotingSigner.h"
#include "catapult/utils/RandomGenerator.h"
#include "tests/test/crypto/CurveUtils.h"
#include "tests/test/crypto/SignVerifyTests.h"
#include "tests/TestHarness.h"
#include <numeric>

#if defined(__clang__) || defined(__GNUC__)
#define C99
#endif

extern "C" {
#include <amcl/config_curve_BLS381.h>
#include <amcl/bls_BLS381.h>
#include <amcl/big_512_56.h>
}

namespace catapult { namespace crypto {

#define TEST_CLASS VotingSignerTests

	// region basic sign verify tests

	namespace {
		constexpr uint8_t Coordinate_Mask = 0x1F;
		constexpr uint8_t Compressed_Bit = 0x80;

		struct SignVerifyTraits {
		public:
			using KeyPair = VotingKeyPair;
			using Signature = VotingSignature;

		public:
			static VotingKeyPair GenerateKeyPair() {
				utils::LowEntropyRandomGenerator generator;
				return VotingKeyPair::FromPrivate(GenerateVotingPrivateKey(generator));
			}

			static bool CoerceToBool(VotingVerifyResult result) {
				return VotingVerifyResult::Success == result;
			}

			static auto GenerateKeyPairForNonCanonicalSignatureTest() {
				return KeyPair::FromString("0102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F20");
			}

			static auto GetPayloadsForNonCanonicalSignatureTest() {
				// for keypair above, last byte has been selected in a way
				// that one of the components of the signature + modulus still fits on 381-bits
				// first payload is for q.a component, second payload for q.b component
				return std::vector{
					std::array<uint8_t, 10>{ { 1, 2, 3, 4, 5, 6, 7, 8, 9, 40 } },
					std::array<uint8_t, 10>{ { 1, 2, 3, 4, 5, 6, 7, 8, 9, 35 } }
				};
			}

			static auto MakeNonCanonical(const Signature& canonicalSignature, size_t index) {
				BIG_384_58 modulus;
				BIG_384_58_rcopy(modulus, Modulus_BLS381);
				Signature nonCanonicalSignature = canonicalSignature;

				if (0 == index) {
					BIG_384_58 xa;
					BIG_384_58_fromBytes(xa, reinterpret_cast<char*>(&nonCanonicalSignature[MODBYTES_384_58]));
					BIG_384_58_add(xa, xa, modulus);
					BIG_384_58_toBytes(reinterpret_cast<char*>(&nonCanonicalSignature[MODBYTES_384_58]), xa);
				} else if (1 == index) {
					char bCopy[MODBYTES_384_58];
					std::memcpy(bCopy, nonCanonicalSignature.data(), MODBYTES_384_58);
					bCopy[0] &= Coordinate_Mask;

					BIG_384_58 xb;
					BIG_384_58_fromBytes(xb, bCopy);
					BIG_384_58_add(xb, xb, modulus);
					BIG_384_58_toBytes(reinterpret_cast<char*>(&nonCanonicalSignature[0]), xb);

					// fix flags
					nonCanonicalSignature[0] = nonCanonicalSignature[0] | Compressed_Bit | 0x20;
				}

				// Sanity:
				EXPECT_NE(canonicalSignature, nonCanonicalSignature);
				return nonCanonicalSignature;
			}
		};
	}

	DEFINE_SIGN_VERIFY_TESTS(SignVerifyTraits)

	// endregion

	// region test vectors

	namespace {
		struct TestVectorsInput {
			std::string InputData;
			std::vector<std::string> PrivateKeys;
			std::vector<std::string> ExpectedPublicKeys;
			std::vector<std::string> ExpectedSignatures;
		};

		TestVectorsInput GetTestVectorsInputKeys() {
			TestVectorsInput input;

			input.PrivateKeys = {
				"65EE8DE6512F3DB4937403D446DFC8FC0B05E245A6A7D670956B0A119F67461F",
				"6BF1EC345B429ED691C3E705D088446F8D11234C4556909F454B82D276B7B4D0",
				"221CD859A351AD34423D8F72402D172B97026CB3CDB3D9D67092660CC25FA6F1",
				"11468904C63C2BB72534B5FA719FB6027B0B7CF5E302B167F4DC83B9EEF41889",
				"21C1E1BAF6ECAF8C0D18C28818DE5A9756D5594BE8C6C9E838936813DA8B7B54"
			};

			input.ExpectedPublicKeys = {
				"AA072A3C3241D659BE2C49F31D4A860388B4565A737B7D02227D1E41197885583E15C7225914068B2810D1D067171FC9",
				"A15534BD60D9EABD987EE72B92D4A1D67FA2439221A7F893B02D4420F341AD519B6C6C382D7E34ED1CD763877E968C62",
				"92C8CAA9D3B01AFFCC7909EE3205347481390FE35AA87B8C79E261C1E2B3E13F2D79E11017895F78A5C28A4AA092C6BF",
				"A3F2DA269915329DABE103DD68AD833F9EAB90976F37DF6FA208A94D0869FC99F884BCD6C8AA10C14E6DDF5359A8F39E",
				"841C72FC5271C2631108045589D836C4C3530C64DABF37986F0988888DBCA0FBD1E34AD700C93AB70547951D8F9CAF93"
			};

			return input;
		}

		// test vectors based on:
		// https://github.com/kwantam/bls_sigs_ref/blob/sgn0_fix/test-vectors/sig_g2_basic/rfc6979
		TestVectorsInput GetTestVectorsInputSample() {
			auto input = GetTestVectorsInputKeys();
			input.InputData = "sample";

			input.ExpectedSignatures = {
				"ADE4251A0136CCD502D441E47D2DF8462A96CC85ED1720B85A8BF2BE1AA49EEDB96F73297302C5A85599225896AEF1CE"
				"028A459ADDC39D8617B825C65119FF8D22B437B70C8C36DEF6411102278274816A8C585BD31F8EBFD0BBB3BD66A74A33",
				"A49DEE0999240934E9A2D49B52E4B6B0F10A3BA51900A46CD110878CD9BC75860239ECFBE1FEC097BFCDB243F931EB93"
				"09A849A26354FE58A87E3E1C640669FB445CCD90D7E8E064F265991261115257436F44D268F3B249D77ED0D15ED8ED0E",
				"8891B7054F731CAB4AF712D3BCD51D23158C957C2A4F59DA0C9FFF50344F9CE756E9C7E11247838B3D3A21E28F863F07"
				"05C0957B81CF84DBC35C040C6CD2C706352D932592A53900E11C59345F4B53E60361D7FB4B5F9A56E6B06DE73CBA1F91",
				"8FACD1D63AE37EF863FA91947BFF40B6D108C55BA4A0B9808A8CC44CDD776A72CE28D61E8251CACAF9CEDE95CD0792BE"
				"1750FFCA14786689A55723B86A29CB223E85E2B03DA184C4BE7468E509F93C9184AEFC7AA9BB155178C38FF86702DFDF",
				"A96761A5B79FA3D20D31CA04CBDB269EE6118C61B4E0F06BD6C348A4DDBE5F71DA6206D6620EEEA65CCF5DD36CEB316A"
				"1632620D5C509AF48331480FEB134AE815AA1918FA4D39D3D8C362AA86B5508CC1991B8EC11E962959F4D6E2A791402A"
			};

			// Sanity:
			EXPECT_EQ(input.PrivateKeys.size(), input.ExpectedPublicKeys.size());
			EXPECT_EQ(input.PrivateKeys.size(), input.ExpectedSignatures.size());
			return input;
		}

		TestVectorsInput GetTestVectorsInputTest() {
			auto input = GetTestVectorsInputKeys();
			input.InputData = "test";

			input.ExpectedSignatures = {
				"B184D62FE3052488A4A56C7301988DB544F12B4F8F34553F4CFF2C3E39322893EB8E34943487C1D6EEAD742F6797DC73"
				"0E22C4817114D69D3BDC83E3C8EB2242D8B844D5C7CB56F0FF14E6E2CE5892B842D7D653B02E8FC63BFEFC2941F2855B",
				"950074853757536FA65D215ADE813228F5FED1C94426302DC0380F21CE9D2C22D65ED92CBCA41910CDA40AFCC46061EF"
				"051B042FF7E3B8277269CE687773B1F64B4FC3FA31292FAD2BC4ABE61FEDD89A734701524DB4778041F79994C85B6ED8",
				"B2BE787378D0871FE5CFBE3118187FA14E1228ABF8CAE6F07370F0CD8E498F71747245F03B991D5F9542294A60923477"
				"0EA5BBBA854E37A87435DBD0E03F60CF1E5F16D5FD1A44B6908C56761B85E85C786913F0B490B4F85D1A5E0B679B2C25",
				"803FF119DABA856FB81800FFF41FB1E435BD3998904C342FA024CE7688C6B518F943568FC7AF8803D804C47962E35B4B"
				"0BFCD5DE1225F94C239AB7180FDA593814618E4816897B8D6C82F9ECC2D9976742EC5F868EC63B72C6DB25C986C3F339",
				"98687ABC1CE9F3AB02CA85593BDBCB7EC208255546F6879FEE48A9C66DEC342D39A7DEA254C02BEEFE7F152DB28CDBE8"
				"1321723F1B2160EA9D1EFA0DD8A8FB46BFD4A1463F4E52E17300F27EFEC6D733FA1B015D4AE9C8484B3D75B075224B2D"
			};

			// Sanity:
			EXPECT_EQ(input.PrivateKeys.size(), input.ExpectedPublicKeys.size());
			EXPECT_EQ(input.PrivateKeys.size(), input.ExpectedSignatures.size());
			return input;
		}

		template<typename TArray>
		VotingSignature SignPayload(const VotingKeyPair& keyPair, const TArray& payload) {
			VotingSignature signature;
			EXPECT_NO_THROW(Sign(keyPair, payload, signature));
			return signature;
		}

		void AssertSignPassesTestVectors(const TestVectorsInput& input) {
			for (auto i = 0u; i < input.ExpectedSignatures.size(); ++i) {
				// Act:
				auto keyPair = VotingKeyPair::FromString(input.PrivateKeys[i]);
				auto payload = RawBuffer{ reinterpret_cast<const uint8_t*>(input.InputData.data()), input.InputData.size() };
				auto signature = SignPayload(keyPair, payload);

				// Assert:
				auto message = "test vector at " + std::to_string(i);
				EXPECT_EQ(utils::ParseByteArray<VotingKey>(input.ExpectedPublicKeys[i]), keyPair.publicKey()) << message;
				EXPECT_EQ(utils::ParseByteArray<VotingSignature>(input.ExpectedSignatures[i]), signature) << message;
			}
		}

		void AssertVerifyPassesTestVectors(const TestVectorsInput& input) {
			for (auto i = 0u; i < input.ExpectedSignatures.size(); ++i) {
				// Act:
				auto keyPair = VotingKeyPair::FromString(input.PrivateKeys[i]);
				auto payload = RawBuffer{ reinterpret_cast<const uint8_t*>(input.InputData.data()), input.InputData.size() };
				auto signature = SignPayload(keyPair, payload);
				auto verifyResult = Verify(keyPair.publicKey(), payload, signature);

				// Assert:
				auto message = "test vector at " + std::to_string(i);
				EXPECT_EQ(VotingVerifyResult::Success, verifyResult) << message;
			}
		}
	}

	TEST(TEST_CLASS, SignPassesTestVectors_Sample) {
		AssertSignPassesTestVectors(GetTestVectorsInputSample());
	}

	TEST(TEST_CLASS, SignPassesTestVectors_Test) {
		AssertSignPassesTestVectors(GetTestVectorsInputTest());
	}

	TEST(TEST_CLASS, VerifyPassesTestVectors_Sample) {
		AssertVerifyPassesTestVectors(GetTestVectorsInputSample());
	}

	TEST(TEST_CLASS, VerifyPassesTestVectors_Test) {
		AssertVerifyPassesTestVectors(GetTestVectorsInputTest());
	}

	// endregion

	// region invalid signatures

	namespace {
		void AssertVerifyRejects(VotingVerifyResult expectedResult, const consumer<VotingKey&, VotingSignature&>& mutate) {
			// Arrange:
			auto keyPair = SignVerifyTraits::GenerateKeyPair();
			auto payload = test::GenerateRandomArray<17>();
			auto signature = SignPayload(keyPair, payload);

			// Sanity:
			auto verifyResult = Verify(keyPair.publicKey(), payload, signature);
			EXPECT_EQ(VotingVerifyResult::Success, verifyResult);

			// Act:
			auto publicKey = keyPair.publicKey();
			mutate(publicKey, signature);
			verifyResult = Verify(publicKey, payload, signature);

			// Assert:
			EXPECT_EQ(expectedResult, verifyResult) << "verification should fail";
		}
	}

	TEST(TEST_CLASS, VerifyRejectsInvalidSignatureFlags) {
		AssertVerifyRejects(VotingVerifyResult::Failure_Invalid_Signature_Flags, [](const auto&, auto& signature) {
			signature[0] ^= 0x80;
		});
		AssertVerifyRejects(VotingVerifyResult::Failure_Invalid_Signature_Flags, [](const auto&, auto& signature) {
			signature[0] ^= 0x40;
		});

		AssertVerifyRejects(VotingVerifyResult::Failure_Invalid_Signature_Flags, [](const auto&, auto& signature) {
			signature[MODBYTES_384_58] |= 0x80;
		});
		AssertVerifyRejects(VotingVerifyResult::Failure_Invalid_Signature_Flags, [](const auto&, auto& signature) {
			signature[MODBYTES_384_58] |= 0x40;
		});
		AssertVerifyRejects(VotingVerifyResult::Failure_Invalid_Signature_Flags, [](const auto&, auto& signature) {
			signature[MODBYTES_384_58] |= 0x20;
		});
	}

	TEST(TEST_CLASS, VerifyRejectsWhenSignatureHasInvalidSign) {
		AssertVerifyRejects(VotingVerifyResult::Failure_Verification_Failed, [](const auto&, auto& signature) {
			signature[0] ^= 0x20;
		});
	}

	TEST(TEST_CLASS, VerifyRejectsWhenSignatureIsInvalidPoint) {
		AssertVerifyRejects(VotingVerifyResult::Failure_Signature_Is_Invalid_Point, [](const auto&, auto& signature) {
			// prepare signature with x-coord=(0,1) that does not result in valid point
			signature = VotingSignature();
			signature[0] = 0x80;
			signature[95] = 1;
		});
		AssertVerifyRejects(VotingVerifyResult::Failure_Signature_Is_Invalid_Point, [](const auto&, auto& signature) {
			// prepare signature with x-coord=(0,1) that does not result in valid point
			signature = VotingSignature();
			signature[0] = 0xA0;
			signature[95] = 1;
		});
	}

	TEST(TEST_CLASS, VerifyRejectsWhenSignatureIsNotInSubgroup) {
		AssertVerifyRejects(VotingVerifyResult::Failure_Signature_Subgroup_Check, [](const auto&, auto& signature) {
			// prepare signature with x-coord=(0,2), this will result in valid point, but not in subgroup
			signature = VotingSignature();
			signature[0] = 0x80;
			signature[95] = 2;
		});

		AssertVerifyRejects(VotingVerifyResult::Failure_Signature_Subgroup_Check, [](const auto&, auto& signature) {
			// prepare signature with x-coord=(0,2), this will result in valid point, but not in subgroup
			signature = VotingSignature();
			signature[0] = 0xA0;
			signature[95] = 2;
		});
	}

	// endregion

	// region invalid public key

	TEST(TEST_CLASS, VerifyRejectsInvalidPublicKeyFlags) {
		AssertVerifyRejects(VotingVerifyResult::Failure_Invalid_Public_Key_Flags, [](auto& key, const auto&) {
			key[0] ^= 0x80;
		});
		AssertVerifyRejects(VotingVerifyResult::Failure_Invalid_Public_Key_Flags, [](auto& key, const auto&) {
			key[0] ^= 0x40;
		});
	}

	TEST(TEST_CLASS, VerifyRejectsWhenPublicKeyHasInvalidSign) {
		AssertVerifyRejects(VotingVerifyResult::Failure_Verification_Failed, [](auto& key, const auto&) {
			key[0] ^= 0x20;
		});
	}

	TEST(TEST_CLASS, VerifyRejectsWhenPublicKeyIsInvalidPoint) {
		AssertVerifyRejects(VotingVerifyResult::Failure_Public_Key_Is_Invalid_Point, [](auto& key, const auto&) {
			// prepare public key that does not result in valid point
			key = VotingKey();
			key[0] = 0x80;
			key[47] = 1;
		});
		AssertVerifyRejects(VotingVerifyResult::Failure_Public_Key_Is_Invalid_Point, [](auto& key, const auto&) {
			// prepare public key that does not result in valid point
			key = VotingKey();
			key[0] = 0xA0;
			key[47] = 1;
		});
	}

	TEST(TEST_CLASS, VerifyRejectsWhenPublicKeyIsNotInSubgroup) {
		AssertVerifyRejects(VotingVerifyResult::Failure_Public_Key_Subgroup_Check, [](auto& key, const auto&) {
			// prepare "zero" public key, this will result in valid point, but not in subgroup
			key = VotingKey();
			key[0] = 0x80;
		});

		AssertVerifyRejects(VotingVerifyResult::Failure_Public_Key_Subgroup_Check, [](auto& key, const auto&) {
			// prepare "zero" public key, this will result in valid point, but not in subgroup
			key = VotingKey();
			key[0] = 0xA0;
		});
	}

	namespace {
		auto MakeNonCanonicalPublicKey(const VotingKey& originalKey) {
			VotingKey key = originalKey;
			BIG_384_58 modulus;
			BIG_384_58_rcopy(modulus, Modulus_BLS381);

			char bCopy[MODBYTES_384_58];
			std::memcpy(bCopy, key.data(), MODBYTES_384_58);
			key[0] &= Coordinate_Mask;

			BIG_384_58 xb;
			BIG_384_58_fromBytes(xb, bCopy);
			BIG_384_58_add(xb, xb, modulus);
			BIG_384_58_toBytes(reinterpret_cast<char*>(&key[0]), xb);

			// fix flags
			key[0] = key[0] | Compressed_Bit | 0x20;
			return key;
		}
	}

	TEST(TEST_CLASS, VerifyRejectsNonCanonicalPublicKey) {
		// Arrange:
		// last byte of a key pair has been selected, so that resulting public key is < 2^381
		auto keyPair = VotingKeyPair::FromString("0102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F07");
		auto payload = std::array<uint8_t, 10>{ { 1, 2, 3, 4, 5, 6, 7, 8, 9, 0 } };
		auto publicKey = keyPair.publicKey();
		auto signature = SignPayload(keyPair, payload);

		// Act:
		auto nonCanonicalPublicKey = MakeNonCanonicalPublicKey(publicKey);
		auto canonicalResult = crypto::Verify(publicKey, payload, signature);
		auto nonCanonicalResult = crypto::Verify(nonCanonicalPublicKey, payload, signature);

		// Assert:
		EXPECT_EQ(VotingVerifyResult::Success, canonicalResult);
		EXPECT_EQ(VotingVerifyResult::Failure_Public_Key_Not_Reduced, nonCanonicalResult);
	}

	// endregion
}}
