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

#include "catapult/crypto_voting/VotingKeyPair.h"
#include "catapult/crypto/SecureRandomGenerator.h"
#include "catapult/utils/HexParser.h"
#include "tests/test/nodeps/RandomnessTestUtils.h"
#include "tests/TestHarness.h"

namespace catapult { namespace crypto {

#define TEST_CLASS VotingKeyPairTests

	// region VotingKeyPair

	TEST(TEST_CLASS, KeyPairPassesNemTestVectors) {
		// Arrange: based on milagro's example_ecdh_bls381
		// https://github.com/apache/incubator-milagro-crypto-c/blob/develop/examples/example_ecdh_ZZZ.c.in
		std::string dataSet[] {
			"06A89AD2E96D5132670F01612D10F0C38923679C5D9449ADB4201BA9E37245F9",
			"6C6DE1132EABAE9D3F42DF5D6E378EE588B8AEBD2D7B569AA973CD3DE908D843"
		};

		// skipping first byte from example and OR-ing with 0x80 or 0xA0 as needed
		std::string expectedSet[] {
			"8428D6096DE4AF679FAC73B9558FB18556F249C1D70908378B1590DC0831D8ED391B2C2E2796DB4E681FB41E5B0BE99A",
			"AF80009A642CA8FAAED086376C41EB6C926F466D31DE2E252B28CC0DA369C4BE49C449622E7CB4EB3175C4B2C1BC7EBE"
		};

		ASSERT_EQ(CountOf(dataSet), CountOf(expectedSet));
		for (size_t i = 0; i < CountOf(dataSet); ++i) {
			// Act:
			auto keyPair = VotingKeyPair::FromString(dataSet[i]);

			// Assert:
			EXPECT_EQ(utils::ParseByteArray<VotingKey>(expectedSet[i]), keyPair.publicKey());
		}
	}

	namespace {
		void AssertVotingKeyPairFailsForInvalidPrivateKey(const std::string& key) {
			EXPECT_THROW(VotingKeyPair::FromString(key), catapult_invalid_argument);
		}
	}

	TEST(TEST_CLASS, PublicKeyGenerationFailsForZeroPrivateKey) {
		AssertVotingKeyPairFailsForInvalidPrivateKey("0000000000000000000000000000000000000000000000000000000000000000");
	}

	TEST(TEST_CLASS, PublicKeyGenerationFailsForPrivateKeyThatIsMultipleOfCurveOrder) {
		AssertVotingKeyPairFailsForInvalidPrivateKey("73EDA753299D7D483339D80809A1D80553BDA402FFFE5BFEFFFFFFFF00000001");
		AssertVotingKeyPairFailsForInvalidPrivateKey("E7DB4EA6533AFA906673B0101343B00AA77B4805FFFCB7FDFFFFFFFE00000002");
	}

	// endregion

	// region GenerateVotingPrivateKey

	namespace {
		class WrappedVotingPrivateKeyGenerator {
		public:
			uint8_t operator()() {
				if (VotingPrivateKey::Size == m_position) {
					m_privateKey = GenerateVotingPrivateKey(m_rng);
					m_position = 0;
				}

				return *(m_privateKey.data() + m_position++);
			}

		private:
			SecureRandomGenerator m_rng;
			VotingPrivateKey m_privateKey;
			size_t m_position = VotingPrivateKey::Size;
		};
	}

	TEST(TEST_CLASS, GenerateVotingPrivateKeyGeneratesRandomKey) {
		test::RandomnessTestUtils::AssertExhibitsRandomness<WrappedVotingPrivateKeyGenerator>();
	}

	// endregion
}}
