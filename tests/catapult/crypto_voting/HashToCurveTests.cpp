/**
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

#include "catapult/crypto_voting/HashToCurve.h"
#include "catapult/utils/HexParser.h"
#include "tests/test/nodeps/Conversions.h"
#include "tests/TestHarness.h"

#if defined(__clang__) || defined(__GNUC__)
#define C99
#endif

extern "C" {
#include <amcl/config_curve_BLS381.h>
#include <amcl/bls_BLS381.h>
#include <amcl/big_512_56.h>
}

namespace catapult { namespace crypto {

#define TEST_CLASS HashToCurveTests

	namespace {
		// region test vectors

		struct TestVector {
			std::string Message;
			std::pair<std::string, std::string> ExpectedPx;
			std::pair<std::string, std::string> ExpectedPy;
		};

		std::vector<TestVector> GetTestVectors() {
			return {
				{
					"",
					// px
					{
						"0141EBFBDCA40EB85B87142E130AB689C673CF60F1A3E98D69335266F30D9B8D4AC44C1038E9DCDD5393FAF5C41FB78A",
						"05CB8437535E20ECFFAEF7752BADDF98034139C38452458BAEEFAB379BA13DFF5BF5DD71B72418717047F5B0F37DA03D"
					},
					// py
					{
						"0503921D7F6A12805E72940B963C0CF3471C7B2A524950CA195D11062EE75EC076DAF2D4BC358C4B190C0C98064FDD92",
						"12424AC32561493F3FE3C260708A12B7C620E7BE00099A974E259DDC7D1F6395C3C811CDD19F1E8DBF3E9ECFDCBAB8D6"
					}
				},
				{
					"abc",
					// px
					{
						"02C2D18E033B960562AAE3CAB37A27CE00D80CCD5BA4B7FE0E7A210245129DBEC7780CCC7954725F4168AFF2787776E6",
						"139CDDBCCDC5E91B9623EFD38C49F81A6F83F175E80B06FC374DE9EB4B41DFE4CA3A230ED250FBE3A2ACF73A41177FD8"
					},
					// py
					{
						"1787327B68159716A37440985269CF584BCB1E621D3A7202BE6EA05C4CFE244AEB197642555A0645FB87BF7466B2BA48",
						"00AA65DAE3C8D732D10ECD2C50F8A1BAF3001578F71C694E03866E9F3D49AC1E1CE70DD94A733534F106D4CEC0EDDD16"
					}
				},
				{
					"abcdef0123456789",
					// px
					{
						"121982811D2491FDE9BA7ED31EF9CA474F0E1501297F68C298E9F4C0028ADD35AEA8BB83D53C08CFC007C1E005723CD0",
						"190D119345B94FBD15497BCBA94ECF7DB2CBFD1E1FE7DA034D26CBBA169FB3968288B3FAFB265F9EBD380512A71C3F2C"
					},
					// py
					{
						"05571A0F8D3C08D094576981F4A3B8EDA0A8E771FCDCC8ECCEAF1356A6ACF17574518ACB506E435B639353C2E14827C8",
						"0BB5E7572275C567462D91807DE765611490205A941A5A6AF3B1691BFE596C31225D3AABDF15FAFF860CB4EF17C7C3BE"
					}
				},
				{
					"q128_qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq"
					"qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq",
					// px
					{
						"19A84DD7248A1066F737CC34502EE5555BD3C19F2ECDB3C7D9E24DC65D4E25E50D83F0F77105E955D78F4762D33C17DA",
						"0934ABA516A52D8AE479939A91998299C76D39CC0C035CD18813BEC433F587E2D7A4FEF038260EEF0CEF4D02AAE3EB91"
					},
					// py
					{
						"14F81CD421617428BC3B9FE25AFBB751D934A00493524BC4E065635B0555084DD54679DF1536101B2C979C0152D09192",
						"09BCCCFA036B4847C9950780733633F13619994394C23FF0B32FA6B795844F4A0673E20282D07BC69641CEE04F5E5662"
					}
				},
				{
					"a512_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
					"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
					"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
					"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
					"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
					"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
					// px
					{
						"01A6BA2F9A11FA5598B2D8ACE0FBE0A0EACB65DECEB476FBBCB64FD24557C2F4B18ECFC5663E54AE16A84F5AB7F62534",
						"11FCA2FF525572795A801EED17EB12785887C7B63FB77A42BE46CE4A34131D71F7A73E95FEE3F812AEA3DE78B4D01569"
					},
					// py
					{
						"0B6798718C8AED24BC19CB27F866F1C9EFFCDBF92397AD6448B5C9DB90D2B9DA6CBABF48ADC1ADF59A1A28344E79D57E",
						"03A47F8E6D1763BA0CAD63D6114C0ACCBEF65707825A511B251A660A9B3994249AE4E63FAC38B23DA0C398689EE2AB52"
					}
				}
			};
		}

		// endregion

		void ToBig(BIG_384_58& bigValue, const std::string& hexString) {
			auto buffer = test::HexStringToVector(hexString);
			BIG_384_58_fromBytes(bigValue, reinterpret_cast<char*>(buffer.data()));
		}

		FP2_BLS381 ToFp2(const std::pair<std::string, std::string>& hexStringPair) {
			BIG_384_58 a;
			BIG_384_58 b;

			ToBig(a, hexStringPair.first);
			ToBig(b, hexStringPair.second);

			FP2_BLS381 point;
			FP2_BLS381_from_BIGs(&point, a, b);
			return point;
		}

		void AssertPoint(G2Point& point, const TestVector& testVector, size_t index) {
			// Assert:
			auto px = ToFp2(testVector.ExpectedPx);
			auto py = ToFp2(testVector.ExpectedPy);
			auto& p = point.ref<ECP2_BLS381>();

			EXPECT_TRUE(FP2_BLS381_equals(&px, &p.x)) << index;
			EXPECT_TRUE(FP2_BLS381_equals(&py, &p.y)) << index;

			// - last operation in hash2curve is clear_cofactor, afterwards z should always be "1"
			FP2_BLS381 one;
			FP2_BLS381_one(&one);
			EXPECT_TRUE(FP2_BLS381_equals(&one, &p.z)) << index;
		}
	}

	TEST(TEST_CLASS, HashToCurvePassesTestVectors) {
		// Arrange:
		auto testVectors = GetTestVectors();

		size_t i = 0u;
		for (const auto& testVector : testVectors) {
			// Act:
			RawBuffer buffer{ reinterpret_cast<const uint8_t*>(testVector.Message.data()), testVector.Message.size() };
			G2Point point;
			HashToCurveG2(point, { buffer });

			// Assert:
			AssertPoint(point, testVector, i);
			++i;
		}
	}
}}
