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

#include "catapult/crypto_voting/ExpandHash.h"
#include "catapult/utils/HexParser.h"
#include "tests/TestHarness.h"

namespace catapult { namespace crypto {

#define TEST_CLASS ExpandHashTests

	namespace {
		std::string AsciiToHexString(const std::string& str) {
			const auto* pAsciiData = reinterpret_cast<const uint8_t*>(str.data());

			std::stringstream out;
			out << utils::HexFormat(pAsciiData, pAsciiData + str.size());
			return out.str();
		}

		// region traits

		struct InputTraits {
			static std::vector<std::string> SampleTestVectorsInput() {
				return {
					AsciiToHexString(""),
					AsciiToHexString("abc"),
					AsciiToHexString("abcdef0123456789"),
					AsciiToHexString(
						"a512_"
						"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
						"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
						"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
						"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
						"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
						"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
						"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
						"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
				};
			}
		};

		// vectors from https://tools.ietf.org/html/draft-irtf-cfrg-hash-to-curve-09#appendix-I.1
		struct Sha256_Traits : public InputTraits {
			using HashBuilder = Sha256_Builder;

			static std::vector<std::string> SampleTestVectorsOutput20() {
				return {
					// ''
					"F659819A6473C1835B25EA59E3D38914C98B374F0970B7E4C92181DF928FCA88",
					// abc
					"1C38F7C211EF233367B2420D04798FA4698080A8901021A795A1151775FE4DA7",
					// abcdef0123456789
					"8F7E7B66791F0DA0DBB5EC7C22EC637F79758C0A48170BFB7C4611BD304ECE89",
					// a512_ + 512 'a'
					"3B8E704FC48336ACA4C2A12195B720882F2162A4B7B13A9C350DB46F429B771B"
				};
			}

			static std::vector<std::string> SampleTestVectorsOutput80() {
				return {
					// ''
					"8BCFFD1A3CAE24CF9CD7AB85628FD111BB17E3739D3B53F89580D217AA79526F"
					"1708354A76A402D3569D6A9D19EF3DE4D0B991E4F54B9F20DCDE9B95A66824CB"
					"DF6C1A963A1913D43FD7AC443A02FC5D9D8D77E2071B86AB114A9F34150954A7"
					"531DA568A1EA8C760861C0CDE2005AFC2C114042EE7B5848F5303F0611CF297F",

					// abc
					"FE994EC51BDAA821598047B3121C149B364B178606D5E72BFBB713933ACC29C1"
					"86F316BAECF7EA22212F2496EF3F785A27E84A40D8B299CEC56032763ECEEFF4"
					"C61BD1FE65ED81DECAFFF4A31D0198619C0AA0C6C51FCA15520789925E813DCF"
					"D318B542F8799441271F4DB9EE3B8092A7A2E8D5B75B73E28FB1AB6B4573C192",

					// abcdef0123456789
					"C9EC7941811B1E19CE98E21DB28D22259354D4D0643E301175E2F474E030D326"
					"94E9DD5520DDE93F3600D8EDAD94E5C364903088A7228CC9EFF685D7EAAC50D5"
					"A5A8229D083B51DE4CCC3733917F4B9535A819B445814890B7029B5DE805BF62"
					"B33A4DC7E24ACDF2C924E9FE50D55A6B832C8C84C7F82474B34E48C6D43867BE",

					// a512_ + 512 'a'
					"396962DB47F749EC3B5042CE2452B619607F27FD3939ECE2746A7614FB83A1D0"
					"97F554DF3927B084E55DE92C7871430D6B95C2A13896D8A33BC48587B1F66D21"
					"B128A1A8240D5B0C26DFE795A1A842A0807BB148B77C2EF82ED4B6C9F7FCB732"
					"E7F94466C8B51E52BF378FBA044A31F5CB44583A892F5969DCD73B3FA128816E"
				};
			}
		};

		// vectors from https://tools.ietf.org/html/draft-irtf-cfrg-hash-to-curve-09#appendix-I.2
		struct Sha512_Traits : public InputTraits {
			using HashBuilder = Sha512_Builder;

			static std::vector<std::string> SampleTestVectorsOutput20() {
				return {
					// ''
					"2EAA1F7B5715F4736E6A5DBE288257ABF1FAA028680C1D938CD62AC699EAD642",
					// abc
					"0EEDA81F69376C80C0F8986496F22F21124CB3C562CF1DC608D2C13005553B0F",
					// abcdef0123456789
					"2E375FC05E05E80DBF3083796FDE2911789D9E8847E1FCEBF4CA4B36E239B338",
					// a512_ + 512 'a'
					"AF57A7F56E9ED2AA88C6EAB45C8C6E7638AE02DA7C92CC04F6648C874EBD560E"
				};
			}

			static std::vector<std::string> SampleTestVectorsOutput80() {
				return {
					// ''
					"0687CE02EBA5EB3FAF1C3C539D1F04BABD3C0F420EDAE244EEB2253B6C6D6865"
					"145C31458E824B4E87CA61C3442DC7C8C9872B0B7250AA33E0668CCEBBD2B386"
					"DE658CA11A1DCCEB51368721AE6DCD2D4BC86EAEBC4E0D11FA02AD053289C9B2"
					"8A03DA6C942B2E12C14E88DBDE3B0BA619D6214F47212B628F3E1B537B66EFCF",

					// abc
					"779AE4FD8A92F365E4DF96B9FDE97B40486BB005C1A2096C86F55F3D92875D89"
					"045FBDBC4A0E9F2D3E1E6BCD870B2D7131D868225B6FE72881A81CC5166B5285"
					"393F71D2E68BB0AC603479959370D06BDBE5F0D8BFD9AF9494D1E4029BD68AB3"
					"5A561341DD3F866B3EF0C95C1FDFAAB384CE24A23427803DDA1DB0C7D8D5344A",

					// abcdef0123456789
					"F0953D28846A50E9F88B7AE35B643FC43733C9618751B569A73960C655C068DB"
					"7B9F044AD5A40D49D91C62302EAA26163C12ABFA982E2B5D753049E000ADF763"
					"0AE117AEB1FB9B61FC724431AC68B369E12A9481B4294384C3C890D576A79264"
					"787BC8076E7CDABE50C044130E480501046920FF090C1A091C88391502F0FBAC",

					// a512_ + 512 'a'
					"01524feea5b22f6509f6b1e805c97df94faf4d821b01aadeebc89e9daaed0733"
					"b4544e50852fd3e019d58eaad6d267a134c8bc2c08bc46c10bfeff3ee03110bc"
					"d8a0d695d75a34092bd8b677bdd369a13325549abab54f4ac907b712bdd3567f"
					"38c4554c51902b735b81f43a7ef6f938c7690d107c052c7e7b795ac635b3200a"
				};
			}
		};

		template<typename TTraits>
		struct TraitsSelector20 : public TTraits {
			static constexpr size_t Requested_Size = 0x20;

			static std::vector<std::string> SampleTestVectorsOutput() {
				return TTraits::SampleTestVectorsOutput20();
			}
		};

		template<typename TTraits>
		struct TraitsSelector80 : public TTraits {
			static constexpr size_t Requested_Size = 0x80;

			static std::vector<std::string> SampleTestVectorsOutput() {
				return TTraits::SampleTestVectorsOutput80();
			}
		};

		// endregion

		template<typename TSelectorTraits>
		void AssertSampleTestVectorsViaSelector() {
			// Arrange:
			using HE = HashExpanderXmd<typename TSelectorTraits::HashBuilder>;
			auto dataSet = TSelectorTraits::SampleTestVectorsInput();
			auto expectedHashes = TSelectorTraits::SampleTestVectorsOutput();

			// Sanity:
			ASSERT_EQ(dataSet.size(), expectedHashes.size());

			auto i = 0u;
			for (const auto& dataHexStr : dataSet) {
				auto buffer = test::HexStringToVector(dataHexStr);
				std::vector<uint8_t> output(TSelectorTraits::Requested_Size, 0);

				// Act:
				std::string dst = "QUUX-V01-CS02-with-expander";
				HE::Expand(buffer, { reinterpret_cast<const uint8_t*>(dst.data()), dst.size() }, output);

				// Assert:
				std::vector<uint8_t> expectedOutput(TSelectorTraits::Requested_Size);
				utils::ParseHexStringIntoContainer(expectedHashes[i].c_str(), expectedHashes[i].size(), expectedOutput);
				EXPECT_EQ(expectedOutput, output) << " at vector " << i;
				++i;
			}
		}
	}

#define EXPAND_HASH_TRAITS_BASED_TEST(TEST_NAME) \
	template<typename TTraits> void TRAITS_TEST_NAME(TEST_CLASS, TEST_NAME)(); \
	TEST(TEST_CLASS, TEST_NAME##_Sha256) { TRAITS_TEST_NAME(TEST_CLASS, TEST_NAME)<Sha256_Traits>(); } \
	TEST(TEST_CLASS, TEST_NAME##_Sha512) { TRAITS_TEST_NAME(TEST_CLASS, TEST_NAME)<Sha512_Traits>(); } \
	template<typename TTraits> void TRAITS_TEST_NAME(TEST_CLASS, TEST_NAME)()

	EXPAND_HASH_TRAITS_BASED_TEST(SampleTestVectors20) {
		AssertSampleTestVectorsViaSelector<TraitsSelector20<TTraits>>();
	}

	EXPAND_HASH_TRAITS_BASED_TEST(SampleTestVectors80) {
		AssertSampleTestVectorsViaSelector<TraitsSelector80<TTraits>>();
	}

	namespace {
		auto Split(const std::vector<uint8_t>& buffer, int numParts) {
			std::vector<std::vector<uint8_t>> parts;
			auto partSize = static_cast<int>(buffer.size()) / numParts;
			for (auto i = 0; i < numParts - 1; ++i)
				parts.emplace_back(buffer.cbegin() + i * partSize, buffer.cbegin() + (i + 1) * partSize);

			parts.emplace_back(buffer.cbegin() + (numParts - 1) * partSize, buffer.cend());
			return parts;
		}
	}

	EXPAND_HASH_TRAITS_BASED_TEST(BufferListVariantMatchesSingleBufferVariant) {
		// Arrange:
		using SelectorTraits = TraitsSelector80<TTraits>;
		using HE = HashExpanderXmd<typename TTraits::HashBuilder>;
		auto dataSet = InputTraits::SampleTestVectorsInput();
		auto expectedHashes = SelectorTraits::SampleTestVectorsOutput();

		auto i = 0u;
		for (const auto& dataHexStr : dataSet) {
			auto buffer = test::HexStringToVector(dataHexStr);
			auto buffers = Split(buffer, 3);
			std::vector<uint8_t> output(SelectorTraits::Requested_Size, 0);

			// Act:
			std::string dst = "QUUX-V01-CS02-with-expander";
			HE::Expand({ buffers[0], buffers[1], buffers[2] }, { reinterpret_cast<const uint8_t*>(dst.data()), dst.size() }, output);

			// Assert:
			std::vector<uint8_t> expectedOutput(SelectorTraits::Requested_Size);
			utils::ParseHexStringIntoContainer(expectedHashes[i].c_str(), expectedHashes[i].size(), expectedOutput);
			EXPECT_EQ(expectedOutput, output) << " at vector " << i;
			++i;
		}
	}

	EXPAND_HASH_TRAITS_BASED_TEST(ThrowsWhenRequestedDataIsTooLarge) {
		// Arrange:
		using HE = HashExpanderXmd<typename TTraits::HashBuilder>;
		RawBuffer buffer(nullptr, 0);

		// Act + Assert:
		MutableRawBuffer output(nullptr, TTraits::HashBuilder::OutputType::Size * 255 + 1);
		EXPECT_THROW(HE::Expand(buffer, buffer, output), catapult_invalid_argument);
	}

	EXPAND_HASH_TRAITS_BASED_TEST(ProducesOutputWhenRequestedDataSizeIsAtBoundary) {
		// Arrange:
		using HE = HashExpanderXmd<typename TTraits::HashBuilder>;
		RawBuffer buffer(nullptr, 0);

		// Act + Assert:
		std::vector<uint8_t> zero(TTraits::HashBuilder::OutputType::Size * 255, 0);
		std::vector<uint8_t> output(TTraits::HashBuilder::OutputType::Size * 255, 0);
		EXPECT_NO_THROW(HE::Expand(buffer, buffer, output));
		EXPECT_NE(zero, output);
	}
}}
