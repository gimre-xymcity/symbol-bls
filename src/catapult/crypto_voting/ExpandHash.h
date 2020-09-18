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

#pragma once
#include "catapult/crypto/Hashes.h"
#include "catapult/exceptions.h"

namespace catapult { namespace crypto {

	/// HMAC-like hash expander, as described in hash to curve draft.
	template<typename THashBuilder>
	class HashExpanderXmd {
		private:
			static constexpr size_t Hash_Output_Size = THashBuilder::OutputType::Size;

			static constexpr size_t NumOutputBlocks(size_t requestedLength) {
				return (requestedLength + Hash_Output_Size - 1) / Hash_Output_Size;
			}

			static void PrepareB0(
					std::initializer_list<const RawBuffer> buffersList,
					const RawBuffer& dst,
					uint16_t expandedSize,
					typename THashBuilder::OutputType& b0) {
				THashBuilder builder;
				std::array<uint8_t, THashBuilder::Hash_Block_Size> Zpad{ 0 };
				builder.update(Zpad);

				builder.update(buffersList);

				// l_i_b_str (big endian) + index
				std::array<uint8_t, 3> libWithId{
					static_cast<uint8_t>(expandedSize >> 8),
					static_cast<uint8_t>(expandedSize & 0xFF),
					0
				};
				builder.update(libWithId);

				std::array<uint8_t, 1> dstLen{ static_cast<uint8_t>(dst.Size) };
				builder.update(dst);
				builder.update(dstLen);

				builder.final(b0);
			}

		public:
			/// Produces pseudo-random byte string \a expanded using \a buffersList and a tag \a dst.
			/// \note https://tools.ietf.org/html/draft-irtf-cfrg-hash-to-curve-09#section-5.4.1
			static void Expand(
					std::initializer_list<const RawBuffer> buffersList,
					const RawBuffer& dst,
					const MutableRawBuffer& expanded) {
				size_t ell = NumOutputBlocks(expanded.Size);
				if (ell > 255)
					CATAPULT_THROW_INVALID_ARGUMENT_1("invalid buffer size", expanded.Size);

				typename THashBuilder::OutputType b0;
				PrepareB0(buffersList, dst, static_cast<uint16_t>(expanded.Size), b0);

				// zero initialized to avoid special case for b_1 calculation
				typename THashBuilder::OutputType prevHash;
				auto* pExpanded = expanded.pData;
				for (auto i = 0u; i < ell; ++i) {
					THashBuilder subBuilder;
					for (auto j = 0u; j < Hash_Output_Size; ++j)
						prevHash[j] = static_cast<uint8_t>(prevHash[j] ^ b0[j]);

					subBuilder.update(prevHash);
					std::array<uint8_t, 1> blockId{ static_cast<uint8_t>(i + 1) };
					subBuilder.update(blockId);

					// Dst_Prime
					std::array<uint8_t, 1> dstLen{ static_cast<uint8_t>(dst.Size) };
					subBuilder.update(dst);
					subBuilder.update(dstLen);

					subBuilder.final(prevHash);

					auto dataToWrite = std::min<size_t>(Hash_Output_Size, expanded.Size - static_cast<size_t>(pExpanded - expanded.pData));
					std::memcpy(pExpanded, prevHash.data(), dataToWrite);
					pExpanded += dataToWrite;
				}
			}

			/// Produces pseudo-random byte string \a expanded using \a msg and a tag \a dst.
			/// \note https://tools.ietf.org/html/draft-irtf-cfrg-hash-to-curve-09#section-5.4.1
			static void Expand(const RawBuffer& msg, const RawBuffer& dst, const MutableRawBuffer& expanded) {
				Expand({ msg }, dst, expanded);
			}
	};
}}
