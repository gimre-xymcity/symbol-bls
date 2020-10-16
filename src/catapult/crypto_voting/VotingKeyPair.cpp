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

#include "VotingKeyPair.h"
#include "catapult/crypto/KeyPair.h"
#include "catapult/crypto/SecureRandomGenerator.h"
#include "catapult/crypto/SecureZero.h"

#if defined(__clang__) || defined(__GNUC__)
#define C99
#endif

extern "C" {
#include <amcl/config_curve_BLS381.h>
#include <amcl/bls_BLS381.h>
#include <amcl/big_512_56.h>
}

namespace catapult { namespace crypto {

	namespace {
		bool Big38458IsNegative(BIG_384_58 big) {
			BIG_384_58 Half_Modulus = {
				0xFF7FFFFFFFD555, 0x17FFFD62A7FFFF7, 0x29507B587B120F5, 0x309E70A257ECE61,
				0x321A5D66BB23BA5, 0x32FFCD3496374F6, 0xD0088F51
			};

			return -1 == BIG_384_58_comp(Half_Modulus, big);
		}

		// G1
		void ECP_BLS381_toReduced(VotingKey& g1Elem, const ECP_BLS381& point) {
			BIG_384_58 x, y;
			if (-1 == ECP_BLS381_get(x, y, const_cast<ECP_BLS381*>(&point)))
				CATAPULT_THROW_INVALID_ARGUMENT("invalid private key used");

			BIG_384_58_toBytes(reinterpret_cast<char*>(g1Elem.data()), x);

			// TODO: check if we can use parity here instead
			uint8_t maskValue = Big38458IsNegative(y) ? 0xA0 : 0x80;
			g1Elem[0] = static_cast<uint8_t>(g1Elem[0] | maskValue);
		}
	}

	VotingPrivateKey GenerateVotingPrivateKey(const supplier<uint64_t>& generator) {
		std::array<uint8_t, MODBYTES_384_58> privateKeyBuffer;

		DBIG_384_58 randomData;
		BIG_384_58 secretKeyScalar;
		BIG_384_58 order;
		BIG_384_58_rcopy(order, CURVE_Order_BLS381);

		// (D)BIG_384_58 uses 58-bits per each chunk
		for (auto& chunk : randomData)
			chunk = static_cast<__int64_t>(generator() & 0x3FFFFFF'FFFFFFFF);

		BIG_384_58_dmod(secretKeyScalar, randomData, order);
		SecureZero(randomData);

		BIG_384_58_toBytes(reinterpret_cast<char*>(privateKeyBuffer.data()), secretKeyScalar);
		SecureZero(secretKeyScalar);

		static constexpr size_t Private_Key_Offset = MODBYTES_384_58 - VotingPrivateKey::Size;
		return VotingPrivateKey::FromBufferSecure({ privateKeyBuffer.data() + Private_Key_Offset, VotingPrivateKey::Size });
	}

	void VotingKeyPairTraits::ExtractPublicKeyFromPrivateKey(const PrivateKey& privateKey, PublicKey& publicKey) {
		ECP_BLS381 g;
		ECP_BLS381_generator(&g);

		// multiply private key times group generator
		BIG_384_58 secretKeyScalar;
		BIG_384_58_fromBytesLen(
				secretKeyScalar,
				const_cast<char*>(reinterpret_cast<const char*>(privateKey.data())),
				static_cast<int>(VotingPrivateKey::Size));
		PAIR_BLS381_G1mul(&g, secretKeyScalar);
		SecureZero(secretKeyScalar);

		ECP_BLS381_toReduced(publicKey, g);
	}
}}
