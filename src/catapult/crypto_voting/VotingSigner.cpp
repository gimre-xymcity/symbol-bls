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

#include "VotingSigner.h"
#include "HashToCurve.h"
#include "catapult/crypto/Hashes.h"
#include "catapult/crypto/SecureZero.h"
#include "catapult/crypto/Signer.h"

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
		using ExtendedPrivateKeyBuffer = std::array<uint8_t, MODBYTES_384_58>;

		constexpr const char* Signing_Dst_Tag = "BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_";
		constexpr size_t Private_Key_Offset = BGS_BLS381 - VotingPrivateKey::Size;
		constexpr uint8_t Flags_Mask = 0xE0;
		constexpr uint8_t Compressed_Bit = 0x80;
		constexpr uint8_t Compressed_Sign_Bit = 0x20;
		constexpr uint8_t Coordinate_Mask = 0x1F;

		bool AreFlagsValid(uint8_t flagsByte) {
			uint8_t flags = flagsByte & Flags_Mask;
			if (flags != Compressed_Bit && flags != (Compressed_Bit | Compressed_Sign_Bit))
				return false;

			return true;
		}

		// region reduce/unreduce helpers

		// returns true if big > (q - 1) / 2
		bool Big38458IsNegative(BIG_384_58 big) {
			BIG_384_58 Half_Modulus = {
				0xFF7FFFFFFFD555, 0x17FFFD62A7FFFF7, 0x29507B587B120F5, 0x309E70A257ECE61,
				0x321A5D66BB23BA5, 0x32FFCD3496374F6, 0xD0088F51
			};

			return -1 == BIG_384_58_comp(Half_Modulus, big);
		}

		// this follows both zk & algorand definition of signum
		int Fp2SignumLexicographic(FP2_BLS381& u) {
			FP_BLS381& fieldElement = FP_BLS381_iszilch(&u.b) ? u.a : u.b;
			BIG_384_58 big;

			FP_BLS381_redc(big, &fieldElement);
			return Big38458IsNegative(big) ? -1 : 1;
		}

		bool IsReduced(BIG_384_58 coordinate) {
			BIG_384_58 modulus;
			BIG_384_58 temp;
			BIG_384_58_rcopy(modulus, Modulus_BLS381);
			BIG_384_58_copy(temp, coordinate);
			BIG_384_58_mod(temp, modulus);
			return 0 == BIG_384_58_comp(coordinate, temp);
		}

		// G1
		VotingVerifyResult ECP_BLS381_fromReducedG1(ECP_BLS381& p, const VotingKey& publicKey) {
			int storedSign = (publicKey[0] & Compressed_Sign_Bit) ? -1 : 1;
			if (!AreFlagsValid(publicKey[0]))
				return VotingVerifyResult::Failure_Invalid_Public_Key_Flags;

			char xCopy[MODBYTES_384_58];
			std::memcpy(xCopy, publicKey.data(), MODBYTES_384_58);
			xCopy[0] &= Coordinate_Mask;

			BIG_384_58 px;
			BIG_384_58_fromBytes(px, xCopy);

			// note: attacking this might not have much sense in practice, but it's verified for consistency
			if (!IsReduced(px))
				return VotingVerifyResult::Failure_Public_Key_Not_Reduced;

			// this will fail if point is not on the curve
			if (!ECP_BLS381_setx(&p, px, 0))
				return VotingVerifyResult::Failure_Public_Key_Is_Invalid_Point;

			BIG_384_58 py;
			ECP_BLS381_get(px, py, &p);
			if (-1 == storedSign * (Big38458IsNegative(py) ? -1 : 1))
				ECP_BLS381_neg(&p);

			return VotingVerifyResult::Success;
		}

		// G2
		bool ECP2_BLS381_toReducedG2(VotingSignature& signature, const ECP2_BLS381& q) {
			BIG_384_58 temp;
			FP2_BLS381 qx, qy;
			if (-1 == ECP2_BLS381_get(&qx, &qy, const_cast<ECP2_BLS381*>(&q))) {
				// ERROR: point at INF;
				return false;
			}

			// follow zk format, serializing q.b part first
			FP_BLS381_redc(temp, &qx.b);
			BIG_384_58_toBytes(reinterpret_cast<char*>(&signature[0]), temp);
			FP_BLS381_redc(temp, &qx.a);
			BIG_384_58_toBytes(reinterpret_cast<char*>(&signature[MODBYTES_384_58]), temp);

			uint8_t maskValue = Fp2SignumLexicographic(qy) < 0 ? 0xA0 : 0x80;
			signature[0] = static_cast<uint8_t>(signature[0] | maskValue);
			return true;
		}

		bool IsReduced(FP_BLS381& fp, BIG_384_58 expectedValue) {
			BIG_384_58 temp;
			FP_BLS381_redc(temp, &fp);
			return 0 == BIG_384_58_comp(expectedValue, temp);
		}

		VotingVerifyResult ECP2_BLS381_fromReducedG2(ECP2_BLS381& q, const VotingSignature& signature) {
			int storedSign = (signature[0] & Compressed_Sign_Bit) ? -1 : 1;

			// q.b is serialized at 0
			// q.a is serialized at MODBYTES_384_58
			// for consistency, 3 high bits (of 384-bit value) are checked here
			if (!AreFlagsValid(signature[0]) || (signature[MODBYTES_384_58] & Flags_Mask) != 0)
				return VotingVerifyResult::Failure_Invalid_Signature_Flags;

			char bCopy[MODBYTES_384_58];
			std::memcpy(bCopy, signature.data(), MODBYTES_384_58);
			bCopy[0] &= Coordinate_Mask;

			BIG_384_58 xa, xb;
			BIG_384_58_fromBytes(xb, bCopy);
			BIG_384_58_fromBytes(xa, const_cast<char*>(reinterpret_cast<const char*>(&signature[MODBYTES_384_58])));

			FP2_BLS381 qx;
			FP_BLS381_nres(&qx.a, xa);
			FP_BLS381_nres(&qx.b, xb);

			// reduce and compare against original values
			if (!IsReduced(qx.a, xa) || !IsReduced(qx.b, xb))
				return VotingVerifyResult::Failure_Signature_Not_Reduced;

			// this will fail if (x,) is not on curve, that is fine, we'll use it to reject invalid sigs
			if (!ECP2_BLS381_setx(&q, &qx))
				return VotingVerifyResult::Failure_Signature_Is_Invalid_Point;

			FP2_BLS381 qy;
			ECP2_BLS381_get(&qx, &qy, &q);
			if (-1 == storedSign * Fp2SignumLexicographic(qy))
				ECP2_BLS381_neg(&q);

			return VotingVerifyResult::Success;
		}

		// endregion

		// region validation / subgroup checks

		bool SubgroupCheckG2(ECP2_BLS381& point) {
			BIG_384_58 order;
			ECP2_BLS381 p;
			BIG_384_58_rcopy(order, CURVE_Order_BLS381);
			ECP2_BLS381_copy(&p, &point);
			PAIR_BLS381_G2mul(&p, order);
			return ECP2_BLS381_isinf(&p);
		}

		bool SubgroupCheckG1(ECP_BLS381& point) {
			BIG_384_58 order;
			ECP_BLS381 p;
			BIG_384_58_rcopy(order, CURVE_Order_BLS381);
			ECP_BLS381_copy(&p, &point);
			PAIR_BLS381_G1mul(&p, order);
			return ECP_BLS381_isinf(&p);
		}

		bool KeyValidate(ECP_BLS381& point) {
			// note: we don't need additional check if point isinf(), because fromReduce is checking that already
			return SubgroupCheckG1(point);
		}

		// endregion
	}

	void Sign(const VotingKeyPair& keyPair, const RawBuffer& dataBuffer, VotingSignature& computedSignature) {
		Sign(keyPair, { dataBuffer }, computedSignature);
	}

	// variables follow naming in
	// https://tools.ietf.org/html/draft-irtf-cfrg-bls-signature-04#section-2.6
	void Sign(const VotingKeyPair& keyPair, std::initializer_list<const RawBuffer> buffersList, VotingSignature& computedSignature) {
		G2Point qr;
		HashToCurveG2(qr, Signing_Dst_Tag, buffersList);

		// copy private key to larger buffer
		ExtendedPrivateKeyBuffer extendedPrivateKey{};
		std::memcpy(extendedPrivateKey.data() + Private_Key_Offset, keyPair.privateKey().data(), VotingPrivateKey::Size);

		BIG_384_58 sk;
		BIG_384_58_fromBytes(sk, reinterpret_cast<char*>(extendedPrivateKey.data()));
		PAIR_BLS381_G2mul(qr.get<ECP2_BLS381>(), sk);

		SecureZero(extendedPrivateKey);
		SecureZero(sk);

		// qr should be proper point, so this will always succeed
		ECP2_BLS381_toReducedG2(computedSignature, qr.ref<ECP2_BLS381>());
	}

	VotingVerifyResult Verify(const VotingKey& publicKey, const RawBuffer& dataBuffer, const VotingSignature& signature) {
		return Verify(publicKey, { dataBuffer }, signature);
	}

	// variables follow naming in
	// https://tools.ietf.org/html/draft-irtf-cfrg-bls-signature-04#section-2.7
	VotingVerifyResult Verify(
			const VotingKey& publicKey,
			std::initializer_list<const RawBuffer> buffersList,
			const VotingSignature& signature) {
		ECP2_BLS381 r;
		auto result = ECP2_BLS381_fromReducedG2(r, signature);
		if (VotingVerifyResult::Success != result)
			return result;

		if (!SubgroupCheckG2(r))
			return VotingVerifyResult::Failure_Signature_Subgroup_Check;

		ECP_BLS381 xp;
		result = ECP_BLS381_fromReducedG1(xp, publicKey);
		if (VotingVerifyResult::Success != result)
			return result;

		if (!KeyValidate(xp))
			return VotingVerifyResult::Failure_Public_Key_Subgroup_Check;

		ECP_BLS381 g;
		ECP_BLS381_generator(&g);

		G2Point q;
		HashToCurveG2(q, Signing_Dst_Tag, buffersList);

		// verify that: e(g1, sig) = e(pub, H(m))
		// this is equivalent to
		// e(-g1, sig) * e(pub, H(m)) = 1
		//
		// note that:
		// e(-a, b) = e(a, b)^{-1} = e(a, -b)
		// so either g or sig could be negated, we're negating g
		ECP_BLS381_neg(&g);

		FP12_BLS381 v;
		PAIR_BLS381_double_ate(&v, &r, &g, q.get<ECP2_BLS381>(), &xp);
		PAIR_BLS381_fexp(&v);

		return FP12_BLS381_isunity(&v) ? VotingVerifyResult::Success : VotingVerifyResult::Failure_Verification_Failed;
	}
}}
