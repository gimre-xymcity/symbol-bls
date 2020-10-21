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

#include "catapult/crypto_voting/VotingSigner.h"
#include "catapult/crypto_voting/HashToCurve.h"
#include "catapult/utils/Logging.h"
#include "catapult/utils/RandomGenerator.h"
#include "tests/bench/nodeps/Random.h"
#include <benchmark/benchmark.h>

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
		constexpr auto Data_Size = 279;
		constexpr const char* Signing_Dst_Tag = "BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_";

		bool Big38458IsNegative(BIG_384_58 big) {
			BIG_384_58 Half_Modulus = {
				0xFF7FFFFFFFD555, 0x17FFFD62A7FFFF7, 0x29507B587B120F5, 0x309E70A257ECE61,
				0x321A5D66BB23BA5, 0x32FFCD3496374F6, 0xD0088F51
			};

			return -1 == BIG_384_58_comp(Half_Modulus, big);
		}

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

		void ECP_BLS381_fromReducedG1(ECP_BLS381& p, const VotingKey& publicKey) {
			int storedSign = (publicKey[0] & 0x20) ? -1 : 1;

			char xCopy[MODBYTES_384_58];
			std::memcpy(xCopy, publicKey.data(), MODBYTES_384_58);
			xCopy[0] &= 0x1F;

			BIG_384_58 px;
			BIG_384_58_fromBytes(px, xCopy);

			ECP_BLS381_setx(&p, px, 0);

			BIG_384_58 py;
			ECP_BLS381_get(px, py, &p);
			if (-1 == storedSign * (Big38458IsNegative(py) ? -1 : 1))
				ECP_BLS381_neg(&p);
		}

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

		bool IsReduced(FP_BLS381& fp, BIG_384_58 expectedValue) {
			BIG_384_58 temp;
			FP_BLS381_redc(temp, &fp);
			return 0 == BIG_384_58_comp(expectedValue, temp);
		}

		int Fp2SignumLexicographic(FP2_BLS381& u) {
			FP_BLS381& fieldElement = FP_BLS381_iszilch(&u.b) ? u.a : u.b;
			BIG_384_58 big;

			FP_BLS381_redc(big, &fieldElement);
			return Big38458IsNegative(big) ? -1 : 1;
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

		template<size_t Count>
		void BenchmarkAggregate(benchmark::State& state) {
			auto numFailures = 0u;
			std::vector<uint8_t> buffer(Data_Size);
			VotingSignature signatures[Count];

			std::vector<VotingKeyPair> keyPairs;
			for (size_t i = 0; i < Count; ++i)
				keyPairs.emplace_back(VotingKeyPair::FromPrivate(GenerateVotingPrivateKey(bench::RandomByte)));

			for (auto _ : state) {
				state.PauseTiming();

				// 1. sign payload
				bench::FillWithRandomData(buffer);
				for (size_t i = 0; i < Count; ++i)
					Sign(keyPairs[i], { keyPairs[i].publicKey(), buffer }, signatures[i]);

				// 2. calculate aggregate signature
				ECP2_BLS381 rs[Count];
				for (size_t i = 0; i < Count; ++i)
					ECP2_BLS381_fromReducedG2(rs[i], signatures[i]);

				for (size_t i = 0; i < Count; ++i)
					SubgroupCheckG2(rs[i]);

				ECP2_BLS381 aggSig;
				ECP2_BLS381_copy(&aggSig, &rs[0]);
				for (size_t i = 1; i < Count; ++i)
					ECP2_BLS381_add(&aggSig, &rs[i]);

				state.ResumeTiming();

				// 3. convert public keys to points
				ECP_BLS381 xp[Count];
				for (size_t i = 0; i < Count; ++i)
					ECP_BLS381_fromReducedG1(xp[i], keyPairs[i].publicKey());

				for (size_t i = 0; i < Count; ++i)
					SubgroupCheckG1(xp[i]);

				// 4. calculate AUG hashes
				G2Point qs[Count];
				for (size_t i = 0; i < Count; ++i)
					HashToCurveG2(qs[i], Signing_Dst_Tag, { keyPairs[i].publicKey(), buffer });

				// 5. compute n pairing
				FP12_BLS381 vs[Count];
				for (size_t i = 0; i < Count; ++i)
					PAIR_BLS381_ate(&vs[i], qs[i].template get<ECP2_BLS381>(), &xp[i]);

				// 6. multiply pairings (note, loop goes from 1, result will be in 0)
				for (size_t i = 1; i < Count; ++i)
					FP12_BLS381_mul(&vs[0], &vs[i]);

				// 6.b. exp can be delayed
				PAIR_BLS381_fexp(&vs[0]);

				// 7. calculate other 'side' of the pairing
				ECP_BLS381 g;
				ECP_BLS381_generator(&g);

				FP12_BLS381 c2;
				PAIR_BLS381_ate(&c2, &aggSig, &g);
				PAIR_BLS381_fexp(&c2);

				// 8. compare results
				if (1 != FP12_BLS381_equals(&c2, &vs[0]))
					++numFailures;
			}

			if (0 != numFailures)
				CATAPULT_LOG(warning) << numFailures << " calls to Verify failed";
			else
				CATAPULT_LOG(info) << "All OK, zero failures";
		}
	}
}}

void RegisterTests();
void RegisterTests() {
	benchmark::RegisterBenchmark("BenchmarkAggregate", catapult::crypto::BenchmarkAggregate<250>)
			->UseRealTime()
			->Threads(1);

	benchmark::RegisterBenchmark("BenchmarkAggregate", catapult::crypto::BenchmarkAggregate<500>)
			->UseRealTime()
			->Threads(1);

	benchmark::RegisterBenchmark("BenchmarkAggregate", catapult::crypto::BenchmarkAggregate<1000>)
			->UseRealTime()
			->Threads(1);
}
