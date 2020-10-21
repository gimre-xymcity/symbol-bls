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

		void PrepareData(G2Point& q, ECP_BLS381& xp) {
			std::array<uint8_t, Data_Size> buffer;
			bench::FillWithRandomData(buffer);
			HashToCurveG2(q, Signing_Dst_Tag, { buffer });

			auto keyPair = VotingKeyPair::FromPrivate(GenerateVotingPrivateKey(bench::RandomByte));
			ECP_BLS381_fromReducedG1(xp, keyPair.publicKey());
		}

		void BenchmarkPairing(benchmark::State& state) {
			G2Point q;
			ECP_BLS381 xp;

			for (auto _ : state) {
				state.PauseTiming();
				PrepareData(q, xp);
				state.ResumeTiming();

				FP12_BLS381 v;
				PAIR_BLS381_ate(&v, q.get<ECP2_BLS381>(), &xp);
			}
		}

		void BenchmarkPairingExp(benchmark::State& state) {
			G2Point q;
			ECP_BLS381 xp;

			for (auto _ : state) {
				state.PauseTiming();
				PrepareData(q, xp);
				state.ResumeTiming();

				FP12_BLS381 v;
				PAIR_BLS381_ate(&v, q.get<ECP2_BLS381>(), &xp);
				PAIR_BLS381_fexp(&v);
			}
		}

		void BenchmarkSubgroupCheckG1(benchmark::State& state) {
			auto numFailures = 0u;
			ECP_BLS381 xp;

			for (auto _ : state) {
				state.PauseTiming();
				auto keyPair = VotingKeyPair::FromPrivate(GenerateVotingPrivateKey(bench::RandomByte));
				ECP_BLS381_fromReducedG1(xp, keyPair.publicKey());
				state.ResumeTiming();

				if (!SubgroupCheckG1(xp))
					++numFailures;
			}

			if (0 != numFailures)
				CATAPULT_LOG(warning) << numFailures << " G1 subgroup checks failed";
		}

		void BenchmarkSubgroupCheckG2(benchmark::State& state) {
			auto numFailures = 0u;
			std::array<uint8_t, Data_Size> buffer;
			G2Point q;

			for (auto _ : state) {
				state.PauseTiming();
				bench::FillWithRandomData(buffer);
				HashToCurveG2(q, Signing_Dst_Tag, { buffer });
				state.ResumeTiming();

				if (!SubgroupCheckG2(q.ref<ECP2_BLS381>()))
					++numFailures;
			}

			if (0 != numFailures)
				CATAPULT_LOG(warning) << numFailures << " G2 subgroup checks failed";
		}
	}
}}

void RegisterTests();
void RegisterTests() {
	benchmark::RegisterBenchmark("BenchmarkPairing", catapult::crypto::BenchmarkPairing)
			->UseRealTime()
			->Threads(1)
			->Threads(2)
			->Threads(4)
			->Threads(8);

	benchmark::RegisterBenchmark("BenchmarkPairingExp", catapult::crypto::BenchmarkPairingExp)
			->UseRealTime()
			->Threads(1)
			->Threads(2)
			->Threads(4)
			->Threads(8);

	benchmark::RegisterBenchmark("BenchmarkSubgroupCheckG1", catapult::crypto::BenchmarkSubgroupCheckG1)
			->UseRealTime()
			->Threads(1)
			->Threads(2)
			->Threads(4)
			->Threads(8);

	benchmark::RegisterBenchmark("BenchmarkSubgroupCheckG2", catapult::crypto::BenchmarkSubgroupCheckG2)
			->UseRealTime()
			->Threads(1)
			->Threads(2)
			->Threads(4)
			->Threads(8);
}
