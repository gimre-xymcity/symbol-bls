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
#include "catapult/crypto/SecureRandomGenerator.h"
#include "catapult/utils/Logging.h"
#include "catapult/utils/RandomGenerator.h"
#include "tests/bench/nodeps/Random.h"
#include <benchmark/benchmark.h>

namespace catapult { namespace crypto {

	namespace {
		constexpr auto Data_Size = 279;

		void BenchmarkVotingKeygen(benchmark::State& state) {
			SecureRandomGenerator generator;

			for (auto _ : state)
				VotingKeyPair::FromPrivate(GenerateVotingPrivateKey(generator));
		}

		void BenchmarkVotingVerify(benchmark::State& state) {
			auto numFailures = 0u;
			std::vector<uint8_t> buffer(Data_Size);
			VotingSignature signature;

			for (auto _ : state) {
				state.PauseTiming();
				auto keyPair = VotingKeyPair::FromPrivate(GenerateVotingPrivateKey(bench::RandomByte));
				bench::FillWithRandomData(buffer);
				Sign(keyPair, buffer, signature);
				state.ResumeTiming();

				if (VotingVerifyResult::Success != Verify(keyPair.publicKey(), buffer, signature))
					++numFailures;
			}

			state.SetBytesProcessed(static_cast<int64_t>(Data_Size * state.iterations()));
			if (0 != numFailures)
				CATAPULT_LOG(warning) << numFailures << " calls to Verify failed";
		}
	}
}}

void RegisterTests();
void RegisterTests() {
	benchmark::RegisterBenchmark("BenchmarkVotingKeygen", catapult::crypto::BenchmarkVotingKeygen)
			->UseRealTime()
			->Threads(1)
			->Threads(2)
			->Threads(4)
			->Threads(8);

	benchmark::RegisterBenchmark("BenchmarkVotingVerify", catapult::crypto::BenchmarkVotingVerify)
			->UseRealTime()
			->Threads(1)
			->Threads(2)
			->Threads(4)
			->Threads(8);
}
