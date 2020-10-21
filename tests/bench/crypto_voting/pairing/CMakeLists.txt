cmake_minimum_required(VERSION 3.14)

catapult_bench_executable_target(bench.catapult.crypto_voting.pairing)
target_link_libraries(bench.catapult.crypto_voting.pairing catapult.crypto_voting bench.catapult.bench.nodeps)
