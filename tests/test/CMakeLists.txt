cmake_minimum_required(VERSION 3.14)

catapult_add_gtest_dependencies()

add_subdirectory(core)
add_subdirectory(crypto)
add_subdirectory(nodeps)
