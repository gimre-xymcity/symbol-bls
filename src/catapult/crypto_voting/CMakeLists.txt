cmake_minimum_required(VERSION 3.14)

message("--- locating amcl dependencies ---")
find_package(AMCL COMPONENTS bls_BLS381 REQUIRED)

get_target_property(LOCAL_AMCL_INCLUDE_DIRECTORY AMCL::bls_BLS381 INTERFACE_INCLUDE_DIRECTORIES)
message("amcl      ver: ${AMCL_VERSION}")
message("amcl      inc: ${LOCAL_AMCL_INCLUDE_DIRECTORY}")

catapult_library_target(catapult.crypto_voting)
target_link_libraries(catapult.crypto_voting catapult.crypto AMCL::bls_BLS381)
