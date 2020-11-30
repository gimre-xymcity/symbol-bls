cmake_minimum_required(VERSION 3.14)
project(catapult_base)

include(CMakeGlobalSettings.cmake)

set_property(GLOBAL PROPERTY USE_FOLDERS ON)

message(STATUS "USE_CONAN:                    ${USE_CONAN}")

message(STATUS "CMAKE_CXX_COMPILER_ID: ${CMAKE_CXX_COMPILER_ID}")
message(STATUS "CMAKE_CXX_FLAGS:       ${CMAKE_CXX_FLAGS}")
message(STATUS "CMAKE_PREFIX_PATH:     ${CMAKE_PREFIX_PATH}")
message(STATUS "CMAKE_MODULE_PATH:     ${CMAKE_MODULE_PATH}")
message(STATUS "CMAKE_BUILD_TYPE:      ${CMAKE_BUILD_TYPE}")

set(CORE_CATAPULT_LIBS catapult.thread catapult.utils)

# finds the imported location of TARGET_NAME and assigns it to OUTPUT_LIBRARY_PATH
function(get_library_path OUTPUT_LIBRARY_PATH TARGET_NAME)
	get_property(LIBRARY_PATH TARGET ${TARGET_NAME} PROPERTY IMPORTED_LOCATION_RELEASE)
	if(NOT LIBRARY_PATH)
		get_property(LIBRARY_PATH TARGET ${TARGET_NAME} PROPERTY IMPORTED_LOCATION_RELWITHDEBINFO)
	endif()

	set("${OUTPUT_LIBRARY_PATH}" "${LIBRARY_PATH}" PARENT_SCOPE)
endfunction()

### setup boost
message("--- locating boost dependencies ---")
find_package(Boost COMPONENTS ${CATAPULT_BOOST_COMPONENTS} REQUIRED)
include_directories(SYSTEM ${Boost_INCLUDE_DIR})

message("boost     ver: ${Boost_VERSION}")
message("boost     inc: ${Boost_INCLUDE_DIR}")
message("boost    libs: ${Boost_LIBRARIES}")

### setup openssl
message("--- locating openssl dependencies ---")

find_package(OpenSSL REQUIRED)
message("OpenSSL   ver: ${OPENSSL_VERSION}")
message("OpenSSL  root: ${OPENSSL_ROOT_DIR}")
message("OpenSSL   inc: ${OPENSSL_INCLUDE_DIR}")
message("OpenSSL  libs: ${OPENSSL_LIBRARIES}")

# used to add openssl dependencies to a target
function(catapult_add_openssl_dependencies TARGET_NAME)
	include_directories(${OPENSSL_INCLUDE_DIR})
	target_link_libraries(${TARGET_NAME} OpenSSL::SSL)
endfunction()

### add source directories
add_subdirectory(external)

# run catapult tests first
add_subdirectory(src)
catapult_add_tests_subdirectory(tests)
