cmake_minimum_required(VERSION 3.14)

catapult_library_target(tests.catapult.test.nodeps)
target_link_libraries(tests.catapult.test.nodeps catapult.utils ${CMAKE_DL_LIBS})
