project(sshping)
cmake_minimum_required(VERSION 2.8)

#find_package(libssh)

#set(CMAKE_CXX_FLAGS "-I ../ext/ -std=c++11 -O3 -Werror -Wall -Wextra -Wshadow -Wnon-virtual-dtor -pedantic -Wold-style-cast -Wcast-align -Wunused -Wcast-qual -Woverloaded-virtual -Wconversion -Wsign-conversion -Wformat-security -Wwrite-strings -fdiagnostics-show-option")
set(CMAKE_CXX_FLAGS "-I ../ext/ -Wall")

add_executable(${PROJECT_NAME} src/sshping.cxx)

target_link_libraries(${PROJECT_NAME} ssh)

install(TARGETS ${PROJECT_NAME} DESTINATION bin)

find_program(rpmbuild_path "rpmbuild" FALSE)
if (rpmbuild_path)
  message(STATUS "rpmbuild found, enabling RPM for the 'package' target")
  list(APPEND CPACK_GENERATOR RPM)
endif(rpmbuild_path)

find_program(dpkg_path "dpkg" FALSE)
if (dpkg_path)
  message(STATUS "dpkg found, enabling DEB for the 'package' target")
  list(APPEND CPACK_GENERATOR DEB)
endif(dpkg_path)

set(CPACK_PACKAGE_NAME "sshping")
set(CPACK_PACKAGE_CONTACT "spook@MisfitMountain.org")
set(CPACK_PACKAGE_DESCRIPTION_SUMMARY "sshping is an SSH-based ping-like utility that measures interactive character echo latency and file transfer throughput.")

include(CPack)

