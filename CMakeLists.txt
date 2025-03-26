# See https://github.com/spook/sshping
cmake_minimum_required(VERSION 3.10)
project(sshping)

#find_package(libssh)

# Build the sshping binary
include_directories(ext)
add_executable(${PROJECT_NAME} src/sshping.cxx)
if (UNIX)
	target_link_libraries(${PROJECT_NAME} ssh)
else (UNIX)
	target_link_libraries(${PROJECT_NAME} ${CMAKE_SOURCE_DIR}/ext/ssh.lib ${CMAKE_SOURCE_DIR}/ext/libeay32.lib ${CMAKE_SOURCE_DIR}/ext/zlibstatic.lib)
endif (UNIX)
install(TARGETS ${PROJECT_NAME} DESTINATION bin)

# man Pages
if (UNIX)
	find_program(P2M NAMES pod2man pod2man.pl)
	if (P2M)
		message(STATUS "pod2man found, use the 'man' target to build")
	endif (P2M)
	set(DOC_DIR  ${CMAKE_SOURCE_DIR}/doc)
	set(P2M_OPTS --section=8 -c "ssh-based ping test utility" -d 2018-03-13 -r v0.1.4)
	set(MAN_SRC  ${DOC_DIR}/sshping.pod)
	set(MAN_TGT  ${DOC_DIR}/sshping.8)
	add_custom_command(
	    OUTPUT  ${MAN_TGT}
	    COMMAND ${P2M} ${P2M_OPTS} ${MAN_SRC} ${MAN_TGT}
	    DEPENDS ${MAN_SRC}
	    WORKING_DIRECTORY ${DOC_DIR}
	    COMMENT "Building manpage ${MAN_TGT}"
	    VERBATIM)
endif (UNIX)

add_custom_target(man ALL DEPENDS ${MAN_TGT})
install(FILES ${MAN_TGT} DESTINATION ${CMAKE_INSTALL_PREFIX}/share/man/man8)

# Packaging for RPM or DEB
find_program(rpmbuild_path "rpmbuild" FALSE)
if (rpmbuild_path)
  message(STATUS "rpmbuild found, enabling RPM for the 'package' target")
  list(APPEND CPACK_GENERATOR RPM)
endif (rpmbuild_path)

find_program(dpkg_path "dpkg" FALSE)
if (dpkg_path)
  message(STATUS "dpkg found, enabling DEB for the 'package' target")
  list(APPEND CPACK_GENERATOR DEB)
endif (dpkg_path)

set(CPACK_PACKAGE_NAME "sshping")
set(CPACK_PACKAGE_CONTACT "spook@MisfitMountain.org")
set(CPACK_PACKAGE_DESCRIPTION_SUMMARY "sshping is an SSH-based ping-like utility that measures interactive character echo latency and file transfer throughput.")
SET(CPACK_PACKAGE_VERSION_MAJOR "0")
SET(CPACK_PACKAGE_VERSION_MINOR "1")
SET(CPACK_PACKAGE_VERSION_PATCH "5")
include(CPack)

