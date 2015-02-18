# Copyright (C) 2010-2014 GRNET S.A.
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

cmake_minimum_required(VERSION 2.8)
INCLUDE(FindPkgConfig)

project (archipelago_peers)

include_directories("${CMAKE_CURRENT_SOURCE_DIR}/include")
add_subdirectory(poold)

pkg_check_modules(GLIB REQUIRED glib-2.0>=2.0.0)

include_directories(${CMAKE_CURRENT_SOURCE_DIR} ${GLIB_INCLUDE_DIRS})
link_directories(${GLIB_LIBRARY_DIRS})

set(DUMMY_SRC dummy/dummy.c peer.c util/logger_wrap)
add_executable(archip-dummy ${DUMMY_SRC})
target_link_libraries(archip-dummy xseg pthread log4cplus)
set_target_properties(archip-dummy
	PROPERTIES
	COMPILE_DEFINITIONS "MT"
	)

set(RADOS_SRC radosd/radosd.c peer.c util/hash.c util/logger_wrap.cc)
add_executable(archip-radosd ${RADOS_SRC})
target_link_libraries(archip-radosd xseg pthread rados crypto log4cplus)
set_target_properties(archip-radosd
	PROPERTIES
	COMPILE_DEFINITIONS "MT"
	)

set(BENCH_SRC bench/bench-xseg.c peer.c bench/bench-lfsr.c bench/bench-timer.c
    bench/bench-utils.c bench/bench-report.c bench/bench-verify.c
    util/logger_wrap.cc)
add_executable(archip-bench ${BENCH_SRC})
target_link_libraries(archip-bench xseg pthread m log4cplus)

add_executable(archip-benchfd ${BENCH_SRC})
target_link_libraries(archip-benchfd xseg pthread m log4cplus)
set_target_properties(archip-benchfd
	PROPERTIES
	COMPILE_DEFINITIONS "FD"
	)


set(FILED_SRC filed/filed.c peer.c util/hash.c util/logger_wrap.cc)
add_executable(archip-filed ${FILED_SRC})
target_link_libraries(archip-filed xseg pthread crypto log4cplus)
set_target_properties(archip-filed
	PROPERTIES
	COMPILE_DEFINITIONS "MT"
	)

set(VLMCD_SRC vlmcd/mt-vlmcd.c peer.c util/logger_wrap.cc)
add_executable(archip-vlmcd ${VLMCD_SRC})
target_link_libraries(archip-vlmcd xseg log4cplus)

set(MAPPERD_SRC mapperd/mapper.c peer.c util/hash.c mapperd/mapper-handling.c
    mapperd/mapper-version3.c mapperd/mapper-helpers.c
    mapperd/mapper-version0.c mapperd/mapper-version2.c util/logger_wrap.cc)
add_executable(archip-mapperd ${MAPPERD_SRC})
target_link_libraries(archip-mapperd xseg st crypto log4cplus ${GLIB_LIBRARIES})
set_target_properties(archip-mapperd
	PROPERTIES
	COMPILE_DEFINITIONS "ST_THREADS"
	)

INSTALL_TARGETS(/bin archip-filed archip-radosd archip-vlmcd archip-mapperd
	archip-bench archip-dummy archip-benchfd)
