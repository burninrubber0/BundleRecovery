cmake_minimum_required(VERSION 3.14)
project(Bundle_Recovery CXX)
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED True)

set(ROOT ${CMAKE_CURRENT_SOURCE_DIR})

set(SOURCES
	${SOURCES}
	main.cpp
	src/BundleRecovery.cpp
	src/Finder.cpp
	src/Reader.cpp
	src/Validator.cpp
	src/Defragmenter.cpp
	src/Extractor.cpp
	)

set(HEADERS
	${HEADERS}
	BundleRecovery.h
	)

set(UIS
	${UIS}
	BundleRecovery.ui
	)

set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTOUIC ON)
set(CMAKE_AUTORCC ON)

add_executable(Bundle_Recovery WIN32 ${SOURCES} ${HEADERS} ${UIS})

find_package(Qt6 COMPONENTS Core Gui Widgets REQUIRED)

# libdeflate
set(LIBDEFLATE_ROOT ${ROOT}\\3rdparty\\libdeflate)
add_subdirectory(3rdparty/libdeflate "${CMAKE_CURRENT_BINARY_DIR}/3rdparty/libdeflate" EXCLUDE_FROM_ALL)
target_include_directories(Bundle_Recovery PRIVATE ${LIBDEFLATE_ROOT} "${CMAKE_CURRENT_BINARY_DIR}/3rdparty/libdeflate")

# libbinaryio
set(LIBBINARYIO_ROOT ${ROOT}\\3rdparty\\libbinaryio)
add_subdirectory(3rdparty/libbinaryio "${CMAKE_CURRENT_BINARY_DIR}/3rdparty/libbinaryio" EXCLUDE_FROM_ALL)
target_include_directories(Bundle_Recovery PRIVATE ${LIBBINARYIO_ROOT} "${CMAKE_CURRENT_BINARY_DIR}/3rdparty/libbinaryio")

# CRC++
target_include_directories(Bundle_Recovery PRIVATE "${ROOT}/3rdparty/CRCpp/inc")

target_link_libraries(Bundle_Recovery PRIVATE deflate libbinaryio Qt6::Core Qt6::Gui Qt6::Widgets)

# VS stuff
set_property(DIRECTORY ${ROOT} PROPERTY VS_STARTUP_PROJECT Bundle_Recovery)
source_group(TREE ${ROOT} FILES ${SOURCES} ${HEADERS} ${UIS})