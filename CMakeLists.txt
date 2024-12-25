cmake_minimum_required(VERSION 3.16)

project(wscurl LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

option(BUILD_TEST "test utility build" OFF)
option(BUILD_SHARED "make shared library" OFF)

if(BUILD_SHARED)
    set(CMAKE_POSITION_INDEPENDENT_CODE ON)
endif(BUILD_SHARED)

set(ENABLE_PROGRAMS OFF CACHE BOOL "" FORCE)
set(ENABLE_TESTING OFF CACHE BOOL "" FORCE)
set(LINK_WITH_PTHREAD ON CACHE BOOL "" FORCE)

add_subdirectory(3rdparty/mbedtls-3.6.2)
set(MBEDTLS_INCLUDE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/3rdparty/mbedtls-3.6.2/include CACHE STRING "" FORCE)
set(MBEDTLS_LIBRARY ${CMAKE_CURRENT_BINARY_DIR}/3rdparty/mbedtls-3.6.2/library/libmbedtls.a CACHE STRING "" FORCE)
set(MBEDCRYPTO_LIBRARY ${CMAKE_CURRENT_BINARY_DIR}/3rdparty/mbedtls-3.6.2/library/libmbedcrypto.a CACHE STRING "" FORCE)
set(MBEDX509_LIBRARY ${CMAKE_CURRENT_BINARY_DIR}/3rdparty/mbedtls-3.6.2/library/libmbedx509.a CACHE STRING "" FORCE)

set(BUILD_CURL_EXE OFF CACHE BOOL "" FORCE)
set(BUILD_EXAMPLES OFF CACHE BOOL "" FORCE)
set(BUILD_LIBCURL_DOCS OFF CACHE BOOL "" FORCE)
set(BUILD_MISC_DOCS OFF CACHE BOOL "" FORCE)
set(BUILD_SHARED_LIBS OFF CACHE BOOL "" FORCE)
set(BUILD_STATIC_CURL OFF CACHE BOOL "" FORCE)
set(BUILD_STATIC_LIBS ON CACHE BOOL "" FORCE)
set(BUILD_TESTING OFF CACHE BOOL "" FORCE)
set(CURL_USE_MBEDTLS ON CACHE BOOL "" FORCE)
set(CURL_USE_OPENSSL OFF CACHE BOOL "" FORCE)
set(CURL_USE_PKGCONFIG OFF CACHE BOOL "" FORCE)
set(CURL_USE_LIBPSL OFF CACHE BOOL "" FORCE)

add_custom_target(forcurlbuid "" DEPENDS mbedtls)

add_subdirectory(3rdparty/curl-8.11.1)
set(CURL_INCLUDE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/3rdparty/curl-8.11.1/include CACHE STRING "" FORCE)
set(CURL_LIBRARY libcurl_static CACHE STRING "" FORCE)

find_package(CURL REQUIRED)

include_directories(
    ${MBEDTLS_INCLUDE_DIR}
    ${CURL_INCLUDE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${CMAKE_CURRENT_SOURCE_DIR}/3rdparty/cppcodec
    ${CMAKE_CURRENT_SOURCE_DIR}/3rdparty/sha1
)

set(src
    ${CMAKE_CURRENT_SOURCE_DIR}/3rdparty/sha1/sha1.cpp

    include/wsframe.h src/wsframe.cpp
    include/wsio.h src/wsio.cpp
)
set(src_test
    main.cpp
)

add_library(${PROJECT_NAME}_static STATIC ${src})
target_link_libraries(${PROJECT_NAME}_static ${CURL_LIBRARIES})
add_dependencies(${PROJECT_NAME}_static forcurlbuid)

if(BUILD_SHARED)
    add_library(${PROJECT_NAME} SHARED ${src})
    target_link_libraries(${PROJECT_NAME} ${CURL_LIBRARIES})
endif(BUILD_SHARED)


if(BUILD_TEST)
    add_executable(${PROJECT_NAME}_test ${src} ${src_test})
    target_link_libraries(${PROJECT_NAME}_test ${PROJECT_NAME}_static)
endif(BUILD_TEST)

include(GNUInstallDirs)
install(TARGETS ${PROJECT_NAME}_static
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
)
if(BUILD_SHARED)
    install(TARGETS ${PROJECT_NAME}
        LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
        RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
    )
endif(BUILD_SHARED)
