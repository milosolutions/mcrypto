# This is helper script for CMake FindOpenSSL.cmake module

# Currently CMake version expect that custom build of OpenSSL will contain header and libraries
# under single root directory. This helper allow to provide header and libraries dir separetely
# as environemental variables and the create dir with proper symlinks to allow proper dectection.
# Script must be called before find_package(OpenSSL)

# WARNING: as you provide headers and builds from different locations make sure the versions match

set(OPENSSL_INCLUDE $ENV{OPENSSL_INCLUDE_DIR})
if (OPENSSL_INCLUDE STREQUAL "")
  message(SEND_ERROR "Environment variable OPENSSL_INCLUDE_DIR must be set to path of openssl/ssl.h")
endif()

set(OPENSSL_LIBS $ENV{OPENSSL_LIB_DIR})
if (OPENSSL_LIBS STREQUAL "")
  message(SEND_ERROR "Environment variable OPENSSL_LIB_DIR must be set to proper path containing ssl and crypto libraries.")
endif()

# Create directory with symlinks imitating structure expected by FinOpenSSL.cmake
file(MAKE_DIRECTORY ${CMAKE_BINARY_DIR}/virtual-openssl-build)
file(MAKE_DIRECTORY ${CMAKE_BINARY_DIR}/virtual-openssl-build/include)
file(CREATE_LINK ${OPENSSL_INCLUDE} ${CMAKE_BINARY_DIR}/virtual-openssl-build/include/openssl SYMBOLIC)
file(CREATE_LINK ${OPENSSL_LIBS} ${CMAKE_BINARY_DIR}/virtual-openssl-build/lib SYMBOLIC)
# Assuming those paths are outside current prefix
set(OLD_CMAKE_FIND_ROOT_PATH ${CMAKE_FIND_ROOT_PATH})
set(CMAKE_FIND_ROOT_PATH "${CMAKE_BINARY_DIR}/virtual-openssl-build")
# Now cmake should find OpenSSL package
find_package(OpenSSL)
set(CMAKE_FIND_ROOT_PATH ${OLD_CMAKE_FIND_ROOT_PATH})
