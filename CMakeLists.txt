if (POLICY CMP0048)
  cmake_policy(SET CMP0048 NEW)
endif ()

project(mcrypto
  VERSION 0.0.1
  DESCRIPTION "Milo simple cryptography wrapper"
  LANGUAGES CXX
)

message("MCrypto: cmake support for MCrypto is incomplete! Please fix Android etc.!")

find_package(Qt5 COMPONENTS REQUIRED Core)
find_package(OpenSSL)

set(CMAKE_AUTOMOC ON)

set(SOURCES mcrypto.h mcrypto.cpp qaesencryption.h qaesencryption.cpp)

add_library(mcrypto STATIC ${SOURCES} ${OTHER_FILES})

if (OPENSSL_FOUND)
  message("MCrypto: using OpenSSL ${OPENSSL_VERSION}")
  target_compile_definitions(mcrypto PUBLIC OPENSSL_INCLUDED)
  target_link_libraries(mcrypto
    Qt5::Core
    OpenSSL::SSL
    OpenSSL::Crypto
  )
else ()
  message("MCrypto: using default backend (not OpenSSL). Warning: it has not undergone security audit!")
  target_link_libraries(mcrypto
    Qt5::Core
  )
endif ()

# Defines
target_compile_definitions(mcrypto PUBLIC MCRYPTO_LIB)

target_include_directories(mcrypto
  PUBLIC
  $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
)

add_subdirectory(tst_mcrypto)
