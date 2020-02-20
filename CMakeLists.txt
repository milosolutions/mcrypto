
project(mcrypto
  VERSION 0.0.1
  DESCRIPTION "Milo simple cryptography wrapper"
  LANGUAGES CXX
)

message("MCrypto: cmake support for MCrypto is incomplete! Please fix Android etc.!")

find_package(Qt5 COMPONENTS REQUIRED Core)
find_package(OpenSSL)

if (OPENSSL_FOUND)
  message("MCrypto: using default backend (not OpenSSL). Warning: it has not undergone security audit!")
  target_compile_definitions(mconfig PUBLIC OPENSSL_INCLUDED)
else ()
  message("MCrypto: using OpenSSL")
endif ()

set(SOURCES mcrypto.h mcrypto.cpp qaesencryption.h qaesencryption.cpp)

add_library(mcrypto OBJECT ${SOURCES} ${OTHER_FILES})

# Defines
target_compile_definitions(mconfig PUBLIC MCRYPTO_LIB)

target_include_directories(mcrypto
  PUBLIC
  $<INSTALL_INTERFACE:include>
  $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
)

target_link_libraries(mcrypto
  Qt5::Core
  $<OPENSSL_FOUND:OpenSSL::SSL>
  $<OPENSSL_FOUND:OpenSSL::Crypto>
)

add_subdirectory(tst_mcrypto)
