cmake_minimum_required(VERSION 3.16)

project(mcrypto
  VERSION 0.0.1
  DESCRIPTION "Milo simple cryptography wrapper"
  LANGUAGES CXX
)

find_package(Qt6 COMPONENTS REQUIRED Core)
set(CMAKE_AUTOMOC ON)

option(mcrypto-nossl "MCrypto: Manual switch for disabling OpenSSL library" OFF)

if (mcrypto-nossl)
    message("MCrypto: OpenSSL is manually disabled.")
else()
  if (ANDROID)
    # For Android we need to help find OpenSSL
    # To run code below prepare:
    # * location of OpenSSL header
    # * proper libraries (get prebuilt libs from https://github.com/KDAB/android_openssl.git)
    include(${CMAKE_CURRENT_SOURCE_DIR}/FindOpenSSLHelper.cmake)
  endif()
endif()
find_package(OpenSSL)


set(SOURCES mcrypto.h mcrypto.cpp)
if (OPENSSL_FOUND AND NOT mcrypto-nossl)
    list(APPEND SOURCES backend/mcb_openssl.cpp)
else()
    list(APPEND SOURCES backend/mcb_qaes.cpp backend/qaesencryption.cpp)
endif ()

add_library(mcrypto STATIC ${SOURCES})
target_link_libraries(mcrypto PUBLIC Qt6::Core)

if (OPENSSL_FOUND AND NOT mcrypto-nossl)
  message("MCrypto: using OpenSSL ${OPENSSL_VERSION}")
  target_link_libraries(mcrypto PRIVATE
    OpenSSL::SSL
    OpenSSL::Crypto
  )
else ()
  message("MCrypto: using default backend (not OpenSSL). Warning: it has not undergone security audit!")
endif ()

# Defines
target_compile_definitions(mcrypto PUBLIC MCRYPTO_LIB)

target_include_directories(mcrypto
  PUBLIC
  $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
)

#add_subdirectory(tst_mcrypto)
