
find_package(Qt5 COMPONENTS REQUIRED Core Test)
find_package(OpenSSL)

add_executable(tst_mcrypto tst_mcrypto.cpp
  $<TARGET_OBJECTS:mcrypto>
)

target_include_directories(tst_mcrypto PUBLIC
  $<TARGET_PROPERTY:mcrypto,INCLUDE_DIRECTORIES>
)

target_link_libraries(tst_mcrypto
  Qt5::Core Qt5::Test
    OpenSSL::SSL
    OpenSSL::Crypto
)

add_test(tst_mcrypto tst_mcrypto)
