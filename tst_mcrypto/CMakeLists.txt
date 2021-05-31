find_package(Qt5 COMPONENTS REQUIRED Core Test)
find_package(OpenSSL)

add_executable(tst_mcrypto tst_mcrypto.cpp)

target_link_libraries(tst_mcrypto mcrypto
  Qt5::Core
  Qt5::Test
)

add_test(tst_mcrypto tst_mcrypto)
