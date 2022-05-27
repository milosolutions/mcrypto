find_package(Qt6 COMPONENTS REQUIRED Test)
if (NOT Qt6_FOUND)
    find_package(Qt5 5.15 REQUIRED COMPONENTS Test)
endif()

add_executable(tst_mcrypto tst_mcrypto.cpp)
target_link_libraries(tst_mcrypto mcrypto Qt::Test)

add_test(tst_mcrypto tst_mcrypto)
