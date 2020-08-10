find_package(Qt5 COMPONENTS REQUIRED Core Test)

set(CMAKE_AUTOMOC ON)

add_executable(example-mcrypto main.cpp)

target_link_libraries(example-mcrypto mcrypto
  Qt5::Core
)
