cmake_minimum_required(VERSION 3.22.1)

project(AthenaProj)

add_library(athena SHARED athena.cpp)

target_compile_options(athena PRIVATE
        -Wall
        -Wextra
        -Winline
        -Wpedantic
        -Wshadow
        -Wconversion
        -Wsign-conversion
        -Wdouble-promotion
        -Wno-unused-parameter
        -ffunction-sections
        -fdata-sections
        -fno-omit-frame-pointer
        -funwind-tables
        -fasynchronous-unwind-tables
        -Os
        -g
)

target_link_options(athena PRIVATE
        "-Wl,-z,max-page-size=16384"
        "-Wl,--gc-sections"
        "-Wl,-z,relro"
        "-Wl,-z,now"
)

target_link_libraries(athena log android)