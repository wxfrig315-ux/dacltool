cmake_minimum_required(VERSION 3.15)
project(dacltool CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

if (MSVC)
    add_compile_options(/utf-8 /W4)
else()
    add_compile_options(-Wall -Wextra)
endif()

add_executable(dacltool
    main.cpp
    dacl-enum.cpp
    add-per.cpp
    remove-per.cpp
    lnk-check.cpp
    table.cpp
    utils.cpp
)

target_link_libraries(dacltool PRIVATE advapi32 shell32 ole32 uuid)
