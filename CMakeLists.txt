cmake_minimum_required(VERSION 3.16)
project(RPFExplorer VERSION 1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_AUTOMOC ON)

find_package(Qt6 REQUIRED COMPONENTS Widgets)

# zlib：优先用系统/工具链自带的，找不到就直接链 -lz
find_package(ZLIB QUIET)
if(NOT ZLIB_FOUND)
    add_library(zlib_fallback INTERFACE)
    target_link_libraries(zlib_fallback INTERFACE z)
    add_library(ZLIB::ZLIB ALIAS zlib_fallback)
endif()

add_executable(RPFExplorer
    src/main.cpp
    src/RpfReader.h
    src/RpfReader.cpp
    src/GxtParser.h
    src/GxtParser.cpp
    src/EmbeddedScan.h
    src/EmbeddedScan.cpp
    src/DrpFile.h
    src/DrpFile.cpp
    src/MainWindow.h
    src/MainWindow.cpp
)

target_link_libraries(RPFExplorer PRIVATE Qt6::Widgets ZLIB::ZLIB)

if(WIN32)
    set_target_properties(RPFExplorer PROPERTIES WIN32_EXECUTABLE TRUE)
endif()
