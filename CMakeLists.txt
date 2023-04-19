cmake_minimum_required(VERSION 3.7)
project(mypr)

set(CMAKE_CXX_STANDARD 11)

include(FindPCAP.cmake)

set(Boost_USE_STATIC_LIBS ON) 
set(Boost_USE_MULTITHREADED OFF)  
set(Boost_USE_STATIC_RUNTIME OFF) 
find_package(Boost 1.82.0 COMPONENTS log) 

if(NOT TARGET Boost::filesystem)
    add_library(Boost::filesystem IMPORTED INTERFACE)
    set_property(TARGET Boost::filesystem PROPERTY
        INTERFACE_INCLUDE_DIRECTORIES ${Boost_INCLUDE_DIR})
    set_property(TARGET Boost::filesystem PROPERTY
        INTERFACE_LINK_LIBRARIES ${Boost_LIBRARIES})
endif()

include_directories(${Boost_INCLUDE_DIRS}) 
set(SOURCE_FILES main.cpp)
add_executable(mypr ${SOURCE_FILES})
target_link_libraries(mypr ${PCAP_LIBRARY} ${Boost_LIBRARIES})