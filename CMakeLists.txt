cmake_minimum_required( VERSION 3.1 FATAL_ERROR )

project(ADDRVALJS)


set( CMAKE_CXX_STANDARD 11 )
set( CMAKE_CXX_STANDARD_REQUIRED YES )

include(ExternalProject)

ExternalProject_Add( project_cryptopp
    PREFIX ${CMAKE_CURRENT_BINARY_DIR}/cryptopp
    SOURCE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/cryptopp
    CONFIGURE_COMMAND cmake <SOURCE_DIR> -DCMAKE_BUILD_TYPE=Release -DBUILD_SHARED=OFF -DBUILD_TESTING=OFF -DCMAKE_INSTALL_PREFIX=<INSTALL_DIR>
#    BUILD_IN_SOURCE 1
    BUILD_COMMAND make static
    INSTALL_COMMAND make install
    BUILD_BYPRODUCTS <BINARY_DIR>/libcryptopp.a
    )

ExternalProject_Add_Step(project_cryptopp cp_cryptopp_cmake
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/cryptopp
    COMMAND cp ${CMAKE_CURRENT_SOURCE_DIR}/cryptopp-cmake/CMakeLists.txt . && cp ${CMAKE_CURRENT_SOURCE_DIR}/cryptopp-cmake/cryptopp-config.cmake .
    DEPENDERS configure
    )

#ExternalProject_Add_Step(project_cryptopp rm_cryptopp_cmake
#    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/cryptopp
#    COMMAND rm CMakeLists.txt && rm cryptopp-config.cmake && rm -rf cryptopp-cmake
#    DEPENDEES install
#    )

ExternalProject_Get_Property(project_cryptopp INSTALL_DIR)
ExternalProject_Get_Property(project_cryptopp SOURCE_DIR)
file(MAKE_DIRECTORY ${INSTALL_DIR}/include)
add_library(cryptopp STATIC IMPORTED)
set_target_properties(cryptopp PROPERTIES
    IMPORTED_LOCATION "${INSTALL_DIR}/lib/libcryptopp.a"
    INTERFACE_INCLUDE_DIRECTORIES "${INSTALL_DIR}/include"
    )

add_dependencies(cryptopp project_cryptopp)

add_executable(addrvaljs "main.cpp")
if(JS)
    set_target_properties(addrvaljs PROPERTIES LINK_FLAGS "--bind -O3 -s ENVIRONMENT=web -s WASM=1 -s BINARYEN_METHOD='native-wasm'")
    set_target_properties(
        addrvaljs
        PROPERTIES
            SUFFIX ".js"
    )
else()

endif()

target_include_directories(addrvaljs PUBLIC cryptopp)
target_link_libraries(addrvaljs PUBLIC cryptopp)
