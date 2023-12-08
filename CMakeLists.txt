if(POLICY CMP0048)
  cmake_policy(SET CMP0048 NEW)
endif()
if (CMAKE_VERSION VERSION_LESS 3.0)
  project(aes_library)
else()
  project(aes_library VERSION 1.0.0 LANGUAGES C)
endif()
#find_package(OpenSSL REQUIRED)
#if(OPENSSL_FOUND)
#  include_directories(${OPENSSL_INCLUDE_DIRS})
#  message(STATUS "OpenSSL Found!")
#else(OPENSSL_FOUND)
#  message(FATAL_ERROR "Could not find the CURL library and development files.")
#endif()
set(CMAKE_C_FLAGS_DEBUG "-I/usr/local/opt/openssl@1.1/include -Wall")
set(CMAKE_C_FLAGS_RELEASE "-I/usr/local/opt/openssl@1.1/include -Wall")
include_directories(/usr/local/opt/openssl@1.1/include)
LINK_DIRECTORIES(/usr/local/opt/openssl@1.1/lib/)
set(crypto_library /usr/local/opt/openssl@1.1/lib/libcrypto.a)
add_library(aes_library SHARED src/aes.c)
add_library(aes_static STATIC src/aes.c)
cmake_minimum_required(VERSION 3.24)

#target_link_libraries(aes_library OpenSSL::Crypto)
target_link_libraries(aes_library
"${crypto_library}")
target_link_libraries(aes_static
"${crypto_library}")
set_target_properties(aes_library PROPERTIES
    PUBLIC_HEADER src/aes.h
    VERSION ${PROJECT_VERSION}
    SOVERSION 1
    OUTPUT_NAME "aes"
)
set_target_properties(aes_static PROPERTIES
    PUBLIC_HEADER /srcaes.h
    VERSION ${PROJECT_VERSION}
    SOVERSION 1
    OUTPUT_NAME "aes"
)
