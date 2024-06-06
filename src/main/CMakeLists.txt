aux_source_directory(. DIR_SRCS)
add_executable(${CANDY_EXECUTE_NAME} ${DIR_SRCS})

set_target_properties(${CANDY_EXECUTE_NAME} PROPERTIES CXX_STANDARD 20)

if (${CMAKE_SYSTEM_NAME} STREQUAL "Windows" OR ${CANDY_STATIC})
    include(FetchContent)

    FetchContent_Declare(
        argp-standalone
        GIT_REPOSITORY https://github.com/lanthora/argp-standalone.git
        GIT_TAG        416f73e0badd0089dc759892f6e982dc39fb6fc6
    )

    FetchContent_GetProperties(argp-standalone)
    if(NOT argp-standalone_POPULATED)
        FetchContent_Populate(argp-standalone)
        add_subdirectory(${argp-standalone_SOURCE_DIR} ${argp-standalone_BINARY_DIR} EXCLUDE_FROM_ALL)
    endif()

    target_link_libraries(${CANDY_EXECUTE_NAME} PRIVATE argp-standalone)  
else()
    find_library(ARGP_LIB argp)
    if(ARGP_LIB)
        target_link_libraries(${CANDY_EXECUTE_NAME} PRIVATE ${ARGP_LIB})
    endif()
endif()

if (${CANDY_STATIC})
    include_directories(${libconfig_SOURCE_DIR}/lib)
    target_link_libraries(${CANDY_EXECUTE_NAME} PRIVATE spdlog::spdlog)
    target_link_libraries(${CANDY_EXECUTE_NAME} PRIVATE config++)
    target_link_libraries(${CANDY_EXECUTE_NAME} PRIVATE ${OPENSSL_LIB_CRYPTO} ${OPENSSL_LIB_SSL})
    target_link_libraries(${CANDY_EXECUTE_NAME} PRIVATE Poco::Foundation Poco::Net Poco::NetSSL)
else()
    find_package(PkgConfig REQUIRED)
    pkg_check_modules(DEPS REQUIRED spdlog libconfig++)
    add_definitions(${DEPS_CFLAGS})
    include_directories(${DEPS_INCLUDEDIR})
    target_link_libraries(${CANDY_EXECUTE_NAME} PRIVATE ${DEPS_LIBRARIES})
endif()


set(THREADS_PREFER_PTHREAD_FLAG ON)
find_package(Threads REQUIRED)
target_link_libraries(${CANDY_EXECUTE_NAME} PRIVATE Threads::Threads)

target_link_libraries(${CANDY_EXECUTE_NAME} PRIVATE core)
target_link_libraries(${CANDY_EXECUTE_NAME} PRIVATE utility)

if (NOT ${CANDY_NOEXE})
    install(TARGETS ${CANDY_EXECUTE_NAME})
endif()
