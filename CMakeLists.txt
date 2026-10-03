cmake_minimum_required(VERSION 3.25)

project(game_gateway
    VERSION 0.1.0
    DESCRIPTION "Real-Time Game Gateway"
    LANGUAGES CXX)

# --- Platform guard: the net layer is epoll-based (architecture §2.4) -------
if(NOT CMAKE_SYSTEM_NAME STREQUAL "Linux")
    message(FATAL_ERROR "game_gateway requires Linux (epoll).")
endif()

# --- Options -----------------------------------------------------------------
option(GATEWAY_BUILD_TESTS        "Build unit tests"                ON)
option(GATEWAY_ENABLE_SANITIZERS  "Enable ASan/UBSan (Debug only)"  OFF)

if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
    set(CMAKE_BUILD_TYPE Release CACHE STRING "Build type" FORCE)
endif()

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# --- Shared compile settings (§6 guardrails) ---------------------------------
add_library(gateway_options INTERFACE)
target_compile_features(gateway_options INTERFACE cxx_std_20)
set_target_properties(gateway_options PROPERTIES CXX_EXTENSIONS OFF)
target_compile_options(gateway_options INTERFACE
    -Wall -Wextra -Wpedantic -Wconversion -Werror)

if(GATEWAY_ENABLE_SANITIZERS)
    target_compile_options(gateway_options INTERFACE
        $<$<CONFIG:Debug>:-fsanitize=address,undefined -fno-omit-frame-pointer>)
    target_link_options(gateway_options INTERFACE
        $<$<CONFIG:Debug>:-fsanitize=address,undefined>)
endif()

find_package(Threads REQUIRED)

# --- Core library (everything except main.cpp) -------------------------------
add_library(gateway_core STATIC
    src/net/socket.cpp
    src/net/epoll_event_loop.cpp
    src/protocol/codec.cpp
    src/session/session.cpp
    src/session/session_pool.cpp
)
target_include_directories(gateway_core PUBLIC
    ${PROJECT_SOURCE_DIR}/include)
target_link_libraries(gateway_core
    PUBLIC  Threads::Threads
    PRIVATE gateway_options)

# --- Gateway executable ------------------------------------------------------
add_executable(gateway src/main.cpp)
target_link_libraries(gateway PRIVATE gateway_core gateway_options)

# --- Tests -------------------------------------------------------------------
if(GATEWAY_BUILD_TESTS)
    enable_testing()

    set(GATEWAY_TESTS
        test_ring_buffer
        test_protocol_codec
        test_session_pool
        test_epoll_event_loop
    )

    foreach(test_name IN LISTS GATEWAY_TESTS)
        add_executable(${test_name} tests/${test_name}.cpp)
        target_link_libraries(${test_name} PRIVATE gateway_core gateway_options)
        add_test(NAME ${test_name} COMMAND ${test_name})
    endforeach()
endif()
