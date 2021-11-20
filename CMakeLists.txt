project(funcgen-scpi)
cmake_minimum_required(VERSION 3.2)
add_definitions("-std=gnu++17 -ggdb3")

add_executable(
  funcgen-scpi
  error.cpp
  main.cpp
  utils.cpp
)

include_directories(scpi-parser/libscpi/inc)

target_link_directories(funcgen-scpi PUBLIC scpi-parser/libscpi/build)
target_link_libraries(funcgen-scpi libscpi)

set(CMAKE_BUILD_TYPE Debug)

set(CMAKE_THREAD_PREFER_PTHREAD TRUE)
set(THREADS_PREFER_PTHREAD_FLAG TRUE)
find_package(Threads)
target_link_libraries(funcgen-scpi Threads::Threads)

include(FindPkgConfig)

# pipewire
find_package(PipeWire)
pkg_check_modules(PIPEWIRE libpipewire-0.3)
target_link_libraries(funcgen-scpi ${PIPEWIRE_LIBRARIES})
target_include_directories(funcgen-scpi PUBLIC ${PIPEWIRE_INCLUDE_DIRS})
target_compile_options(funcgen-scpi PUBLIC ${PIPEWIRE_CFLAGS_OTHER})

pkg_check_modules(AVAHI REQUIRED avahi-client)
target_link_libraries(funcgen-scpi ${AVAHI_LIBRARIES})
target_include_directories(funcgen-scpi PUBLIC ${AVAHI_INCLUDE_DIRS})
target_compile_options(funcgen-scpi PUBLIC ${AVAHI_CFLAGS_OTHER})

set_target_properties(funcgen-scpi PROPERTIES OUTPUT_NAME funcgen-scpi)
