cmake_minimum_required(VERSION 3.16)
project(spp CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Release CACHE STRING "" FORCE)
endif()

find_package(ftxui 6 REQUIRED COMPONENTS screen dom component)

add_executable(spp
  main.cpp
  modules/SafeFile.cpp
  modules/State.cpp
  modules/Kernel.cpp
  modules/Namespaces.cpp
  modules/Optimization.cpp
  modules/DNS.cpp
  modules/SSH.cpp
  modules/SELinux.cpp
  modules/AppArmor.cpp
  modules/HostsBlocker.cpp
  modules/FileIntegrity.cpp
  modules/Cleanup.cpp
)

target_compile_options(spp PRIVATE -Wall -Wextra -Wpedantic)
target_link_libraries(spp PRIVATE ftxui::screen ftxui::dom ftxui::component)

# Un outil de durcissement qui tourne en root doit lui-meme etre durci.
target_compile_options(spp PRIVATE
  $<$<CONFIG:Release>:-D_FORTIFY_SOURCE=2 -fstack-protector-strong -fPIE>)
target_link_options(spp PRIVATE
  $<$<CONFIG:Release>:-pie -Wl,-z,relro,-z,now -Wl,-z,noexecstack>)

install(TARGETS spp RUNTIME DESTINATION bin)
