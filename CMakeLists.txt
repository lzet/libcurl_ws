cmake_minimum_required(VERSION 2.8)

project(WS_Curl)

FILE(GLOB_RECURSE INCLFILES "*.h" "*.hpp")
add_custom_target(headers SOURCES ${INCLFILES})

FILE(GLOB_RECURSE SRCFILES "*.cpp" "*.cxx" "*.c")

add_executable(${PROJECT_NAME} ${SRCFILES})
target_link_libraries(${PROJECT_NAME} pthread curl )
