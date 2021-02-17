cmake_minimum_required(VERSION 3.18)
project(lib-gamehack
  DESCRIPTION "Set of function to enhance the quality of life when making cheat"
)

add_library(lib-gamehack "src/lib-gamehack.cpp")
include_directories("include")