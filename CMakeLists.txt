cmake_minimum_required(VERSION 3.18)

project(Mosquittopp CXX)

add_library(mosquittopp INTERFACE)
target_include_directories(mosquittopp INTERFACE include)
