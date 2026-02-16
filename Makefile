BUILD_DIR := build
CMAKE_ARGS :=

.PHONY: all clean

all: build/CMakeCache.txt
	cmake --build $(BUILD_DIR) -j$(nproc)

build/CMakeCache.txt: CMakeLists.txt
	cmake -S tests -B $(BUILD_DIR) $(CMAKE_ARGS)

clean:
	rm -rf build/

get_cpm:
	mkdir -p cmake
	wget -O cmake/CPM.cmake https://github.com/cpm-cmake/CPM.cmake/releases/latest/download/get_cpm.cmake
