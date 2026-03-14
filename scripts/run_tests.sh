#!/bin/bash

cd "$(dirname "$0")"
cd ..

[ -d ./build_tests ] && rm -rf ./build_tests
mkdir ./build_tests
cd ./build_tests

rm -f tests/main.c
CMAKE_FLAGS="-DENABLE_TESTS=on -DCMAKE_BUILD_TYPE=Debug -DASAN=on"

if [ "$1" == "full" ]; then
    cmake $CMAKE_FLAGS -DENABLE_KEYSTONE=on -DENABLE_CAPSTONE=on .. > /dev/null
else
    cmake $CMAKE_FLAGS .. > /dev/null
fi

make -j > /dev/null
./bhex_tests
