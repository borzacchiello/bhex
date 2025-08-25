#!/bin/bash

cd "$(dirname "$0")"

rm -rf ./build_coverage
mkdir ./build_coverage

cd ./build_coverage
cmake -DENABLE_TESTS=on -DCMAKE_BUILD_TYPE=Debug -DASAN=on ..
make -j

# I don't know why it complains about these files...
cp ../bhengine/lexer.* .
cp ../bhengine/parser.* .

ctest -T Coverage -T Test
lcov --directory . --capture --output-file coverage.info
genhtml --demangle-cpp -o coverage coverage.info
open coverage/index.html
