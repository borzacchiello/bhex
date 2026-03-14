#!/bin/bash

cd "$(dirname "$0")"
cd ..

[ -d ./build ] && rm -rf ./build
mkdir ./build
cd ./build

cmake -DCMAKE_BUILD_TYPE=Release -DENABLE_KEYSTONE=on -DENABLE_CAPSTONE=on -DPython_EXECUTABLE=$(which python3) ..
make
sudo make install
