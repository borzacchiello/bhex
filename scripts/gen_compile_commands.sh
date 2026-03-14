#!/bin/bash

cd "$(dirname "$0")"
cd ..

mkdir ./tmp

pushd ./tmp
cmake -DCMAKE_EXPORT_COMPILE_COMMANDS=ON -DENABLE_KEYSTONE=on -DENABLE_CAPSTONE=on ..
cp ./compile_commands.json ..
popd

rm -r ./tmp
