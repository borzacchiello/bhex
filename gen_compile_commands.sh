#!/bin/bash

cd "$(dirname "$0")"

mkdir ./tmp

pushd ./tmp
cmake -DCMAKE_EXPORT_COMPILE_COMMANDS=ON ..
cp ./compile_commands.json ..
popd

rm -r ./tmp
