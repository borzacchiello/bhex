#!/bin/bash

cd "$(dirname "$0")"
cd ..

# Directories to exclude (submodules)
EXCLUDE_DIRS="capstone keystone"

# Files to exclude
EXCLUDE_FILES="bhengine/parser.c bhengine/parser.h bhengine/lexer.c"

# Build find exclusion arguments
EXCLUDE_DIR_ARGS=""
for d in $EXCLUDE_DIRS; do
    EXCLUDE_DIR_ARGS="$EXCLUDE_DIR_ARGS -not -path \"./$d/*\""
done

EXCLUDE_FILE_ARGS=""
for f in $EXCLUDE_FILES; do
    EXCLUDE_FILE_ARGS="$EXCLUDE_FILE_ARGS -not -path \"./$f\""
done

FILES=$(eval "find . -type f \( -name \"*.c\" -o -name \"*.h\" \) $EXCLUDE_DIR_ARGS $EXCLUDE_FILE_ARGS" | sort)

if [ -z "$FILES" ]; then
    echo "No files found to format."
    exit 0
fi

clang-format -i $FILES
echo "Formatted $(echo "$FILES" | wc -l) files."
