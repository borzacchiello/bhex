# Toolchain file for building bhex with the Cosmopolitan (cosmocc) toolchain.
#
# Produces a single fat APE binary that runs on Linux, macOS, Windows, FreeBSD,
# OpenBSD and NetBSD, on both x86_64 and aarch64.
#
#   cmake -B build_cosmopolitan -DCMAKE_TOOLCHAIN_FILE=cmake/cosmopolitan.cmake ...
#
# The toolchain is located, in order of preference, from -DCOSMOCC_HOME=<dir>,
# the COSMOCC_HOME environment variable, or a cosmocc found on PATH.

set(COSMOCC_HOME "" CACHE PATH "Root of the cosmocc toolchain")

if(NOT COSMOCC_HOME AND DEFINED ENV{COSMOCC_HOME})
    set(COSMOCC_HOME "$ENV{COSMOCC_HOME}" CACHE PATH "" FORCE)
endif()

if(NOT COSMOCC_HOME)
    find_program(COSMOCC_EXECUTABLE cosmocc)
    if(COSMOCC_EXECUTABLE)
        get_filename_component(_cosmocc_bin "${COSMOCC_EXECUTABLE}" DIRECTORY)
        get_filename_component(_cosmocc_root "${_cosmocc_bin}" DIRECTORY)
        set(COSMOCC_HOME "${_cosmocc_root}" CACHE PATH "" FORCE)
    endif()
endif()

if(NOT COSMOCC_HOME)
    message(FATAL_ERROR
        "cosmocc toolchain not found. Pass -DCOSMOCC_HOME=/path/to/cosmocc, "
        "set the COSMOCC_HOME environment variable, or put cosmocc on PATH. "
        "Get the toolchain from https://cosmo.zip/pub/cosmocc/")
endif()

if(NOT EXISTS "${COSMOCC_HOME}/bin/cosmocc")
    message(FATAL_ERROR
        "COSMOCC_HOME=${COSMOCC_HOME} does not contain bin/cosmocc")
endif()

# try_compile() runs a sub-project with a fresh cache, which re-reads this file
# but does not inherit -DCOSMOCC_HOME from our command line. Forward it, or the
# compiler probe fails to locate the toolchain.
list(APPEND CMAKE_TRY_COMPILE_PLATFORM_VARIABLES COSMOCC_HOME)

# APE binaries are not native ELF, so CMake must not try to run what it builds.
set(CMAKE_SYSTEM_NAME Linux)
set(CMAKE_SYSTEM_PROCESSOR x86_64)

set(CMAKE_C_COMPILER   "${COSMOCC_HOME}/bin/cosmocc")
set(CMAKE_CXX_COMPILER "${COSMOCC_HOME}/bin/cosmoc++")

# cosmoar archives both halves of a fat build: it writes <lib>.a alongside
# .aarch64/<lib>.a. Plain binutils ar only writes the x86_64 half, and the
# link then fails with "linker input missing concomitant ... file".
set(CMAKE_AR "${COSMOCC_HOME}/bin/cosmoar" CACHE FILEPATH "")

# Skip the ranlib step: cosmoar already writes a symbol index into both
# archives, and the shipped cosmoranlib is unusable anyway (it is missing its
# executable bit, and execs x86_64-linux-cosmo-ranlib by bare name, so it only
# resolves when the toolchain bin/ happens to be on PATH).
set(CMAKE_C_ARCHIVE_FINISH   "")
set(CMAKE_CXX_ARCHIVE_FINISH "")

# Linking a full APE executable takes a while (apelink runs over both
# architectures), so let the compiler probe stop at a static library.
set(CMAKE_TRY_COMPILE_TARGET_TYPE STATIC_LIBRARY)

# cosmocc rejects -shared and always links statically; CMake would otherwise
# add -rdynamic to every executable link, which a -static -nostdlib link
# cannot honour.
set(CMAKE_SHARED_LIBRARY_LINK_C_FLAGS   "")
set(CMAKE_SHARED_LIBRARY_LINK_CXX_FLAGS "")

# No CMAKE_FIND_ROOT_PATH here on purpose. cosmocc supplies its own sysroot
# through the compiler driver rather than through CMake, so restricting finds
# buys nothing and breaks discovery of host build tools -- keystone's LLVM
# needs a host Python interpreter to run LLVMBuild.py at configure time.
