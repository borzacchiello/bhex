cmake_minimum_required(VERSION 3.19)

set(CMAKE_POLICY_DEFAULT_CMP0063 NEW)
set(CMAKE_POLICY_DEFAULT_CMP0075 NEW)
set(CMAKE_POLICY_DEFAULT_CMP0077 NEW)
# the LLVM bundled in keystone passes a backslash-heavy source to a macro, and
# only the new behaviour is quiet about it (the probe answers the same either
# way). Guarded: the policy is younger than the cmake this project asks for
if (POLICY CMP0219)
    set(CMAKE_POLICY_DEFAULT_CMP0219 NEW)
endif()

project(bhex)

option(ASAN "Compile with asan (only for debug builds)" OFF)
option(ENABLE_CAPSTONE "Enable Capstone (disas command)" OFF)
option(ENABLE_KEYSTONE "Enable Keystone (assemble command)" OFF)
option(ENABLE_TESTS "Compile test binary" OFF)
option(ENABLE_FUZZ_TESTS "Compile fuzz test binaries" OFF)
option(ENABLE_COVERAGE "Compile with coverage collection (only for test builds)" OFF)
option(STATIC_BUILD "Statically link libc" OFF)

set(CMAKE_C_STANDARD 99)

# Section splitting has to be in place before the vendored subdirectories are
# added: capstone and keystone are where nearly all of the code lives, and
# compiling them without it leaves --gc-sections nothing to drop. cosmocc
# already links with --gc-sections of its own accord; a GNU ld link needs the
# flag spelled out.
add_compile_options(
    "$<$<CONFIG:Release>:-ffunction-sections>"
    "$<$<CONFIG:Release>:-fdata-sections>")
add_link_options("$<$<CONFIG:Release>:-Wl,--gc-sections>")

include_directories("${CMAKE_SOURCE_DIR}/common")
include_directories("${CMAKE_SOURCE_DIR}/common/ml")

if (ENABLE_CAPSTONE)
    set(BUILD_SHARED_LIBS OFF)
    set(BUILD_LIBS_ONLY ON)

    set(CAPSTONE_X86_ATT_DISABLE ON)
    set(CAPSTONE_OSXKERNEL_SUPPORT OFF)

    # Every architecture capstone ships, so that 'disas' can name every one of
    # them. Setting CAPSTONE_<arch>_SUPPORT for a name capstone does not have
    # is silently ignored -- CAPSTONE_SYSZ_SUPPORT sat here doing nothing for
    # years, the option being called CAPSTONE_SYSTEMZ_SUPPORT -- so the names
    # are checked against capstone's own list first. It cannot be read out of
    # capstone's scope after the fact: under CMP0077 NEW the set() below stops
    # capstone's option() from ever declaring the cache entry.
    set(BHEX_CAPSTONE_ARCHS
        AARCH64 ALPHA ARC ARM BPF EVM HPPA LOONGARCH M680X M68K MIPS MOS65XX
        PPC RISCV SH SPARC SYSTEMZ TMS320C64X TRICORE WASM X86 XCORE XTENSA)

    file(STRINGS "${CMAKE_SOURCE_DIR}/capstone/CMakeLists.txt" _cs_arch_line
         REGEX "^set\\(SUPPORTED_ARCHITECTURES ")
    if (NOT _cs_arch_line)
        message(FATAL_ERROR
            "cannot find SUPPORTED_ARCHITECTURES in capstone/CMakeLists.txt")
    endif()
    string(REGEX REPLACE "^set\\(SUPPORTED_ARCHITECTURES |\\)$" ""
           _cs_archs "${_cs_arch_line}")
    string(REPLACE " " ";" _cs_archs "${_cs_archs}")
    foreach(a ${BHEX_CAPSTONE_ARCHS})
        if (NOT a IN_LIST _cs_archs)
            message(FATAL_ERROR
                "capstone does not support '${a}': the submodule renamed or "
                "dropped it, fix BHEX_CAPSTONE_ARCHS. capstone has: ${_cs_archs}")
        endif()
        set(CAPSTONE_${a}_SUPPORT ON)
    endforeach()

    # Disable coverage for capstone to avoid gcov link errors
    # and to collect coverage only for bhex code
    set(BHEX_SAVED_ENABLE_COVERAGE ${ENABLE_COVERAGE})
    set(ENABLE_COVERAGE OFF)
    add_subdirectory(capstone)
    set(ENABLE_COVERAGE ${BHEX_SAVED_ENABLE_COVERAGE})

    # capstone's SH decoder names two enumerators "read" and "write" (enum
    # direction, SHDisassembler.c). That builds against a libc whose headers
    # capstone happens not to pull in, but cosmopolitan has the POSIX read()
    # and write() declared by the time the enum is reached and gcc rejects the
    # redeclaration, so SH alone of the 23 does not compile for the APE.
    #
    # The two are told apart by the parentheses: every declaration of the
    # functions is followed by its argument list, and none of the 74 uses of
    # the enumerators in that file is -- nothing there calls either function.
    # So a function-like macro renames the declarations and leaves the enum
    # alone, which keeps SH in without touching the submodule. An object-like
    # -Dread=... would rename both and clash all over again. It goes through
    # COMPILE_OPTIONS because COMPILE_DEFINITIONS drops function-style ones.
    set_source_files_properties(
        "${CMAKE_SOURCE_DIR}/capstone/arch/SH/SHDisassembler.c"
        TARGET_DIRECTORY capstone
        PROPERTIES COMPILE_OPTIONS
                   "-Dread(a,b,c)=cs_sh_unused_read(a,b,c);-Dwrite(a,b,c)=cs_sh_unused_write(a,b,c)")

    include_directories("${CMAKE_SOURCE_DIR}/capstone/include")
else()
    add_compile_definitions(DISABLE_CAPSTONE)
endif()

if (ENABLE_KEYSTONE)
    set(BUILD_SHARED_LIBS OFF)
    set(BUILD_LIBS_ONLY ON)
    # keystone's llvm/CMakeLists.txt does set(LLVM_TARGETS_TO_BUILD "all" CACHE
    # ...), which under CMP0126 OLD drops a plain variable of the same name --
    # so a normal set() here is silently ignored and every target gets built.
    # Write the cache entry instead, and list all of them, since 'assemble'
    # names all of them.
    set(LLVM_TARGETS_TO_BUILD
        "AArch64;ARM;Hexagon;Mips;PowerPC;RISCV;Sparc;SystemZ;X86"
        CACHE STRING "LLVM targets keystone assembles for" FORCE)
    add_subdirectory(keystone EXCLUDE_FROM_ALL)

    include_directories("${CMAKE_SOURCE_DIR}/keystone/include")
else()
    add_compile_definitions(DISABLE_KEYSTONE)
endif()

set(common_src
    common/alloc.c
    common/crc.c
    common/checksums.c
    common/entropy.c
    common/histogram.c
    common/dlist.c
    common/ll.c
    common/log.c
    common/color.c
    common/unicode.c
    common/map.c
    common/strbuilder.c
    common/display.c
    common/filebuffer.c
    common/cmdline_parser.c
    common/expr_eval.c
    common/terminal.c
    common/util/byte_to_num.c
    common/util/byte_to_str.c
    common/util/endian.c
    common/util/print.c
    common/util/str.c
    common/util/math.c
    common/hash/hash_registry.c
    common/hash/md2.c
    common/hash/md4.c
    common/hash/md5.c
    common/hash/md6.c
    common/hash/sm3.c
    common/hash/sha1.c
    common/hash/sha224-256.c
    common/hash/sha384-512.c
    common/hash/sha3.c
    common/hash/ripemd.c
    common/hash/blake2b-ref.c
    common/hash/blake2s-ref.c
    common/hash/blake3.c
    common/hash/blake3_impl.c
    common/hash/gost.c
    common/hash/streebog.c
    common/hash/skein.c
    common/hash/skein_block.c
    common/hash/fnv.c
    common/hash/murmur3.c
    common/hash/xxhash.c
    common/hash/xxh3.c
    common/hash/groestl-ref.c
    common/hash/haval.c
    common/hash/shash.c
    common/hash/snefru.c
    common/hash/tiger.c
    common/hash/whirlpool.c
    common/ml/rf_model.c
    common/ml/model_locator.c
    common/ml/isadetect_features.c
    common/ml/isadetect.c
    common/ml/binexec.c
    common/disassemble/disassemble.c
    common/disassemble/x86.c
    common/disassemble/arm.c
    common/disassemble/aarch64.c
    common/disassemble/mips.c
    common/disassemble/ppc.c
    common/disassemble/m68k.c
    common/disassemble/alpha.c
    common/disassemble/riscv.c
    common/disassemble/systemz.c
    common/disassemble/sparc.c
    common/disassemble/bpf.c
    common/disassemble/xcore.c
    common/disassemble/tms320c64x.c
    common/disassemble/m680x.c
    common/disassemble/evm.c
    common/disassemble/mos65xx.c
    common/disassemble/wasm.c
    common/disassemble/sh.c
    common/disassemble/tricore.c
    common/disassemble/hppa.c
    common/disassemble/loongarch.c
    common/disassemble/xtensa.c
    common/disassemble/arc.c)

set(command_src
    cmd/cmd_arg_handler.c
    cmd/cmd.c
    cmd/cmd_crc.c
    cmd/cmd_checksum.c
    cmd/cmd_hash.c
    cmd/cmd_template.c
    cmd/cmd_search.c
    cmd/cmd_strings.c
    cmd/cmd_findbase.c
    cmd/cmd_info.c
    cmd/cmd_write.c
    cmd/cmd_transform.c
    cmd/cmd_delete.c
    cmd/cmd_print.c
    cmd/cmd_disas.c
    cmd/cmd_assemble.c
    cmd/cmd_seek.c
    cmd/cmd_undo.c
    cmd/cmd_commit.c
    cmd/cmd_diff.c
    cmd/cmd_export.c
    cmd/cmd_import.c
    cmd/cmd_entropy.c
    cmd/cmd_hist.c
    cmd/cmd_map.c
    cmd/cmd_echo.c
    cmd/cmd_setbase.c
    cmd/cmd_interactive.c
    cmd/cmd_isa_identify.c
    cmd/cmd_identify.c
    cmd/tui.c)

set(bhengine_src
    bhengine/ast.c
    bhengine/builtin.c
    bhengine/scope.c
    bhengine/lexer.c
    bhengine/parser.c
    bhengine/interpreter.c
    bhengine/vm.c
    bhengine/value.c
    bhengine/formatter.c
    bhengine/formatter_term.c
    bhengine/formatter_xml.c)

# Warnings that catch the classes of bug that caused real crashes: unchecked
# NULL returns, signed/unsigned mix-ups in size computations, and bad formats.
set(BHEX_WARNINGS "-Wall -Wsign-compare -Wnull-dereference -Wformat -Wformat-security")

set(CMAKE_C_FLAGS_RELEASE "${CMAKE_C_FLAGS_RELEASE} ${BHEX_WARNINGS}")
set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} -Wall")
set(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -fno-omit-frame-pointer ${BHEX_WARNINGS}")
set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -fno-omit-frame-pointer -Wall")

# lexer.c is generated by flex: the leftover warnings in it (unused
# yy_fatal_error, null derefs in yy_init_buffer/yy_scan_bytes) come from the
# generator, not from our code.
set_source_files_properties(bhengine/lexer.c PROPERTIES COMPILE_OPTIONS
    "-Wno-unused-function;-Wno-null-dereference")

if(ASAN)
    set(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -fsanitize=address,undefined")
    set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -fsanitize=address,undefined")
    set(CMAKE_EXE_LINKER_FLAGS_DEBUG "${CMAKE_EXE_LINKER_FLAGS_DEBUG} -fsanitize=address,undefined")
endif()

file(GLOB MODEL_FILES CONFIGURE_DEPENDS ${CMAKE_SOURCE_DIR}/models/*.bin)

add_custom_target(copy_models_to_build ALL
        COMMAND ${CMAKE_COMMAND} -E make_directory ${CMAKE_CURRENT_BINARY_DIR}/models
        COMMAND ${CMAKE_COMMAND} -E copy_if_different ${MODEL_FILES} ${CMAKE_CURRENT_BINARY_DIR}/models
        COMMENT "Copying models to build")

if (ENABLE_TESTS)
    include(CTest)
    find_package(Python COMPONENTS Interpreter Development)
    file(GLOB TEST_SOURCE_FILES CONFIGURE_DEPENDS ${CMAKE_SOURCE_DIR}/tests/test_*.c)
    # The sample files in tests/data (any extension but .h) are turned into
    # headers by gen_tests.py
    file(GLOB TEST_DATA_FILES CONFIGURE_DEPENDS LIST_DIRECTORIES false ${CMAKE_SOURCE_DIR}/tests/data/*)
    list(FILTER TEST_DATA_FILES EXCLUDE REGEX "\\.h$")

    add_custom_command(
            OUTPUT ${CMAKE_SOURCE_DIR}/tests/main.c
            COMMAND ${CMAKE_COMMAND} -E remove -f ${CMAKE_SOURCE_DIR}/tests/main.c
            COMMAND python ${CMAKE_SOURCE_DIR}/tests/gen_tests.py
            DEPENDS ${TEST_SOURCE_FILES} ${TEST_DATA_FILES} ${CMAKE_SOURCE_DIR}/tests/gen_tests.py ${CMAKE_SOURCE_DIR}/tests/t.h
            WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
            COMMENT "Generating test main")

    add_custom_target(gen_test_main ALL
        DEPENDS ${CMAKE_SOURCE_DIR}/tests/main.c)

    add_custom_target(copy_templates_to_build ALL
            COMMAND ${CMAKE_COMMAND} -E copy_directory
            ${CMAKE_SOURCE_DIR}/templates
            ${CMAKE_CURRENT_BINARY_DIR}/templates
            COMMENT "Copying templates to build")

    add_executable(bhex_tests
        ${common_src}
        ${bhengine_src}
        ${command_src}
        tests/dummy_filebuffer.c
        ${CMAKE_SOURCE_DIR}/tests/main.c)

    if (ENABLE_COVERAGE)
        target_compile_options(bhex_tests PRIVATE -coverage)
        target_link_options(bhex_tests PRIVATE -coverage)
    endif()

    add_dependencies(bhex_tests gen_test_main)
    add_dependencies(bhex_tests copy_templates_to_build)
    add_dependencies(bhex_tests copy_models_to_build)
    target_compile_definitions(bhex_tests PRIVATE BHEX_SOURCE_DIR="${CMAKE_SOURCE_DIR}")

    add_test(NAME bhex_tests COMMAND bhex_tests)

    target_link_libraries(bhex_tests LINK_PUBLIC m)
    if (ENABLE_CAPSTONE)
        target_link_libraries(bhex_tests LINK_PUBLIC capstone)
    endif()
    if (ENABLE_KEYSTONE)
        target_link_libraries(bhex_tests LINK_PUBLIC keystone)
    endif()
endif()

if (ENABLE_FUZZ_TESTS)
    if ("${CMAKE_C_COMPILER_ID}" STREQUAL "Clang")
        add_custom_target(copy_corpus ALL
                COMMAND ${CMAKE_COMMAND} -E copy_directory
                ${CMAKE_SOURCE_DIR}/templates
                ${CMAKE_CURRENT_BINARY_DIR}/corpus
                COMMENT "Copying templates to corpus")

        add_executable(bhex_fuzz_tengine
            ${common_src}
            ${bhengine_src}
            ${CMAKE_SOURCE_DIR}/tests/fuzz_test_tengine.c)

        target_compile_options(bhex_fuzz_tengine PRIVATE -fsanitize=address,fuzzer,undefined)
        target_link_libraries(bhex_fuzz_tengine PRIVATE -fsanitize=address,fuzzer,undefined)
        add_dependencies(bhex_fuzz_tengine copy_corpus)
    else()
        message(FATAL_ERROR "You must use CLANG to compile fuzz tests")
    endif()
endif()

# Main executable
add_executable(bhex
    ${common_src}
    ${command_src}
    ${bhengine_src}
    linenoise/linenoise.c
    completion.c
    main.c)

add_dependencies(bhex copy_models_to_build)

if (STATIC_BUILD)
    set_target_properties(bhex PROPERTIES LINK_SEARCH_START_STATIC ON)
    set_target_properties(bhex PROPERTIES LINK_SEARCH_END_STATIC ON)
    target_link_options(bhex PRIVATE -static-libgcc -static)
endif()

target_link_libraries(bhex LINK_PUBLIC m)
if (ENABLE_CAPSTONE)
    target_link_libraries(bhex LINK_PUBLIC capstone)
endif()
if (ENABLE_KEYSTONE)
    target_link_libraries(bhex LINK_PUBLIC keystone)
endif()

install(TARGETS bhex RUNTIME DESTINATION bin)
install(PROGRAMS ${CMAKE_SOURCE_DIR}/bin/bxxd DESTINATION bin)
install(PROGRAMS ${CMAKE_SOURCE_DIR}/bin/bdiff DESTINATION bin)
install(PROGRAMS ${CMAKE_SOURCE_DIR}/bin/bhengine DESTINATION bin)
install(DIRECTORY templates/
        DESTINATION share/bhex/templates
        FILES_MATCHING PATTERN "*.bhe")
install(DIRECTORY models/
        DESTINATION share/bhex/models
        FILES_MATCHING PATTERN "*.bin")
