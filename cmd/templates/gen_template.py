#!/usr/bin/python3
import glob
import os

from pyclibrary import CParser

template_c = """
#include <stdio.h>
#include <stddef.h>
#include "../../defs.h"

#include "template.h"
#include "../util/byte_to_str.h"
#include "../util/endian.h"

{struct_defs}

Template templates[] = {{
{template_array_src}
}};
"""

template_h = """
#ifndef TEMPLATE_H
#define TEMPLATE_H

typedef struct Template {{
    const char* name;
    size_t (*get_size)();
    void (*pretty_print)(const u8_t*, size_t, int);
}} Template;

extern Template templates[{num_templates}];

#endif
"""

array_template = """  {{
    .name         = "{struct_name}",
    .get_size     = sizeof_{struct_name},
    .pretty_print = prettyprint_{struct_name}}},
"""

struct_template = """
#include "{struct_file}"

static size_t sizeof_{struct_name}()
{{
    return sizeof({struct_name});
}}

static void prettyprint_{struct_name}(const u8_t* data, size_t size, int le)
{{
    if (size < sizeof_{struct_name}())
        return;

    __attribute__((unused)) char* hexstr;
    const {struct_name}* s = (const {struct_name}*)data;
    printf("{struct_name}: (%lu)\\n", sizeof({struct_name}));

{struct_el_code}
}}
"""

print_el_num_template = """    {{
        {el_type} v = le 
            ? {read_le}(&s->{el_name})
            : {read_be}(&s->{el_name});
        printf("  %{alignNum}s: {el_format}\\n", "{el_name}", v);
    }}
"""

print_el_num_with_hex_template = """    {{
        {el_type} v = le 
            ? {read_le}(&s->{el_name})
            : {read_be}(&s->{el_name});
        printf("  %{alignNum}s: {el_format_1} [{el_format_2}]\\n", "{el_name}", v, v);
    }}
"""

print_el_str_template = """    printf("  %{alignNum}s: %s\\n", "{el_name}", s->{el_name});"""

print_el_array_template = \
"""    hexstr = bytes_to_hex((u8_t*)s->{el_name}, sizeof(s->{el_name}));
    printf("  %{alignNum}s: %s\\n", "{el_name}", hexstr);
    free(hexstr);
"""

def get_read_functions_from_type_name(tname):
    if tname in {"uint8_t", "int8_t", "unsigned char", "char"}:
        return "read8", "read8"
    if tname in {"uint16_t", "int16_t", "unsigned short", "short"}:
        return "read_le16", "read_be16"
    if tname in {"uint32_t", "int32_t", "unsigned", "unsigned int", "int"}:
        return "read_le32", "read_be32"
    if tname in {"uint64_t", "int64_t", "unsigned long", "long", "unsigned long long", "long long"}:
        return "read_le64", "read_be64"
    return None, None

def is_ambiguous_type(t):
    return t in {"unsigned long", "long", "void*", "uintptr_t"}

def get_code_from_type(t, name, alignNum):
    if len(t.declarators) != 0:
        # an array
        assert len(t.declarators) == 1
        assert len(t.declarators[0]) == 1

        # number of elements
        _ = t.declarators[0][0]
        return print_el_array_template.format(alignNum=alignNum, el_name=name)

    spec = t.type_spec
    if spec.startswith("const"):
        spec = " ".join(spec.split(" ")[1:])

    if is_ambiguous_type(spec):
        print(
            "WARNING: you are using an ambiguous type that has different meanings on\n" +
            "         32-bit and 64-bit machines. Consider using uint32_t/int32_t or\n" +
            "         uint64_t/int64_t")

    readle, readbe = get_read_functions_from_type_name(spec)
    if t.type_spec in {"uint8_t", "uint16_t", "uint32_t", "unsigned", "unsigned int", "unsigned short", "unsigned char"}:
        if readle is None or readbe is None:
            return None
        return print_el_num_with_hex_template.format(
            alignNum=alignNum,
            read_le=readle,
            read_be=readbe,
            el_type=t.type_spec,
            el_format_1="%-12u",
            el_format_2="0x%x",
            el_name=name)
    elif t.type_spec in {"uint64_t", "unsigned long", "unsigned long long"}:
        if readle is None or readbe is None:
            return None
        return print_el_num_with_hex_template.format(
            alignNum=alignNum,
            read_le=readle,
            read_be=readbe,
            el_type=t.type_spec,
            el_format_1="%-12llu",
            el_format_2="0x%llx",
            el_name=name)
    elif t.type_spec in {"int8_t", "int16_t", "int32_t", "char", "short", "int"}:
        if readle is None or readbe is None:
            return None
        return print_el_num_with_hex_template.format(
            alignNum=alignNum,
            read_le=readle,
            read_be=readbe,
            el_type=t.type_spec,
            el_format_1="%-12d",
            el_format_2="0x%x",
            el_name=name)
    elif t.type_spec in {"int64_t", "long", "long long"}:
        if readle is None or readbe is None:
            return None
        return print_el_num_with_hex_template.format(
            alignNum=alignNum,
            read_le=readle,
            read_be=readbe,
            el_type=t.type_spec,
            el_format_1="%-12lld",
            el_format_2="0x%llx",
            el_name=name)
    elif t.type_spec in {"char*"}:
        return print_el_str_template.format(
            alignNum=alignNum,
            el_name=name)
    elif t.type_spec in {"uintptr_t", "void*"}:
        if readle is None or readbe is None:
            return None
        return print_el_num_with_hex_template.format(
            alignNum=alignNum,
            read_le=readle,
            read_be=readbe,
            el_type=t.type_spec,
            el_format="%p",
            el_name=name)
    return None

def parse_structs(sources):
    functions_code = []
    template_array_code = []

    for source_file in sorted(sources):
        os.system("gcc -DCPARSER=on -E %s > /tmp/src.c" % source_file)
        parser = CParser(
            ["../../defs.h", "/tmp/src.c"],
            replace={"__attribute__((__packed__))": " "})
        structs = parser.defs["structs"]

        for struct_name in structs:
            struct = structs[struct_name]
            els_str = ""
            max_len_name = \
                max([len(x[0]) for x in struct.members])
            for member_name, t, _ in struct.members:
                t = parser.eval_type(t)
                code = get_code_from_type(t, member_name, max_len_name)
                if code is None:
                    print("WARNING: unable to process type", t)
                    continue
                els_str += code

            c_code = struct_template.format(
                struct_file = source_file,
                struct_name = struct_name,
                struct_el_code = els_str)
            array_code = array_template.format(
                struct_name = struct_name)

            functions_code.append(c_code)
            template_array_code.append(array_code)

    return functions_code, template_array_code

if __name__=="__main__":

    sources = list()
    for file in glob.glob("*.h"):
        if file == "template.h":
            continue
        sources.append(file)

    c_code_list, array_code_list = parse_structs(sources)

    struct_functions = "\n".join(c_code_list)
    array_code = "\n".join(array_code_list)

    c_code = template_c.format(
        struct_defs=struct_functions,
        template_array_src=array_code)

    h_code = template_h.format(
        num_templates=len(c_code_list)
    )

    with open("template.c", "w") as fout:
        fout.write(c_code)

    with open("template.h", "w") as fout:
        fout.write(h_code)

    os.system("clang-format -i template.c")
    os.system("clang-format -i template.h")
