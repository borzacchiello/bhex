#!/usr/bin/python3
import glob

from pyclibrary import CParser

template_c = """
#include <stdio.h>
#include <stddef.h>
#include "../../defs.h"

#include "template.h"
#include "../util/byte_to_str.h"

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
    void (*pretty_print)(const u8_t*, size_t);
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

static void prettyprint_{struct_name}(const u8_t* data, size_t size)
{{
    if (size < sizeof_{struct_name}())
        return;

    char* hexstr;
    const {struct_name}* s = (const {struct_name}*)data;
    printf("{struct_name}:\\n");

{struct_el_code}
}}
"""

print_el_template_1 = """    printf("  %16s: {el_format}\\n", "{el_name}", s->{el_name});
"""

print_el_template_2 = """    printf("  %16s: {el_format_1} [{el_format_2}]\\n", "{el_name}", s->{el_name}, s->{el_name});
"""

print_el_template_array = \
"""    hexstr = bytes_to_hex(s->{el_name}, sizeof(s->{el_name}));
    printf("  %16s: %s\\n", "{el_name}", hexstr);
    free(hexstr);
"""

def get_format_from_type(t):
    if len(t.declarators) != 0:
        # an array
        assert len(t.declarators) == 1
        assert len(t.declarators[0]) == 1

        # number of elements
        _ = t.declarators[0][0]
        return "%s", None, True

    spec = t.type_spec
    if spec.startswith("const"):
        spec = " ".join(spec.split(" ")[1:])

    if t.type_spec in {"u8_t", "u16_t", "u32_t", "unsigned", "unsigned int"}:
        return "%-12u", "0x%x", False
    elif t.type_spec in {"u64_t", "unsigned long", "unsigned long long"}:
        return "%-12llu", "0x%llx", False
    elif t.type_spec in {"s8_t", "s16_t", "s32_t", "int"}:
        return "%-12d", "0x%x", False
    elif t.type_spec in {"s64_t", "long", "long long"}:
        return "%-12lld", "%llx", False
    elif t.type_spec in {"char*"}:
        return "%s", None, False
    elif t.type_spec in {"uptr_t", "void*"}:
        return "%p", None, False
    return None, None

def parse_structs(sources):
    functions_code = []
    template_array_code = []

    for source_file in sources:
        parser = CParser(source_file)
        structs = parser.defs["structs"]

        for struct_name in structs:
            struct = structs[struct_name]
            els_str = ""
            for member_name, t, _ in struct.members:
                t = parser.eval_type(t)
                format1, format2, array = get_format_from_type(t)
                if format is None:
                    print("WARNING: unable to get format for", t)
                    continue
                if array:
                    els_str += print_el_template_array.format(
                        el_name = member_name)
                elif format2 is None:
                    els_str += print_el_template_1.format(
                        el_name = member_name,
                        el_format = format1)
                else:
                    els_str += print_el_template_2.format(
                        el_name = member_name,
                        el_format_1 = format1,
                        el_format_2 = format2)

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
