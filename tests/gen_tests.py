import re
import os

script_folder = os.path.realpath(os.path.dirname(__file__))

def iterate_files(path: str, recursive=False):
    for subdir, _, files in os.walk(path):
        for file in files:
            yield os.path.join(subdir, file)
        if not recursive:
            break

def get_all_tests(fullpath):
    result = list()

    pattern = r"int TEST\s*\((.*)\)\(.*\)"
    with open(fullpath, "r") as fin:
        for line in fin:
            data = re.findall(pattern, line)
            result.extend(data)
    return result

if __name__ == "__main__":
    tests = list()
    for f in iterate_files(script_folder):
        dirname = os.path.dirname(f)
        basename = os.path.basename(f)
        if basename.startswith("test_"):
            name = basename
            test_names = get_all_tests(os.path.join(script_folder, f))
            tests.append((name, test_names))

    header  = '#include "t.h"\n\n'
    footer  = 'int main(int argc, char const* argv[])\n'
    footer += '{\n'
    footer += '    TESTS_MAIN_BODY(tests)\n'
    footer += '}\n'

    with open(os.path.join(script_folder, "main.c"), "w") as fout:
        fout.write(header)
        for fname, _ in tests:
            tname = fname.replace(".c", "").replace("test_", "")
            fout.write(f'#define TEST(n) {tname}_test_##n\n')
            fout.write(f'#include "{fname}"\n')
            fout.write(f'#undef TEST\n')
        fout.write('\n')
        fout.write('static test_t tests[] = {\n')
        for fname, test_names in tests:
            tname = fname.replace(".c", "").replace("test_", "")
            fout.write(f'#define TEST(n) {tname}_test_##n\n')
            for name in test_names:
                fout.write('    {"%s.%s", &TEST(%s)},\n' % (tname, name, name))
            fout.write(f'#undef TEST\n')

        fout.write('};\n\n')
        fout.write(footer)
