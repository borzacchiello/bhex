from lxml import objectify
from io import StringIO
import subprocess
import os

def process_file(fname: str, template: str):
    if not os.path.isfile(fname):
        raise ValueError(f"{fname} is not a valid file")
    proc = subprocess.Popen(
        ["tengine", "-x", fname, template], stderr=subprocess.PIPE, stdout=subprocess.PIPE)
    stdout, stderr = proc.communicate()
    if stderr != b"":
        raise ValueError(stderr.decode("ascii"))

    return objectify.parse(StringIO(stdout.decode("ascii"))).getroot()
    root = ET.fromstring(stdout.decode("ascii"))
    if root.tag != "root":
        raise ValueError("invalid XML")


    return root

if __name__ == "__main__":
    root = process_file("/bin/sh", "zip")
    import IPython; IPython.embed()
