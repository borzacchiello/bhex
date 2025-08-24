import xml.etree.ElementTree as ET
import subprocess
import os

class Var(object):
    def __init__(self, el):
        if el.tag != "var":
            raise ValueError(f"unexpected tag in var [{el.tag}]")
        self.name = el.attrib["name"]
        self.type = el.attrib["type"]
        self.off  = int(el.attrib["off"])

        if len(el) == 1 and list(el)[0].tag != "var":
            self.value = TagParser.parse(list(el)[0])
        else:
            self.value = dict()
            for c in el:
                if c.tag != "var":
                    raise ValueError(f"unexpected tag in var child [{c.tag}]")
                pc = TagParser.parse(c)
                if pc.name in self.value:
                    self.value = [ self.value[pc.name], pc ]
                else:
                    self.value[pc.name] = pc

    def has_primitive_value(self):
        return not isinstance(self.value, dict)

    def __getattribute__(self, name):
        if not name.startswith("_") or self.has_primitive_value() or name[1:] not in self.value:
            return super().__getattribute__(name)
        return self.value[name[1:]]

    @property
    def values(self):
        if hasattr(self, "sorted_values"):
            return self.sorted_values

        self.sorted_values = list()
        if self.has_primitive_value():
            self.sorted_values.append(self.value)
            return self.sorted_values

        for k in self.value:
            v = self.value[k]
            if isinstance(v, list):
                for e in v:
                    self.sorted_values.append(e)
            else:
                self.sorted_values.append(v)
        self.sorted_values = sorted(self.sorted_values, key=lambda x: x.off)
        return self.sorted_values

    def __str__(self):
        return "<%s %s @ 0x%x>" % (self.type, self.name, self.off)

    __repr__ = __str__

class EnumValue(object):
    def __init__(self, el):
        if el.tag != "enum_value":
            raise ValueError("unexpected tag")
        self.mnemonic = el.attrib["mnemonic"]
        self.value    = int(el.text)

class TagParser(object):
    @staticmethod
    def parse(el):
        method = "parse_" + el.tag
        if not hasattr(TagParser, method):
            raise ValueError(f"unable to parse {el.tag}")
        return getattr(TagParser, method)(el)

    @staticmethod
    def parse_var(el):
        return Var(el)

    @staticmethod
    def parse_unum(el):
        return int(el.text)

    @staticmethod
    def parse_snum(el):
        return int(el.text)

    @staticmethod
    def parse_char(el):
        return int(el.text)

    @staticmethod
    def parse_buffer(el):
        return bytes.fromhex(el.text)

    @staticmethod
    def parse_array(el):
        return [ TagParser.parse(c) for c in el.children ]

def process(fname: str, template: str):
    if not os.path.isfile(fname):
        raise ValueError(f"{fname} is not a valid file")
    proc = subprocess.Popen(
        ["bhengine", "-x", fname, template], stderr=subprocess.PIPE, stdout=subprocess.PIPE)
    stdout, stderr = proc.communicate()
    if stderr != b"":
        raise ValueError(stderr.decode("ascii"))

    root = ET.fromstring(stdout.decode("ascii"))
    if root.tag != "root":
        raise ValueError("invalid XML")

    vars = list()
    for c in root:
        vars.append(TagParser.parse(c))
    return vars
