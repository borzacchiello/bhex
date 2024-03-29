# BHex

```
 ____  _    _
|  _ \| |  | |
| |_) | |__| | _____  __
|  _ <|  __  |/ _ \ \/ /
| |_) | |  | |  __/>  <
|____/|_|  |_|\___/_/\_\

```

Minimalistic and lightweight shell-based hex editor.

It is designed to have a low memory footprint. This makes the program usable on *very low-end* devices.

Supported features:
- print file content in various format
- write/overwrite data into the file
- undo writes until _committed_
- enumerate (ascii) strings
- search strings or binary data
- disassemble opcodes (using Capstone)
- assemble opcodes (using Keystone)

Just run `bhex <file>` to start the shell.

Supported flags:

```
Usage:  bhex [ options ] inputfile
  -h  --help        Display this usage information
  -w  --write       Open the file in write mode
  -b  --backup      Backup original file in "filename.bk"
  -2  --no_warning  Disable warnings
  -n  --no_history  Do not save command history
  -c  "c1; c2; ..." Execute the commands given as arguments and exit

command history is saved in "$HOME/.bhex_history", but it can be changed setting BHEX_HISTORY_FILE env variable
```

# Compilation

The project can be compiled using cmake. Without Captone and Keystone, it has no runtime dependencies (apart from libc), so it should be quite strightforward:

```
$ mkdir build
$ cd build
$ cmake ..
$ make
```

To enable the disassembler command, use "-DENABLE_CAPSTONE=on".

To enable the assembler command, use "-DENABLE_KEYSTONE=on".

# Command Format

Every command has the following structure:
```
$ command_name/mod1/mod2/mod3/... arg1 arg2 ...
```

where the _modifiers_ (e.g. mod1) are optional parameters of the command.

The documentation of a each command can be accessed typing "?" after the name of the command.

# Commands

Typing "help" prints the list of commands:

```
[0x0000000] $ h

Available commands:
    help [h]
    info [i]
    search [src]
    strings [str]
    template [t]
    seek [s]
    print [p]
    assemble [as]
    disas [ds]
    write [w]
    delete [d]
    undo [u]
    commit [c]
```

### Info

```
[0x0000000] $ i?

info: prints information about the opened binary
```

### Search

```
[0x0000000] $ src?

search: search a string or a sequence of bytes in the file

  src[/{x, s}/sk/p] <data>
     x:  data is an hex string
     s:  data is a string (default)
     sk: seek to first match
     p:  print blocks info

  data: either a string or an hex string
```

### Strings

```
[0x0000000] $ str?

enumerate the strings in the file (i.e., sequences of printable ascii characters)

  str[/n] [<num>]
     n: look for null-terminated strings

  num: minimum length (default: 3)
```

### Template

```
[0x0000000] $ t?

template: parse a struct template at current offset

  t[/l/{le,be}] <template_name>
     l:  list available templates
     le: interpret numbers as little-endian (default)
     be: interpret numbers as big-endian

  template_name: the name of the template to use

[0x0000000] $ t/l

Available templates:
    ZipHeader
    TarHeader
    Elf32_Ehdr
    Elf64_Ehdr
    IMAGE_DOS_HEADER
    IMAGE_NT_HEADERS64
    IMAGE_NT_HEADERS32
```

### Seek

```
[0x0000000] $ s?

seek: change current offset
  s[/{+,-}] <off>
    +: sum 'off' to current offset (wrap if greater than filesize)
    -: subtract 'off' to current offset (wrap if lower than zero)

  off: can be either a number or the character '-'.
       In the latter case seek to the offset before the last seek.

  NOTE: if called without arguments, print current offset
```

### Assemble

```
[0x0000000] $ as?

assemble: assemble code and write it at current offset

  as[/l/i/s] <arch> "<code>"
     l:  list supported architectures
     i:  insert instead of overwrite
     s:  seek to the end of the write

  arch: the architecture to use
  code: assembly code string (e.g., "inc eax; inc ecx; ret")
```

### Disassemble

```
[0x0000000] $ ds?

disas: disassemble code at current offset

  ds[/l] <arch> [<nbytes>]
     l:  list supported architectures

  arch:   the architecture to use
  nbytes: the number of opcodes to disassemble, default value: 8
```

### Print

```
[0x0000000] $ p?

print: display the data at current offset in various formats

  p[/{x,w,d,q}/{le,be}/r/{+,-}] <nelements>
     x:  hex output (default)
     w:  words
     d:  dwords
     q:  qwords
     a:  as ascii
     C:  as C buffer
     le: little-endian (default)
     be: big-endian
     r:  raw mode (no ascii, no header and no addresses)
     +:  seek forward after printing
     -:  seek backwards after printing

  nelements: the number of elements to display
  (default: enough to display 256 bytes)
```

### Write

```
[0x0000000] $ w?

write: write data at current offset

  w[{s,x,b,w,d,q}/{le,be}/u/i] <data>
     s:   string input (default)
     x:   hex input
     b:   byte
     w:   word
     d:   dword
     q:   qword
     le:  little-endian (default)
     be:  big-endian
     u:   unsigned
     i:   insert

  data: the data to write. The format depends on the type of 
        write. Here there are some examples:
            w/x "00 01 02 03"
            w/s "a string"
            w/q/be 0x1234
```

### Delete

```
[0x0000000] $ d?

delete: delete bytes at current offset

  d <len>
```

### Undo

```
[0x0000000] $ u?
undo the last write
```

### Commit

```
[0x0000000] $ c?
commit all the writes to file
```
