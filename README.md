# BHex

```
 ____  _    _
|  _ \| |  | |
| |_) | |__| | _____  __
|  _ <|  __  |/ _ \ \/ /
| |_) | |  | |  __/>  <
|____/|_|  |_|\___/_/\_\

```

Minimalistic and lightweight shell-based hex editor that runs everywhere (or at least on most *nix systems).

Supported features:
- print file content in various format;
- write data overwriting the content of the file;
- undo writes until _committed_;
- search strings or binary data;

Just run `bhex <file>` to start the shell.

# Compilation

The project can be compiled using cmake. It has no runtime dependencies a part from libc, so it should be quite strightforward:

```
$ mkdir build
$ cd build
$ cmake ..
$ make
```

# Command Format

Every command has the following structure:
```
$ command_name\mod1\mod2\mod3\... arg1 arg2 ...
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
    template [t]
    seek [s]
    print [p]
    write [w]
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

  s[/{x, s}] <data>
     x: data is an hex string
     s: data is a string (default)

  data: either a string or an hex string
```

### Template

```
[0x0000000] $ t?

template: parse a struct template at current offset

  t[/l] <template_name>
     l: list available templates

  template_name: the name of the template to use

[0x0000000] $ t/l

Available templates:
    Elf32_Ehdr
    Elf64_Ehdr
```

### Seek

```
[0x0000000] $ s?

seek: change current offset
  s <off>
```

### Write

```
[0x0000000] $ w?

write: write data at current offset

  w[{s,x,b,w,d,q}/{le,be}/u] <data>
     s:   string input (default)
     x:   hex input
     b:   byte
     w:   word
     d:   dword
     q:   qword
     le:  little-endian (default)
     be:  big-endian
     u:   unsigned

  data: the data to write. The format depends on the type of
        write. Here there are some examples:
            w/x "00 01 02 03"
            w/s "a string"
            w/q/be 0x1234
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
