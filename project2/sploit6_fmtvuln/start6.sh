make
rm .gdbinit
ln -s gdbinit6 .gdbinit
gdb -e sploitfmt -s fmt_vuln
rm .gdbinit
