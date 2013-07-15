make
rm .gdbinit
ln -s gdbinit6 .gdbinit
gdb -e sploit6 -s /tmp/target6
rm .gdbinit
