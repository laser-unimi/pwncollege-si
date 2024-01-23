#!/usr/bin/python3
from pwn import *

# Nome: Mario
# Cognome: Rossi
# Matricola: 1234567890
# Appello del xx/yy/2024
# Breve spiegazione della soluzione persentata:
#
#
#
#
#
#
#
#
#
#
# Si richiede che il codice sia il piu' leggibile e comprensibile possibile,
# eventualmente anche aggiungendo commenti nelle sezioni meno chiare.
# La soluzione deve essere coerente con la tipologia di esercizio (e.g. un esercizio di ROP DEVE(!) essere risolto con tecniche ROP)


# INITIALIZATION
FILENAME = '/challenge/' #TODO aggiungere nome del binario
context.arch = 'amd64' # Setting the correct architecture
context.log_level = 'CRITICAL' # Change this line to 'DEBUG' for a more detailed output

elf = ELF(FILENAME)

# Calculating buffer length with cyclic strings and corefile dump
pattern_size=512
io = elf.process(setuid=False)
io.sendline(f"{pattern_size}".encode())
io.sendline(cyclic(pattern_size,n=8))
io.wait()
buff_len = int(cyclic_find(io.corefile.fault_addr,n=8))
io.close()
# Assuming i want to retrieve the string "test" from the binary:
# string_addr = next(elf.search(b'test\x00'))
# function_addr = elf.symbols.function_name # TODO replace function_name with the actual name of the function
# shellcode = asm(shellcraft.cat('/flag'))
#EXPLOIT GOES HERE
