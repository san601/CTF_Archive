## UTCTF 2024
# Beginner: Basic Reversing Problem
# Fruit Deals
# PES-128
After a while, I noticed that:
- The output string is not affected by a whole input string.
- The program treat oủ input as a string of hex bytes.
Here is my script to brute forcing the flag.
```python
from pwn import *

enc_flag = '75ac713a945e9f78f657b735b7e1913cdece53b8853f3a7daade83b319c49139f8f655b0b77b'

flag = ''

flag_len = len(enc_flag)//2

for i in range(flag_len):
    for j in range(33, 126):
        binary_path = './PES'
        p = process(binary_path)
        p.sendline(flag + str(hex(j)[2:]))

        output = p.recvall().decode()
        output = output.split()
        current_length = len(output[1])
        if output[1] == enc_flag[:current_length]:
            print(chr(j), end='')
            flag += str(hex(j)[2:])
        p.close()

print(bytes.fromhex(flag))
```
![image](https://github.com/san601/CTF_Archive/assets/144963803/d3b4acb1-c6bc-4871-8fd9-c4e1fcc69397)

