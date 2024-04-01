# UTCTF 2024
## Beginner: Basic Reversing Problem
## Fruit Deals
## PES-128
After a while, I noticed that:
- Each character in the output string is not calculated based on a whole input string.
- The program treat our input as a string of hex bytes:
This was my input:
![image](https://github.com/san601/CTF_Archive/assets/144963803/9a8d78c6-d231-4bbe-95ed-a656085d0936)

This was how the program store my input:
![image](https://github.com/san601/CTF_Archive/assets/144963803/7a9183b7-1145-40be-9bbd-ca1feab07174)

This was my input after some calculation:
![image](https://github.com/san601/CTF_Archive/assets/144963803/46404e51-1210-44b1-a73a-ff239ef2c45a)

This was the output:
![image](https://github.com/san601/CTF_Archive/assets/144963803/d100e88e-7398-442f-9a97-94e291efd03b)

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

