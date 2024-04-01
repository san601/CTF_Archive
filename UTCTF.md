**UTCTF 2024**
*PES-128*
Sau 1 lúc chạy thử thì em thấy từng ký tự output không ảnh hưởng bởi cả đoạn input nên em dùng script để brute
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

