# ROVM

The challenge gives us 3 files: ```chall```, ```opcode``` and ```chain```

From IDA's pseudocode and ltrace command, we know that the program maps ```opcode``` and ```chain``` into the stack at address 0x122400 and 0x122500 respectively.

![image](https://github.com/san601/CTF_Archive/assets/144963803/712c9614-7711-4bb3-9cbf-6ade7c772bbd)

Knowing the address, we can rebase the program of ```opcode``` and ```chain``` for later use.

```opcode```:

![image](https://github.com/san601/CTF_Archive/assets/144963803/adf8667a-38a4-4406-9281-cb8fd13e63b6)

```chain```:

![image](https://github.com/san601/CTF_Archive/assets/144963803/913e9384-6754-42b0-a696-bff65a104825)


```python
enc = [
    0x96, 0x44, 0x5B, 0x25, 0x47, 0x8C, 0x59, 
    0x25, 0x92, 0x5A, 0x25, 0x41, 0xF0, 0x44, 
    0x27, 0xF0, 0x8C, 0x4C, 0x4C, 0x29, 0x59, 
    0x27, 0x25, 0x29, 0x2C, 0x59, 0x27, 0x76, 
    0x8C, 0x27, 0x5A, 0x25, 0x29, 0xC7, 0x29
]

for i in enc:
    for char in range(33, 127):
        if (char * i) % 0xfb == 1:
            print(chr(char), end='')
            break

```

Flag: ```R0P_c4n_b5_pr0gr4mm1ng_1angu4g5_1o1```

![image](https://github.com/san601/CTF_Archive/assets/144963803/6582219c-be83-4b05-8264-858400ea1988)

