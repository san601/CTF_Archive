# ROVM

The challenge gives us 3 files: ```chall```, ```opcode``` and ```chain```

From IDA's pseudocode and ltrace command, we know that the program maps ```opcode``` and ```chain``` into the stack at address 0x122400 and 0x122500 respectively.

![image](https://github.com/san601/CTF_Archive/assets/144963803/712c9614-7711-4bb3-9cbf-6ade7c772bbd)

Knowing the address, we can rebase the program of ```opcode``` and ```chain``` for later use.

```opcode```:

![image](https://github.com/san601/CTF_Archive/assets/144963803/adf8667a-38a4-4406-9281-cb8fd13e63b6)

```chain```:

![image](https://github.com/san601/CTF_Archive/assets/144963803/913e9384-6754-42b0-a696-bff65a104825)

The fact that the program uses ROP to execute, we can't do anything other than debugging through every ROP gadget and see what it does.

Keep debugging until the program reach the end of the input, which is a Line Feed character (0xA)

![image](https://github.com/san601/CTF_Archive/assets/144963803/380316a3-1433-48a3-9b33-862c03b35d31)

The program subtract our input's length with a value at 0x1225948 on the stack, which is 0x24. So the length of the flag is 0x24.

![image](https://github.com/san601/CTF_Archive/assets/144963803/0e4c3638-8670-4a22-be99-6b0f4d40272f)

There's a constant 0xFB that is fetched into RAX for every character in the input. Each character in the input will be multiply with a list of number 

![image](https://github.com/san601/CTF_Archive/assets/144963803/1487f989-a73a-4fbc-91a3-1d16ddcbc85b)

and then mod with 0xFB, subtract with 1. If the result is 0, the character is correct.

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

