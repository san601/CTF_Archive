# Prob.exe

## Explanation

Let's open the file in IDA

Firstly, it reads the flag in flag.txt

![image](https://github.com/san601/CTF_Archive/assets/144963803/7d19079b-79ac-4770-8659-9b0cae2195b1)

and then go through this encryption stuff, with Str is ```'have a good day! enjoy wargame!'```.

![image](https://github.com/san601/CTF_Archive/assets/144963803/360286c6-a317-465b-8f67-8f16ee531e71)

Lastly, it prints out the encrypted flag in the format of ```%#llX```, which means a long long hex value with ```0X``` at the start.

![image](https://github.com/san601/CTF_Archive/assets/144963803/26fe69ed-0caa-4469-8e84-e03fae715421)

## Script:

```python
enc = [0x29AF, 0x2493, 0x35A9, 0x2729, 0x414, 0x2453, 0x458, 0x28EF, 0x2F9E, 0x2FFC, 0x26D0, 0x467, 0x26EB, 0x2439,
       0x3914, 0x42C, 0x43F, 0x275F, 0x2EDD, 0x2B2B, 0x300F, 0x389C, 0x41D, 0x36A6, 0x2474, 0x3229, 0x2979, 0x24A9,
       0x2E89, 0x2756, 0x427, 0x29EE, 0x2448, 0x3698, 0x2750, 0x44E, 0x247D, 0x41F, 0x2967, 0x302F, 0x2FCF, 0x26CD,
       0x426, 0x26D0, 0x24A7, 0x391D, 0x46B, 0x42A, 0x2809, 0x2F10, 0x2BF7, 0x302B, 0x3912, 0x416, 0x3771, 0x24A3,
       0x3294, 0x296D, 0x24A8, 0x2E61, 0x27F8, 0x468, 0x2A22, 0x2513, 0x365C, 0x2805, 0x495, 0x2512, 0x497, 0x296C,
       0x3035, 0x2FED, 0x273C, 0x472, 0x2740, 0x24F6, 0x3950, 0x4BA, 0x47C, 0x2812, 0x2F76]

Str = 'have a good day! enjoy wargame!'

for i in range(0, 0x51):
    enc[i] = enc[i] - i                                                      # v4 -> v3
    enc[i] = enc[i] + ord(Str[i % len(Str)])                                 # v3 -> v2
    enc[i] = enc[i] ^ (ord(Str[i % len(Str)]) * ord(Str[i % len(Str)]) + i)  # v2 -> v1

for i in range(len(enc)):
    print(chr(enc[i]), end='')
```

## Flag

![image](https://github.com/san601/CTF_Archive/assets/144963803/74c7020c-b9b2-4721-b190-87f8fba6723f)

