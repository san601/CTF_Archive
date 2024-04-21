hihihaha = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 196, 180, 45, 13, 53, 112, 133, 142, 221, 121, 3, 157, 113, 81,
            80, 195, 253, 225, 197, 202, 197, 48, 46, 21, 121, 40, 23, 239, 35, 175, 254, 103, 36, 126, 183, 218, 112,
            235, 9, 98, 99, 29, 109, 196, 120, 43, 68, 126, 100, 81]

for score in range(1, 10000001):
    R = 0
    for i in hihihaha:
        R <<= 8
        R += i
    V = 2933342412243178360246913963653176924656287769470170577218737
    u = 2663862733012296707089609302317500558193537358171126836499053
    d = V * u
    O = pow(R, 65537, d)

    for k in range(64):
        hihihaha[len(hihihaha) - 1 - k] = O & 255
        O = O >> 8

    for G in range(len(hihihaha) - 1, 23, -1):
        h = G * score % 40 + 24
        hihihaha[G], hihihaha[h] = hihihaha[h], hihihaha[G]

    j = score & 255
    for m in range(24, len(hihihaha)):
        hihihaha[m] ^= j
        j = hihihaha[m]

flag = ''.join([chr(i) for i in hihihaha])
print(flag[16:])

