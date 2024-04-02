# picoCTF 2024 write up
## WinAntiDbg0x300

Let's run this program to see what it does.

![image](https://github.com/san601/CTF_Archive/assets/144963803/104b40eb-c86d-4894-bfca-a959bdb8ac5d)

So this challenge was created to stop us from debugging it by, maybe, terminating the process. Glad it didn't shut my computer down like one of my friend did with his aNTi-dEbuGgEr chall.

Next, I always use Detect-It-Easy to scan for early information about any executable file.

![image](https://github.com/san601/CTF_Archive/assets/144963803/5217098d-5771-4ef5-9477-84a78427b880)

This file was packed using UPX. Decompressed it and run it in IDA debugger (as administrator), I got this message box:

![image](https://github.com/san601/CTF_Archive/assets/144963803/e8f3030d-5c68-475c-8d0d-e7c91686f8b2)

Searching for the text and 
