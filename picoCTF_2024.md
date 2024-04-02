# picoCTF 2024 write up
## WinAntiDbg0x300

Let's run this program to see what it does.

![image](https://github.com/san601/CTF_Archive/assets/144963803/104b40eb-c86d-4894-bfca-a959bdb8ac5d)

So this challenge was created to stop us from debugging it by, maybe, terminating the process. Glad it didn't shut my computer down like one of my friend did with his aNTi-dEbuGgEr chall.

Next, I always use Detect-It-Easy to scan for early information about any executable file.

![image](https://github.com/san601/CTF_Archive/assets/144963803/5217098d-5771-4ef5-9477-84a78427b880)

This file was packed using UPX. Decompressed it and run it in IDA debugger (as administrator), I got this message box:

![image](https://github.com/san601/CTF_Archive/assets/144963803/e8f3030d-5c68-475c-8d0d-e7c91686f8b2)

Because this challenge was aim to detect my debugger so I needed to figure out which mechanic this challenge was using. Searching for the text "debugger" gave me a bunch of references but pay attention to IsDebuggerPresent() because it might be the case I was looking for. 

![image](https://github.com/san601/CTF_Archive/assets/144963803/71fa74bb-b56f-48af-b3ea-554890af81ad)

I also found the text from the message box earlier, let's set a breakpoint where it checked my debugger and run:

![image](https://github.com/san601/CTF_Archive/assets/144963803/c3a677e5-9f9a-407d-bdc8-bb3eb68ca74f)

As EAX = 1, my debugger was detected and it was about to messed up my stuffs. So I set EAX to 0 and continue:

![image](https://github.com/san601/CTF_Archive/assets/144963803/a8e15e6c-6c26-4c60-a459-eeb14d1c623b)

Oops, it shutted down my IDA. From this, I know that the program didn't check my debugger once and I need to know where it checked for the second time. Since it shutted down my IDA whenever I get to the condition checker, I have to use SysinternalsSuite Dbgview to track its output. Repeating what I had done and see if anything useful was captured in Dbgview:

![image](https://github.com/san601/CTF_Archive/assets/144963803/ac84fceb-d5b0-4d6c-9bf9-a8648166044b)

Bingo! "Debugger process terminated successfully" was what it said. Using the same method as I did earlier, I found where it actually close my IDA and interfere the condition-checking process with a breakpoint.

![image](https://github.com/san601/CTF_Archive/assets/144963803/192809bf-27cc-4631-8638-550784c2afc3)

But the program stopped before it even met my breakpoint.




