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

![image](https://github.com/san601/CTF_Archive/assets/144963803/5e97594f-7d5b-45e6-b857-5abd6ce31abd)

Oops, it shutted down my IDA. From this, I know that the program didn't check my debugger once and I need to know where it checked for the second time. Since it shutted down my IDA whenever I get to the condition checker, I have to use SysinternalsSuite Dbgview to track its output. Repeating what I had done and see if anything useful was captured in Dbgview:

![image](https://github.com/san601/CTF_Archive/assets/144963803/ac84fceb-d5b0-4d6c-9bf9-a8648166044b)

Bingo! "Debugger process terminated successfully" was what it said. Using the same method as I did earlier to find where it close my debugger but IDA was brutally shutted down even before it reached my breakpoint.

![image](https://github.com/san601/CTF_Archive/assets/144963803/d9b134bb-fb4b-4b56-adf9-48cd33ea078d)

So I knew I have to look for something else. Then I noticed that the program create a new thread at a offset called StartAddress.

![image](https://github.com/san601/CTF_Archive/assets/144963803/007436fc-4c96-4785-b50c-68424db21c07)

This felt like a loop. 

![image](https://github.com/san601/CTF_Archive/assets/144963803/43885da3-3926-4727-bd80-d831defadf6c)

Jump into it, there is a part of code at loc_BA3929 where it check for the flag. But you can't see this in pseudo code because the condition to call to loc_BA3929 is never satisfied. In other words, this is a infinite loop and we can get the flag whenever we can break out of it.

![image](https://github.com/san601/CTF_Archive/assets/144963803/8a7cba59-9bf8-4b23-adbe-0c39d7c17e8f)

![image](https://github.com/san601/CTF_Archive/assets/144963803/72a74f6f-9b1a-4808-b8ae-7150d3f4983a)

This chunk of code was the condition for while loop. As jz would only jump if eax = 0, this jump could never be used. Let's set a breakpoint to modify eax. 

![image](https://github.com/san601/CTF_Archive/assets/144963803/31b9ddc9-1265-41ad-aff4-ae05031ed2a9)

And this gave me my flag:

![image](https://github.com/san601/CTF_Archive/assets/144963803/2822a644-9945-48ca-931a-9ae9777049cd)






