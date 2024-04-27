# HTB Uni 2020 
## my_name_is

Let's examine the pseudocode from IDA:
![image](https://github.com/san601/CTF_Archive/assets/144963803/3181f057-4f41-4bc4-bfd9-220d069dd488)

We can see that this challenge uses getpwuid() to get the name of the user and use it to decrypt an encrypted flag. There are also 2 anti-debugging techniques in it.

Firstly, while debugging, the eax register will be set to 0xFFFFFFFF if the program detects debugging, 0x00000000 otherwise. This is because a process can only have one trace and the ```PTRACE_TRACEME``` argument means that the process which observes and controls the execution of this program is itself. This is the reason why using a debugger, which means attaching one more trace on the program, can cause errors.

To bypass this, just patch the program to jump if eax is not zero.

![image](https://github.com/san601/CTF_Archive/assets/144963803/953c7acb-8a26-4d80-81bb-30dfbf706bd2)

Secondly, this right here is another technique to check if I have any breakpoint in the program.

![image](https://github.com/san601/CTF_Archive/assets/144963803/f13ba6a4-d762-4e99-ba13-6eff2af72c40)

Basically, whenever a debugger sets a breakpoint to an address, it will change the first byte of the machine code, which was fetched to memory before, to ```0xCC```. This for loop iterates from ```main``` to ```marker```, in other words, iterates through every instruction in the ```main``` function to check if any breakpoints exist.

We can also patch it to skip the process. I did a small patch to the jump command, from jl to jge to break out of the loop immediately.

![image](https://github.com/san601/CTF_Archive/assets/144963803/c7e604c4-9e3d-4a3f-8021-c09602d0f624)

Lastly, we just need to set the value for s1 to be "\~#L-:4;f". From observation while debugging, I know that the string "\~#L-:4;f" is stored in address 0x0804A05C and therefore we can use it to change the value of s1.

![image](https://github.com/san601/CTF_Archive/assets/144963803/a537c8af-ecfb-4fd7-9f5c-112ce5765947)

And now we can get the flag.

![image](https://github.com/san601/CTF_Archive/assets/144963803/471132b7-9a8c-4039-8d2b-f977b829b117)
