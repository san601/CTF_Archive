# HTB Uni 2020 - my_name_is

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

# A 2016 anti-debugging problem for SecCon

As observed, the program uses a lot of anti-debugger techniques.

```C
if ( !v11 )
    {
        puts("Your password is correct.");
        if ( IsDebuggerPresent() )
        {
            puts("But detected debugger!");
            exit(1);
        }

        if ( sub_401120() == 0x70 )
        {
            puts("But detected NtGlobalFlag!");
            exit(1);
        }

        CurrentProcess = GetCurrentProcess();
        CheckRemoteDebuggerPresent(CurrentProcess, pbDebuggerPresent);
        if ( pbDebuggerPresent[0] )
        {
            printf("But detected remotedebug.\n");
            exit(1);
        }

        TickCount = GetTickCount();
        pbDebuggerPresent[3] = 0;
        pbDebuggerPresent[1] = 0x3E8;
        if ( GetTickCount() - TickCount > 0x3E8 )
        {
            printf("But detected debug.\n");
            exit(1);
        }

        lpFileName = "\\\\.\\Global\\ProcmonDebugLogger";
        if ( CreateFileA("\\\\.\\Global\\ProcmonDebugLogger", 0x80000000, 7u, 0, 3u, 0x80u, 0) != (HANDLE)0xFFFFFFFF )
        {
            printf("But detect %s.\n", (const char *)&lpFileName);
            exit(1);
        }

        v6 = sub_401130();
        switch ( v6 )
        {
            case 1:
                printf("But detected Ollydbg.\n");
                exit(1);

            case 2:
                printf("But detected ImmunityDebugger.\n");
                exit(1);

            case 3:
                printf("But detected IDA.\n");
                exit(1);

            case 4:
                printf("But detected WireShark.\n");
                exit(1);
        }

        if ( sub_401240() == 1 )
        {
            printf("But detected VMware.\n");
            exit(1);
        }

        pbDebuggerPresent[2] = 1;
        pbDebuggerPresent[5] = 1;
        pbDebuggerPresent[4] = 1 / 0;
        ms_exc.registration.TryLevel = 0xFFFFFFFE;
        printf("But detected Debugged.\n");
        exit(1);
    }
```
Let's go through one by one.

## IsDebuggerPresent()

```C
if ( IsDebuggerPresent() )
{
    puts("But detected debugger!");
    exit(1);
}
```


## NtGlobalFlag

```C
if ( sub_401120() == 0x70 )
{
    puts("But detected NtGlobalFlag!");
    exit(1);
}
```

## CheckRemoteDebuggerPresent

```C
CurrentProcess = GetCurrentProcess();
CheckRemoteDebuggerPresent(CurrentProcess, pbDebuggerPresent);
if ( pbDebuggerPresent[0] )
{
    printf("But detected remotedebug.\n");
    exit(1);
}
```

## Time difference detection

```C
TickCount = GetTickCount();
pbDebuggerPresent[3] = 0;
pbDebuggerPresent[1] = 0x3E8;
if ( GetTickCount() - TickCount > 0x3E8 )
{
    printf("But detected debug.\n");
    exit(1);
}
```

## ProcessMonitor

```C
lpFileName = "\\\\.\\Global\\ProcmonDebugLogger";
if ( CreateFileA("\\\\.\\Global\\ProcmonDebugLogger", 0x80000000, 7u, 0, 3u, 0x80u, 0) != (HANDLE)0xFFFFFFFF )
{
    printf("But detect %s.\n", (const char *)&lpFileName);
    exit(1);
}
```

## Detection process name


```C
int sub_401130()
{
    PROCESSENTRY32 pe; // [esp+0h] [ebp-138h] BYREF
    HANDLE hSnapshot; // [esp+130h] [ebp-8h]
    BOOL i; // [esp+134h] [ebp-4h]

    pe.dwSize = 0x128;
    memset(&pe.cntUsage, 0, 0x124u);
    hSnapshot = CreateToolhelp32Snapshot(2u, 0);
    for ( i = Process32First(hSnapshot, &pe); i; i = Process32Next(hSnapshot, &pe) )
    {
        if ( !_stricmp(pe.szExeFile, "ollydbg.exe") )
        {
            return 1;
        }

        if ( !_stricmp(pe.szExeFile, "ImmunityDebugger.exe") )
        {
            return 2;
        }

        if ( !_stricmp(pe.szExeFile, "idaq.exe") )
        {
            return 3;
        }

        if ( !_stricmp(pe.szExeFile, "Wireshark.exe") )
        {
            return 4;
        }
    }

    return 0;
}
```

## Detecting VMware
