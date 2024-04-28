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
        ms_exc.registration.TryLevel = -2;
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
When using a debugger, the ```IsDebuggerPresent()``` returns an 1. To bypass this, we can set a breakpoint at the instruction where the program compare the result of ```IsDebuggerPresent()``` with 1 and set the register to 0. 

![image](https://github.com/san601/CTF_Archive/assets/144963803/8a67d770-404c-4c1d-b368-60e89230ee89)


## NtGlobalFlag

```C
if ( sub_401120() == 0x70 )
{
    puts("But detected NtGlobalFlag!");
    exit(1);
}
```

```NtGlobalFlag``` is the flag that the system uses to determine how to create heap structures. It is stored at an undocumented location in the ```PEB``` (process environment block) at offset ```0x68``` (32-bit machine) or offset ```0xBC``` (64-bit machine). 

![image](https://github.com/san601/CTF_Archive/assets/144963803/5fe70169-2238-4079-9164-eb58a6365bcb)


The default value for this is 0. If the process was created by a debugger, the following flags will be set:

```
FLG_HEAP_ENABLE_TAIL_CHECK (0x10)
FLG_HEAP_ENABLE_FREE_CHECK (0x20)
FLG_HEAP_VALIDATE_PARAMETERS (0x40)
```

The combination of these flag (sum up to 0x70) can be a sign that a debugger is running.

Just like the previous one, just set eax to another value and you're good to go.

![image](https://github.com/san601/CTF_Archive/assets/144963803/c770632b-a855-4eef-9230-3fca3c62d8ac)


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

From Microsoft's document about CheckRemoteDebuggerPresent function:

```C
BOOL CheckRemoteDebuggerPresent(
  [in]      HANDLE hProcess,
  [in, out] PBOOL  pbDebuggerPresent
);
```

hProcess is the handle to the process, pbDebuggerPresent is where the function return its value (True if the process is being debugged, or False otherwise.

To bypass this, we can either change the value or patch the jz instruction (to jnz)

![image](https://github.com/san601/CTF_Archive/assets/144963803/38142264-79a5-4113-abf3-8119adb04d77)

![image](https://github.com/san601/CTF_Archive/assets/144963803/4f101761-f45b-48b7-9edf-59d4b7f4df67)

## Time difference detection

```C
TickCount = GetTickCount();
pbDebuggerPresent[3] = 0;
pbDebuggerPresent[1] = 1000;
if ( GetTickCount() - TickCount > 1000 )
{
    printf("But detected debug.\n");
    exit(1);
}
```

GetTickCount() retrieves the number of milliseconds that have elapsed since my computer boot up.
![image](https://github.com/san601/CTF_Archive/assets/144963803/1b663d4b-e5bc-452e-859d-ac1d881a6879)
![image](https://github.com/san601/CTF_Archive/assets/144963803/e44fb8e8-e3f6-4f66-96d7-3aeb0da4cbf5)

As you can see, they are off by a very little number.

So basically, the executing time between ```TickCount = GetTickCount();``` and ```if ( GetTickCount() - TickCount > 1000 )``` is calculated and check if it exceed 1000 milliseconds. If this is true, surely there is a debugger.

To bypass, just change the value in eax, right about where the program compares eax and the value 1000.

![image](https://github.com/san601/CTF_Archive/assets/144963803/4efaeb4b-b222-4ea4-abb0-97273b4640c1)

## ProcessMonitor

```C
lpFileName = "\\\\.\\Global\\ProcmonDebugLogger";
if ( CreateFileA("\\\\.\\Global\\ProcmonDebugLogger", 0x80000000, 7u, 0, 3u, 0x80u, 0) != (HANDLE)0xFFFFFFFF )
{
    printf("But detect %s.\n", (const char *)&lpFileName);
    exit(1);
}
```

When using Process Monitor to debug/analyse, ```\\.\Global\ProcmonDebugLogger``` is created to keep track of the information from Process Monitor. This line of code detects the existence of the file to check whether this program is being debugged or not.

Set eax to 0xFFFFFFFF to bypass.

![image](https://github.com/san601/CTF_Archive/assets/144963803/a7a149b0-a250-46cc-b41e-404f391d78d4)


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

This creates a snapshot to capture all the currently running processes, iterate through all and check if there exist any debugging tool

To bypass, again, set eax to 0 right after this function is called. One weird thing is that I was using IDA to debug but the program could not detect it.

## Detecting VMware

```C
int __spoils<ecx> sub_401240()
{
    __indword(0x5658u);
    return 1;
}
```

```__indword``` is used to read one double word of data from the specified port, in this case it is port number 0x5658. VMware uses I/O port 0x5658/0x5659 as a backdoor for its internal connection between VMware tools and VM Manager.

```assembly
:00401273 ;   __try { // __except at loc_4012A4
.text:00401273                 mov     [ebp+ms_exc.registration.TryLevel], 0
.text:0040127A                 push    edx
.text:0040127B                 push    ecx
.text:0040127C                 push    ebx
.text:0040127D                 mov     eax, 564D5868h  ; VMXh
.text:00401282                 mov     ebx, 0
.text:00401287                 mov     ecx, 0Ah
.text:0040128C                 mov     edx, 5658h
.text:00401291                 in      eax, dx
.text:00401292                 pop     ebx
.text:00401293                 pop     ecx
.text:00401294                 pop     edx
.text:00401294 ;   } // starts at 401273
.text:00401295                 mov     [ebp+ms_exc.registration.TryLevel], 0FFFFFFFEh
.text:0040129C                 jmp     short loc_4012C1
.text:0040129C
.text:0040129E ; ---------------------------------------------------------------------------
.text:0040129E
.text:0040129E loc_40129E:                             ; DATA XREF: .rdata:stru_40BC20↓o
.text:0040129E ;   __except filter // owned by 401273
.text:0040129E                 mov     eax, 1
.text:004012A3                 retn
.text:004012A3
.text:004012A4 ; ---------------------------------------------------------------------------
.text:004012A4
.text:004012A4 loc_4012A4:                             ; DATA XREF: .rdata:stru_40BC20↓o
.text:004012A4 ;   __except(loc_40129E) // owned by 401273
.text:004012A4                 mov     esp, [ebp+ms_exc.old_esp]
.text:004012A7                 mov     [ebp+var_1C], 0
.text:004012AE                 mov     [ebp+ms_exc.registration.TryLevel], 0FFFFFFFEh
.text:004012B5                 mov     eax, [ebp+var_1C]
.text:004012B8                 jmp     short loc_4012C6
.text:004012B8
.text:004012BA ; ---------------------------------------------------------------------------
.text:004012BA                 mov     [ebp+ms_exc.registration.TryLevel], 0FFFFFFFEh
.text:004012BA
.text:004012C1
.text:004012C1 loc_4012C1:                             ; CODE XREF: sub_401240+5C↑j
.text:004012C1                 mov     eax, 1
.text:004012C1
.text:004012C6
.text:004012C6 loc_4012C6:                             ; CODE XREF: sub_401240+78↑j
.text:004012C6                 mov     ecx, [ebp+ms_exc.registration.Next]
.text:004012C9                 mov     large fs:0, ecx
.text:004012D0                 pop     ecx
.text:004012D1                 pop     edi
.text:004012D2                 pop     esi
.text:004012D3                 pop     ebx
.text:004012D4                 mov     esp, ebp
.text:004012D6                 pop     ebp
.text:004012D7                 retn
```

Take a look at assembly instruction, IDA did a great job as it gave us intel about exception handlers and stuff. As you can see, the program will ```try``` the following block until an exception occurs, which mean there is no VMware. 

```assembly
:00401273 ;   __try { // __except at loc_4012A4
.text:00401273                 mov     [ebp+ms_exc.registration.TryLevel], 0
.text:0040127A                 push    edx
.text:0040127B                 push    ecx
.text:0040127C                 push    ebx
.text:0040127D                 mov     eax, 564D5868h  ; VMXh
.text:00401282                 mov     ebx, 0
.text:00401287                 mov     ecx, 0Ah
.text:0040128C                 mov     edx, 5658h
.text:00401291                 in      eax, dx
.text:00401292                 pop     ebx
.text:00401293                 pop     ecx
.text:00401294                 pop     edx
```

In the case there is no VMware, it will jump to loc_4012A4

```assembly
.text:004012A4 loc_4012A4:                             ; DATA XREF: .rdata:stru_40BC20↓o
.text:004012A4 ;   __except(loc_40129E) // owned by 401273
.text:004012A4                 mov     esp, [ebp+ms_exc.old_esp]
.text:004012A7                 mov     [ebp+var_1C], 0
.text:004012AE                 mov     [ebp+ms_exc.registration.TryLevel], 0FFFFFFFEh
.text:004012B5                 mov     eax, [ebp+var_1C]
.text:004012B8                 jmp     short loc_4012C6
```

And jump to loc_4012C6

```assembly
.text:004012C6 loc_4012C6:                             ; CODE XREF: sub_401240+78↑j
.text:004012C6                 mov     ecx, [ebp+ms_exc.registration.Next]
.text:004012C9                 mov     large fs:0, ecx
.text:004012D0                 pop     ecx
.text:004012D1                 pop     edi
.text:004012D2                 pop     esi
.text:004012D3                 pop     ebx
.text:004012D4                 mov     esp, ebp
.text:004012D6                 pop     ebp
.text:004012D7                 retn
```

Therefore, the block where it set eax to 1 will not be used. 

To bypass this, change the comparison instruction, from jnz to jz.

![image](https://github.com/san601/CTF_Archive/assets/144963803/29bfde9d-2bb0-4351-b6b7-7c1b6c783cfd)

## Exception handler

```C
pbDebuggerPresent[2] = 1;
pbDebuggerPresent[5] = 1;
pbDebuggerPresent[4] = 1 / 0;
ms_exc.registration.TryLevel = -2;
printf("But detected Debugged.\n");
exit(1);
```

Clearly, the ```1 / 0``` will trigger divide by zero exception.

![image](https://github.com/san601/CTF_Archive/assets/144963803/7d19d537-093c-4e91-8ffa-0d5734f0b705)

```assembly
.text:004015B8 loc_4015B8:                             ; CODE XREF: _main+2B2↑j
.text:004015B8 mov     [ebp+var_88], 1
.text:004015C2 mov     [ebp+var_7C], 1
.text:004015C9 mov     [ebp+var_9C], 0
.text:004015C9
.text:004015D3 ;   __try { // __except at loc_4015F6
.text:004015D3 mov     [ebp+ms_exc.registration.TryLevel], 0
.text:004015DA mov     eax, [ebp+var_7C]
.text:004015DD cdq
.text:004015DE idiv    [ebp+var_9C]
.text:004015E4 mov     [ebp+var_80], eax
.text:004015E4 ;   } // starts at 4015D3
.text:004015E7 mov     [ebp+ms_exc.registration.TryLevel], -2
.text:004015EE jmp     short loc_40160A
.text:004015EE
```

First, it sets ```[ebp+var_88]``` to 1 and try to divide ```[ebp+var_9C]``` with 0. The program will jump to ```__except at loc_4015F6```

```assembly
.text:004015F6 loc_4015F6:                             ; DATA XREF: .rdata:stru_40BC40↓o
.text:004015F6 ;   __except(loc_4015F0) // owned by 4015D3
.text:004015F6 mov     esp, [ebp+ms_exc.old_esp]
.text:004015F9 mov     [ebp+var_88], 0
```

Here, it sets ```[ebp+var_88]``` to 0. 

At ```loc_40160A``` where the code ```printf("But detected Debugged.\n");``` is executed, it checks if ```[ebp+var_88]``` is equal to 1 or not. If not, there is no debugging process that currently interfere with the flow of the program. 

```assembly
.text:0040160A loc_40160A:                             ; CODE XREF: _main+2FE↑j
.text:0040160A cmp     [ebp+var_88], 1
.text:00401611 jnz     short loc_401627
.text:00401611
.text:00401613 push    offset szButdetectedDe          ; "But detected Debugged.\n"
.text:00401618 call    _printf
```

Just don't interfere with the flow of the program and it will run normally, even when using a debugger.

## Get the flag

![image](https://github.com/san601/CTF_Archive/assets/144963803/0dfaa201-2733-4bf6-8898-e6db101fe933)

The program will never go into left branch because of the condition being ```if (1 == 0)```. So just patch it to ```jz``` and we can run it with the key ```I have a pen.``` to get the flag.

![image](https://github.com/san601/CTF_Archive/assets/144963803/ce422a3f-2622-4f10-8cb1-f299e426bd52)
