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

![image](https://github.com/san601/CTF_Archive/assets/144963803/a8c3decb-32b5-4d02-bba3-13a7d49b4004)

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
