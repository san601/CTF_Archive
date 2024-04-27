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
