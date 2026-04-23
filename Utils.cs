using System;
using System.IO;
using System.IO.Compression;
using System.Text;

public static class Utils
{
    public static byte[] CreateZipInMemory(string content)
    {
        using (var ms = new MemoryStream())
        {
            using (var archive = new ZipArchive(ms, ZipArchiveMode.Create, true))
            {
                var entry = archive.CreateEntry("system_info.txt");

                using (var entryStream = entry.Open())
                using (var writer = new StreamWriter(entryStream, Encoding.UTF8))
                {
                    writer.Write(content);
                }
            }

            return ms.ToArray();
        }
    }
}