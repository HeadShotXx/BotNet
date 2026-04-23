using System;
using System.Linq;
using System.Text;
using System.Management;
using Microsoft.Win32;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.IO;

public static class SystemInfo
{
    public static string GetAll()
    {
        var sb = new StringBuilder();

        sb.AppendLine("===== SYSTEM INFO =====");
        sb.AppendLine($"Machine Name: {Environment.MachineName}");
        sb.AppendLine($"User Name: {Environment.UserName}");
        sb.AppendLine($"OS Version: {GetOS()}");
        sb.AppendLine($"Architecture: {(Environment.Is64BitOperatingSystem ? "64-bit" : "32-bit")}");
        sb.AppendLine($"Processor Count: {Environment.ProcessorCount}");
        sb.AppendLine($".NET Version: {Environment.Version}");

        sb.AppendLine("\n===== CPU =====");
        sb.AppendLine(GetCPU());

        sb.AppendLine("\n===== GPU =====");
        sb.AppendLine(GetGPU());

        sb.AppendLine("\n===== RAM =====");
        sb.AppendLine(GetRAM());

        sb.AppendLine("\n===== MOTHERBOARD =====");
        sb.AppendLine(GetMotherboard());

        sb.AppendLine("\n===== BIOS =====");
        sb.AppendLine(GetBIOS());

        sb.AppendLine("\n===== NETWORK =====");
        sb.AppendLine(GetNetworkInfo());

        sb.AppendLine("===== STORAGE =====");
        sb.AppendLine(GetStorageInfo());

        return sb.ToString();
    }

    private static string GetOS()
    {
        try
        {
            using (var key = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows NT\CurrentVersion"))
            {
                string name = key?.GetValue("ProductName")?.ToString() ?? "Windows";
                string ver = key?.GetValue("DisplayVersion")?.ToString() ?? "";
                string build = key?.GetValue("CurrentBuild")?.ToString() ?? "";
                string ubr = key?.GetValue("UBR")?.ToString() ?? "";
                return $"{name} {ver} (Build {build}.{ubr})".Trim();
            }
        }
        catch { return "Unknown"; }
    }

    private static string GetCPU()
    {
        try
        {
            using (var s = new ManagementObjectSearcher("select Name, NumberOfCores, MaxClockSpeed from Win32_Processor"))
            {
                foreach (var obj in s.Get())
                {
                    string name = obj["Name"]?.ToString().Trim() ?? "Unknown";
                    uint cores = Convert.ToUInt32(obj["NumberOfCores"] ?? 0);
                    uint speed = Convert.ToUInt32(obj["MaxClockSpeed"] ?? 0);
                    return $"{name} | Cores: {cores} | Max Speed: {speed} MHz";
                }
            }
        }
        catch { }
        return "Unknown CPU";
    }

    private static string GetGPU()
    {
        try
        {
            var sb = new StringBuilder();
            using (var s = new ManagementObjectSearcher("select Name, AdapterRAM from Win32_VideoController"))
            {
                foreach (var obj in s.Get())
                {
                    string name = obj["Name"]?.ToString() ?? "Unknown";
                    UInt64 ram = Convert.ToUInt64(obj["AdapterRAM"] ?? 0);
                    double ramGB = ram / 1024.0 / 1024.0 / 1024.0;
                    sb.AppendLine($"{name} | VRAM: {ramGB:F2} GB");
                }
            }
            return sb.Length > 0 ? sb.ToString().TrimEnd() : "No GPU found";
        }
        catch { return "Unknown GPU"; }
    }

    private static string GetRAM()
    {
        try
        {
            using (var s = new ManagementObjectSearcher("select TotalPhysicalMemory from Win32_ComputerSystem"))
            {
                foreach (var obj in s.Get())
                {
                    double ram = Convert.ToDouble(obj["TotalPhysicalMemory"]);
                    return $"{ram / 1024 / 1024 / 1024:F2} GB";
                }
            }
        }
        catch { }
        return "Unknown";
    }

    private static string GetMotherboard()
    {
        try
        {
            using (var s = new ManagementObjectSearcher("select Product, Manufacturer from Win32_BaseBoard"))
            {
                foreach (var obj in s.Get())
                {
                    string manufacturer = obj["Manufacturer"]?.ToString() ?? "";
                    string product = obj["Product"]?.ToString() ?? "";
                    return $"{manufacturer} {product}".Trim();
                }
            }
        }
        catch { }
        return "Unknown";
    }

    private static string GetBIOS()
    {
        try
        {
            using (var s = new ManagementObjectSearcher("select Manufacturer, SMBIOSBIOSVersion, ReleaseDate from Win32_BIOS"))
            {
                foreach (var obj in s.Get())
                {
                    string mfr = obj["Manufacturer"]?.ToString() ?? "";
                    string ver = obj["SMBIOSBIOSVersion"]?.ToString() ?? "";
                    string date = obj["ReleaseDate"]?.ToString()?.Substring(0, 8) ?? "";
                    if (date.Length == 8)
                        date = $"{date.Substring(0, 4)}-{date.Substring(4, 2)}-{date.Substring(6, 2)}";
                    return $"{mfr} | Version: {ver} | Date: {date}".Trim();
                }
            }
        }
        catch { }
        return "Unknown";
    }

    private static string GetNetworkInfo()
    {
        var sb = new StringBuilder();
        foreach (NetworkInterface ni in NetworkInterface.GetAllNetworkInterfaces())
        {
            if (ni.OperationalStatus != OperationalStatus.Up) continue;

            sb.AppendLine($"Adapter: {ni.Name}");
            sb.AppendLine($"  Type: {ni.NetworkInterfaceType}");
            sb.AppendLine($"  Speed: {(ni.Speed / 1_000_000)} Mbps");
            sb.AppendLine($"  MAC: {ni.GetPhysicalAddress()}");

            var ip = ni.GetIPProperties();
            foreach (var addr in ip.UnicastAddresses)
            {
                if (addr.Address.AddressFamily == AddressFamily.InterNetwork)
                    sb.AppendLine($"  IPv4: {addr.Address} | Mask: {addr.IPv4Mask}");
                else if (addr.Address.AddressFamily == AddressFamily.InterNetworkV6 && !addr.Address.IsIPv6LinkLocal)
                    sb.AppendLine($"  IPv6: {addr.Address}");
            }

            var gw = ip.GatewayAddresses.FirstOrDefault();
            if (gw != null) sb.AppendLine($"  Gateway: {gw.Address}");

            if (ip.DnsAddresses.Count > 0)
                sb.AppendLine($"  DNS: {string.Join(", ", ip.DnsAddresses)}");

            sb.AppendLine();
        }
        return sb.Length > 0 ? sb.ToString().TrimEnd() : "No active network adapters";
    }

    private static string GetStorageInfo()
    {
        var sb = new StringBuilder();
        foreach (DriveInfo d in DriveInfo.GetDrives())
        {
            if (!d.IsReady) continue;

            double total = d.TotalSize / 1024.0 / 1024.0 / 1024.0;
            double free = d.TotalFreeSpace / 1024.0 / 1024.0 / 1024.0;
            double used = total - free;

            sb.AppendLine($"{d.Name} [{d.VolumeLabel}] - {d.DriveFormat} ({d.DriveType})");
            sb.AppendLine($"  Total: {total:F2} GB | Used: {used:F2} GB ({(used / total) * 100:F1}%) | Free: {free:F2} GB");
            sb.AppendLine();
        }
        return sb.ToString().TrimEnd();
    }
}