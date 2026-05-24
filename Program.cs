using System.Diagnostics;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Xml.Linq;

Console.WriteLine("Netmap - Nmap local network scanner");
Console.WriteLine();

var options = ScanOptions.Parse(args);

Console.WriteLine($"Network range: {options.NetworkRange}");
Console.WriteLine($"Scan ports:    {(string.IsNullOrWhiteSpace(options.Ports) ? "default" : options.Ports)}");
Console.WriteLine();

try
{
    EnsureNmapIsAvailable();

    Console.WriteLine("Discovering live hosts...");
    var hosts = await DiscoverHostsAsync(options.NetworkRange);

    if (hosts.Count == 0)
    {
        Console.WriteLine("No live hosts found.");
        return;
    }

    Console.WriteLine($"Found {hosts.Count} host(s):");
    foreach (var host in hosts)
        Console.WriteLine($" - {host}");

    Console.WriteLine();

    foreach (var host in hosts)
    {
        Console.WriteLine("==================================================");
        Console.WriteLine($"Scanning {host}");
        Console.WriteLine("==================================================");

        var scanArguments = BuildHostScanArguments(host, options.Ports);
        var result = await RunNmapAsync(scanArguments);

        Console.WriteLine(result.Output);

        if (!string.IsNullOrWhiteSpace(result.Error))
        {
            Console.WriteLine("Nmap stderr:");
            Console.WriteLine(result.Error);
        }
    }
}
catch (Exception ex)
{
    Console.Error.WriteLine($"Error: {ex.Message}");
    Environment.ExitCode = 1;
}

static void EnsureNmapIsAvailable()
{
    var result = RunNmapAsync(["--version"]).GetAwaiter().GetResult();

    if (result.ExitCode != 0)
        throw new InvalidOperationException("Nmap was not found or could not be executed. Install Nmap and make sure it is available in PATH.");
}

static async Task<IReadOnlyList<string>> DiscoverHostsAsync(string networkRange)
{
    var result = await RunNmapAsync(["-sn", "-oX", "-", networkRange]);

    if (result.ExitCode != 0)
        throw new InvalidOperationException($"Nmap discovery failed: {result.Error}");

    return ParseLiveHostsFromXml(result.Output);
}

static string[] BuildHostScanArguments(string host, string? ports)
{
    var arguments = new List<string>
    {
        "-sV",
        "-Pn",
        "-T3",
        "--reason"
    };

    if (!string.IsNullOrWhiteSpace(ports))
    {
        arguments.Add("-p");
        arguments.Add(ports);
    }

    arguments.Add(host);
    return [.. arguments];
}

static async Task<NmapResult> RunNmapAsync(IReadOnlyCollection<string> arguments)
{
    var startInfo = new ProcessStartInfo
    {
        FileName = "nmap",
        RedirectStandardOutput = true,
        RedirectStandardError = true,
        UseShellExecute = false,
        CreateNoWindow = true
    };

    foreach (var argument in arguments)
        startInfo.ArgumentList.Add(argument);

    using var process = new Process { StartInfo = startInfo };

    process.Start();

    var outputTask = process.StandardOutput.ReadToEndAsync();
    var errorTask = process.StandardError.ReadToEndAsync();

    await process.WaitForExitAsync();

    return new NmapResult(
        process.ExitCode,
        await outputTask,
        await errorTask);
}

static IReadOnlyList<string> ParseLiveHostsFromXml(string xml)
{
    var document = XDocument.Parse(xml);

    return document
        .Descendants("host")
        .Where(host => host.Element("status")?.Attribute("state")?.Value == "up")
        .SelectMany(host => host.Elements("address"))
        .Where(address => address.Attribute("addrtype")?.Value == "ipv4")
        .Select(address => address.Attribute("addr")?.Value)
        .Where(address => IPAddress.TryParse(address, out _))
        .Select(address => address!)
        .Distinct()
        .OrderBy(ParseIpForOrdering)
        .ToList();
}

static uint ParseIpForOrdering(string ip)
{
    var bytes = IPAddress.Parse(ip).GetAddressBytes();
    return ((uint)bytes[0] << 24) |
           ((uint)bytes[1] << 16) |
           ((uint)bytes[2] << 8) |
           bytes[3];
}

static string GetFirstLocalNetworkCidr()
{
    var interfaces = NetworkInterface.GetAllNetworkInterfaces()
        .Where(networkInterface =>
            networkInterface.OperationalStatus == OperationalStatus.Up &&
            networkInterface.NetworkInterfaceType != NetworkInterfaceType.Loopback &&
            networkInterface.NetworkInterfaceType != NetworkInterfaceType.Tunnel);

    foreach (var networkInterface in interfaces)
    {
        foreach (var address in networkInterface.GetIPProperties().UnicastAddresses)
        {
            if (address.Address.AddressFamily != AddressFamily.InterNetwork)
                continue;

            if (address.IPv4Mask is null)
                continue;

            var network = GetNetworkAddress(address.Address, address.IPv4Mask);
            var prefix = GetPrefixLength(address.IPv4Mask);

            return $"{network}/{prefix}";
        }
    }

    throw new InvalidOperationException("Could not detect a local IPv4 network. Pass one manually, for example: dotnet run -- --network 192.168.0.0/24");
}

static IPAddress GetNetworkAddress(IPAddress ip, IPAddress mask)
{
    var ipBytes = ip.GetAddressBytes();
    var maskBytes = mask.GetAddressBytes();
    var networkBytes = new byte[ipBytes.Length];

    for (var i = 0; i < ipBytes.Length; i++)
        networkBytes[i] = (byte)(ipBytes[i] & maskBytes[i]);

    return new IPAddress(networkBytes);
}

static int GetPrefixLength(IPAddress mask)
{
    var prefix = 0;

    foreach (var value in mask.GetAddressBytes())
    {
        var current = value;

        while (current > 0)
        {
            prefix += current & 1;
            current >>= 1;
        }
    }

    return prefix;
}

internal sealed record NmapResult(int ExitCode, string Output, string Error);

internal sealed record ScanOptions(string NetworkRange, string? Ports)
{
    public static ScanOptions Parse(string[] args)
    {
        string? networkRange = null;
        string? ports = null;

        for (var i = 0; i < args.Length; i++)
        {
            switch (args[i])
            {
                case "--network" when i + 1 < args.Length:
                    networkRange = args[++i];
                    break;

                case "--ports" when i + 1 < args.Length:
                    ports = args[++i];
                    break;

                case "-h":
                case "--help":
                    PrintHelpAndExit();
                    break;

                default:
                    if (networkRange is null && !args[i].StartsWith('-'))
                        networkRange = args[i];
                    break;
            }
        }

        return new ScanOptions(
            networkRange ?? GetFirstLocalNetworkCidr(),
            ports);
    }

    private static void PrintHelpAndExit()
    {
        Console.WriteLine("Usage:");
        Console.WriteLine("  dotnet run");
        Console.WriteLine("  dotnet run -- --network 192.168.0.0/24");
        Console.WriteLine("  dotnet run -- --network 192.168.0.0/24 --ports 80,443,2020,8899,9080");
        Environment.Exit(0);
    }
}
