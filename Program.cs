using System.Diagnostics;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Xml.Linq;

internal static class Program
{
    private static async Task Main(string[] args)
    {
        Console.WriteLine("Netmap - Nmap local network scanner");
        Console.WriteLine();

        var options = ScanOptions.Parse(args);

        Console.WriteLine($"Network range: {options.NetworkRange}");
        Console.WriteLine($"Scan ports:    {(string.IsNullOrWhiteSpace(options.Ports) ? "default" : options.Ports)}");
        Console.WriteLine($"Vuln scan:     {(options.DetectVulnerabilities ? "enabled" : "disabled")}");
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
                Console.WriteLine(options.DetectVulnerabilities
                    ? $"Scanning vulnerabilities on {host}"
                    : $"Scanning {host}");
                Console.WriteLine("==================================================");

                if (options.DetectVulnerabilities)
                    await RunVulnerabilityScanAsync(host, options.Ports);
                else
                    await RunStandardScanAsync(host, options.Ports);

                Console.WriteLine();
            }
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"Error: {ex.Message}");
            Environment.ExitCode = 1;
        }
    }

    private static void EnsureNmapIsAvailable()
    {
        var result = RunNmapAsync(new[] { "--version" }).GetAwaiter().GetResult();

        if (result.ExitCode != 0)
            throw new InvalidOperationException("Nmap was not found or could not be executed. Install Nmap and make sure it is available in PATH.");
    }

    private static async Task<IReadOnlyList<string>> DiscoverHostsAsync(string networkRange)
    {
        var result = await RunNmapAsync(new[] { "-sn", "-oX", "-", networkRange });

        if (result.ExitCode != 0)
            throw new InvalidOperationException($"Nmap discovery failed: {result.Error}");

        return ParseLiveHostsFromXml(result.Output);
    }

    private static async Task RunStandardScanAsync(string host, string? ports)
    {
        var result = await RunNmapAsync(BuildHostScanArguments(host, ports));

        Console.WriteLine(result.Output);
        WriteStderrIfPresent(result.Error);
    }

    private static async Task RunVulnerabilityScanAsync(string host, string? ports)
    {
        var result = await RunNmapAsync(BuildVulnerabilityScanArguments(host, ports));

        if (result.ExitCode != 0)
        {
            Console.WriteLine("Nmap vulnerability scan failed.");
            WriteStderrIfPresent(result.Error);
            return;
        }

        var findings = ParseVulnerabilityFindingsFromXml(result.Output)
            .Where(finding => finding.IpAddress == host)
            .ToList();

        PrintVulnerabilityFindings(host, findings);
        WriteStderrIfPresent(result.Error);
    }

    private static string[] BuildHostScanArguments(string host, string? ports)
    {
        var arguments = new List<string>
        {
            "-sV",
            "-Pn",
            "-T3",
            "--reason"
        };

        AddPortsArgument(arguments, ports);
        arguments.Add(host);

        return arguments.ToArray();
    }

    private static string[] BuildVulnerabilityScanArguments(string host, string? ports)
    {
        var arguments = new List<string>
        {
            "-sV",
            "-Pn",
            "-T3",
            "--reason",
            "--script",
            "vuln",
            "-oX",
            "-"
        };

        AddPortsArgument(arguments, ports);
        arguments.Add(host);

        return arguments.ToArray();
    }

    private static void AddPortsArgument(List<string> arguments, string? ports)
    {
        if (string.IsNullOrWhiteSpace(ports))
            return;

        arguments.Add("-p");
        arguments.Add(ports);
    }

    private static async Task<NmapResult> RunNmapAsync(IReadOnlyCollection<string> arguments)
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

    private static IReadOnlyList<string> ParseLiveHostsFromXml(string xml)
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

    private static IReadOnlyList<VulnerabilityFinding> ParseVulnerabilityFindingsFromXml(string xml)
    {
        var document = XDocument.Parse(xml);
        var findings = new List<VulnerabilityFinding>();

        foreach (var host in document.Descendants("host"))
        {
            var ipAddress = GetHostIpAddress(host);
            if (ipAddress is null)
                continue;

            foreach (var hostScript in host.Element("hostscript")?.Elements("script") ?? Enumerable.Empty<XElement>())
            {
                AddFindingIfRelevant(
                    findings,
                    ipAddress,
                    "host",
                    "host",
                    "host script",
                    hostScript);
            }

            foreach (var port in host.Descendants("port"))
            {
                var state = port.Element("state")?.Attribute("state")?.Value;
                if (!string.Equals(state, "open", StringComparison.OrdinalIgnoreCase))
                    continue;

                var protocol = port.Attribute("protocol")?.Value ?? "tcp";
                var portId = port.Attribute("portid")?.Value ?? "unknown";
                var service = FormatService(port.Element("service"));

                foreach (var script in port.Elements("script"))
                {
                    AddFindingIfRelevant(
                        findings,
                        ipAddress,
                        portId,
                        protocol,
                        service,
                        script);
                }
            }
        }

        return findings;
    }

    private static void AddFindingIfRelevant(
        List<VulnerabilityFinding> findings,
        string ipAddress,
        string portLabel,
        string protocol,
        string service,
        XElement script)
    {
        var scriptId = script.Attribute("id")?.Value ?? "unknown-script";
        var output = NormalizeOutput(script.Attribute("output")?.Value);
        var status = ClassifyVulnerabilityOutput(scriptId, output);

        if (status is null)
            return;

        findings.Add(new VulnerabilityFinding(
            ipAddress,
            portLabel,
            protocol,
            service,
            scriptId,
            status,
            output));
    }

    private static string? ClassifyVulnerabilityOutput(string scriptId, string output)
    {
        if (string.IsNullOrWhiteSpace(output))
            return null;

        var normalized = output.ToUpperInvariant();

        if (normalized.Contains("NOT VULNERABLE") ||
            normalized.Contains("NOT AFFECTED") ||
            normalized.Contains("NOT EXPLOITABLE") ||
            normalized.Contains("NO VULNERABILIT") ||
            normalized.Contains("COULDN'T FIND") ||
            normalized.Contains("COULD NOT FIND"))
        {
            return null;
        }

        if (normalized.Contains("STATE: VULNERABLE") ||
            normalized.Contains("VULNERABLE") ||
            normalized.Contains("EXPLOITABLE"))
        {
            return "VULNERABLE";
        }

        if (normalized.Contains("CVE-") ||
            scriptId.Contains("vuln", StringComparison.OrdinalIgnoreCase))
        {
            return "REVIEW";
        }

        return null;
    }

    private static void PrintVulnerabilityFindings(string host, IReadOnlyList<VulnerabilityFinding> findings)
    {
        var hostFindings = findings
            .OrderBy(finding => finding.PortLabel == "host" ? 0 : 1)
            .ThenBy(finding => ParsePortForOrdering(finding.PortLabel))
            .ThenBy(finding => finding.ScriptId)
            .ToList();

        if (hostFindings.Count == 0)
        {
            Console.WriteLine($"No vulnerability findings reported by Nmap vuln scripts for {host}.");
            return;
        }

        foreach (var portGroup in hostFindings.GroupBy(finding => new
        {
            finding.IpAddress,
            finding.PortLabel,
            finding.Protocol,
            finding.Service
        }))
        {
            Console.WriteLine($"{portGroup.Key.IpAddress} {portGroup.Key.Protocol}/{portGroup.Key.PortLabel} {portGroup.Key.Service}");

            foreach (var finding in portGroup)
            {
                Console.WriteLine($"  [{finding.Status}] {finding.ScriptId}");
                WriteIndented(finding.Output, "    ");
            }

            Console.WriteLine();
        }
    }

    private static string? GetHostIpAddress(XElement host)
    {
        return host
            .Elements("address")
            .Where(address => address.Attribute("addrtype")?.Value == "ipv4")
            .Select(address => address.Attribute("addr")?.Value)
            .FirstOrDefault(address => IPAddress.TryParse(address, out _));
    }

    private static string FormatService(XElement? service)
    {
        if (service is null)
            return "unknown service";

        var parts = new[]
            {
                service.Attribute("name")?.Value,
                service.Attribute("product")?.Value,
                service.Attribute("version")?.Value,
                service.Attribute("extrainfo")?.Value
            }
            .Where(value => !string.IsNullOrWhiteSpace(value));

        var serviceText = string.Join(" ", parts);
        return string.IsNullOrWhiteSpace(serviceText) ? "unknown service" : serviceText;
    }

    private static string NormalizeOutput(string? output)
    {
        return string.IsNullOrWhiteSpace(output)
            ? string.Empty
            : output.Replace("\r\n", "\n").Trim();
    }

    private static void WriteIndented(string text, string indentation)
    {
        foreach (var line in text.Split('\n'))
            Console.WriteLine($"{indentation}{line}");
    }

    private static void WriteStderrIfPresent(string error)
    {
        if (string.IsNullOrWhiteSpace(error))
            return;

        Console.WriteLine("Nmap stderr:");
        Console.WriteLine(error);
    }

    private static uint ParseIpForOrdering(string ip)
    {
        var bytes = IPAddress.Parse(ip).GetAddressBytes();
        return ((uint)bytes[0] << 24) |
               ((uint)bytes[1] << 16) |
               ((uint)bytes[2] << 8) |
               bytes[3];
    }

    private static int ParsePortForOrdering(string port)
    {
        return int.TryParse(port, out var value) ? value : 0;
    }

    private static string GetFirstLocalNetworkCidr()
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

    private static IPAddress GetNetworkAddress(IPAddress ip, IPAddress mask)
    {
        var ipBytes = ip.GetAddressBytes();
        var maskBytes = mask.GetAddressBytes();
        var networkBytes = new byte[ipBytes.Length];

        for (var i = 0; i < ipBytes.Length; i++)
            networkBytes[i] = (byte)(ipBytes[i] & maskBytes[i]);

        return new IPAddress(networkBytes);
    }

    private static int GetPrefixLength(IPAddress mask)
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

    private sealed record NmapResult(int ExitCode, string Output, string Error);

    private sealed record VulnerabilityFinding(
        string IpAddress,
        string PortLabel,
        string Protocol,
        string Service,
        string ScriptId,
        string Status,
        string Output);

    private sealed record ScanOptions(string NetworkRange, string? Ports, bool DetectVulnerabilities)
    {
        public static ScanOptions Parse(string[] args)
        {
            string? networkRange = null;
            string? ports = null;
            var detectVulnerabilities = false;

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

                    case "--vuln":
                    case "--vulnerability-scan":
                        detectVulnerabilities = true;
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
                ports,
                detectVulnerabilities);
        }

        private static void PrintHelpAndExit()
        {
            Console.WriteLine("Usage:");
            Console.WriteLine("  dotnet run");
            Console.WriteLine("  dotnet run -- --network 192.168.0.0/24");
            Console.WriteLine("  dotnet run -- --network 192.168.0.0/24 --ports 80,443,2020,8899,9080");
            Console.WriteLine("  dotnet run -- --network 192.168.0.0/24 --ports 80,443 --vuln");
            Environment.Exit(0);
        }
    }
}
