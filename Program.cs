using System.Collections.Concurrent;
using System.Diagnostics;
using System.Net;
using System.Net.Http.Json;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Text;
using System.Text.Json.Serialization;
using System.Xml.Linq;

internal static class Program
{
    private const int DefaultParallelism = 5;
    private const int MaxOllamaReportCharacters = 60_000;
    private const string DefaultOllamaUrl = "http://localhost:11434";
    private const string DefaultOllamaModel = "qwen2.5-coder:3b";

    private static readonly string[] TargetedValidationScripts =
    [
        "ssl-cert",
        "ssl-enum-ciphers",
        "http-title",
        "http-headers",
        "http-security-headers",
        "ssh2-enum-algos",
        "smb-protocols",
        "smb2-security-mode",
        "ftp-anon",
        "ftp-syst"
    ];

    private static async Task Main(string[] args)
    {
        Console.WriteLine("Netmap - Nmap local network vulnerability scanner");
        Console.WriteLine();

        var options = ScanOptions.Parse(args);

        Console.WriteLine($"Network range: {options.NetworkRange}");
        Console.WriteLine($"Scan ports:    {(string.IsNullOrWhiteSpace(options.Ports) ? "default" : options.Ports)}");
        Console.WriteLine($"Parallelism:   {options.Parallelism}");
        Console.WriteLine($"Ollama:        {(options.HasOllamaAnalysis ? $"enabled ({options.OllamaModel})" : "disabled")}");
        Console.WriteLine("Vuln scan:     enabled");
        Console.WriteLine("Validation:    enabled");
        Console.WriteLine();

        try
        {
            if (options.HasOllamaAnalysis)
                await EnsureOllamaIsAvailableAsync(options);

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
            Console.WriteLine($"Running host analysis with up to {options.Parallelism} parallel Nmap worker(s)...");
            Console.WriteLine();

            var consoleLock = new object();
            var hostReports = new ConcurrentDictionary<string, string>();
            var parallelOptions = new ParallelOptions
            {
                MaxDegreeOfParallelism = options.Parallelism
            };

            await Parallel.ForEachAsync(hosts, parallelOptions, async (host, _) =>
            {
                var report = await ScanHostAsync(host, options.Ports);
                hostReports[host] = report;

                lock (consoleLock)
                {
                    Console.Write(report);
                }
            });

            if (options.HasOllamaAnalysis)
            {
                var fullReport = string.Join(
                    Environment.NewLine,
                    hosts.Select(host => hostReports.TryGetValue(host, out var report) ? report : string.Empty));

                await RunOllamaDefensiveAnalysisAsync(options, fullReport);
            }
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"Error: {ex.Message}");
            Environment.ExitCode = 1;
        }
    }

    private static async Task<string> ScanHostAsync(string host, string? ports)
    {
        using var writer = new StringWriter();

        writer.WriteLine("==================================================");
        writer.WriteLine($"Scanning vulnerabilities on {host}");
        writer.WriteLine("==================================================");

        var openPorts = await RunVulnerabilityScanAsync(host, ports, writer);
        await RunTargetedValidationAsync(host, openPorts, writer);

        writer.WriteLine();

        return writer.ToString();
    }

    private static async Task EnsureOllamaIsAvailableAsync(ScanOptions options)
    {
        Console.WriteLine($"Checking Ollama at {options.OllamaUrl}...");

        try
        {
            using var httpClient = CreateOllamaHttpClient(options, TimeSpan.FromSeconds(10));
            using var response = await httpClient.GetAsync("/api/tags");
            var responseText = await response.Content.ReadAsStringAsync();

            if (!response.IsSuccessStatusCode)
            {
                throw new InvalidOperationException(
                    $"Ollama is reachable, but /api/tags returned HTTP {(int)response.StatusCode}: {responseText}");
            }

            var tags = System.Text.Json.JsonSerializer.Deserialize<OllamaTagsResponse>(responseText);
            var modelFound = tags?.Models?.Any(model =>
                string.Equals(model.Name, options.OllamaModel, StringComparison.OrdinalIgnoreCase) ||
                string.Equals(model.Model, options.OllamaModel, StringComparison.OrdinalIgnoreCase)) == true;

            if (!modelFound)
            {
                throw new InvalidOperationException(
                    $"Ollama is available, but model '{options.OllamaModel}' was not found. Run: ollama pull {options.OllamaModel}");
            }

            Console.WriteLine($"Ollama is available and model '{options.OllamaModel}' is installed.");
            Console.WriteLine();
        }
        catch (HttpRequestException ex)
        {
            throw new InvalidOperationException(
                $"Ollama is enabled but not reachable at {options.OllamaUrl}. Start it with 'ollama serve' or disable it with --no-ollama.",
                ex);
        }
        catch (TaskCanceledException ex)
        {
            throw new InvalidOperationException(
                $"Ollama availability check timed out at {options.OllamaUrl}. Disable it with --no-ollama if needed.",
                ex);
        }
    }

    private static async Task RunOllamaDefensiveAnalysisAsync(ScanOptions options, string report)
    {
        Console.WriteLine("==================================================");
        Console.WriteLine("Local Ollama defensive analysis");
        Console.WriteLine("==================================================");

        if (string.IsNullOrWhiteSpace(report))
        {
            Console.WriteLine("No scan report content available for Ollama analysis.");
            return;
        }

        var prompt = BuildDefensiveAnalysisPrompt(report);
        var request = new OllamaGenerateRequest(options.OllamaModel, prompt, Stream: false);

        try
        {
            using var httpClient = CreateOllamaHttpClient(options, TimeSpan.FromMinutes(10));
            using var response = await httpClient.PostAsJsonAsync("/api/generate", request);
            var responseText = await response.Content.ReadAsStringAsync();

            if (!response.IsSuccessStatusCode)
            {
                Console.WriteLine($"Ollama request failed with HTTP {(int)response.StatusCode}.");
                Console.WriteLine(responseText);
                return;
            }

            var ollamaResponse = System.Text.Json.JsonSerializer.Deserialize<OllamaGenerateResponse>(responseText);

            if (string.IsNullOrWhiteSpace(ollamaResponse?.Response))
            {
                Console.WriteLine("Ollama returned an empty response.");
                return;
            }

            Console.WriteLine(ollamaResponse.Response.Trim());
        }
        catch (HttpRequestException ex)
        {
            Console.WriteLine($"Could not connect to Ollama at {options.OllamaUrl}: {ex.Message}");
        }
        catch (TaskCanceledException ex)
        {
            Console.WriteLine($"Ollama analysis timed out: {ex.Message}");
        }
    }

    private static HttpClient CreateOllamaHttpClient(ScanOptions options, TimeSpan timeout)
    {
        return new HttpClient
        {
            BaseAddress = new Uri(options.OllamaUrl),
            Timeout = timeout
        };
    }

    private static string BuildDefensiveAnalysisPrompt(string report)
    {
        var truncatedReport = TruncateReportForPrompt(report);
        var prompt = new StringBuilder();

        prompt.AppendLine("You are a defensive security analyst reviewing an authorized internal network scan.");
        prompt.AppendLine("Keep the response focused on triage, risk, evidence, validation, hardening, patching, and monitoring.");
        prompt.AppendLine("Return:");
        prompt.AppendLine("1. Executive summary");
        prompt.AppendLine("2. Highest-risk hosts and services");
        prompt.AppendLine("3. Likely exposure and business impact");
        prompt.AppendLine("4. Safe validation checks");
        prompt.AppendLine("5. Recommended remediation actions, ordered by priority");
        prompt.AppendLine("6. Follow-up evidence to collect");
        prompt.AppendLine();
        prompt.AppendLine("Nmap report:");
        prompt.AppendLine("```text");
        prompt.AppendLine(truncatedReport);
        prompt.AppendLine("```");

        return prompt.ToString();
    }

    private static string TruncateReportForPrompt(string report)
    {
        if (report.Length <= MaxOllamaReportCharacters)
            return report;

        return report[..MaxOllamaReportCharacters] +
               Environment.NewLine +
               "[Report truncated before sending to Ollama because it exceeded the local prompt size limit.]";
    }

    private static void EnsureNmapIsAvailable()
    {
        var result = RunNmapAsync(["--version"]).GetAwaiter().GetResult();

        if (result.ExitCode != 0)
            throw new InvalidOperationException("Nmap was not found or could not be executed. Install Nmap and make sure it is available in PATH.");
    }

    private static async Task<IReadOnlyList<string>> DiscoverHostsAsync(string networkRange)
    {
        var result = await RunNmapAsync(["-sn", "-oX", "-", networkRange]);

        if (result.ExitCode != 0)
            throw new InvalidOperationException($"Nmap discovery failed: {result.Error}");

        return ParseLiveHostsFromXml(result.Output);
    }

    private static async Task<IReadOnlyList<OpenPortInfo>> RunVulnerabilityScanAsync(string host, string? ports, TextWriter writer)
    {
        var result = await RunNmapAsync(BuildVulnerabilityScanArguments(host, ports));

        if (result.ExitCode != 0)
        {
            writer.WriteLine("Nmap vulnerability scan failed.");
            WriteStderrIfPresent(result.Error, writer);
            return [];
        }

        var findings = ParseVulnerabilityFindingsFromXml(result.Output)
            .Where(finding => finding.IpAddress == host)
            .ToList();

        var openPorts = ParseOpenPortsFromXml(result.Output)
            .Where(port => port.IpAddress == host)
            .ToList();

        PrintVulnerabilityFindings(host, findings, writer);
        WriteStderrIfPresent(result.Error, writer);

        return openPorts;
    }

    private static async Task RunTargetedValidationAsync(string host, IReadOnlyList<OpenPortInfo> openPorts, TextWriter writer)
    {
        writer.WriteLine("Targeted validation evidence:");

        if (openPorts.Count == 0)
        {
            writer.WriteLine($"  No open ports available for targeted validation on {host}.");
            return;
        }

        var result = await RunNmapAsync(BuildTargetedValidationArguments(host, openPorts));

        if (result.ExitCode != 0)
        {
            writer.WriteLine("  Nmap targeted validation failed.");
            WriteStderrIfPresent(result.Error, writer);
            return;
        }

        var evidence = ParseValidationEvidenceFromXml(result.Output)
            .Where(item => item.IpAddress == host)
            .ToList();

        PrintValidationEvidence(host, evidence, writer);
        WriteStderrIfPresent(result.Error, writer);
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

    private static string[] BuildTargetedValidationArguments(string host, IReadOnlyList<OpenPortInfo> openPorts)
    {
        var ports = string.Join(",", openPorts
            .Where(port => string.Equals(port.Protocol, "tcp", StringComparison.OrdinalIgnoreCase))
            .Select(port => port.PortLabel)
            .Where(port => int.TryParse(port, out _))
            .Distinct()
            .OrderBy(ParsePortForOrdering));

        var arguments = new List<string>
        {
            "-sV",
            "-Pn",
            "-T3",
            "--reason",
            "--script",
            string.Join(",", TargetedValidationScripts),
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

    private static IReadOnlyList<OpenPortInfo> ParseOpenPortsFromXml(string xml)
    {
        var document = XDocument.Parse(xml);
        var openPorts = new List<OpenPortInfo>();

        foreach (var host in document.Descendants("host"))
        {
            var ipAddress = GetHostIpAddress(host);
            if (ipAddress is null)
                continue;

            foreach (var port in host.Descendants("port"))
            {
                var state = port.Element("state")?.Attribute("state")?.Value;
                if (!string.Equals(state, "open", StringComparison.OrdinalIgnoreCase))
                    continue;

                openPorts.Add(new OpenPortInfo(
                    ipAddress,
                    port.Attribute("portid")?.Value ?? "unknown",
                    port.Attribute("protocol")?.Value ?? "tcp",
                    FormatService(port.Element("service"))));
            }
        }

        return openPorts;
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

    private static IReadOnlyList<ValidationEvidence> ParseValidationEvidenceFromXml(string xml)
    {
        var document = XDocument.Parse(xml);
        var evidence = new List<ValidationEvidence>();

        foreach (var host in document.Descendants("host"))
        {
            var ipAddress = GetHostIpAddress(host);
            if (ipAddress is null)
                continue;

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
                    var scriptId = script.Attribute("id")?.Value ?? "unknown-script";
                    var output = NormalizeOutput(script.Attribute("output")?.Value);

                    if (string.IsNullOrWhiteSpace(output))
                        continue;

                    evidence.Add(new ValidationEvidence(
                        ipAddress,
                        portId,
                        protocol,
                        service,
                        scriptId,
                        output));
                }
            }
        }

        return evidence;
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

    private static void PrintVulnerabilityFindings(string host, IReadOnlyList<VulnerabilityFinding> findings, TextWriter writer)
    {
        var hostFindings = findings
            .OrderBy(finding => finding.PortLabel == "host" ? 0 : 1)
            .ThenBy(finding => ParsePortForOrdering(finding.PortLabel))
            .ThenBy(finding => finding.ScriptId)
            .ToList();

        if (hostFindings.Count == 0)
        {
            writer.WriteLine($"No vulnerability findings reported by Nmap vuln scripts for {host}.");
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
            writer.WriteLine($"{portGroup.Key.IpAddress} {portGroup.Key.Protocol}/{portGroup.Key.PortLabel} {portGroup.Key.Service}");

            foreach (var finding in portGroup)
            {
                writer.WriteLine($"  [{finding.Status}] {finding.ScriptId}");
                WriteIndented(finding.Output, "    ", writer);
            }

            writer.WriteLine();
        }
    }

    private static void PrintValidationEvidence(string host, IReadOnlyList<ValidationEvidence> evidence, TextWriter writer)
    {
        var hostEvidence = evidence
            .OrderBy(item => ParsePortForOrdering(item.PortLabel))
            .ThenBy(item => item.ScriptId)
            .ToList();

        if (hostEvidence.Count == 0)
        {
            writer.WriteLine($"  No targeted validation evidence reported for {host}.");
            return;
        }

        foreach (var portGroup in hostEvidence.GroupBy(item => new
        {
            item.IpAddress,
            item.PortLabel,
            item.Protocol,
            item.Service
        }))
        {
            writer.WriteLine($"{portGroup.Key.IpAddress} {portGroup.Key.Protocol}/{portGroup.Key.PortLabel} {portGroup.Key.Service}");

            foreach (var item in portGroup)
            {
                writer.WriteLine($"  [EVIDENCE] {item.ScriptId}");
                WriteIndented(item.Output, "    ", writer);
            }

            writer.WriteLine();
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

    private static void WriteIndented(string text, string indentation, TextWriter writer)
    {
        foreach (var line in text.Split('\n'))
            writer.WriteLine($"{indentation}{line}");
    }

    private static void WriteStderrIfPresent(string error, TextWriter writer)
    {
        if (string.IsNullOrWhiteSpace(error))
            return;

        writer.WriteLine("Nmap stderr:");
        writer.WriteLine(error);
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

    private sealed record OpenPortInfo(
        string IpAddress,
        string PortLabel,
        string Protocol,
        string Service);

    private sealed record VulnerabilityFinding(
        string IpAddress,
        string PortLabel,
        string Protocol,
        string Service,
        string ScriptId,
        string Status,
        string Output);

    private sealed record ValidationEvidence(
        string IpAddress,
        string PortLabel,
        string Protocol,
        string Service,
        string ScriptId,
        string Output);

    private sealed record OllamaGenerateRequest(
        [property: JsonPropertyName("model")] string Model,
        [property: JsonPropertyName("prompt")] string Prompt,
        [property: JsonPropertyName("stream")] bool Stream);

    private sealed record OllamaGenerateResponse(
        [property: JsonPropertyName("response")] string? Response);

    private sealed record OllamaTagsResponse(
        [property: JsonPropertyName("models")] IReadOnlyList<OllamaModelInfo>? Models);

    private sealed record OllamaModelInfo(
        [property: JsonPropertyName("name")] string? Name,
        [property: JsonPropertyName("model")] string? Model);

    private sealed record ScanOptions(
        string NetworkRange,
        string? Ports,
        int Parallelism,
        bool OllamaEnabled,
        string OllamaModel,
        string OllamaUrl)
    {
        public bool HasOllamaAnalysis => OllamaEnabled;

        public static ScanOptions Parse(string[] args)
        {
            string? networkRange = null;
            string? ports = null;
            var ollamaEnabled = true;
            var ollamaModel = DefaultOllamaModel;
            var ollamaUrl = DefaultOllamaUrl;
            var parallelism = DefaultParallelism;

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

                    case "--parallelism" when i + 1 < args.Length:
                        parallelism = ParseParallelism(args[++i]);
                        break;

                    case "--ollama-model" when i + 1 < args.Length:
                        ollamaModel = args[++i];
                        ollamaEnabled = true;
                        break;

                    case "--ollama-url" when i + 1 < args.Length:
                        ollamaUrl = NormalizeOllamaUrl(args[++i]);
                        break;

                    case "--no-ollama":
                        ollamaEnabled = false;
                        break;

                    case "--vuln":
                    case "--vulnerability-scan":
                        // Kept for backward compatibility. Vulnerability scanning is always enabled.
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
                parallelism,
                ollamaEnabled,
                ollamaModel,
                ollamaUrl);
        }

        private static int ParseParallelism(string value)
        {
            if (int.TryParse(value, out var parallelism) && parallelism > 0)
                return parallelism;

            throw new ArgumentException("The --parallelism value must be a positive integer.");
        }

        private static string NormalizeOllamaUrl(string value)
        {
            if (!Uri.TryCreate(value, UriKind.Absolute, out var uri))
                throw new ArgumentException("The --ollama-url value must be an absolute URL, for example http://localhost:11434.");

            return uri.ToString().TrimEnd('/');
        }

        private static void PrintHelpAndExit()
        {
            Console.WriteLine("Usage:");
            Console.WriteLine("  dotnet run");
            Console.WriteLine("  dotnet run -- --network 192.168.0.0/24");
            Console.WriteLine("  dotnet run -- --network 192.168.0.0/24 --ports 80,443,2020,8899,9080");
            Console.WriteLine("  dotnet run -- --network 192.168.0.0/24 --parallelism 5");
            Console.WriteLine("  dotnet run -- --network 192.168.0.0/24 --ollama-model llama3.1");
            Console.WriteLine("  dotnet run -- --network 192.168.0.0/24 --ollama-url http://localhost:11434 --ollama-model llama3.1");
            Console.WriteLine("  dotnet run -- --network 192.168.0.0/24 --no-ollama");
            Environment.Exit(0);
        }
    }
}
