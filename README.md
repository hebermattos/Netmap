# Netmap

C#/.NET 8 console app that discovers live hosts on the local network using Nmap, runs vulnerability-focused checks, collects targeted validation evidence for open services, and sends the final report to a local Ollama model for defensive triage and remediation guidance.

## Requirements

- .NET 8 SDK
- Nmap installed and available in `PATH`
- Ollama running locally
- Default Ollama model installed: `qwen2.5-coder:3b`

Install the default model:

```bash
ollama pull qwen2.5-coder:3b
```

If Ollama has GPU issues on your machine, run it in CPU mode:

```bash
sudo systemctl stop ollama
OLLAMA_NO_GPU=1 ollama serve
```

## Usage

Automatically detect the first local IPv4 network, scan the discovered hosts, and send the report to Ollama:

```bash
dotnet run
```

Manually provide the network range:

```bash
dotnet run -- --network 192.168.0.0/24
```

Limit the scan to specific ports:

```bash
dotnet run -- --network 192.168.0.0/24 --ports 80,443,2020,8899,9080
```

Control how many hosts are analyzed in parallel:

```bash
dotnet run -- --network 192.168.0.0/24 --parallelism 5
```

Use another local Ollama model:

```bash
dotnet run -- --network 192.168.0.0/24 --ollama-model llama3.1
```

Use a custom Ollama URL:

```bash
dotnet run -- --network 192.168.0.0/24 --ollama-url http://localhost:11434 --ollama-model llama3.1
```

Disable Ollama for a scan:

```bash
dotnet run -- --network 192.168.0.0/24 --no-ollama
```

You can combine the options:

```bash
dotnet run -- --network 192.168.0.0/24 --ports 80,443,2020,8899,9080 --parallelism 3 --ollama-model llama3.1
```

You can also pass the network range as the first argument:

```bash
dotnet run -- 192.168.0.0/24
```

The default parallelism is `5`. Increase it carefully. Higher values run more Nmap processes at the same time and can make scans faster, but they also create more traffic and CPU usage.

The `--vuln` and `--vulnerability-scan` flags are still accepted for backward compatibility, but they are no longer required because this scan mode is always enabled.

## Ollama analysis

Ollama is enabled by default. Before starting the Nmap scan, Netmap checks:

- whether Ollama is reachable at the configured URL
- whether the configured model is installed locally

Default Ollama endpoint:

```text
http://localhost:11434
```

Default Ollama model:

```text
qwen2.5-coder:3b
```

If the Ollama preflight check fails, Netmap stops before starting the scan and prints the fix, such as:

```bash
ollama pull qwen2.5-coder:3b
```

or:

```bash
ollama serve
```

The Ollama prompt is intentionally defensive. It asks for:

- Executive summary
- Highest-risk hosts and services
- Likely exposure and business impact
- Safe validation checks
- Recommended remediation actions ordered by priority
- Follow-up evidence to collect

Large reports are truncated before being sent to Ollama to avoid oversized local prompts.

## Output

Netmap prints two main sections per host.

### Vulnerability findings

Findings are grouped by IP address, protocol, port, and detected service:

```text
IP protocol/port service
  [STATUS] script-id
    script output
```

Statuses:

- `VULNERABLE`: the scan output indicates a vulnerable or exploitable state.
- `REVIEW`: the scan returned CVE or vulnerability-related output that should be manually reviewed.

Negative results such as `not vulnerable` or `not affected` are suppressed to keep the report focused.

### Targeted validation evidence

After the vulnerability-focused scan, Netmap runs a second validation pass against the open TCP ports found for that host.

It uses service-oriented scripts for common protocols, including:

- TLS/SSL: certificate and cipher information
- HTTP/HTTPS: title, headers, and security headers
- SSH: supported algorithms
- SMB: protocol and security mode information
- FTP: service information and anonymous access indication

Validation evidence is printed as:

```text
Targeted validation evidence:
IP protocol/port service
  [EVIDENCE] script-id
    script output
```

This section is intended to help confirm service configuration and collect technical evidence without relying only on generic vulnerability output.

## Notes

Use this tool only on networks and devices where you have authorization. Vulnerability-focused scans can be slower and more intrusive than regular service discovery. Parallel scans can amplify network traffic, so start with a low `--parallelism` value on small or sensitive networks.
