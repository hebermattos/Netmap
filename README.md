# Netmap

C#/.NET 8 console app that discovers live hosts on the local network using Nmap, runs vulnerability-focused checks, and then collects targeted validation evidence for open services.

## Requirements

- .NET 8 SDK
- Nmap installed and available in `PATH`

## Usage

Automatically detect the first local IPv4 network and scan the discovered hosts:

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

You can also pass the network range as the first argument:

```bash
dotnet run -- 192.168.0.0/24
```

The `--vuln` and `--vulnerability-scan` flags are still accepted for backward compatibility, but they are no longer required because this scan mode is always enabled.

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

Use this tool only on networks and devices where you have authorization. Vulnerability-focused scans can be slower and more intrusive than regular service discovery.
