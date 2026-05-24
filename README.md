# Netmap

C#/.NET 8 console app that discovers live hosts on the local network using Nmap and then runs either a standard service scan or a vulnerability scan against each discovered IP address.

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

Limit the standard scan to specific ports:

```bash
dotnet run -- --network 192.168.0.0/24 --ports 80,443,2020,8899,9080
```

Run vulnerability detection by IP and port using Nmap `vuln` scripts:

```bash
dotnet run -- --network 192.168.0.0/24 --ports 80,443,2020,8899,9080 --vuln
```

You can also pass the network range as the first argument:

```bash
dotnet run -- 192.168.0.0/24
```

## Standard scan flow

1. Runs host discovery with:

```bash
nmap -sn -oX - <network>
```

2. Reads the `up` hosts from the XML returned by Nmap.
3. For each discovered IP address, runs:

```bash
nmap -sV -Pn -T3 --reason <ip>
```

With specific ports:

```bash
nmap -sV -Pn -T3 --reason -p 80,443 <ip>
```

## Vulnerability scan flow

When `--vuln` or `--vulnerability-scan` is provided, Netmap runs this command for each discovered IP address:

```bash
nmap -sV -Pn -T3 --reason --script vuln -oX - <ip>
```

With specific ports:

```bash
nmap -sV -Pn -T3 --reason --script vuln -oX - -p 80,443 <ip>
```

The application parses the XML output and prints findings grouped by:

```text
IP protocol/port service
  [STATUS] script-id
    script output
```

Statuses:

- `VULNERABLE`: the script output indicates a vulnerable or exploitable state.
- `REVIEW`: the script returned CVE or vulnerability-related output that should be manually reviewed.

Outputs that clearly state `not vulnerable`, `not affected`, or similar negative results are suppressed to keep the report focused.

## Notes

Use this tool only on networks and devices where you have authorization. Nmap `vuln` scripts can be slower and more intrusive than a regular service scan.
