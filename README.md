# Netmap

C#/.NET 8 console app that discovers live hosts on the local network using Nmap and then runs a scan against each discovered IP address.

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

## Flow

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

## Notes

Use this tool only on networks and devices where you have authorization.
