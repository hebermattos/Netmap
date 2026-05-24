# Netmap

Console app em C#/.NET 8 para descobrir hosts ativos na rede local usando Nmap e executar um scan em cada IP encontrado.

## Requisitos

- .NET 8 SDK
- Nmap instalado e disponível no `PATH`

## Uso

Detectar automaticamente a primeira rede IPv4 local e escanear os hosts encontrados:

```bash
dotnet run
```

Informar a rede manualmente:

```bash
dotnet run -- --network 192.168.0.0/24
```

Limitar o scan a portas específicas:

```bash
dotnet run -- --network 192.168.0.0/24 --ports 80,443,2020,8899,9080
```

Também é possível passar a rede como primeiro argumento:

```bash
dotnet run -- 192.168.0.0/24
```

## Fluxo

1. Executa discovery com:

```bash
nmap -sn -oX - <rede>
```

2. Lê os hosts `up` do XML retornado pelo Nmap.
3. Para cada IP encontrado, executa:

```bash
nmap -sV -Pn -T3 --reason <ip>
```

Com portas específicas:

```bash
nmap -sV -Pn -T3 --reason -p 80,443 <ip>
```

## Observação

Use somente em redes e dispositivos onde você tem autorização.
