# Net-Probe

A PowerShell script that continuously tests connectivity to a target using
ICMP echo or TCP connect probes, logging each result to the console and a
per-run log file.

## Features

- **Two probe modes**: `ICMP` (default, one echo request per probe) or `TCP`
  (connect attempts against one or more ports; reachable if any port accepts
  a connection).
- **Configurable interval, timeout, and log folder.**
- **Two log formats**: `Plain_Text` (default) or `CMTrace`.
- Runs until interrupted with `Ctrl+C`, or the `Q` key in an interactive
  session.

## Requirements

Windows PowerShell 5.1 or PowerShell 7+.

## Usage

```powershell
# Default ICMP probe, every 5 seconds, plain-text log
.\Net-Probe.ps1 -ProbeTarget 'example.com'

# ICMP probe every 10 seconds, CMTrace-format log
.\Net-Probe.ps1 -ProbeTarget '10.0.0.5' -ProbeIntervalSeconds 10 -LogFormat CMTrace

# TCP probe against the default HTTPS port (443)
.\Net-Probe.ps1 -ProbeTarget 'example.com' -ProbeMode TCP

# TCP probe against multiple ports with a custom timeout
.\Net-Probe.ps1 -ProbeTarget 'server01' -ProbeMode TCP -ProbePort 443,3389,8080 -TimeoutMs 2000
```

See the comment-based help in `Net-Probe.ps1` (`Get-Help .\Net-Probe.ps1 -Full`)
for the complete parameter reference.

## Parameters

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `-ProbeTarget` | `string` | *(required)* | Destination to probe: an IPv4 address, IPv6 address, or domain name (1-253 characters). Positional (position 0). |
| `-ProbeIntervalSeconds` | number | `5` | Wait, in seconds, measured from the start of one probe to the start of the next. Valid range: 1-86400. |
| `-LogFolderPath` | `string` | `%LOCALAPPDATA%\pwshNetProbeLogs` | Folder to write the run log file into. Valid length: 1-260 non-whitespace characters. |
| `-LogFormat` | `CMTrace` \| `Plain_Text` | `Plain_Text` | Format of the per-run log file (tab-completes). `CMTrace` writes canonical CMTrace-format log lines; `Plain_Text` writes each log line identical to its console line. Matched case-insensitively. Does not affect console output. |
| `-ProbeMode` | `ICMP` \| `TCP` | `ICMP` | Probing method (tab-completes). `ICMP` sends one echo request per probe; `TCP` attempts a connection to each port in `-ProbePort`. Matched case-insensitively. |
| `-ProbePort` | `int[]` | `443` (TCP mode only) | TCP port numbers to probe, each in the range 1-65535; duplicates are removed while preserving first-seen order. Applicable only to TCP mode - must be omitted in ICMP mode. |
| `-TimeoutMs` | number | `4000` | Shared timeout, in milliseconds, applied to both probe modes: the ICMP echo timeout and the per-port TCP connect timeout. Valid range: 1-300000. |
