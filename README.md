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
