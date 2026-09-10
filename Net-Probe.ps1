<#
.SYNOPSIS
    PowerShell Net Probe - continuously tests connectivity to a target using
    ICMP echo or TCP connect probes, and logs each result to the console and a
    per-run log file.

.DESCRIPTION
    Net-Probe repeatedly probes a caller-supplied target (IPv4 address, IPv6
    address, or domain name) at a configurable interval and writes each result
    to both the console and a single per-run .log file. Each result is
    classified as reachable, unreachable, or resolution-failure.

    Two probe modes are supported, selected with -ProbeMode:
      - ICMP (default): sends one ICMP echo request per probe. This preserves
        the original behavior, so existing invocations are unaffected.
      - TCP: attempts a TCP connection to each port in -ProbePort (default 443)
        and reports the target as reachable if ANY port accepts a connection,
        recording the best (minimum) connect latency. TCP mode is useful in
        environments where ICMP is filtered but application ports are open.

    A single shared -TimeoutMs (default 4000 ms) governs both modes: it is the
    ICMP echo timeout and the per-port TCP connect timeout.

    The log file format is selected with -LogFormat ('CMTrace' or 'Plain_Text').
    The run continues until interrupted (Ctrl+C, or the Q key in an interactive
    host), after which the log path is reported and an option to open the log is
    offered in interactive sessions.

    This file is structured so that its functions can be dot-sourced by tests
    (e.g. Pester) WITHOUT triggering the imperative run loop. The run loop only
    executes when the script is invoked directly (see the entry-point guard at
    the bottom of the file).

.PARAMETER ProbeTarget
    The destination to probe: a single IPv4 address, IPv6 address, or domain
    name (1-253 characters). Required for a run.

.PARAMETER ProbeIntervalSeconds
    Optional wait, in seconds, measured from the start of one probe to the
    start of the next. Valid range is 1-86400. Defaults to 5 when not supplied.

.PARAMETER LogFolderPath
    Optional folder to write the run log file into. Valid length is 1-260
    non-whitespace characters. Defaults to %LOCALAPPDATA%\pwshNetProbeLogs.

.PARAMETER LogFormat
    Optional format for the per-run log file. Accepted values are 'CMTrace'
    and 'Plain_Text', matched case-insensitively (e.g. 'cmtrace' or
    'PLAIN_TEXT' are accepted). 'CMTrace' writes canonical CMTrace-format log
    lines; 'Plain_Text' writes each log line identical to its console line.
    Defaults to 'Plain_Text' when not supplied. The console output is
    unaffected by this parameter.

.PARAMETER ProbeMode
    Optional probing method for the run. Accepted values are 'ICMP' and 'TCP',
    matched case-insensitively (e.g. 'icmp' or 'tcp' are accepted). 'ICMP' sends
    one echo request per probe; 'TCP' attempts a TCP connection to each port in
    ProbePort. Defaults to 'ICMP' when not supplied, preserving existing
    behavior.

.PARAMETER ProbePort
    Optional list of TCP port numbers to probe in TCP mode. Each value must be an
    integer in the range 1-65535; duplicates are removed while preserving
    first-seen order. Applicable only to TCP mode. Defaults to a single port 443
    (HTTPS) in TCP mode when not supplied, and must be omitted in ICMP mode.

.PARAMETER TimeoutMs
    Optional single shared timeout, in milliseconds, applied to both probe
    modes: the ICMP echo timeout and the per-port TCP connect timeout. Valid
    range is 1-300000. Defaults to 4000 when not supplied, preserving existing
    behavior.

.EXAMPLE
    .\Net-Probe.ps1 -ProbeTarget 'example.com'

    Runs the default ICMP probe against example.com every 5 seconds, logging in
    Plain_Text format to %LOCALAPPDATA%\pwshNetProbeLogs.

.EXAMPLE
    .\Net-Probe.ps1 -ProbeTarget '10.0.0.5' -ProbeIntervalSeconds 10 -LogFormat CMTrace

    Runs ICMP probes every 10 seconds and writes canonical CMTrace-format log
    lines instead of the default plain-text log lines.

.EXAMPLE
    .\Net-Probe.ps1 -ProbeTarget 'example.com' -ProbeMode TCP

    Runs a TCP probe against the default HTTPS port (443). The target is
    reported reachable if the connection is accepted.

.EXAMPLE
    .\Net-Probe.ps1 -ProbeTarget 'server01' -ProbeMode TCP -ProbePort 443,3389,8080 -TimeoutMs 2000

    Runs a TCP probe against ports 443, 3389, and 8080 with a 2000 ms per-port
    connect timeout. The target is reachable if ANY of the ports accepts a
    connection; the per-port outcomes are recorded in the result Detail.

.NOTES
    Target runtime: Windows PowerShell 5.1 and PowerShell 7+.
#>

[CmdletBinding()]
param(
    [Parameter(Position = 0)]
    [string] $ProbeTarget,

    [Parameter()]
    $ProbeIntervalSeconds,

    [Parameter()]
    [string] $LogFolderPath,

    [Parameter()]
    [ValidateSet('CMTrace', 'Plain_Text')]
    [string] $LogFormat,

    [Parameter()]
    [ValidateSet('ICMP', 'TCP')]
    [string] $ProbeMode,

    [Parameter()]
    [int[]] $ProbePort,

    [Parameter()]
    $TimeoutMs
)

#region Internal functions

# NOTE: The function bodies below are intentionally stubs. Each is implemented
# in a later task. Signatures and contracts follow the design document.

function Test-ProbeTargetFormat {
    <#
        Pure. Validates and classifies a probe target.
        Returns [pscustomobject]@{ IsValid=[bool]; Kind='IPv4'|'IPv6'|'Domain'|$null; Reason=[string] }
        Requirements: 1.1, 1.2, 1.3, 1.4, 1.5
    #>
    [CmdletBinding()]
    param(
        [string] $Target
    )

    # Requirements 1.2 / 1.3: null, empty, or whitespace-only input is invalid.
    if ([string]::IsNullOrWhiteSpace($Target)) {
        return [pscustomobject]@{
            IsValid = $false
            Kind    = $null
            Reason  = 'Target is null, empty, or whitespace-only.'
        }
    }

    # Requirements 1.1 / 1.5: classify IP addresses first via .NET parsing.
    # [System.Net.IPAddress]::TryParse plus the address family distinguishes
    # IPv4 (InterNetwork) from IPv6 (InterNetworkV6). No DNS resolution occurs.
    $parsed = $null
    if ([System.Net.IPAddress]::TryParse($Target, [ref] $parsed)) {
        if ($parsed.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetwork) {
            return [pscustomobject]@{ IsValid = $true; Kind = 'IPv4'; Reason = '' }
        }
        if ($parsed.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetworkV6) {
            return [pscustomobject]@{ IsValid = $true; Kind = 'IPv6'; Reason = '' }
        }

        return [pscustomobject]@{
            IsValid = $false
            Kind    = $null
            Reason  = "Parsed as an IP address with unsupported family '$($parsed.AddressFamily)'."
        }
    }

    # Requirement 1.1: a domain name must be between 1 and 253 characters total.
    if ($Target.Length -gt 253) {
        return [pscustomobject]@{
            IsValid = $false
            Kind    = $null
            Reason  = 'Target exceeds the 253-character maximum length for a domain name.'
        }
    }

    # Requirements 1.4 / 1.5: label-based domain-name validation.
    # Each dot-separated label must be 1-63 characters, contain only ASCII
    # letters, digits, and hyphens, and must not start or end with a hyphen.
    # Empty labels (e.g. leading/trailing/double dots) are rejected.
    $labelPattern = '^[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?$'
    $labels = $Target -split '\.'

    foreach ($label in $labels) {
        if ($label -notmatch $labelPattern) {
            return [pscustomobject]@{
                IsValid = $false
                Kind    = $null
                Reason  = 'Target does not match a valid IPv4 address, IPv6 address, or domain-name format.'
            }
        }
    }

    # Requirement 1.4: reject dotted-numeric strings that are not valid IP
    # addresses (e.g. '234.621.1.1', where an octet is out of range so
    # IPAddress.TryParse above already failed). Such a string has more than one
    # label and every label is entirely numeric, so it looks like a
    # dotted-decimal address rather than a domain name. A genuine domain name
    # has at least one non-numeric label (including domains with a numeric
    # top-level label such as 'oyf.1'), so it is unaffected. Genuine IP
    # addresses are handled earlier by IPAddress.TryParse.
    if ($labels.Length -gt 1) {
        $allNumericLabels = $true
        foreach ($label in $labels) {
            if ($label -notmatch '^[0-9]+$') {
                $allNumericLabels = $false
                break
            }
        }
        if ($allNumericLabels) {
            return [pscustomobject]@{
                IsValid = $false
                Kind    = $null
                Reason  = 'Target does not match a valid IPv4 address, IPv6 address, or domain-name format (dotted-numeric value is not a valid IP address).'
            }
        }
    }

    return [pscustomobject]@{ IsValid = $true; Kind = 'Domain'; Reason = '' }
}

function Test-ProbeInterval {
    <#
        Pure. Validates the probe interval.
        Returns [pscustomobject]@{ IsValid=[bool]; Value=[int]; Reason=[string] }
        Requirements: 3.3, 3.4, 3.6
    #>
    [CmdletBinding()]
    param(
        $IntervalSeconds
    )

    # Requirement 3.3: when the caller does not supply an interval ($null), use
    # the Default_Probe_Interval of 5 seconds.
    if ($null -eq $IntervalSeconds) {
        return [pscustomobject]@{ IsValid = $true; Value = 5; Reason = '' }
    }

    # Requirement 3.6: a non-numeric interval is invalid. Booleans are value
    # types that coerce to 0/1, so reject them explicitly rather than treating
    # them as numbers.
    if ($IntervalSeconds -is [bool]) {
        return [pscustomobject]@{
            IsValid = $false
            Value   = 0
            Reason  = "Probe interval '$IntervalSeconds' is not a number."
        }
    }

    # Normalize the supplied value to a [double] regardless of the type it was
    # passed as. Command-line arguments frequently arrive as strings, so numeric
    # strings (parsed with the invariant culture) are accepted; native numeric
    # value types are used directly. Anything else is treated as non-numeric.
    $numeric   = [double] 0
    $isNumeric = $false

    if ($IntervalSeconds -is [string]) {
        $text   = $IntervalSeconds.Trim()
        $parsed = [double] 0
        if ($text.Length -gt 0 -and [double]::TryParse(
                $text,
                [System.Globalization.NumberStyles]::Float,
                [System.Globalization.CultureInfo]::InvariantCulture,
                [ref] $parsed)) {
            $numeric   = $parsed
            $isNumeric = $true
        }
    }
    elseif ($IntervalSeconds -is [byte]   -or $IntervalSeconds -is [sbyte]  -or
            $IntervalSeconds -is [int16]  -or $IntervalSeconds -is [uint16] -or
            $IntervalSeconds -is [int]    -or $IntervalSeconds -is [uint32] -or
            $IntervalSeconds -is [long]   -or $IntervalSeconds -is [uint64] -or
            $IntervalSeconds -is [single] -or $IntervalSeconds -is [double] -or
            $IntervalSeconds -is [decimal]) {
        $numeric   = [double] $IntervalSeconds
        $isNumeric = $true
    }

    if (-not $isNumeric) {
        return [pscustomobject]@{
            IsValid = $false
            Value   = 0
            Reason  = "Probe interval '$IntervalSeconds' is not a number."
        }
    }

    # Guard against non-finite doubles (NaN / +-Infinity) that can result from
    # parsing tokens such as 'NaN' or 'Infinity'.
    if ([double]::IsNaN($numeric) -or [double]::IsInfinity($numeric)) {
        return [pscustomobject]@{
            IsValid = $false
            Value   = 0
            Reason  = "Probe interval '$IntervalSeconds' is not a finite number."
        }
    }

    # Requirement 3.6: reject values below 1 or above 86400 seconds.
    if ($numeric -lt 1 -or $numeric -gt 86400) {
        return [pscustomobject]@{
            IsValid = $false
            Value   = 0
            Reason  = "Probe interval '$IntervalSeconds' is out of the valid range [1, 86400] seconds."
        }
    }

    # Requirement 3.4: a numeric value within [1, 86400] is valid.
    return [pscustomobject]@{ IsValid = $true; Value = [int] $numeric; Reason = '' }
}

function Test-LogFolderPath {
    <#
        Pure. Validates and resolves the log folder path.
        Returns [pscustomobject]@{ IsValid=[bool]; ResolvedPath=[string]; Reason=[string] }
        Requirements: 5.2, 5.3, 5.4
    #>
    [CmdletBinding()]
    param(
        $LogFolderPath
    )

    # Requirement 5.4: when the caller does not supply a path ($null), resolve
    # the Default_Log_Folder by expanding %LOCALAPPDATA%\pwshNetProbeLogs. This
    # case is always valid; the effective path comes from Resolve-LogFolderPath.
    if ($null -eq $LogFolderPath) {
        return [pscustomobject]@{
            IsValid      = $true
            ResolvedPath = Resolve-LogFolderPath -LogFolderPath $null
            Reason       = ''
        }
    }

    # A supplied value is coerced to its string form for length/whitespace
    # checks. Non-string inputs are treated by their string representation.
    $path = [string] $LogFolderPath

    # Requirement 5.3: empty or whitespace-only supplied paths are invalid.
    if ([string]::IsNullOrWhiteSpace($path)) {
        return [pscustomobject]@{
            IsValid      = $false
            ResolvedPath = ''
            Reason       = 'Log folder path is empty or consists solely of whitespace.'
        }
    }

    # Requirement 5.3: supplied paths longer than 260 characters are invalid.
    if ($path.Length -gt 260) {
        return [pscustomobject]@{
            IsValid      = $false
            ResolvedPath = ''
            Reason       = "Log folder path exceeds the 260-character maximum length (length $($path.Length))."
        }
    }

    # Requirement 5.2: a non-whitespace path of 1-260 characters is valid and is
    # used as supplied (resolution is a no-op for a supplied path).
    return [pscustomobject]@{
        IsValid      = $true
        ResolvedPath = Resolve-LogFolderPath -LogFolderPath $path
        Reason       = ''
    }
}

function Test-LogFormat {
    <#
        Pure. Validates and canonicalizes the requested log format.
        Returns [pscustomobject]@{ IsValid=[bool]; Value=[string]; Reason=[string] }
        Requirements: 1.2, 1.3, 1.4, 1.5, 1.6, 2.1
    #>
    [CmdletBinding()]
    param(
        $LogFormat
    )

    # Requirement 2.1: when the caller does not supply a log format ($null), use
    # the Default_Log_Format of 'Plain_Text'.
    if ($null -eq $LogFormat) {
        return [pscustomobject]@{ IsValid = $true; Value = 'Plain_Text'; Reason = '' }
    }

    # A supplied value is coerced to its string form for the whitespace and
    # membership checks below.
    $format = [string] $LogFormat

    # Requirement 1.6: empty or whitespace-only supplied values are invalid.
    if ([string]::IsNullOrWhiteSpace($format)) {
        return [pscustomobject]@{
            IsValid = $false
            Value   = ''
            Reason  = "Log format '$LogFormat' is empty or consists solely of whitespace."
        }
    }

    # Requirements 1.2, 1.3, 1.4: case-insensitive matching against the members
    # of Log_Format_Values, canonicalized to their exact spelling.
    $trimmed = $format.Trim()
    switch -Exact ($trimmed.ToLowerInvariant()) {
        'cmtrace'    { return [pscustomobject]@{ IsValid = $true; Value = 'CMTrace';    Reason = '' } }
        'plain_text' { return [pscustomobject]@{ IsValid = $true; Value = 'Plain_Text'; Reason = '' } }
    }

    # Requirement 1.5: any other value is invalid; the Reason names the value.
    return [pscustomobject]@{
        IsValid = $false
        Value   = ''
        Reason  = "Log format '$LogFormat' is not a recognized log format (expected 'CMTrace' or 'Plain_Text')."
    }
}

function Test-ProbeMode {
    <#
        Pure. Validates and canonicalizes the requested probe mode.
        Returns [pscustomobject]@{ IsValid=[bool]; Value=[string]; Reason=[string] }
        Requirements: 1.1, 1.2, 1.3, 1.4, 1.6
    #>
    [CmdletBinding()]
    param(
        $Mode
    )

    # Requirement 1.1: when the caller does not supply a probe mode ($null), use
    # the Default_Probe_Mode of 'ICMP', preserving existing behavior.
    if ($null -eq $Mode) {
        return [pscustomobject]@{ IsValid = $true; Value = 'ICMP'; Reason = '' }
    }

    # A supplied value is coerced to its string form for the whitespace and
    # membership checks below.
    $mode = [string] $Mode

    # Requirement 1.3: empty or whitespace-only supplied values are invalid.
    if ([string]::IsNullOrWhiteSpace($mode)) {
        return [pscustomobject]@{
            IsValid = $false
            Value   = ''
            Reason  = "Probe mode '$Mode' is empty or consists solely of whitespace."
        }
    }

    # Requirement 1.2: case-insensitive matching against the members of
    # Probe_Mode_Values, canonicalized to their exact spelling.
    $trimmed = $mode.Trim()
    switch -Exact ($trimmed.ToLowerInvariant()) {
        'icmp' { return [pscustomobject]@{ IsValid = $true; Value = 'ICMP'; Reason = '' } }
        'tcp'  { return [pscustomobject]@{ IsValid = $true; Value = 'TCP';  Reason = '' } }
    }

    # Requirement 1.4: any other value is invalid; the Reason names the value.
    return [pscustomobject]@{
        IsValid = $false
        Value   = ''
        Reason  = "Probe mode '$Mode' is not recognized (expected 'ICMP' or 'TCP')."
    }
}

function Test-ProbePorts {
    <#
        Pure. Validates a TCP port list against the resolved probe mode and
        produces a normalized, de-duplicated, order-preserving [int[]].
        Returns [pscustomobject]@{ IsValid=[bool]; Value=[int[]]; Reason=[string] }
        Requirements: 2.1, 2.2, 2.3, 2.4, 2.5, 2.6, 2.7, 2.8, 2.10
    #>
    [CmdletBinding()]
    param(
        $Ports,
        [string] $Mode
    )

    # Flatten the supplied ports into a list of the individual (non-null) items,
    # so scalars, arrays, and nested arrays are all handled uniformly. A value
    # is "supplied" only when at least one non-null item is present; $null, an
    # empty array, or an array of only $null entries all count as "not supplied".
    $items = New-Object System.Collections.Generic.List[object]
    if ($null -ne $Ports) {
        foreach ($item in $Ports) {
            if ($null -ne $item) {
                $items.Add($item)
            }
        }
    }
    $supplied = ($items.Count -gt 0)

    # Requirements 2.3, 2.5: ports are not applicable to ICMP mode.
    if ($Mode -eq 'ICMP') {
        if ($supplied) {
            # Requirement 2.3: supplied ports with ICMP are rejected with a
            # distinct reason.
            return [pscustomobject]@{
                IsValid = $false
                Value   = [int[]] @()
                Reason  = 'Ports are not applicable to ICMP mode; remove -ProbePort or use -ProbeMode TCP.'
            }
        }
        # Requirement 2.5: no ports with ICMP is valid with an empty list.
        return [pscustomobject]@{ IsValid = $true; Value = [int[]] @(); Reason = '' }
    }

    # Mode = TCP from here on.
    # Requirement 2.4: TCP mode with no supplied ports defaults to the single
    # Default_Probe_Port 443 (HTTPS).
    if (-not $supplied) {
        return [pscustomobject]@{ IsValid = $true; Value = [int[]] @(443); Reason = '' }
    }

    # Requirements 2.1, 2.6, 2.7: validate every supplied element, then dedupe.
    $normalized = New-Object System.Collections.Generic.List[int]
    $seen       = New-Object System.Collections.Generic.HashSet[int]

    foreach ($raw in $items) {
        # Loop invariant: every element already in $normalized is a distinct
        # integer within the Port_Range [1, 65535].

        # Requirement 2.6: booleans are value types that coerce to 0/1, so
        # reject them explicitly rather than treating them as numbers.
        if ($raw -is [bool]) {
            return [pscustomobject]@{
                IsValid = $false
                Value   = [int[]] @()
                Reason  = "Port '$raw' is not a valid integer."
            }
        }

        # Normalize the element to a [double] regardless of the type it was
        # passed as. Command-line arguments frequently arrive as strings, so
        # numeric strings (parsed with the invariant culture) are accepted;
        # native numeric value types are used directly. Anything else is
        # treated as non-numeric.
        $numeric   = [double] 0
        $isNumeric = $false

        if ($raw -is [string]) {
            $text   = $raw.Trim()
            $parsed = [double] 0
            if ($text.Length -gt 0 -and [double]::TryParse(
                    $text,
                    [System.Globalization.NumberStyles]::Float,
                    [System.Globalization.CultureInfo]::InvariantCulture,
                    [ref] $parsed)) {
                $numeric   = $parsed
                $isNumeric = $true
            }
        }
        elseif ($raw -is [byte]   -or $raw -is [sbyte]  -or
                $raw -is [int16]  -or $raw -is [uint16] -or
                $raw -is [int]    -or $raw -is [uint32] -or
                $raw -is [long]   -or $raw -is [uint64] -or
                $raw -is [single] -or $raw -is [double] -or
                $raw -is [decimal]) {
            $numeric   = [double] $raw
            $isNumeric = $true
        }

        # Requirement 2.6: a non-numeric element is invalid; the Reason names it.
        if (-not $isNumeric) {
            return [pscustomobject]@{
                IsValid = $false
                Value   = [int[]] @()
                Reason  = "Port '$raw' is not a valid integer."
            }
        }

        # Requirement 2.6: guard against non-finite doubles (NaN / +-Infinity)
        # that can result from parsing tokens such as 'NaN' or 'Infinity'.
        if ([double]::IsNaN($numeric) -or [double]::IsInfinity($numeric)) {
            return [pscustomobject]@{
                IsValid = $false
                Value   = [int[]] @()
                Reason  = "Port '$raw' is not a finite integer."
            }
        }

        # Requirement 2.6: a non-integer numeric value (e.g. 443.5) is invalid.
        if ($numeric -ne [System.Math]::Truncate($numeric)) {
            return [pscustomobject]@{
                IsValid = $false
                Value   = [int[]] @()
                Reason  = "Port '$raw' must be a whole number."
            }
        }

        # Requirement 2.7: the integer must lie within the Port_Range [1, 65535].
        if ($numeric -lt 1 -or $numeric -gt 65535) {
            return [pscustomobject]@{
                IsValid = $false
                Value   = [int[]] @()
                Reason  = "Port '$raw' is out of the valid range [1, 65535]."
            }
        }

        # Requirement 2.2: de-duplicate while preserving first-seen order.
        $port = [int] $numeric
        if ($seen.Add($port)) {
            $normalized.Add($port)
        }
    }

    # Requirement 2.8: reject a distinct-port count exceeding the number of
    # distinct values available in the Port_Range. (With the [1, 65535] range
    # check above this bound cannot be exceeded, but the guard makes the
    # contract explicit.)
    if ($normalized.Count -gt 65535) {
        return [pscustomobject]@{
            IsValid = $false
            Value   = [int[]] @()
            Reason  = "The number of distinct ports ($($normalized.Count)) exceeds the 65535 distinct values in the range [1, 65535]."
        }
    }

    # Requirement 2.1: a well-formed, non-empty, de-duplicated, order-preserving
    # integer list within the Port_Range is valid.
    return [pscustomobject]@{
        IsValid = $true
        Value   = [int[]] $normalized.ToArray()
        Reason  = ''
    }
}

function Test-ProbeTimeout {
    <#
        Pure. Validates the shared probe timeout (applies to ICMP and TCP alike).
        Returns [pscustomobject]@{ IsValid=[bool]; Value=[int]; Reason=[string] }
        Requirements: 6.1, 6.2, 6.3, 6.4, 6.9
    #>
    [CmdletBinding()]
    param(
        $TimeoutMs
    )

    # Requirement 6.1: when the caller does not supply a timeout ($null), use the
    # Default_Timeout_Ms of 4000, the timeout ICMP mode already used.
    if ($null -eq $TimeoutMs) {
        return [pscustomobject]@{ IsValid = $true; Value = 4000; Reason = '' }
    }

    # Requirement 6.3: a non-numeric timeout is invalid. Booleans are value types
    # that coerce to 0/1, so reject them explicitly rather than treating them as
    # numbers.
    if ($TimeoutMs -is [bool]) {
        return [pscustomobject]@{
            IsValid = $false
            Value   = 0
            Reason  = "Probe timeout '$TimeoutMs' is not a number."
        }
    }

    # Normalize the supplied value to a [double] regardless of the type it was
    # passed as. Command-line arguments frequently arrive as strings, so numeric
    # strings (parsed with the invariant culture) are accepted; native numeric
    # value types are used directly. Anything else is treated as non-numeric.
    $numeric   = [double] 0
    $isNumeric = $false

    if ($TimeoutMs -is [string]) {
        $text   = $TimeoutMs.Trim()
        $parsed = [double] 0
        if ($text.Length -gt 0 -and [double]::TryParse(
                $text,
                [System.Globalization.NumberStyles]::Float,
                [System.Globalization.CultureInfo]::InvariantCulture,
                [ref] $parsed)) {
            $numeric   = $parsed
            $isNumeric = $true
        }
    }
    elseif ($TimeoutMs -is [byte]   -or $TimeoutMs -is [sbyte]  -or
            $TimeoutMs -is [int16]  -or $TimeoutMs -is [uint16] -or
            $TimeoutMs -is [int]    -or $TimeoutMs -is [uint32] -or
            $TimeoutMs -is [long]   -or $TimeoutMs -is [uint64] -or
            $TimeoutMs -is [single] -or $TimeoutMs -is [double] -or
            $TimeoutMs -is [decimal]) {
        $numeric   = [double] $TimeoutMs
        $isNumeric = $true
    }

    # Requirement 6.3: a non-numeric value is invalid; the Reason names it.
    if (-not $isNumeric) {
        return [pscustomobject]@{
            IsValid = $false
            Value   = 0
            Reason  = "Probe timeout '$TimeoutMs' is not a number."
        }
    }

    # Requirement 6.3: guard against non-finite doubles (NaN / +-Infinity) that
    # can result from parsing tokens such as 'NaN' or 'Infinity'.
    if ([double]::IsNaN($numeric) -or [double]::IsInfinity($numeric)) {
        return [pscustomobject]@{
            IsValid = $false
            Value   = 0
            Reason  = "Probe timeout '$TimeoutMs' is not a finite number."
        }
    }

    # Requirement 6.3: a non-integer numeric value (e.g. 1500.5) is invalid.
    if ($numeric -ne [System.Math]::Truncate($numeric)) {
        return [pscustomobject]@{
            IsValid = $false
            Value   = 0
            Reason  = "Probe timeout '$TimeoutMs' must be a whole number of milliseconds."
        }
    }

    # Requirement 6.4: reject values below 1 or above 300000 milliseconds.
    if ($numeric -lt 1 -or $numeric -gt 300000) {
        return [pscustomobject]@{
            IsValid = $false
            Value   = 0
            Reason  = "Probe timeout '$TimeoutMs' is out of the valid range [1, 300000] milliseconds."
        }
    }

    # Requirement 6.2: a numeric value within [1, 300000] is valid.
    return [pscustomobject]@{ IsValid = $true; Value = [int] $numeric; Reason = '' }
}

function Resolve-LogFolderPath {
    <#
        Pure. Resolves the effective log folder path (default or supplied).
        Requirements: 5.4
    #>
    [CmdletBinding()]
    param(
        $LogFolderPath
    )

    # Requirement 5.4: with no supplied path, the effective Log_Folder is the
    # Default_Log_Folder at %LOCALAPPDATA%\pwshNetProbeLogs, with the
    # environment variable expanded to its current value.
    if ($null -eq $LogFolderPath) {
        return [System.Environment]::ExpandEnvironmentVariables('%LOCALAPPDATA%\pwshNetProbeLogs')
    }

    # Requirement 5.2: a supplied path is used as-is.
    return [string] $LogFolderPath
}

function New-LogFileName {
    <#
        Pure. Builds "{sanitizedTarget}_{sanitizedTimestamp}.log", sanitizing
        invalid filename characters and bounding total length to <= 255 chars.
        Returns [string] file name including the .log extension.
        Requirements: 6.2, 6.3, 6.4, 6.5
    #>
    [CmdletBinding()]
    param(
        [string] $Target,
        [datetime] $CreationTime
    )

    # Local sanitizer: replace every character that is invalid in a host
    # filename (per [System.IO.Path]::GetInvalidFileNameChars()) with exactly
    # one underscore. Iterating character-by-character guarantees a 1:1 mapping
    # (a single invalid character becomes a single '_'); consecutive invalid
    # characters are NOT collapsed. Requirement 6.4.
    $invalidChars = [System.Collections.Generic.HashSet[char]]::new(
        [System.IO.Path]::GetInvalidFileNameChars())

    $sanitize = {
        param([string] $Value)

        $builder = [System.Text.StringBuilder]::new()
        foreach ($char in $Value.ToCharArray()) {
            if ($invalidChars.Contains($char)) {
                [void] $builder.Append('_')
            }
            else {
                [void] $builder.Append($char)
            }
        }

        return $builder.ToString()
    }

    # Requirement 6.2 / 6.3: the timestamp portion is formatted deterministically
    # with date + time down to millisecond precision using the invariant culture
    # (so output does not vary by host locale). The ':' characters in the time
    # portion are invalid in filenames and are turned into underscores by the
    # sanitizer below. Requirement 6.4.
    $rawTimestamp = $CreationTime.ToString(
        'yyyy-MM-dd_HH:mm:ss.fff',
        [System.Globalization.CultureInfo]::InvariantCulture)

    $sanitizedTarget    = & $sanitize ([string] $Target)
    $sanitizedTimestamp = & $sanitize $rawTimestamp

    $extension = '.log'
    $separator = '_'

    # Requirement 6.5: if the full name (including the '.log' extension) would
    # exceed 255 characters, truncate ONLY the target portion so the total is
    # <= 255, while retaining the full timestamp and the '.log' extension. The
    # fixed cost is the separator + timestamp + extension.
    $fixedLength     = $separator.Length + $sanitizedTimestamp.Length + $extension.Length
    $maxTargetLength = 255 - $fixedLength

    if ($maxTargetLength -lt 0) {
        # Degenerate case: the timestamp + extension alone already exceed 255.
        # Nothing of the target can remain.
        $maxTargetLength = 0
    }

    if ($sanitizedTarget.Length -gt $maxTargetLength) {
        $sanitizedTarget = $sanitizedTarget.Substring(0, $maxTargetLength)
    }

    # Requirement 6.2 / 6.3: concatenate target, a single underscore separator,
    # the timestamp, and the '.log' extension.
    return '{0}{1}{2}{3}' -f $sanitizedTarget, $separator, $sanitizedTimestamp, $extension
}

function Get-CMTraceSeverity {
    <#
        Pure. Maps a Probe_Result to a CMTrace severity: 1 (info), 2 (warn), 3 (error).
        Returns [int]
        Requirements: 8.3, 8.4, 8.5, 8.6
    #>
    [CmdletBinding()]
    param(
        [pscustomobject] $ProbeResult
    )

    # CMTrace severity values: 1 = Informational, 2 = Warning, 3 = Error.
    # ($SeverityError is deliberately NOT named $error to avoid shadowing the
    # PowerShell automatic $error variable.)
    $severityInformational = 1
    $severityWarning       = 2
    $severityError         = 3

    # Requirements 8.3 / 8.4: an unreachable target or a name-resolution failure
    # both map to an error severity.
    if ($ProbeResult.Status -eq 'unreachable' -or
        $ProbeResult.Status -eq 'resolution-failure') {
        return $severityError
    }

    # Requirements 8.5 / 8.6: a reachable target maps to informational when the
    # round-trip time is <= 200 ms and to warning when it is > 200 ms. The
    # boundary (exactly 200 ms) is informational.
    if ($ProbeResult.Status -eq 'reachable') {
        if ($ProbeResult.RoundtripMs -le 200) {
            return $severityInformational
        }

        return $severityWarning
    }

    # Defensive default: any unexpected status is treated as an error so it is
    # surfaced rather than silently classified as informational.
    return $severityError
}

function Format-ConsoleLine {
    <#
        Pure. Builds the single console line for a Probe_Result.
        Returns [string]
        Requirements: 4.1, 4.2, 4.3, 4.4
    #>
    [CmdletBinding()]
    param(
        [pscustomobject] $ProbeResult
    )

    # Requirement 4.1: format the timestamp deterministically with the invariant
    # culture so the console line does not vary by host locale. The pattern
    # includes date + time down to millisecond precision, which satisfies the
    # "at least second-level precision" requirement.
    $timestamp = $ProbeResult.Timestamp.ToString(
        'yyyy-MM-dd HH:mm:ss.fff',
        [System.Globalization.CultureInfo]::InvariantCulture)

    $target = [string] $ProbeResult.Target

    # Requirement 4.4: a resolution failure uses a distinct indicator that is
    # neither the "reachable" nor the "unreachable" status token.
    if ($ProbeResult.Status -eq 'resolution-failure') {
        $line = "[$timestamp] $target resolution-failure"

        # Include any human-readable detail identifying the unresolved target
        # when present, without altering the distinct status indicator.
        if (-not [string]::IsNullOrWhiteSpace([string] $ProbeResult.Detail)) {
            $line = "$line ($($ProbeResult.Detail))"
        }

        return $line
    }

    # Requirement 4.1: for reachable/unreachable results the status indicator is
    # exactly the corresponding token.
    if ($ProbeResult.Status -eq 'reachable') {
        # Requirement 4.2: reachable with an available round-trip time includes
        # the numeric millisecond value.
        if ($null -ne $ProbeResult.RoundtripMs) {
            return "[$timestamp] $target reachable RTT=$($ProbeResult.RoundtripMs)ms"
        }

        # Requirement 4.3: reachable without a round-trip time includes an
        # explicit "unavailable" indicator and no numeric value.
        return "[$timestamp] $target reachable RTT unavailable"
    }

    # Requirement 4.1: any remaining status is 'unreachable'; emit exactly that
    # token with no round-trip time.
    return "[$timestamp] $target unreachable"
}

function Format-CMTraceEntry {
    <#
        Pure. Builds a single canonical CMTrace-format log line.
        Returns [string]
        Requirements: 7.2, 7.3, 7.4, 8.1, 8.2
    #>
    [CmdletBinding()]
    param(
        [pscustomobject] $ProbeResult,
        [pscustomobject] $Context
    )

    $invariant = [System.Globalization.CultureInfo]::InvariantCulture
    $timestamp = $ProbeResult.Timestamp

    # Requirement 8.2: every field must carry a non-empty value. The message is
    # built from the Probe_Result so that it always includes the timestamp, the
    # target, and the status; the remaining CMTrace fields are sourced from the
    # RunContext with defensive fallbacks so a missing/blank context value never
    # produces an empty field.

    # --- message (Requirements 7.2, 7.3, 7.4) ---------------------------------
    # Formatted with the invariant culture so output does not vary by host
    # locale. The pattern carries date + time down to millisecond precision,
    # satisfying the "includes the timestamp" requirement.
    $messageTimestamp = $timestamp.ToString(
        'yyyy-MM-dd HH:mm:ss.fff', $invariant)

    $target = [string] $ProbeResult.Target

    switch ($ProbeResult.Status) {
        'reachable' {
            # Requirement 7.3: include the round-trip time in milliseconds when
            # a reachable result has one available; otherwise mark it as
            # unavailable without emitting a numeric value.
            if ($null -ne $ProbeResult.RoundtripMs) {
                $message = "$messageTimestamp target=$target status=reachable RTT=$($ProbeResult.RoundtripMs)ms"
            }
            else {
                $message = "$messageTimestamp target=$target status=reachable RTT unavailable"
            }
        }
        'resolution-failure' {
            # Requirement 7.4: include a distinct resolution-failure indicator.
            $message = "$messageTimestamp target=$target status=resolution-failure"
            if (-not [string]::IsNullOrWhiteSpace([string] $ProbeResult.Detail)) {
                $message = "$message ($($ProbeResult.Detail))"
            }
        }
        default {
            # 'unreachable' and any unexpected status emit exactly the status.
            $message = "$messageTimestamp target=$target status=$($ProbeResult.Status)"
        }
    }

    # --- time / date (Requirement 8.2) ----------------------------------------
    # The CMTrace 'time' field is HH:mm:ss.fff followed by a UTC-offset suffix
    # expressed as signed minutes (e.g. +000, +120, -480). The offset is derived
    # from the local time zone at the timestamp so daylight-saving transitions
    # are honored.
    $offset       = [System.TimeZoneInfo]::Local.GetUtcOffset($timestamp)
    $totalMinutes = [int] $offset.TotalMinutes
    $offsetSign   = if ($totalMinutes -lt 0) { '-' } else { '+' }
    $offsetSuffix = '{0}{1:000}' -f $offsetSign, [math]::Abs($totalMinutes)

    $timeField = '{0}{1}' -f $timestamp.ToString('HH:mm:ss.fff', $invariant), $offsetSuffix
    $dateField = $timestamp.ToString('MM-dd-yyyy', $invariant)

    # --- type (Requirements 8.1 via Get-CMTraceSeverity) ----------------------
    $typeField = Get-CMTraceSeverity -ProbeResult $ProbeResult

    # --- context-sourced fields with non-empty fallbacks (Requirement 8.2) ----
    $component = if ($null -ne $Context -and
                     -not [string]::IsNullOrWhiteSpace([string] $Context.Component)) {
        [string] $Context.Component
    }
    else { 'Net_Probe' }

    $contextValue = if ($null -ne $Context -and
                        -not [string]::IsNullOrWhiteSpace([string] $Context.Context)) {
        [string] $Context.Context
    }
    else { $component }

    $threadValue = if ($null -ne $Context -and
                       -not [string]::IsNullOrWhiteSpace([string] $Context.ThreadId)) {
        [string] $Context.ThreadId
    }
    else { [string] [System.Threading.Thread]::CurrentThread.ManagedThreadId }

    $fileField = if ($null -ne $Context -and
                     -not [string]::IsNullOrWhiteSpace([string] $Context.FileName)) {
        [string] $Context.FileName
    }
    else { 'Net-Probe.ps1' }

    # Requirement 8.1: emit the canonical CMTrace single-line format.
    return '<![LOG[{0}]LOG]!><time="{1}" date="{2}" component="{3}" context="{4}" type="{5}" thread="{6}" file="{7}">' -f `
        $message, $timeField, $dateField, $component, $contextValue, $typeField, $threadValue, $fileField
}

function Format-LogEntry {
    <#
        Pure. Selects the log-line formatter from the RunContext LogFormat and
        returns the formatted log line (no trailing terminator). Delegates to the
        existing pure formatters without re-implementing either, so the CMTrace
        line is byte-for-byte identical to Format-CMTraceEntry and the Plain_Text
        line is character-for-character identical to Format-ConsoleLine.
        Returns [string]
        Requirements: 6.1, 6.2, 6.3, 6.4, 6.5, 6.6, 3.4
    #>
    [CmdletBinding()]
    param(
        [pscustomobject] $ProbeResult,
        [pscustomobject] $Context
    )

    # Read the selected format from the RunContext. A missing Context or a
    # Context without a LogFormat member yields $null, which falls through to the
    # distinct invalid-log-format error below (Requirements 3.4, 6.6).
    $logFormat = if ($null -ne $Context) { $Context.LogFormat } else { $null }

    switch -Exact ([string] $logFormat) {
        # Requirement 6.1: CMTrace selection returns exactly what
        # Format-CMTraceEntry produces for this Probe_Result and RunContext,
        # preserving the current behavior byte-for-byte.
        'CMTrace' {
            return Format-CMTraceEntry -ProbeResult $ProbeResult -Context $Context
        }
        # Requirement 6.2: Plain_Text selection returns exactly what
        # Format-ConsoleLine produces, so the log line matches the console line.
        'Plain_Text' {
            return Format-ConsoleLine -ProbeResult $ProbeResult
        }
    }

    # Requirements 3.4, 6.6: an absent LogFormat or one that is not a member of
    # Log_Format_Values raises a distinct, value-naming error and returns no line.
    throw "Invalid RunContext LogFormat '$logFormat': expected a member of Log_Format_Values ('CMTrace' or 'Plain_Text')."
}

function ConvertTo-ProbeResult {
    <#
        Pure. Maps a single probe outcome to a normalized Probe_Result. This is
        the pure core that Invoke-SingleProbe wraps around the actual network
        send, so the mapping can be exercised in isolation by the probe-result
        property test (which injects simulated PingReply / exception outcomes)
        without performing any real ICMP I/O.

        Outcome inputs:
          - $ResolutionFailure switch : a name-resolution failure (PingException
            wrapping a SocketException, or a SocketException). Status becomes
            'resolution-failure' and no round-trip time is recorded.
          - $Status = 'Success'       : reachable; $RoundtripTime is rounded to
            the nearest whole, non-negative millisecond.
          - any other $Status         : unreachable; no round-trip time.

        Returns a Probe_Result [pscustomobject]:
          @{ Timestamp; Target; Status; RoundtripMs; Detail }
        Requirements: 2.2, 2.3, 2.4
    #>
    [CmdletBinding()]
    param(
        [string] $Target,
        [datetime] $Timestamp,
        [string] $Status,
        $RoundtripTime = $null,
        [switch] $ResolutionFailure,
        [string] $Detail
    )

    # Requirement 2.4: a name-resolution failure is recorded as a
    # 'resolution-failure' result with no round-trip time and a Detail that
    # identifies the unresolved target.
    if ($ResolutionFailure) {
        $failureDetail = $Detail
        if ([string]::IsNullOrWhiteSpace($failureDetail)) {
            $failureDetail = "Name resolution failed for target '$Target'."
        }

        return [pscustomobject]@{
            Timestamp   = $Timestamp
            Target      = $Target
            Status      = 'resolution-failure'
            RoundtripMs = $null
            Detail      = $failureDetail
        }
    }

    # Requirement 2.2: a successful reply is reachable with the round-trip time
    # rounded to the nearest whole millisecond and clamped to be non-negative.
    if ($Status -eq 'Success') {
        $rounded = [int] [math]::Round([double] $RoundtripTime, 0)
        if ($rounded -lt 0) { $rounded = 0 }

        return [pscustomobject]@{
            Timestamp   = $Timestamp
            Target      = $Target
            Status      = 'reachable'
            RoundtripMs = $rounded
            Detail      = ''
        }
    }

    # Requirement 2.3: any other reply status (including a timeout) is recorded
    # as unreachable with no round-trip time value.
    return [pscustomobject]@{
        Timestamp   = $Timestamp
        Target      = $Target
        Status      = 'unreachable'
        RoundtripMs = $null
        Detail      = if ([string]::IsNullOrWhiteSpace($Status)) { '' } else { "Reply status: $Status." }
    }
}

function ConvertTo-TcpProbeResult {
    <#
        Pure. Maps a single TCP connect outcome for one port to a per-port
        Tcp_Port_Result. This is the pure core that Invoke-TcpProbe wraps around
        each socket attempt, so the mapping can be exercised with simulated
        outcomes and no real network I/O (exactly how ConvertTo-ProbeResult is
        tested for ICMP).

        Outcome inputs:
          - $ResolutionFailure switch : name resolution failed for the target.
            Status becomes 'resolution-failure', no round-trip time is recorded,
            and Detail identifies the resolution failure.
          - $Outcome = 'Connected'    : reachable; $ConnectTimeMs is rounded to
            the nearest whole, non-negative millisecond.
          - any other $Outcome        : unreachable (timeout, refused, reset,
            etc.); no round-trip time and a Detail naming the cause.

        Reuses the same status vocabulary (reachable / unreachable /
        resolution-failure) as ConvertTo-ProbeResult so the downstream formatters
        and severity mapping are unchanged.

        Returns a Tcp_Port_Result [pscustomobject]:
          @{ Timestamp; Target; Port; Status; RoundtripMs; Detail }
        Requirements: 3.1, 3.2, 3.3, 3.4, 3.9
    #>
    [CmdletBinding()]
    param(
        [string] $Target,
        [int] $Port,
        [datetime] $Timestamp,
        [string] $Outcome,
        $ConnectTimeMs = $null,
        [switch] $ResolutionFailure,
        [string] $Detail
    )

    # Requirement 3.3: a name-resolution failure is recorded as a
    # 'resolution-failure' result with no round-trip time and a non-empty Detail
    # that identifies the unresolved target.
    if ($ResolutionFailure) {
        $failureDetail = $Detail
        if ([string]::IsNullOrWhiteSpace($failureDetail)) {
            $failureDetail = "Name resolution failed for target '$Target'."
        }

        return [pscustomobject]@{
            Timestamp   = $Timestamp
            Target      = $Target
            Port        = $Port
            Status      = 'resolution-failure'
            RoundtripMs = $null
            Detail      = $failureDetail
        }
    }

    # Requirement 3.2: a connected attempt is reachable with the connect time
    # rounded to the nearest whole millisecond and clamped to be non-negative.
    if ($Outcome -eq 'Connected') {
        $rounded = [int] [math]::Round([double] $ConnectTimeMs, 0)
        if ($rounded -lt 0) { $rounded = 0 }

        return [pscustomobject]@{
            Timestamp   = $Timestamp
            Target      = $Target
            Port        = $Port
            Status      = 'reachable'
            RoundtripMs = $rounded
            Detail      = ''
        }
    }

    # Requirement 3.4: any other outcome (timeout, refused, reset, ...) is
    # recorded as unreachable with no round-trip time and a non-empty Detail
    # naming the cause.
    $unreachableDetail = $Detail
    if ([string]::IsNullOrWhiteSpace($unreachableDetail)) {
        $causeToken = if ([string]::IsNullOrWhiteSpace($Outcome)) { 'unknown' } else { $Outcome }
        $unreachableDetail = "TCP connect to port $Port failed: $causeToken."
    }

    return [pscustomobject]@{
        Timestamp   = $Timestamp
        Target      = $Target
        Port        = $Port
        Status      = 'unreachable'
        RoundtripMs = $null
        Detail      = $unreachableDetail
    }
}

function Merge-TcpProbeResult {
    <#
        Pure. Folds the per-port Tcp_Port_Result list produced within one probe
        iteration into a single aggregate Probe_Result matching the exact shape
        the existing formatters consume, plus an additive PortResults member that
        base formatters ignore.

        Aggregate status rules (evaluated in order):
          - R1 (resolution failure dominates): if the list is non-empty and EVERY
            port has Status 'resolution-failure', the whole probe is a
            'resolution-failure' with no round-trip time.
          - R2 (any-port-open => reachable): otherwise, if AT LEAST ONE port has
            Status 'reachable', the aggregate is 'reachable' and RoundtripMs is
            the MINIMUM connect latency among the reachable ports (best case).
          - R3 (otherwise unreachable): no port connected and not all-resolution-
            failure => 'unreachable' with no round-trip time.

        Detail is a non-empty string listing every supplied port and its per-port
        status in supplied order, e.g. '443=reachable(12ms); 3389=unreachable'.

        Returns an aggregate Probe_Result [pscustomobject]:
          @{ Timestamp; Target; Status; RoundtripMs; Detail; PortResults }
        Requirements: 3.5, 3.6, 3.7, 3.8, 3.9, 4.1, 4.5
    #>
    [CmdletBinding()]
    param(
        [string] $Target,
        [datetime] $Timestamp,
        [pscustomobject[]] $PortResults
    )

    $reachable = @($PortResults | Where-Object { $_.Status -eq 'reachable' })
    $resolutionFailures = @($PortResults | Where-Object { $_.Status -eq 'resolution-failure' })

    # Rule R1: every attempted port failed name resolution => the probe is a
    # target-level resolution failure.
    if ($PortResults.Count -gt 0 -and $resolutionFailures.Count -eq $PortResults.Count) {
        $status = 'resolution-failure'
        $roundtripMs = $null
    }
    # Rule R2: at least one port accepted a connection => reachable, with the best
    # (minimum) connect latency among the reachable ports.
    elseif ($reachable.Count -gt 0) {
        $status = 'reachable'
        $roundtripMs = ($reachable | ForEach-Object { $_.RoundtripMs } | Measure-Object -Minimum).Minimum
        $roundtripMs = [int] $roundtripMs
    }
    # Rule R3: no port connected and not all-resolution-failure => unreachable.
    else {
        $status = 'unreachable'
        $roundtripMs = $null
    }

    # Requirement 3.8: build a per-port summary that lists every supplied port and
    # its status in supplied order, appending '(<ms>ms)' where a round-trip time
    # was recorded (i.e. for reachable ports).
    $detailParts = foreach ($portResult in $PortResults) {
        if ($null -ne $portResult.RoundtripMs) {
            "$($portResult.Port)=$($portResult.Status)($($portResult.RoundtripMs)ms)"
        }
        else {
            "$($portResult.Port)=$($portResult.Status)"
        }
    }
    $detail = ($detailParts -join '; ')

    return [pscustomobject]@{
        Timestamp   = $Timestamp
        Target      = $Target
        Status      = $status
        RoundtripMs = $roundtripMs
        Detail      = $detail
        PortResults = $PortResults
    }
}

function Invoke-SingleProbe {
    <#
        Side-effecting (network). Sends exactly one ICMP echo request.
        Returns a normalized Probe_Result [pscustomobject].
        Requirements: 2.1, 2.2, 2.3, 2.4, 2.5
    #>
    [CmdletBinding()]
    param(
        [string] $Target,
        [int] $TimeoutMs = 4000
    )

    # Capture time before the probe so the Probe_Result timestamp reflects when
    # the probe was initiated.
    $timestamp = Get-Date

    $ping = [System.Net.NetworkInformation.Ping]::new()
    try {
        # Requirements 2.4 / 2.5: a name-resolution failure surfaces as a
        # PingException wrapping a SocketException (or a SocketException). This
        # is thrown by Send() BEFORE any ICMP packet leaves the host, so
        # catching it here guarantees zero ICMP echo requests are sent for an
        # unresolvable target. (PowerShell matches these catch types against the
        # inner-exception chain of the method-invocation wrapper.)
        try {
            # Requirement 2.1: send exactly one ICMP echo request using the
            # 4000 ms probe timeout.
            $reply = $ping.Send($Target, $TimeoutMs)
        }
        catch [System.Net.NetworkInformation.PingException] {
            return ConvertTo-ProbeResult -Target $Target -Timestamp $timestamp `
                -ResolutionFailure -Detail "Name resolution failed for target '$Target': $($_.Exception.Message)"
        }
        catch [System.Net.Sockets.SocketException] {
            return ConvertTo-ProbeResult -Target $Target -Timestamp $timestamp `
                -ResolutionFailure -Detail "Name resolution failed for target '$Target': $($_.Exception.Message)"
        }

        # Requirements 2.2 / 2.3: map the reply status and round-trip time to a
        # normalized Probe_Result via the pure mapping helper.
        return ConvertTo-ProbeResult -Target $Target -Timestamp $timestamp `
            -Status ([string] $reply.Status) -RoundtripTime $reply.RoundtripTime
    }
    finally {
        # Release the unmanaged Ping resources regardless of outcome.
        $ping.Dispose()
    }
}

function Invoke-TcpProbe {
    <#
        Side-effecting (network). The TCP analog of Invoke-SingleProbe. Performs
        exactly one TCP connection attempt per port for a single probe iteration
        and returns one aggregate Probe_Result. Owns ALL socket I/O; every
        classification decision is delegated to the pure ConvertTo-TcpProbeResult,
        and aggregation to the pure Merge-TcpProbeResult.

        Per port (Algorithm 6):
          - Open a System.Net.Sockets.TcpClient, start an async connect, and wait
            up to $TimeoutMs using Task.Wait(timeout) (portable across Windows
            PowerShell 5.1 and PowerShell 7+; no APM Begin/EndConnect needed).
          - Measure connect latency with a Stopwatch.
          - Classify Connected / Timeout / Refused / resolution-failure. A pending
            connect is torn down by disposing the client after a timeout.
          - A SocketException with HostNotFound / NoData / TryAgain (whether raised
            directly or wrapped in an AggregateException from Task.Wait) maps to a
            resolution failure; any other socket error maps to unreachable.
          - The socket is disposed in a finally on EVERY completion path, and the
            loop continues to the remaining ports after any per-port failure.

        Returns exactly one aggregate Probe_Result [pscustomobject] per iteration.
        Requirements: 5.3, 5.4, 5.5, 5.6, 5.7
    #>
    [CmdletBinding()]
    param(
        [string] $Target,
        [int[]] $Ports,
        [int] $TimeoutMs = 4000
    )

    # Requirement 5.3: capture one timestamp for the whole probe iteration so
    # every per-port result shares the initiation time (matches ICMP semantics).
    $timestamp = Get-Date

    # SocketError codes that indicate a name-resolution failure rather than a
    # connection-level failure.
    $resolutionErrors = @(
        [System.Net.Sockets.SocketError]::HostNotFound
        [System.Net.Sockets.SocketError]::NoData
        [System.Net.Sockets.SocketError]::TryAgain
    )

    $portResults = foreach ($port in $Ports) {
        $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
        $client = [System.Net.Sockets.TcpClient]::new()
        try {
            try {
                # Requirement 5.3: exactly one connection attempt per port,
                # bounded by the shared connect timeout.
                $task = $client.ConnectAsync($Target, $port)
                $completed = $task.Wait($TimeoutMs)
                $stopwatch.Stop()

                if (-not $completed) {
                    # Requirement 5.5: the connect did not complete within the
                    # timeout window => unreachable; disposing the client (finally)
                    # tears down the still-pending connect.
                    ConvertTo-TcpProbeResult -Target $Target -Port $port -Timestamp $timestamp `
                        -Outcome 'Timeout' `
                        -Detail "TCP connect to port $port timed out after $TimeoutMs ms."
                }
                elseif ($client.Connected) {
                    # Reachable: record the measured connect latency.
                    ConvertTo-TcpProbeResult -Target $Target -Port $port -Timestamp $timestamp `
                        -Outcome 'Connected' -ConnectTimeMs $stopwatch.Elapsed.TotalMilliseconds
                }
                else {
                    ConvertTo-TcpProbeResult -Target $Target -Port $port -Timestamp $timestamp `
                        -Outcome 'Failed' `
                        -Detail "TCP connect to port $port did not establish a connection."
                }
            }
            catch [System.AggregateException] {
                # Task.Wait surfaces connect faults wrapped in an AggregateException.
                # Unwrap to find the underlying SocketException and classify it.
                $stopwatch.Stop()
                $socketException = $null
                foreach ($inner in $_.Exception.Flatten().InnerExceptions) {
                    if ($inner -is [System.Net.Sockets.SocketException]) {
                        $socketException = $inner
                        break
                    }
                }

                if ($null -ne $socketException -and $resolutionErrors -contains $socketException.SocketErrorCode) {
                    # Requirement 5.6: resolution failure.
                    ConvertTo-TcpProbeResult -Target $Target -Port $port -Timestamp $timestamp `
                        -ResolutionFailure `
                        -Detail "Name resolution failed for target '$Target': $($_.Exception.GetBaseException().Message)"
                }
                else {
                    # Requirement 5.6: refusal / reset / network-unreachable / any
                    # other socket error => unreachable.
                    $cause = if ($null -ne $socketException) { $socketException.SocketErrorCode } else { 'ConnectFailed' }
                    ConvertTo-TcpProbeResult -Target $Target -Port $port -Timestamp $timestamp `
                        -Outcome 'Refused' `
                        -Detail "TCP connect to port $port failed: $cause."
                }
            }
            catch [System.Net.Sockets.SocketException] {
                # ConnectAsync can also throw a SocketException synchronously.
                $stopwatch.Stop()
                if ($resolutionErrors -contains $_.Exception.SocketErrorCode) {
                    # Requirement 5.6: resolution failure.
                    ConvertTo-TcpProbeResult -Target $Target -Port $port -Timestamp $timestamp `
                        -ResolutionFailure `
                        -Detail "Name resolution failed for target '$Target': $($_.Exception.Message)"
                }
                else {
                    ConvertTo-TcpProbeResult -Target $Target -Port $port -Timestamp $timestamp `
                        -Outcome 'Refused' `
                        -Detail "TCP connect to port $port failed: $($_.Exception.SocketErrorCode)."
                }
            }
        }
        finally {
            # Requirement 5.4: release the socket handle on every completion path
            # (success, timeout, refusal, resolution failure, or any other error).
            $client.Dispose()
        }
    }

    # Requirement 5.7: fold the per-port results into exactly one aggregate
    # Probe_Result for the iteration.
    return Merge-TcpProbeResult -Target $Target -Timestamp $timestamp -PortResults @($portResults)
}

function Get-NextProbeWait {
    <#
        Pure. Given interval and elapsed (seconds), returns max(0, interval - elapsed).
        Returns [double]/[int] seconds to wait before the next probe start.
        Requirements: 3.4, 3.5
    #>
    [CmdletBinding()]
    param(
        $IntervalSeconds,
        $ElapsedSeconds
    )

    # Cadence is measured start-to-start: the next probe should begin exactly
    # $IntervalSeconds after the current probe started. The remaining wait is
    # therefore the interval minus the time already spent on the current probe.
    # Coerce to [double] so the arithmetic is numeric and consistent on both
    # Windows PowerShell 5.1 and PowerShell 7+ regardless of the incoming type.
    $interval = [double] $IntervalSeconds
    $elapsed  = [double] $ElapsedSeconds

    $remaining = $interval - $elapsed

    # When a probe ran at least as long as the interval ($elapsed >= $interval),
    # $remaining is <= 0 and the next probe re-issues immediately (Requirement 3.5).
    return [math]::Max([double] 0, $remaining)
}

function Get-KeyPollSliceMs {
    <#
        Pure. Given the milliseconds remaining in the interval wait, returns the
        next sleep slice for the interruptible wait: min(1000, RemainingMs).
        Capping the slice at 1000 ms ensures a Key_Poll occurs at least once per
        second, so an Interrupt_Key press is detected within 1 second
        (Requirement 1.4). The result is never greater than 1000, never greater
        than the remaining time (so the slice never overshoots the wait), and
        never negative. Performs no I/O.
        Requirements: 1.4
    #>
    [CmdletBinding()]
    param(
        [int] $RemainingMs
    )

    # Clamp negative remaining values to 0 so the returned slice is never
    # negative even if a caller passes a spurious value. A non-negative
    # RemainingMs is unaffected by this floor.
    $remaining = [math]::Max(0, $RemainingMs)

    # The next slice is the smaller of the one-second poll cap and the time
    # actually left in the interval wait.
    return [math]::Min(1000, $remaining)
}

function Initialize-LogFolder {
    <#
        Side-effecting (filesystem). Ensures the resolved Log_Folder exists so a
        run log file can subsequently be created inside it.

        Contract (fail-fast, Requirements 5.5, 5.6, 5.7):
          - When the folder does NOT exist, it is created including any missing
            parent directories (Requirement 5.5).
          - When the folder ALREADY exists, it is reused as-is; this function
            does NOT create, delete, or modify any existing contents
            (Requirement 5.6).
          - On any failure to set up the folder (creation error or insufficient
            permissions), this function THROWS a terminating error whose message
            names the affected folder and the underlying cause (Requirement
            5.7). It writes no log file. Callers (Invoke-NetProbe) let this
            terminating error propagate so the run fails before any probe is
            performed and before any log file is written.

        Returns the resolved [System.IO.DirectoryInfo] for the folder on success.
        The 'throw on failure' contract is chosen over a result object because it
        matches the design's fail-fast setup policy: the entry point simply lets
        the terminating error surface and stop the run.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string] $LogFolder
    )

    # Requirement 5.6: if the folder already exists, reuse it untouched. No
    # creation is attempted and existing contents are not modified.
    if ([System.IO.Directory]::Exists($LogFolder)) {
        return [System.IO.DirectoryInfo]::new($LogFolder)
    }

    # Requirement 5.5: the folder does not exist, so create it including any
    # missing parent directories. [System.IO.Directory]::CreateDirectory creates
    # all directories along the path and is a no-op for any that already exist,
    # so it never disturbs existing sibling contents.
    #
    # Requirement 5.7: any creation/permission failure is surfaced as a
    # terminating error that names the affected folder and the underlying cause,
    # so the run stops before any probe and no log file is written.
    try {
        return [System.IO.Directory]::CreateDirectory($LogFolder)
    }
    catch {
        $cause = $_.Exception.Message
        throw "Failed to set up log folder '$LogFolder': $cause"
    }
}

function New-RunLogFile {
    <#
        Side-effecting (filesystem). Creates exactly one run log file inside the
        resolved Log_Folder and returns its full path.

        Contract (fail-fast, Requirements 6.1, 6.6):
          - The file name is built from New-LogFileName (sanitized, length
            bounded, '.log' extension) and combined with $LogFolder to form the
            full path.
          - Exactly ONE '.log' file is created for the run (Requirement 6.1).
            The file is created empty so that subsequent Write-LogEntry appends
            target an existing file.
          - On any creation failure, this function THROWS a terminating error
            whose message identifies the log-file-creation failure and names the
            affected path and cause (Requirement 6.6). It also ensures NO partial
            file is left behind: if a file was created before the failure, it is
            removed in the failure path. Callers (Invoke-NetProbe) let the
            terminating error propagate so the run stops.

        The 'throw on failure' contract mirrors Initialize-LogFolder and matches
        the design's fail-fast setup policy.

        Returns the full path [string] to the created log file on success.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string] $LogFolder,

        [Parameter(Mandatory)]
        [string] $Target,

        [Parameter(Mandatory)]
        [datetime] $CreationTime
    )

    # Requirements 6.2-6.5: derive the run log file name via the pure helper so
    # sanitization and length-bounding are applied consistently.
    $fileName = New-LogFileName -Target $Target -CreationTime $CreationTime

    # Combine the folder and file name into the full path. [System.IO.Path]::Combine
    # handles the directory separator across platforms.
    $fullPath = [System.IO.Path]::Combine($LogFolder, $fileName)

    # Requirements 6.1 / 6.6: create exactly one empty '.log' file. Any failure
    # (permission denied, invalid path, folder missing, etc.) is surfaced as a
    # terminating error that names the affected path and cause, and any partial
    # file that may have been created is removed so no partial file remains.
    try {
        # [System.IO.File]::Create creates (or truncates) the file and returns an
        # open handle; close/dispose it immediately so the single empty file is
        # left on disk and subsequent appends can open it. Using the .NET API
        # (rather than New-Item) keeps behavior deterministic across PowerShell
        # 5.1 and 7+.
        $stream = [System.IO.File]::Create($fullPath)
        $stream.Dispose()
    }
    catch {
        $cause = $_.Exception.Message

        # Requirement 6.6: ensure no partial file remains. If the create attempt
        # left a file behind before failing, remove it. Cleanup failures are
        # ignored so the original creation error is the one surfaced.
        try {
            if ([System.IO.File]::Exists($fullPath)) {
                [System.IO.File]::Delete($fullPath)
            }
        }
        catch {
            # Intentionally ignored: best-effort cleanup of a partial file.
        }

        throw "Failed to create log file '$fullPath': $cause"
    }

    # Requirement 6.1: return the single run log file path used for every result.
    return $fullPath
}

function Write-LogEntry {
    <#
        Side-effecting (file). Appends exactly one entry to the run log file.
        On failure, reports a log-write error to the console and returns without throwing.
        Requirements: 7.1, 7.5

        Contract (resilient run-phase policy, unlike the fail-fast setup
        functions Initialize-LogFolder / New-RunLogFile):
          - Requirement 7.1: append exactly ONE entry per call. The supplied
            $Line is written once, followed by a single trailing newline, to the
            existing run log file. A single call therefore adds exactly one line.
          - Requirement 7.5: on ANY write failure (full or partial), this
            function does NOT throw. It reports a distinct log-write error to the
            console (via Write-Error, which surfaces on the host without stopping
            the caller) and returns so the probe loop continues with the next
            probe.
    #>
    [CmdletBinding()]
    param(
        [string] $LogFilePath,
        [string] $Line
    )

    # Requirement 7.1: build exactly one entry - the line plus a single trailing
    # newline - so each call appends one complete entry. Environment.NewLine is
    # used so entries are terminated with the host's native line ending
    # (\r\n on Windows, where CMTrace is used).
    $entry = '{0}{1}' -f $Line, [System.Environment]::NewLine

    try {
        # Robust append using the .NET API (deterministic across Windows
        # PowerShell 5.1 and PowerShell 7+). A UTF-8 encoding WITHOUT a BOM is
        # used so no byte-order mark is injected mid-file on appends; this keeps
        # the CMTrace-format file clean and readable. AppendAllText opens,
        # writes, flushes, and closes the file in a single call.
        $utf8NoBom = [System.Text.UTF8Encoding]::new($false)
        [System.IO.File]::AppendAllText($LogFilePath, $entry, $utf8NoBom)
    }
    catch {
        # Requirement 7.5: any write failure (full or partial) is reported to the
        # console as a distinct log-write error and then swallowed so the run
        # continues. Write-Error surfaces the error on the host's error stream
        # without terminating the caller (no 'throw'), so the probe loop proceeds
        # to the next probe.
        Write-Error "Failed to write log entry to '$LogFilePath': $($_.Exception.Message)"
        return
    }
}

function Test-IsAffirmativeResponse {
    <#
        Pure. Classifies a caller's Open_Log_Prompt response as affirmative or not.

        Returns [bool]:
          - $true  ONLY for an accepted affirmative token ('y' or 'yes'),
            compared case-insensitively with surrounding whitespace ignored.
          - $false for accepted negative tokens ('n' / 'no'), for any
            unrecognized text, and for the empty string that represents a
            30-second timeout (the caller supplies '' on timeout).

        Performs no I/O. The timeout is realized by the caller passing an empty
        response, which this function classifies as non-affirmative.
        Requirements: 3.3, 3.4, 4.4
    #>
    [CmdletBinding()]
    param(
        [string] $Response
    )

    # Requirements 3.4 / 4.4: a $null, empty, or whitespace-only response - which
    # includes the empty string the caller supplies on a 30-second timeout - is
    # never affirmative.
    if ([string]::IsNullOrWhiteSpace($Response)) {
        return $false
    }

    # Requirement 3.3: surrounding whitespace is ignored and the comparison is
    # case-insensitive. Only the accepted affirmative tokens 'y' and 'yes' are
    # treated as affirmative; every other value (including the negative tokens
    # 'n'/'no' and any unrecognized text) is non-affirmative.
    $normalized = $Response.Trim()

    return $normalized -eq 'y' -or $normalized -eq 'yes'
}

function Start-ProbeLoop {
    <#
        Side-effecting. Owns the probe loop, timing, and interrupt handling.

        For each iteration the loop:
          1. Records the probe start time (Requirement 3.1: the first probe is
             performed immediately - the loop probes BEFORE sleeping - so it runs
             within ~1 second of the loop start).
          2. Performs one probe, choosing the probe function purely from
             Context.ProbeMode (Requirements 5.1, 5.2, 7.6): 'TCP' invokes
             Invoke-TcpProbe against Context.ProbePorts, any other value ('ICMP')
             invokes Invoke-SingleProbe. Both branches forward the shared
             Context.TimeoutMs (Requirements 6.7, 6.8) and both yield one
             Probe_Result, so the downstream path is identical regardless of mode.
             The ICMP call site now forwards Context.TimeoutMs explicitly; this is
             backward compatible because Invoke-SingleProbe and Context.TimeoutMs
             both default to 4000 ms.
          3. Writes the console line via Format-ConsoleLine (Requirement 4.1).
             Write-Host is used because this is user-facing host output, not
             pipeline data.
          4. Appends one log entry to the run log file via Format-LogEntry
             + Write-LogEntry (Requirements 3.3, 7.1). Format-LogEntry selects the
             log-line format purely from RunContext.LogFormat (CMTrace via
             Format-CMTraceEntry, Plain_Text via Format-ConsoleLine).
             Write-LogEntry is resilient: a write failure is reported and the run
             continues.
          5. Computes the remaining wait via Get-NextProbeWait using the measured
             elapsed seconds of this probe, so cadence is measured start-to-start
             (a long probe re-issues immediately with a 0 wait).
          6. Sleeps for that wait (fractional seconds are honored via
             -Milliseconds) and repeats.

        Interrupt handling (Requirement 3.7): the loop body runs inside
        try/finally. On Ctrl+C PowerShell raises a terminating pipeline stop. The
        in-flight Invoke-SingleProbe completes or hits its 4000 ms timeout, the
        pipeline-stop then propagates, the finally block performs cleanup, and the
        loop exits WITHOUT issuing any further ICMP request. The interrupt is NOT
        swallowed here, so it terminates the loop rather than being retried.

        Interrupt polling (Requirements 1.1, 1.3, 1.4, 1.6, 1.7): interactivity
        is determined ONCE at loop entry (via Test-IsInteractiveHost unless
        overridden by the -Interactive test seam). In an Interactive_Host the
        loop performs a non-blocking Key_Poll after each probe and again during
        the interval wait:
          - After each probe it calls the key poller (Read-PendingInterrupt by
            default) and breaks the loop the moment the InterruptState's
            Requested flag becomes $true, so no further ICMP request is issued
            (Requirement 1.3). The in-flight probe has already completed (or hit
            its 4000 ms timeout) before this check, satisfying the finish-in-flight
            contract.
          - The interval wait is performed in slices of Get-KeyPollSliceMs
            milliseconds (at most 1000 ms each) with a Key_Poll between slices, so
            an Interrupt_Key press is detected within 1 second of the keypress
            (Requirement 1.4) and the wait is abandoned immediately once an
            interruption is requested.
        In a Non_Interactive_Host the loop behaves EXACTLY as the base feature: a
        single Start-Sleep for the computed wait and no key polling at all - the
        run relies solely on the existing Ctrl+C interruption path (Requirement
        1.6). When the loop ends because of an interruption request it returns
        normally so control returns to the Console prompt with the session kept
        open (Requirement 1.7).

        Test seam (-MaxIterations): the loop is naturally infinite (it runs until
        interrupted). To let the integration test (task 10.3) exercise the loop
        deterministically without relying on Ctrl+C, an optional -MaxIterations
        parameter bounds the number of iterations. The default of 0 means
        "infinite / run until interrupt" (production behavior); any positive value
        stops the loop cleanly after that many probes. The final iteration skips
        the trailing sleep so a bounded run does not wait needlessly after its
        last probe.

        Additional test seams:
          -InterruptState : an optional pre-built InterruptState so a test can
             inspect the recorded interruption after the loop returns. Defaults
             to a fresh New-InterruptState.
          -Interactive    : an optional [bool] override for the interactivity
             decision. When not supplied, Test-IsInteractiveHost is consulted
             once at loop entry (production behavior). Supplying $true or $false
             lets a test force the Interactive_Host or Non_Interactive_Host path
             deterministically.
          -KeyPoll        : an optional scriptblock that receives the
             InterruptState and performs the Key_Poll, so a test can drive key
             polling deterministically (for example, flip Requested after N
             calls) without a real console. Defaults to Read-PendingInterrupt.

        Requirements: 1.1, 1.3, 1.4, 1.6, 1.7, 3.1, 3.7, 4.1, 7.1
    #>
    [CmdletBinding()]
    param(
        [pscustomobject] $Context,

        # Test seam only. 0 = infinite (production: run until Ctrl+C). A positive
        # value runs exactly that many probe iterations then exits cleanly.
        [int] $MaxIterations = 0,

        # Optional pre-built InterruptState. Defaults to a fresh state so the
        # loop owns its own single-run interruption flag in production.
        [pscustomobject] $InterruptState,

        # Test seam: force the interactivity decision. $null (unsupplied) means
        # "consult Test-IsInteractiveHost once at loop entry" (production).
        [System.Nullable[bool]] $Interactive = $null,

        # Test seam: the Key_Poll performed after each probe and between interval
        # slices. Defaults to a non-blocking Read-PendingInterrupt of the real
        # console. A test can inject a deterministic poller here.
        [scriptblock] $KeyPoll = { param($State) Read-PendingInterrupt -State $State }
    )

    # Construct the single-run InterruptState if the caller did not supply one.
    if (-not $InterruptState) {
        $InterruptState = New-InterruptState
    }

    # Determine interactivity ONCE at loop entry (Requirements 1.1, 1.6). In a
    # Non_Interactive_Host the loop runs the base single-sleep path with no
    # polling; in an Interactive_Host it performs the Key_Poll after each probe
    # and during the interval wait. The -Interactive seam overrides host
    # detection for deterministic tests.
    if ($null -ne $Interactive) {
        $isInteractive = [bool] $Interactive
    }
    else {
        $isInteractive = Test-IsInteractiveHost
    }

    $iteration = 0

    try {
        # Requirement 3.1: probe immediately (no initial sleep) so the first
        # probe happens within ~1 second of the loop start; repeat until an
        # interrupt is raised (or the bounded test iteration count is reached).
        while ($true) {

            # Measure the start-to-start elapsed time of this probe so the wait
            # to the next probe can be computed from the probe start (Requirement
            # 3.4/3.5 via Get-NextProbeWait).
            $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()

            # Requirements 5.1 / 5.2 / 7.6: the probe function is chosen SOLELY
            # from Context.ProbeMode. 'TCP' issues one aggregate TCP probe across
            # Context.ProbePorts; any other value takes the ICMP path. Both
            # branches forward the shared Context.TimeoutMs (Requirements 6.7 /
            # 6.8) and both return exactly one Probe_Result, so the console line,
            # log entry, cadence, and interrupt polling below are untouched. On
            # Ctrl+C the in-flight call is allowed to finish (or hit its timeout)
            # before the pipeline-stop propagates.
            if ($Context.ProbeMode -eq 'TCP') {
                $result = Invoke-TcpProbe -Target $Context.Target -Ports $Context.ProbePorts -TimeoutMs $Context.TimeoutMs
            }
            else {
                $result = Invoke-SingleProbe -Target $Context.Target -TimeoutMs $Context.TimeoutMs
            }

            $stopwatch.Stop()

            # Requirement 4.1: write one console line for the result. Write-Host
            # is intentional - this is user-facing host output, not pipeline data.
            Write-Host (Format-ConsoleLine -ProbeResult $result)

            # Requirements 3.3 / 5.1: append exactly one log entry to the single
            # run log file. The log line format is selected purely from
            # RunContext.LogFormat via Format-LogEntry, which delegates to
            # Format-CMTraceEntry (CMTrace) or Format-ConsoleLine (Plain_Text)
            # while the console line above stays unconditional. Format-LogEntry
            # throws a distinct error on an invalid/absent RunContext.LogFormat
            # before any entry is appended (Requirement 3.4). Write-LogEntry is
            # resilient (Requirement 7.5) and never throws, so a log-write
            # failure does not stop the run.
            $line = Format-LogEntry -ProbeResult $result -Context $Context
            Write-LogEntry -LogFilePath $Context.LogFilePath -Line $line

            # Requirement 1.1 / 1.3: in an Interactive_Host, perform a
            # non-blocking Key_Poll immediately AFTER the in-flight probe has
            # completed. If an Interrupt_Key was pressed, Requested becomes $true
            # and the loop breaks here so NO further ICMP request is issued.
            if ($isInteractive) {
                [void] (& $KeyPoll $InterruptState)
                if ($InterruptState.Requested) {
                    break
                }
            }

            $iteration++

            # Test seam: stop cleanly once the bounded iteration count is reached.
            # The trailing sleep is skipped on the final bounded iteration.
            if ($MaxIterations -gt 0 -and $iteration -ge $MaxIterations) {
                break
            }

            # Requirement 3.4/3.5: compute the remaining wait to the next probe
            # start from the elapsed duration of this probe. A probe that ran at
            # least as long as the interval yields a 0 wait (immediate re-issue).
            $elapsedSeconds = $stopwatch.Elapsed.TotalSeconds
            $waitSeconds    = Get-NextProbeWait -IntervalSeconds $Context.IntervalSec -ElapsedSeconds $elapsedSeconds

            if ($waitSeconds -gt 0) {
                # Sleep in milliseconds so fractional-second waits are honored
                # across Windows PowerShell 5.1 and PowerShell 7+.
                $waitMs = [int] [math]::Round([double] $waitSeconds * 1000.0, 0)

                if ($isInteractive) {
                    # Requirement 1.4: perform the interval wait in slices of at
                    # most 1000 ms (Get-KeyPollSliceMs), polling for an
                    # Interrupt_Key between slices so a keypress is detected
                    # within 1 second and the wait is abandoned the moment an
                    # interruption is requested.
                    $remainingMs = $waitMs
                    while ($remainingMs -gt 0) {
                        $sliceMs = Get-KeyPollSliceMs -RemainingMs $remainingMs
                        if ($sliceMs -gt 0) {
                            Start-Sleep -Milliseconds $sliceMs
                        }
                        $remainingMs -= $sliceMs

                        [void] (& $KeyPoll $InterruptState)
                        if ($InterruptState.Requested) {
                            break
                        }
                    }

                    # Requirement 1.3: an interruption requested during the wait
                    # ends the loop before the next probe - no further ICMP.
                    if ($InterruptState.Requested) {
                        break
                    }
                }
                elseif ($waitMs -gt 0) {
                    # Requirement 1.6: Non_Interactive_Host uses the base single
                    # Start-Sleep with no polling; Ctrl+C remains the only
                    # interruption path.
                    Start-Sleep -Milliseconds $waitMs
                }
            }
        }
    }
    finally {
        # Requirement 3.7: teardown after an interrupt (or bounded completion).
        # No further ICMP requests are issued from here; the loop has already
        # exited. This block exists so that on Ctrl+C - once the in-flight probe
        # has finished or timed out - cleanup runs and the loop ends cleanly.
        # There are no unmanaged handles to release here (Invoke-SingleProbe and
        # Write-LogEntry each own and release their own resources per call), so
        # this is a clean exit point. The interrupt is not swallowed.
    }
}

function Invoke-NetProbe {
    <#
        Entry point. Wires parameter validation (fail-fast), log setup, log file
        creation, and the probe loop together. Called by the imperative shell
        below only when the script is invoked directly.
        Requirements: 1.2, 1.3, 1.4, 3.6, 5.3, 5.7, 6.1, 6.6
    #>
    [CmdletBinding()]
    param(
        [string] $ProbeTarget,
        $ProbeIntervalSeconds,
        [string] $LogFolderPath,
        [string] $LogFormat,
        [string] $ProbeMode,
        [int[]] $ProbePort,
        $TimeoutMs
    )

    # Fail-fast validation phase (design: "Validation phase"). All parameter
    # validation and log setup happen before any probe. The FIRST failure writes
    # a specific error to the console and terminates the run: no ICMP request and
    # no log file (created only in step 6) are produced when validation fails.

    # ---- Step 1: probe target (Requirements 1.2, 1.3, 1.4) -------------------

    # Requirement 1.2: a missing (not supplied) or empty target terminates the
    # run before any probe with a distinct missing-target error. Because the
    # parameter is [string], an omitted value arrives as an empty string;
    # $PSBoundParameters.ContainsKey covers the "not bound at all" case as well.
    if (-not $PSBoundParameters.ContainsKey('ProbeTarget') -or [string]::IsNullOrEmpty($ProbeTarget)) {
        Write-Error 'No probe target was supplied. Specify a ProbeTarget (an IPv4 address, IPv6 address, or domain name) to probe.'
        return
    }

    # Requirements 1.3 / 1.4: a whitespace-only or malformed target terminates
    # the run before any probe with an invalid-target error that names the
    # specific reason returned by the pure validator.
    $targetResult = Test-ProbeTargetFormat -Target $ProbeTarget
    if (-not $targetResult.IsValid) {
        Write-Error "Invalid probe target '$ProbeTarget': $($targetResult.Reason)"
        return
    }

    # ---- Step 2: probe interval (Requirement 3.6) ----------------------------

    # Requirement 3.6: a non-numeric interval, or one outside [1, 86400], is
    # reported (with the offending value named by the validator's Reason) and
    # terminates the run before any probe. Requirement 3.3: an unsupplied
    # interval yields the default of 5 via the validator's Value.
    $intervalResult = Test-ProbeInterval -IntervalSeconds $ProbeIntervalSeconds
    if (-not $intervalResult.IsValid) {
        Write-Error "Invalid probe interval: $($intervalResult.Reason)"
        return
    }
    $intervalSeconds = $intervalResult.Value

    # ---- Step 3: log folder path (Requirements 5.3, 5.4) ---------------------

    # Distinguish "not supplied at all" from "supplied empty/whitespace":
    #   - Not supplied  -> resolve the Default_Log_Folder (Test-LogFolderPath $null).
    #   - Supplied      -> validate the given value; empty/whitespace/>260 is
    #                      invalid (Requirement 5.3).
    # $PSBoundParameters is used because a [string] parameter cannot otherwise
    # distinguish an omitted value (empty string) from an explicit empty string.
    if ($PSBoundParameters.ContainsKey('LogFolderPath')) {
        $folderResult = Test-LogFolderPath -LogFolderPath $LogFolderPath
    }
    else {
        $folderResult = Test-LogFolderPath -LogFolderPath $null
    }
    if (-not $folderResult.IsValid) {
        Write-Error "Invalid log folder path: $($folderResult.Reason)"
        return
    }
    $resolvedLogFolder = $folderResult.ResolvedPath

    # ---- Step 3a: log format (Requirements 1.5, 1.6, 2.1, 2.3) ---------------

    # Distinguish "not supplied at all" from "supplied empty/whitespace":
    #   - Not supplied  -> default to the Default_Log_Format 'Plain_Text'
    #                      (Test-LogFormat $null).
    #   - Supplied      -> validate the given value; empty/whitespace or any
    #                      non-member token is invalid (Requirements 1.5, 1.6).
    # $PSBoundParameters is used because a [string] parameter cannot otherwise
    # distinguish an omitted value (empty string) from an explicit empty string.
    if ($PSBoundParameters.ContainsKey('LogFormat')) {
        $logFormatResult = Test-LogFormat -LogFormat $LogFormat
    }
    else {
        $logFormatResult = Test-LogFormat -LogFormat $null
    }
    # Requirements 1.5 / 1.6: an invalid or empty/whitespace value writes a
    # distinct invalid-log-format error (naming the value via the validator's
    # Reason) and terminates the run before folder setup, log-file creation, and
    # any probe.
    if (-not $logFormatResult.IsValid) {
        Write-Error "Invalid log format: $($logFormatResult.Reason)"
        return
    }
    $logFormatValue = $logFormatResult.Value

    # Requirement 2.3: defensive post-condition. After defaulting, the resolved
    # value must be a member of Log_Format_Values ('CMTrace' or 'Plain_Text').
    # If it is not, terminate the run before any probe rather than proceed with
    # an unset log format.
    if ($logFormatValue -cne 'CMTrace' -and $logFormatValue -cne 'Plain_Text') {
        Write-Error "Could not default log format to 'Plain_Text'; resolved value '$logFormatValue' is not a recognized log format."
        return
    }

    # ---- Step 3b: probe mode (Requirements 1.1, 1.5, 7.1) --------------------

    # Distinguish "not supplied at all" from "supplied empty/whitespace":
    #   - Not supplied  -> default to the Default_Probe_Mode 'ICMP'
    #                      (Test-ProbeMode $null).
    #   - Supplied      -> validate the given value; empty/whitespace or any
    #                      non-member token is invalid (Requirements 1.3, 1.4).
    # $PSBoundParameters is used because a [string] parameter cannot otherwise
    # distinguish an omitted value (empty string) from an explicit empty string.
    if ($PSBoundParameters.ContainsKey('ProbeMode')) {
        $probeModeResult = Test-ProbeMode -Mode $ProbeMode
    }
    else {
        $probeModeResult = Test-ProbeMode -Mode $null
    }
    # Requirement 1.5: an invalid or empty/whitespace value writes a distinct
    # invalid-probe-mode error (naming the value via the validator's Reason) and
    # terminates the run before the RunContext is built, before log-file
    # creation, and before any probe.
    if (-not $probeModeResult.IsValid) {
        Write-Error "Invalid probe mode: $($probeModeResult.Reason)"
        return
    }
    $probeModeValue = $probeModeResult.Value

    # ---- Step 3c: probe ports (Requirements 2.4, 2.5, 2.9, 7.3) --------------

    # Ports are validated against the resolved probe mode. Distinguish "not
    # supplied at all" from "supplied":
    #   - Not supplied  -> pass $null so the mode-specific defaults apply
    #                      (ICMP => @(); TCP => @(443)).
    #   - Supplied      -> validate/dedupe/range-check the given list.
    # $PSBoundParameters is used because a bound [int[]] parameter is meaningful
    # while an omitted one must fall back to the defaults.
    if ($PSBoundParameters.ContainsKey('ProbePort')) {
        $probePortsResult = Test-ProbePorts -Ports $ProbePort -Mode $probeModeValue
    }
    else {
        $probePortsResult = Test-ProbePorts -Ports $null -Mode $probeModeValue
    }
    # Requirement 2.9: an invalid port list writes a distinct invalid-probe-port
    # error (naming the offending value via the validator's Reason) and
    # terminates the run before the RunContext is built, before log-file
    # creation, and before any probe.
    if (-not $probePortsResult.IsValid) {
        Write-Error "Invalid probe port: $($probePortsResult.Reason)"
        return
    }
    $probePortsValue = $probePortsResult.Value

    # ---- Step 3d: shared timeout (Requirements 6.1, 6.5, 6.6) ----------------

    # Distinguish "not supplied at all" from "supplied":
    #   - Not supplied  -> default to the Default_Timeout_Ms 4000
    #                      (Test-ProbeTimeout $null).
    #   - Supplied      -> validate the given value; non-numeric/non-finite/
    #                      non-integer/out-of-range is invalid (Requirements
    #                      6.3, 6.4).
    # $PSBoundParameters is used because an omitted value must fall back to the
    # default rather than be treated as an explicit value.
    if ($PSBoundParameters.ContainsKey('TimeoutMs')) {
        $timeoutResult = Test-ProbeTimeout -TimeoutMs $TimeoutMs
    }
    else {
        $timeoutResult = Test-ProbeTimeout -TimeoutMs $null
    }
    # Requirement 6.5: an invalid timeout writes a distinct invalid-probe-timeout
    # error (naming the value via the validator's Reason) and terminates the run
    # before the RunContext is built, before log-file creation, and before any
    # probe.
    if (-not $timeoutResult.IsValid) {
        Write-Error "Invalid probe timeout: $($timeoutResult.Reason)"
        return
    }
    $timeoutMsValue = $timeoutResult.Value

    # ---- Step 4: build the RunContext ----------------------------------------

    # CMTrace 'context' field must be non-empty (Requirement 8.2). Prefer the
    # current user (domain-qualified when available), falling back progressively
    # so the value is never empty.
    if (-not [string]::IsNullOrWhiteSpace($env:USERNAME)) {
        if (-not [string]::IsNullOrWhiteSpace($env:USERDOMAIN)) {
            $contextValue = "$env:USERDOMAIN\$env:USERNAME"
        }
        else {
            $contextValue = $env:USERNAME
        }
    }
    else {
        $contextValue = 'Net_Probe'
    }

    # CMTrace 'file' field: the script leaf name, with a stable fallback.
    if (-not [string]::IsNullOrWhiteSpace($PSCommandPath)) {
        $scriptFileName = [System.IO.Path]::GetFileName($PSCommandPath)
    }
    else {
        $scriptFileName = 'Net-Probe.ps1'
    }

    $runContext = [pscustomobject]@{
        Target      = $ProbeTarget
        IntervalSec = $intervalSeconds
        LogFolder   = $resolvedLogFolder
        LogFilePath = ''  # filled in after the run log file is created (step 6)
        Component   = 'Net_Probe'
        Context     = $contextValue
        FileName    = $scriptFileName
        ThreadId    = [System.Threading.Thread]::CurrentThread.ManagedThreadId
        # Requirements 3.1 / 3.2: carry the validated, canonical Log_Format on
        # the RunContext so the log-writing path has a single source for the
        # format decision. $logFormatValue is always exactly one member of
        # Log_Format_Values ('CMTrace' or 'Plain_Text') after Step 3a.
        LogFormat   = $logFormatValue
        # Requirements 7.1 / 7.2 / 7.3 / 7.4 / 7.5 / 6.6: carry the validated
        # probe mode, normalized ports, and shared timeout on the RunContext so
        # Start-ProbeLoop has a single source for the mode decision and both
        # probe functions receive the shared timeout. $probeModeValue is exactly
        # one member of Probe_Mode_Values; $probePortsValue is @() for ICMP or a
        # non-empty deduped [int[]] for TCP; $timeoutMsValue is in [1, 300000].
        ProbeMode   = $probeModeValue
        ProbePorts  = $probePortsValue
        TimeoutMs   = $timeoutMsValue
    }

    # ---- Step 5: ensure the log folder exists (Requirement 5.7) --------------

    # Initialize-LogFolder throws a terminating error on any setup failure
    # (creation error or insufficient permissions). Let it propagate so the run
    # stops before any probe and no log file is written (folder-setup error).
    [void] (Initialize-LogFolder -LogFolder $resolvedLogFolder)

    # ---- Step 6: create the single run log file (Requirements 6.1, 6.6) ------

    # New-RunLogFile creates exactly one '.log' file for the run and throws a
    # terminating error on creation failure (leaving no partial file). Let the
    # terminating error propagate as the log-file-creation error. This is the
    # first point at which any file is produced - all validation is already done.
    $logFilePath = New-RunLogFile -LogFolder $resolvedLogFolder -Target $ProbeTarget -CreationTime (Get-Date)
    $runContext.LogFilePath = $logFilePath

    # ---- Step 6a: write the Startup_Banner once, before the first probe ------

    # Requirements 3.1 / 3.2 / 3.3 / 3.4: emit the Startup_Banner exactly one
    # time per Run, after the run log file exists and before any probe runs, so
    # the Caller sees the Session_Details and stop-key before the first probe
    # result and no further banner appears during the loop.
    # Requirement 3.5: Write-StartupBanner never throws (it contains its
    # Write-Host in a try/catch), so the run always advances into the probe loop
    # even if the banner write fails.
    Write-StartupBanner -Context $runContext

    # ---- Step 7: enter the probe loop ----------------------------------------

    # Production wiring: run until the caller interrupts (Ctrl+C or the Q-key).
    # MaxIterations is intentionally left at its default of 0 (infinite); the
    # bounded test seam is not used here.
    #
    # The probe loop is wrapped in try/finally so the teardown phase runs on
    # EVERY Run_Termination (Requirements 1.7, 2.1, 3.1): a Q-key interruption
    # returns from Start-ProbeLoop normally, a bounded completion returns
    # normally, and a Ctrl+C raises a terminating pipeline-stop that propagates
    # out of Start-ProbeLoop - in all three cases the finally block executes so
    # the log path is shown and the open prompt is offered.
    try {
        Start-ProbeLoop -Context $runContext
    }
    finally {
        # ---- Step 8: teardown / interaction phase ----------------------------

        # Requirements 2.1 / 2.3: write the run's Log_File_Path (or the no-log
        # message) to the Console as a single line on Run_Termination.
        Write-TerminationOutput -Context $runContext

        # Requirements 3.1 / 3.x: offer the Open_Log_Prompt and open the log with
        # the Default_Application when applicable (Interactive_Host with a log
        # path). This is a no-op in a Non_Interactive_Host or when no path exists.
        Invoke-OpenLogWorkflow -Context $runContext
    }
}

function Test-IsInterruptKey {
    <#
        Pure. Classifies a single key character as the Interrupt_Key.
        Returns [bool] - $true iff $KeyChar is the Interrupt_Key ('q' or 'Q').
        Performs no I/O.
        Requirements: 1.2, 1.5
    #>
    [CmdletBinding()]
    param(
        [char] $KeyChar
    )

    # Requirement 1.2: the Interrupt_Key is the 'Q' key in either case. The
    # comparison is case-insensitive against the single Interrupt_Key character,
    # so 'q' and 'Q' are the only characters that qualify.
    # Requirement 1.5: every other character is a non-interrupt key and returns
    # $false so the caller discards it.
    return [char]::ToLowerInvariant($KeyChar) -eq 'q'
}

function New-InterruptState {
    <#
        Pure. Creates a fresh single-run interruption-state object.
        Returns [pscustomobject]@{ Requested = [bool] } initialized to $false.
        Requirements: 1.2
    #>
    [CmdletBinding()]
    param()

    # The InterruptState carries a single boolean flag that starts $false and
    # transitions to $true exactly once when the Interrupt_Key is first pressed.
    return [pscustomobject]@{ Requested = $false }
}

function Update-InterruptState {
    <#
        Pure. Accumulates a single key character into the interruption state.
        Returns the (same) $State object, updated in place.
        Requirements: 1.2, 1.5
    #>
    [CmdletBinding()]
    param(
        [pscustomobject] $State,
        [char] $KeyChar
    )

    # Requirement 1.2: record exactly one interruption request. Setting
    # Requested is idempotent - once it is $true it never reverts, so any number
    # of Interrupt_Key presses after the first has no further effect.
    # Requirement 1.5: a non-Interrupt_Key character leaves the state unchanged
    # (the keypress is discarded).
    if (Test-IsInterruptKey -KeyChar $KeyChar) {
        $State.Requested = $true
    }

    return $State
}

function Format-TerminationMessage {
    <#
        Pure. Builds the single-line message written to the Console on
        Run_Termination announcing where (or whether) the run log file was
        written.

        Returns [string] - a single line (no embedded newline):
          - When $LogFilePath is a NON-BLANK value (Requirements 2.1, 2.2): a
            message that contains the complete, unmodified Log_File_Path as an
            exact contiguous substring. The path value is embedded verbatim with
            no truncation, character substitution, or characters inserted within
            it, so the Caller can identify exactly which file holds the run's
            results.
          - When $LogFilePath is $null, empty, or whitespace-only
            (Requirement 2.3): a message stating that no log file was created for
            the run. It contains NO path value.

        Performs no I/O.
        Requirements: 2.1, 2.2, 2.3
    #>
    [CmdletBinding()]
    param(
        [string] $LogFilePath
    )

    # Requirement 2.3: a $null, empty, or whitespace-only path means no
    # Log_File was created for the run. Emit a distinct single-line message that
    # carries no path value.
    if ([string]::IsNullOrWhiteSpace($LogFilePath)) {
        return 'No log file was created for this run.'
    }

    # Requirements 2.1 / 2.2: embed the Log_File_Path verbatim as a contiguous
    # substring on a single line. The path is concatenated unmodified - no
    # trimming, escaping, or truncation - so the complete character sequence is
    # recoverable from the message.
    return "Log file for this run: $LogFilePath"
}

function Format-StartupBanner {
    <#
        Pure. Builds the multi-line Startup_Banner written to the Console once,
        before the first probe of a Run, from the RunContext Session_Details plus
        an interactivity flag.

        Returns [string] - the multi-line banner text (lines joined by newlines):
          - Stop-key line (Requirements 1.1, 1.2, 1.3): when $Interactive is
            $true, includes exactly one line stating that pressing the Q key
            (either 'q' or 'Q') stops the probing. When $Interactive is $false,
            this line is omitted entirely, so the banner contains no reference to
            the Interrupt_Key.
          - Target (Requirement 2.1): includes the RunContext Target value
            verbatim as an exact contiguous substring - no truncation, character
            substitution, or characters inserted within the value.
          - Interval (Requirement 2.2): includes the RunContext IntervalSec
            integer verbatim as a contiguous substring, accompanied by wording
            indicating the value is measured in seconds.
          - Log path (Requirements 2.3, 2.4): when LogFilePath is non-blank,
            includes the complete path verbatim as an exact contiguous substring;
            when it is $null, empty, or whitespace-only, includes text stating
            that no log file path is available for the run and contains no path
            value.

        Deterministic (Requirement 4.2): returns an identical string for any two
        invocations supplied with equal RunContext field values and equal
        $Interactive input.

        Performs no Console, host, or file I/O (Requirement 4.1).
        Requirements: 1.1, 1.2, 1.3, 2.1, 2.2, 2.3, 2.4, 4.1, 4.2
    #>
    [CmdletBinding()]
    param(
        [pscustomobject] $Context,
        [bool] $Interactive
    )

    # Collect the banner lines in a fixed order so the output is deterministic
    # for equal inputs (Requirement 4.2).
    $lines = [System.Collections.Generic.List[string]]::new()

    $lines.Add('=== Net-Probe session starting ===')

    # Requirement 2.1: embed the Probe_Target verbatim as a contiguous substring.
    # The value is concatenated unmodified - no trimming, escaping, or truncation.
    $lines.Add("Target: $($Context.Target)")

    # Requirement 2.2: embed the IntervalSec integer verbatim as a contiguous
    # substring with explicit "seconds" wording so the cadence is unambiguous.
    $lines.Add("Interval: $($Context.IntervalSec) seconds")

    # Requirements 2.3 / 2.4: a $null, empty, or whitespace-only Log_File_Path
    # means no run log path is available; emit a distinct line that carries no
    # path value. Otherwise embed the complete path verbatim as a contiguous
    # substring.
    if ([string]::IsNullOrWhiteSpace($Context.LogFilePath)) {
        $lines.Add('Log file: no log file path is available for this run.')
    }
    else {
        $lines.Add("Log file: $($Context.LogFilePath)")
    }

    # Requirements 1.1 / 1.2 / 1.3: announce the Interrupt_Key ONLY in an
    # Interactive_Host. Exactly one stop-key line names the Q key (either case);
    # when non-interactive the line is omitted so the banner references no
    # Interrupt_Key at all.
    if ($Interactive) {
        $lines.Add("Press the Q key ('q' or 'Q') to stop probing.")
    }

    # Join with the platform newline; the ordering above makes this deterministic
    # for equal RunContext field values and equal $Interactive input.
    return ($lines -join [System.Environment]::NewLine)
}

function Test-IsInteractiveHost {
    <#
        Side-effecting (host inspection). Determines whether the current host is
        an Interactive_Host in which a keypress can be detected and a prompt
        response can be read from the Caller.

        Returns [bool]:
          - $true  ONLY when ALL of the following hold:
              * [System.Environment]::UserInteractive is $true, AND
              * input is NOT redirected (-not [System.Console]::IsInputRedirected), AND
              * [System.Console]::KeyAvailable can be read without throwing.
          - $false otherwise. A $false result classifies a Non_Interactive_Host,
            so the Probe_Loop skips the Key_Poll (Requirement 1.6) and the
            teardown phase skips the Open_Log_Prompt and the open (Requirement 3.5).

        Reading [Console]::KeyAvailable throws when the input stream is redirected
        or headless; that throw is caught and treated as Non_Interactive_Host, so
        this function itself never throws.
        Requirements: 1.6, 3.5
    #>
    [CmdletBinding()]
    param()

    # Requirement 1.6 / 3.5: a host that is not user-interactive, or whose input
    # is redirected, cannot detect a keypress or read a prompt response, so it is
    # a Non_Interactive_Host.
    if (-not [System.Environment]::UserInteractive) {
        return $false
    }

    if ([System.Console]::IsInputRedirected) {
        return $false
    }

    # Reading [Console]::KeyAvailable is the definitive probe: on a redirected or
    # headless stream it throws (e.g. an IOException/InvalidOperationException),
    # which classifies the host as non-interactive. Any throw here yields $false
    # so this function never propagates an exception.
    try {
        [void] [System.Console]::KeyAvailable
    }
    catch {
        return $false
    }

    return $true
}

function Read-PendingInterrupt {
    <#
        Side-effecting (console input). Performs a single non-blocking Key_Poll:
        drains every currently-buffered key without blocking and folds each into
        the supplied InterruptState.

        While [System.Console]::KeyAvailable is $true, consumes the next key with
        [System.Console]::ReadKey($true) (the $true suppresses echo) and feeds its
        KeyChar to Update-InterruptState. When no key is buffered the loop does not
        execute and the function returns immediately, so Probe execution and
        interval waiting are never blocked (Requirement 1.1). Non-Interrupt_Key
        keys are consumed and discarded by Update-InterruptState (Requirement 1.5).

        Returns the (same) $State object, updated in place.
        Requirements: 1.1, 1.5
    #>
    [CmdletBinding()]
    param(
        [pscustomobject] $State
    )

    # Requirement 1.1: [Console]::KeyAvailable is a non-blocking probe of the
    # input buffer, so this loop drains only the keys already buffered and exits
    # the instant the buffer is empty - it never waits for a keypress.
    while ([System.Console]::KeyAvailable) {
        # $true = do not echo the consumed key to the Console.
        $key = [System.Console]::ReadKey($true)

        # Requirement 1.5: Update-InterruptState records an interruption request
        # only for the Interrupt_Key and discards every other key.
        [void] (Update-InterruptState -State $State -KeyChar $key.KeyChar)
    }

    return $State
}

function Show-OpenLogPrompt {
    <#
        Side-effecting (console I/O). Presents the Open_Log_Prompt and reads the
        Caller's response under a bounded timeout.

        Writes a single prompt line to the Console displaying the accepted
        affirmative ('y'/'yes') and negative ('n'/'no') response options
        (Requirement 3.1), then performs a stopwatch-bounded timed read: it polls
        the input buffer with a non-blocking [System.Console]::KeyAvailable and
        consumes ready keys with [System.Console]::ReadKey($true), accumulating
        their characters until the Caller presses Enter or the elapsed time
        reaches $TimeoutSeconds.

        Returns [string]:
          - the accumulated response (trimmed of the terminating newline) when the
            Caller completes an entry by pressing Enter within the timeout, or
          - '' (the empty string) when $TimeoutSeconds elapses with no completed
            response (Requirement 3.4). The empty string is classified as
            non-affirmative by Test-IsAffirmativeResponse.

        A short poll sleep keeps the wait from busy-spinning while remaining well
        under the one-second responsiveness budget used elsewhere in the script.
        Requirements: 3.1, 3.4
    #>
    [CmdletBinding()]
    param(
        [int] $TimeoutSeconds = 30
    )

    # Requirement 3.1: present the prompt showing the accepted affirmative and
    # negative options. Write-Host is intentional - this is user-facing host
    # output, not pipeline data.
    Write-Host "Open the log file now? [y/yes / n/no] (auto-declines in ${TimeoutSeconds}s): " -NoNewline

    # Accumulate the typed characters until Enter or the timeout.
    $builder = [System.Text.StringBuilder]::new()

    # Requirement 3.4: bound the read by a stopwatch so it returns '' on timeout.
    $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
    $timeoutMs = $TimeoutSeconds * 1000

    try {
        while ($stopwatch.ElapsedMilliseconds -lt $timeoutMs) {
            # Non-blocking probe of the input buffer so the stopwatch stays in
            # control of the wait - the read never blocks past the timeout.
            if ([System.Console]::KeyAvailable) {
                # $true = do not echo; we echo intentionally below so the Caller
                # sees what they type without duplicating control keys.
                $key = [System.Console]::ReadKey($true)

                if ($key.Key -eq [System.ConsoleKey]::Enter) {
                    # Completed response: move to a fresh line and return it.
                    Write-Host ''
                    return $builder.ToString().Trim()
                }
                elseif ($key.Key -eq [System.ConsoleKey]::Backspace) {
                    if ($builder.Length -gt 0) {
                        [void] $builder.Remove($builder.Length - 1, 1)
                        # Erase the last echoed character from the Console.
                        Write-Host "`b `b" -NoNewline
                    }
                }
                elseif (-not [char]::IsControl($key.KeyChar)) {
                    [void] $builder.Append($key.KeyChar)
                    Write-Host $key.KeyChar -NoNewline
                }
            }
            else {
                # Yield briefly to avoid a busy spin; 50 ms is well under the
                # one-second responsiveness budget.
                Start-Sleep -Milliseconds 50
            }
        }
    }
    finally {
        $stopwatch.Stop()
    }

    # Requirement 3.4: no completed response before the timeout - move to a fresh
    # line and return '' (classified as non-affirmative by the caller).
    Write-Host ''
    return ''
}

function Open-LogFile {
    <#
        Side-effecting (shell execute). Opens the Log_File at $LogFilePath with
        the operating system's Default_Application. NEVER throws: every outcome
        (including missing file and launch failure) is returned as data so the
        run always returns control to the Caller without an unhandled exception.

        Contract:
          - Missing file: when no file exists at $LogFilePath, returns
            Opened=$false, Kind='not-found', and a Reason identifying the path;
            no application launch is attempted (Requirement 4.2).
          - Existing file: attempts Start-Process -FilePath $LogFilePath, which
            invokes the OS shell-execute (default-handler) behavior identically on
            Windows PowerShell 5.1 and PowerShell 7+ (Requirements 3.2, 4.1). On
            success returns Opened=$true, Kind='opened', Reason=''.
          - Launch failure: any error from the launch is caught and returned as
            Opened=$false, Kind='open-failed', and a Reason naming the path and
            the underlying cause (Requirements 3.7, 4.3).

        The caller (Invoke-OpenLogWorkflow) writes a console error when Opened is
        $false; this function itself only reports results, never messages.

        Returns [pscustomobject]@{ Opened=[bool]; Kind=[string]; Reason=[string] }.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string] $LogFilePath
    )

    # Requirement 4.2: a missing file yields a graceful not-found result whose
    # Reason names the path, and no launch is attempted. Use the .NET API so the
    # existence check is deterministic across PowerShell 5.1 and 7+.
    if (-not [System.IO.File]::Exists($LogFilePath)) {
        return [pscustomobject]@{
            Opened = $false
            Kind   = 'not-found'
            Reason = "Log file not found at '$LogFilePath'."
        }
    }

    # Requirements 3.2 / 4.1: launch the Default_Application via Start-Process,
    # whose shell-execute behavior is identical on 5.1 and 7+. Any failure is
    # converted to data below (Requirements 3.7, 4.3) so this function never
    # throws.
    try {
        # -ErrorAction Stop promotes any non-terminating error into the catch so
        # every failure mode is surfaced uniformly as an 'open-failed' result.
        Start-Process -FilePath $LogFilePath -ErrorAction Stop | Out-Null

        return [pscustomobject]@{
            Opened = $true
            Kind   = 'opened'
            Reason = ''
        }
    }
    catch {
        $cause = $_.Exception.Message

        return [pscustomobject]@{
            Opened = $false
            Kind   = 'open-failed'
            Reason = "Failed to open log file '$LogFilePath': $cause"
        }
    }
}

function Write-TerminationOutput {
    <#
        Side-effecting (console). On Run_Termination, writes the single-line
        termination message for the current run to the Console.

        Builds the message with the pure Format-TerminationMessage using the run
        context's LogFilePath, then writes it to the Console as a single line via
        Write-Host (intentional user-facing host output, not pipeline data). The
        message reports the complete, unmodified Log_File_Path when one exists
        (Requirements 2.1, 2.2) or a distinct no-log-file line when the context
        holds no path (Requirement 2.3). All decision logic lives in the pure
        formatter; this function only performs the write.

        Requirements: 2.1, 2.3
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [pscustomobject] $Context
    )

    # Requirements 2.1 / 2.3: the pure formatter decides the exact single-line
    # content (verbatim path or the no-log-file message); this shell only emits
    # it. Write-Host is intentional - this is user-facing host output.
    Write-Host (Format-TerminationMessage -LogFilePath $Context.LogFilePath)
}

function Write-StartupBanner {
    <#
        Side-effecting (console). Before the first probe of a Run, writes the
        one-time Startup_Banner for the current run to the Console.

        Determines host interactivity via Test-IsInteractiveHost and passes that
        value to the pure Format-StartupBanner (Requirement 4.5), then writes the
        returned banner string to the Console unmodified, exactly once per
        invocation (Requirement 4.3), via Write-Host (intentional user-facing host
        output, not pipeline data - Requirement 4.4). All banner content lives in
        the pure formatter; this shell only performs the write.

        The Write-Host call is contained in a try/catch so any Console write
        failure is swallowed and this function returns normally without throwing
        (Requirement 3.5); the caller (Invoke-NetProbe) therefore always advances
        to the first probe even if the banner write fails. No code path throws.

        Requirements: 3.5, 4.3, 4.4, 4.5
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [pscustomobject] $Context
    )

    # Requirement 4.5: decide interactivity in the shell and thread it into the
    # pure formatter so the formatter stays deterministic and I/O-free.
    $interactive = Test-IsInteractiveHost

    # Requirements 4.3 / 4.4: obtain the banner from the pure formatter and emit
    # it unmodified exactly once via Write-Host (user-facing host output).
    $banner = Format-StartupBanner -Context $Context -Interactive $interactive

    # Requirement 3.5: a cosmetic banner must never abort a run. Contain the write
    # so any Console failure is swallowed and the function returns normally; the
    # caller then proceeds to the first probe. No path throws.
    try {
        Write-Host $banner
    }
    catch {
        # Intentionally swallowed: the run continues to the first probe.
    }
}

function Invoke-OpenLogWorkflow {
    <#
        Side-effecting (orchestration). On Run_Termination, offers the Caller the
        Open_Log_Prompt and opens the Log_File when applicable, wiring together
        the host check, the timed prompt, the pure response classifier, and the
        never-throwing open action.

        Flow:
          - No-op when the host is a Non_Interactive_Host (Test-IsInteractiveHost
            is $false) - the prompt is not shown and no open is attempted
            (Requirement 3.5).
          - No-op when the run context holds no Log_File_Path (blank/whitespace) -
            no prompt, no open (Requirement 3.6).
          - Otherwise presents the Open_Log_Prompt (Show-OpenLogPrompt, up to 30s)
            and classifies the response with the pure Test-IsAffirmativeResponse.
            A non-affirmative response (negative token, unrecognized text, or a
            timeout '') ends the run without opening and without an error
            (Requirements 3.3, 3.4, 4.4).
          - On an affirmative response, opens the file via Open-LogFile
            (Requirements 3.2, 4.1). Open-LogFile never throws; when its result is
            not Opened (a missing file or a launch failure) this function reports a
            log-open error to the Console naming the path and cause
            (Requirements 3.7, 4.2, 4.3).

        The $OpenLogFile injection seam lets tests substitute the shell-execute
        action deterministically without launching a real Default_Application;
        it defaults to the Open-LogFile function.

        Requirements: 3.2, 3.3, 3.5, 3.6, 3.7, 4.2, 4.3, 4.4
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [pscustomobject] $Context,

        # Injection seam (testability): the open action to invoke for an existing
        # affirmative response. Defaults to the real Open-LogFile shell-execute.
        [scriptblock] $OpenLogFile = { param([string] $Path) Open-LogFile -LogFilePath $Path }
    )

    # Requirement 3.5: a Non_Interactive_Host cannot present the prompt or read a
    # response, so end the run without prompting or opening.
    if (-not (Test-IsInteractiveHost)) {
        return
    }

    # Requirement 3.6: with no Log_File_Path for the run there is nothing to open,
    # so end the run without presenting the prompt.
    $logFilePath = $Context.LogFilePath
    if ([string]::IsNullOrWhiteSpace($logFilePath)) {
        return
    }

    # Requirement 3.1: present the Open_Log_Prompt and wait up to 30 seconds.
    $response = Show-OpenLogPrompt

    # Requirements 3.3 / 3.4 / 4.4: only accepted affirmatives open the file;
    # negative tokens, unrecognized text, and the timeout '' end the run without
    # opening and without reporting an error.
    if (-not (Test-IsAffirmativeResponse -Response $response)) {
        return
    }

    # Requirements 3.2 / 4.1: open the Log_File with the Default_Application.
    # Open-LogFile (or the injected seam) never throws - it returns a result.
    $result = & $OpenLogFile $logFilePath

    # Requirements 3.7 / 4.2 / 4.3: a not-found or open-failed result is reported
    # to the Console as a log-open error naming the path and cause, then the run
    # ends without an unhandled exception. Write-Error surfaces on the host's
    # error stream without terminating the caller.
    if (-not $result.Opened) {
        Write-Error $result.Reason
    }
}

#endregion Internal functions

#region Entry point guard

# Only run the imperative shell when this script is invoked directly (not when
# dot-sourced by tests). When dot-sourced, $MyInvocation.InvocationName is '.'
# and the script should merely define the functions above.
if ($MyInvocation.InvocationName -ne '.') {
    # Forward ONLY the parameters the caller actually supplied. Splatting the
    # script's $PSBoundParameters preserves the distinction between "omitted" and
    # "supplied empty", so Invoke-NetProbe can (a) report a missing-target error
    # when no target is given and (b) fall back to the Default_Log_Folder when no
    # LogFolderPath is given, rather than treating an omitted [string] parameter
    # as an explicit empty string.
    Invoke-NetProbe @PSBoundParameters
}

#endregion Entry point guard
