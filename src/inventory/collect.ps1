# RustSweeper Windows inventory collector (Windows PowerShell 5.1+).
# Inputs come from environment variables so secrets never appear on a command line:
#   RSW_TARGET    computer to inventory (DNS name, NetBIOS name or IP)
#   RSW_PROTOCOL  Dcom (default) or Wsman
#   RSW_USER      optional DOMAIN\user; when empty the service's own account is used
#   RSW_SECRET    DPAPI (LocalMachine) protected password, base64, for RSW_USER
# Output: exactly one compressed JSON object on stdout.
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
[Console]::OutputEncoding = [Text.Encoding]::UTF8   # RustSweeper reads stdout as UTF-8

function Out-Result($obj) { $obj | ConvertTo-Json -Depth 5 -Compress; exit 0 }
function Fail($stage, $err) { Out-Result ([pscustomobject]@{ ok = $false; stage = $stage; error = "$err" }) }
function Fmt($d) { if ($d -is [datetime]) { $d.ToString('yyyy-MM-dd HH:mm:ss') } else { $null } }

function Unprotect($blob) {
    Add-Type -AssemblyName System.Security
    $bytes = [Convert]::FromBase64String($blob)
    $entropy = [Text.Encoding]::UTF8.GetBytes('RustSweeper')
    $plain = [Security.Cryptography.ProtectedData]::Unprotect($bytes, $entropy, [Security.Cryptography.DataProtectionScope]::LocalMachine)
    [Text.Encoding]::UTF8.GetString($plain)
}

$protocol = 'Dcom'
if ($env:RSW_PROTOCOL -eq 'Wsman') { $protocol = 'Wsman' }

$sessionArgs = @{
    ComputerName        = $env:RSW_TARGET
    SessionOption       = (New-CimSessionOption -Protocol $protocol)
    OperationTimeoutSec = 30
    ErrorAction         = 'Stop'
}
if ($env:RSW_USER) {
    try {
        $pw = ConvertTo-SecureString (Unprotect $env:RSW_SECRET) -AsPlainText -Force
    } catch { Fail 'credential' "could not decrypt the stored password on this machine: $($_.Exception.Message)" }
    $sessionArgs.Credential = New-Object System.Management.Automation.PSCredential($env:RSW_USER, $pw)
}

try { $s = New-CimSession @sessionArgs } catch { Fail 'connect' $_.Exception.Message }

try {
    $q = @{ CimSession = $s; OperationTimeoutSec = 30; ErrorAction = 'Stop' }
    $cs   = Get-CimInstance @q -ClassName Win32_ComputerSystem
    $bios = Get-CimInstance @q -ClassName Win32_BIOS
    $os   = Get-CimInstance @q -ClassName Win32_OperatingSystem
    $cpus = @(Get-CimInstance @q -ClassName Win32_Processor)
    $disks = @(Get-CimInstance @q -ClassName Win32_LogicalDisk -Filter 'DriveType=3' | ForEach-Object {
        [pscustomobject]@{ drive = $_.DeviceID; filesystem = $_.FileSystem; size_bytes = $_.Size; free_bytes = $_.FreeSpace }
    })
    $nics = @(Get-CimInstance @q -ClassName Win32_NetworkAdapterConfiguration -Filter 'IPEnabled=True' | ForEach-Object {
        [pscustomobject]@{ description = $_.Description; mac = $_.MACAddress; ips = @($_.IPAddress) }
    })

    $cores = 0
    foreach ($c in $cpus) { if ($c.NumberOfCores) { $cores += [int]$c.NumberOfCores } }
    $cpuName = $null
    if ($cpus.Count -gt 0 -and $cpus[0].Name) { $cpuName = $cpus[0].Name.Trim() }

    Out-Result ([pscustomobject]@{
        ok                 = $true
        computer_name      = $cs.Name
        domain             = $cs.Domain
        part_of_domain     = [bool]$cs.PartOfDomain
        manufacturer       = $cs.Manufacturer
        model              = $cs.Model
        system_type        = $cs.SystemType
        last_user          = $cs.UserName
        memory_bytes       = $cs.TotalPhysicalMemory
        logical_processors = $cs.NumberOfLogicalProcessors
        serial_number      = $bios.SerialNumber
        bios_version       = $bios.SMBIOSBIOSVersion
        bios_date          = (Fmt $bios.ReleaseDate)
        os_name            = $os.Caption
        os_version         = $os.Version
        os_build           = $os.BuildNumber
        os_arch            = $os.OSArchitecture
        os_install_date    = (Fmt $os.InstallDate)
        last_boot          = (Fmt $os.LastBootUpTime)
        cpu                = $cpuName
        cpu_count          = $cpus.Count
        cores              = $cores
        disks              = $disks
        nics               = $nics
    })
} catch {
    Fail 'query' $_.Exception.Message
} finally {
    if ($s) { Remove-CimSession $s -ErrorAction SilentlyContinue }
}
