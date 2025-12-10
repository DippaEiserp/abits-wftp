<# 
    ftp-guardian.ps1
    CCDC Windows FTP helper

    - Run once at start to baseline checks
    - Then loops every 2 minutes to re-check critical items
    - Logs to C:\ftp-guardian\ftp-guardian.log
#>

$ErrorActionPreference = "SilentlyContinue"

# ========== CONFIG ==========
$LogDir  = "C:\ftp-guardian"
$LogFile = Join-Path $LogDir "ftp-guardian.log"

# Adjust this if your new admin account has a specific name
$ExpectedAdminUser = "ftp-admin"

# Ports that MUST be blocked inbound (per playbook)
$PortsToBlock = @(23,445,139,3389)  # Telnet, SMB, NetBIOS, RDP [file:54][file:55]

# FTP ports that MUST be allowed inbound
$FtpPortsToAllow = @(20,21)        # FTP data & control [file:54]

# How often to re-check (seconds)
$LoopIntervalSeconds = 120

# ========== LOGGING ==========
function Write-Log {
    param(
        [string]$Message,
        [string]$Level = "INFO"
    )
    if (!(Test-Path $LogDir)) {
        New-Item -ItemType Directory -Path $LogDir -Force | Out-Null
    }
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $line = "[$timestamp] [$Level] $Message"
    $line | Tee-Object -FilePath $LogFile -Append
}

Write-Log "===== FTP Guardian Script Started ====="

# ========== ONE-TIME CHECKS ==========

function Check-LocalAdmins {
    Write-Log "Checking local Administrators group membership..." "INFO"
    $admins = net localgroup Administrators 2>$null | Select-String -NotMatch "command completed"
    $adminsList = $admins | ForEach-Object { $_.ToString().Trim() } | Where-Object { $_ -ne "" }

    Write-Log ("Current local admins: " + ($adminsList -join ", "))

    if ($adminsList -contains "Administrator") {
        Write-Log "Built-in Administrator is still enabled or present in Administrators group. Consider disabling once new admin is confirmed." "WARN"  # [file:54][file:55]
    } else {
        Write-Log "Built-in Administrator appears removed from Administrators group." "INFO"
    }

    if ($adminsList -contains $ExpectedAdminUser) {
        Write-Log "Expected admin user '$ExpectedAdminUser' is in Administrators group." "INFO"
    } else {
        Write-Log "Expected admin user '$ExpectedAdminUser' NOT found in Administrators group. Verify you created a new admin account." "WARN" # [file:54][file:55]
    }
}

function Check-BackupPaths {
    Write-Log "Checking for backup paths C:\backup and IIS/inetpub copies..." "INFO"
    $backupRoot = "C:\backup"
    $configBackup = "C:\backup\config"
    $inetpubBackup = "C:\backup\inetpub"

    if (Test-Path $backupRoot) {
        Write-Log "Backup root exists at $backupRoot." "INFO"
    } else {
        Write-Log "Backup root $backupRoot not found. Run your backup commands for IIS config and inetpub." "WARN" # [file:54]
    }

    if (Test-Path "C:\Windows\System32\inetsrv\config") {
        Write-Log "IIS config directory exists (C:\Windows\System32\inetsrv\config)." "INFO"
    }

    if (Test-Path $configBackup) {
        Write-Log "Config backup folder found at $configBackup." "INFO"
    } else {
        Write-Log "Config backup folder $configBackup not found. Verify Copy-Item for config was run." "WARN" # [file:54]
    }

    if (Test-Path "C:\inetpub") {
        Write-Log "inetpub folder exists (C:\inetpub)." "INFO"
    }

    if (Test-Path $inetpubBackup) {
        Write-Log "inetpub backup folder found at $inetpubBackup." "INFO"
    } else {
        Write-Log "inetpub backup folder $inetpubBackup not found. Verify Copy-Item for inetpub was run." "WARN" # [file:54]
    }
}

function Check-Defender {
    Write-Log "Checking Windows Defender status..." "INFO"
    try {
        $service = Get-Service -Name "WinDefend" -ErrorAction Stop
        if ($service.Status -eq "Running") {
            Write-Log "Windows Defender service is running." "INFO"
        } else {
            Write-Log "Windows Defender service is installed but NOT running. Start it if allowed." "WARN" # [file:54][file:55]
        }
    } catch {
        Write-Log "Windows Defender service not found. This may be a non-Defender image." "WARN"
    }
}

function Check-FirewallBase {
    Write-Log "Checking Windows Firewall base status..." "INFO"
    $profiles = Get-NetFirewallProfile
    foreach ($p in $profiles) {
        Write-Log ("Profile {0}: Enabled={1}, InboundAction={2}, OutboundAction={3}" -f $p.Name,$p.Enabled,$p.DefaultInboundAction,$p.DefaultOutboundAction)
        if (-not $p.Enabled) {
            Write-Log ("Firewall profile {0} is DISABLED. Enable firewall per playbook." -f $p.Name) "WARN" # [file:54][file:55]
        }
    }
}

function Check-FTPAnonymous {
    Write-Log "Checking IIS FTP authentication for Anonymous..." "INFO"
    $appcmd = "$env:SystemRoot\System32\inetsrv\appcmd.exe"
    if (Test-Path $appcmd) {
        $out = & $appcmd list config /section:system.ftpServer/security/authentication/anonymousAuthentication 2>$null
        if ($out -match 'enabled:"true"') {
            Write-Log "FTP Anonymous Authentication appears ENABLED. Disable it in IIS Manager per playbook." "WARN" # [file:54]
        } elseif ($out -match 'enabled:"false"') {
            Write-Log "FTP Anonymous Authentication appears disabled." "INFO"
        } else {
            Write-Log "Could not clearly detect anonymous auth state from appcmd output. Double-check IIS Manager." "WARN"
        }
    } else {
        Write-Log "appcmd.exe not found. Cannot auto-check FTP anonymous auth; verify manually in IIS Manager." "WARN" # [file:54]
    }
}

function Check-SysinternalsAndTools {
    Write-Log "Checking for Sysinternals and tools folder C:\tools..." "INFO"
    if (Test-Path "C:\tools") {
        Write-Log "Tools folder C:\tools exists (likely Sysinternals installed)." "INFO" # [file:54]
    } else {
        Write-Log "C:\tools not found. Confirm Sysinternals/tools install script ran." "WARN"
    }
}

function Check-SplunkForwarder {
    Write-Log "Checking for Splunk Universal Forwarder..." "INFO"
    try {
        $svc = Get-Service -Name "SplunkForwarder" -ErrorAction Stop
        if ($svc.Status -eq "Running") {
            Write-Log "SplunkForwarder service is running." "INFO" # [file:54][file:55]
        } else {
            Write-Log "SplunkForwarder service exists but not running. Start if part of playbook." "WARN"
        }
    } catch {
        Write-Log "SplunkForwarder service not found; Splunk forwarder may not be installed." "WARN"
    }
}

function Invoke-PersistenceHunterIfPresent {
    Write-Log "Checking for persistence-hunter script and executing if found..." "INFO"
    $hunterPaths = @(
        "C:\tools\hunter.ps1",
        "C:\hunter.ps1",
        "C:\persistence-hunter.ps1"
    )
    $foundPath = $null
    foreach ($p in $hunterPaths) {
        if (Test-Path $p) {
            $foundPath = $p
            break
        }
    }

    if ($foundPath) {
        Write-Log "Persistence hunter script found at $foundPath. Executing..." "INFO"
        try {
            powershell -ExecutionPolicy Bypass -File $foundPath *> "$LogDir\hunter-last-run.log"
            Write-Log "Persistence hunter executed successfully (output in hunter-last-run.log)." "INFO" # [file:54][file:55]
        } catch {
            Write-Log ("Error executing persistence hunter: " + $_.Exception.Message) "WARN"
        }
    } else {
        Write-Log "Persistence hunter script not found in expected paths." "WARN"
    }
}

# Run one-time checks right away
Check-LocalAdmins
Check-BackupPaths
Check-Defender
Check-FirewallBase
Check-FTPAnonymous
Check-SysinternalsAndTools
Check-SplunkForwarder
Invoke-PersistenceHunterIfPresent

Write-Log "Initial checks complete. Entering continuous monitoring loop (every $LoopIntervalSeconds seconds)."

# ========== CONTINUOUS MONITORING LOOP ==========

function Check-BlockedPorts {
    Write-Log "Checking that high-risk ports are blocked inbound (23, 445, 139, 3389)..." "INFO" # [file:54][file:55]
    foreach ($port in $PortsToBlock) {
        $fwRules = Get-NetFirewallRule -ErrorAction SilentlyContinue | Where-Object {
            ($_.Direction -eq "Inbound") -and ($_.Enabled -eq "True")
        }

        $inboundOpen = $false
        foreach ($r in $fwRules) {
            $pf = Get-NetFirewallPortFilter -AssociatedNetFirewallRule $r -ErrorAction SilentlyContinue
            if ($pf -and $pf.LocalPort -eq "$port" -and $r.Action -eq "Allow") {
                $inboundOpen = $true
                break
            }
        }

        if ($inboundOpen) {
            Write-Log "Port $port appears ALLOWED inbound. Ensure this is intentional; playbook says to block it." "WARN"
        } else {
            Write-Log "Port $port does not appear to be allowed inbound (good)." "INFO"
        }
    }
}

function Check-FTPPortsAllowed {
    Write-Log "Checking FTP ports 20 and 21 inbound allow rules..." "INFO" # [file:54]
    foreach ($port in $FtpPortsToAllow) {
        $fwRules = Get-NetFirewallRule -ErrorAction SilentlyContinue | Where-Object {
            ($_.Direction -eq "Inbound") -and ($_.Enabled -eq "True") -and ($_.Action -eq "Allow")
        }

        $foundAllow = $false
        foreach ($r in $fwRules) {
            $pf = Get-NetFirewallPortFilter -AssociatedNetFirewallRule $r -ErrorAction SilentlyContinue
            if ($pf -and $pf.LocalPort -eq "$port") {
                $foundAllow = $true
                break
            }
        }

        if ($foundAllow) {
            Write-Log "FTP Port $port appears allowed inbound (good for scoring)." "INFO"
        } else {
            Write-Log "FTP Port $port does NOT appear explicitly allowed inbound. Verify FTP firewall rules." "WARN"
        }
    }
}

function Check-FTPService {
    Write-Log "Checking Microsoft FTP Service (ftpsvc) status..." "INFO" # [file:54]
    try {
        $svc = Get-Service -Name "ftpsvc" -ErrorAction Stop
        Write-Log ("ftpsvc status: {0}, StartType: {1}" -f $svc.Status, $svc.StartType)
        if ($svc.Status -ne "Running") {
            Write-Log "ftpsvc is NOT running. Starting service now..." "WARN"
            Start-Service -Name "ftpsvc" -ErrorAction SilentlyContinue
        }
        if ($svc.StartType -ne "Automatic") {
            Write-Log "ftpsvc is not set to Automatic start. Set it to Automatic per playbook." "WARN"
        }
    } catch {
        Write-Log "Microsoft FTP Service (ftpsvc) not found. Is FTP role installed on this server?" "WARN"
    }
}

function Check-RDPStatus {
    Write-Log "Checking RDP listener and port 3389..." "INFO" # [file:54][file:55]
    $rdpListener = Get-NetTCPConnection -LocalPort 3389 -State Listen -ErrorAction SilentlyContinue
    if ($rdpListener) {
        Write-Log "Port 3389 is LISTENING. Ensure RDP exposure matches scoring/White Team guidance." "WARN"
    } else {
        Write-Log "No process listening on port 3389. RDP not listening (or already restricted)." "INFO"
    }
}

while ($true) {
    try {
        Write-Log "----- Monitoring iteration start -----"

        Check-BlockedPorts
        Check-FTPPortsAllowed
        Check-FTPService
        Check-RDPStatus
        Invoke-PersistenceHunterIfPresent   # run hunter every cycle

        Write-Log "----- Monitoring iteration complete -----"
    } catch {
        Write-Log ("Exception in monitoring loop: " + $_.Exception.Message) "WARN"
    }

    Start-Sleep -Seconds $LoopIntervalSeconds
}
