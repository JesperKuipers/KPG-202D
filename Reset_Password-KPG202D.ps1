param(
    [switch]$StayOpen,
    [string]$TitlePrefix = "KPG-202D",
    [string]$TitleContains,
    [string]$TitleRegex,
    [string]$ProcessName,
    [int]$WaitSeconds = 0,
    [switch]$ListOnFail,
    [switch]$PickOnFail,
    [switch]$IncludeInvisible,
    [switch]$LaunchedInNewWindow
)

# Always (re)launch in a new PowerShell window once
if (-not $LaunchedInNewWindow) {
    $scriptPath = $PSCommandPath
    if (-not $scriptPath) { $scriptPath = $MyInvocation.MyCommand.Path }
    if ($scriptPath) {
        $forwardArgs = New-Object System.Collections.Generic.List[string]
        foreach ($entry in $PSBoundParameters.GetEnumerator()) {
            if ($entry.Key -eq 'LaunchedInNewWindow') { continue }
            $name = '-' + $entry.Key
            $val = $entry.Value
            if ($val -is [System.Management.Automation.SwitchParameter]) {
                if ($val.IsPresent) { [void]$forwardArgs.Add($name) }
            } elseif ($null -ne $val -and "$val" -ne '') {
                [void]$forwardArgs.Add($name)
                [void]$forwardArgs.Add(('"' + ("$val") + '"'))
            }
        }
        # Build final argument list and include sentinel so we don't loop
        $argsList = @('-NoExit','-NoProfile','-ExecutionPolicy','Bypass','-File',('"' + $scriptPath + '"')) + $forwardArgs + @('-LaunchedInNewWindow')
        $argString = ($argsList -join ' ')
        try {
            Start-Process -FilePath "powershell.exe" -ArgumentList $argString | Out-Null
        } catch {
            Write-Host "Failed to open new PowerShell window: $_"
        }
        return
    }
}

if (-not ([System.Management.Automation.PSTypeName] 'Win32').Type) {
    Add-Type @"
using System;
using System.Text;
using System.Runtime.InteropServices;

public class Win32 {
    public delegate bool EnumWindowsProc(IntPtr hWnd, IntPtr lParam);

    [DllImport("user32.dll")]
    public static extern bool EnumWindows(EnumWindowsProc lpEnumFunc, IntPtr lParam);

    [DllImport("user32.dll")]
    public static extern int GetWindowText(IntPtr hWnd, StringBuilder lpString, int nMaxCount);

    [DllImport("user32.dll")]
    public static extern int GetWindowTextLength(IntPtr hWnd);

    [DllImport("user32.dll")]
    public static extern bool IsWindowVisible(IntPtr hWnd);

    [DllImport("user32.dll", SetLastError = true)]
    public static extern bool PostMessage(IntPtr hWnd, uint Msg, IntPtr wParam, IntPtr lParam);

    [DllImport("user32.dll", SetLastError = true)]
    public static extern uint GetWindowThreadProcessId(IntPtr hWnd, out uint lpdwProcessId);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr OpenProcess(uint dwDesiredAccess, bool bInheritHandle, uint dwProcessId);

    [DllImport("advapi32.dll", SetLastError = true)]
    public static extern bool OpenProcessToken(IntPtr ProcessHandle, uint DesiredAccess, out IntPtr TokenHandle);

    [DllImport("advapi32.dll", SetLastError = true)]
    public static extern bool GetTokenInformation(IntPtr TokenHandle, int TokenInformationClass, IntPtr TokenInformation, int TokenInformationLength, out int ReturnLength);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool CloseHandle(IntPtr hObject);

    [DllImport("kernel32.dll")]
    public static extern uint GetLastError();

    public const uint PROCESS_QUERY_LIMITED_INFORMATION = 0x1000;
    public const uint TOKEN_QUERY = 0x0008;
    public const int TokenElevation = 20; // TOKEN_INFORMATION_CLASS.TokenElevation

    [StructLayout(LayoutKind.Sequential)]
    public struct TOKEN_ELEVATION { public int TokenIsElevated; }

    public static bool IsProcessElevated(uint pid) {
        IntPtr hProc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid);
        if (hProc == IntPtr.Zero) return false;
        IntPtr hTok = IntPtr.Zero;
        try {
            if (!OpenProcessToken(hProc, TOKEN_QUERY, out hTok)) return false;
            int size = Marshal.SizeOf(typeof(TOKEN_ELEVATION));
            IntPtr buf = Marshal.AllocHGlobal(size);
            try {
                int retLen;
                if (!GetTokenInformation(hTok, TokenElevation, buf, size, out retLen)) return false;
                TOKEN_ELEVATION te = (TOKEN_ELEVATION)Marshal.PtrToStructure(buf, typeof(TOKEN_ELEVATION));
                return te.TokenIsElevated != 0;
            } finally {
                Marshal.FreeHGlobal(buf);
                if (hTok != IntPtr.Zero) CloseHandle(hTok);
            }
        } finally {
            CloseHandle(hProc);
        }
    }
}
"@
} else {
    Write-Host "Win32 type already loaded. Skipping Add-Type."
}

$WM_COMMAND = 0x0111
$commandId = 1626

function Invoke-ResetAction {
    # Find window whose title matches requested criteria
    $script:foundHwnd = [IntPtr]::Zero
    # Capture criteria locally for use inside the callback
    $matchPrefix   = $TitlePrefix
    $matchContains = $TitleContains
    $matchRegex    = $TitleRegex
    $matchProc     = $ProcessName

    $callback = [Win32+EnumWindowsProc]{
        param([IntPtr]$hWnd, [IntPtr]$lParam)

        if (-not [Win32]::IsWindowVisible($hWnd)) { return $true }

        $length = [Win32]::GetWindowTextLength($hWnd)
        if ($length -eq 0) { return $true }

        $builder = New-Object System.Text.StringBuilder -ArgumentList ($length + 1)
        [Win32]::GetWindowText($hWnd, $builder, $builder.Capacity) | Out-Null
        $title = $builder.ToString()

        $matches = $false
        if ($matchPrefix) {
            $matches = $title.StartsWith($matchPrefix, [System.StringComparison]::OrdinalIgnoreCase)
        }
        if (-not $matches -and $matchContains) {
            $matches = ($title.IndexOf($matchContains, [System.StringComparison]::OrdinalIgnoreCase) -ge 0)
        }
        if (-not $matches -and $matchRegex) {
            try { $matches = ($title -match $matchRegex) } catch { $matches = $false }
        }

        if ($matches -and $matchProc) {
            $pidForWnd = 0
            [void][Win32]::GetWindowThreadProcessId($hWnd, [ref]$pidForWnd)
            if ($pidForWnd -ne 0) {
                try {
                    $p = [System.Diagnostics.Process]::GetProcessById([int]$pidForWnd)
                    if ($p.ProcessName -ne $matchProc) { $matches = $false }
                } catch { $matches = $false }
            } else { $matches = $false }
        }

        if ($matches) { $script:foundHwnd = $hWnd; return $false }
        return $true
    }

    $deadline = [DateTime]::UtcNow.AddSeconds([double]$WaitSeconds)
    do {
        $script:foundHwnd = [IntPtr]::Zero
        [Win32]::EnumWindows($callback, [IntPtr]::Zero) | Out-Null
        if ($script:foundHwnd -ne [IntPtr]::Zero) { break }
        if ([DateTime]::UtcNow -ge $deadline) { break }
        Start-Sleep -Milliseconds 500
    } while ($true)

    if ($script:foundHwnd -eq [IntPtr]::Zero) {
        $criteria = @()
        if ($TitlePrefix) { $criteria += "prefix '$TitlePrefix'" }
        if ($TitleContains) { $criteria += "contains '$TitleContains'" }
        if ($TitleRegex) { $criteria += "regex '$TitleRegex'" }
        if ($ProcessName) { $criteria += "process '$ProcessName'" }
        $critText = if ($criteria.Count) { $criteria -join ", " } else { "(no title criteria provided)" }
        Write-Host "Window not found matching: $critText"

        # Helper to enumerate windows with extra info
        $windows = New-Object System.Collections.ArrayList
        $includeHidden = $IncludeInvisible
        [Win32]::EnumWindows([Win32+EnumWindowsProc]{
            param([IntPtr]$h,[IntPtr]$lp)
            $visible = [Win32]::IsWindowVisible($h)
            if (-not $includeHidden -and -not $visible) { return $true }
            $len = [Win32]::GetWindowTextLength($h)
            if ($len -le 0) { return $true }
            $sb = New-Object System.Text.StringBuilder -ArgumentList ($len + 1)
            [Win32]::GetWindowText($h,$sb,$sb.Capacity) | Out-Null
            $t = $sb.ToString()
            if ($t.Trim().Length -le 0) { return $true }
            $ppid = 0
            [void][Win32]::GetWindowThreadProcessId($h,[ref]$ppid)
            $pname = "?"
            if ($ppid -ne 0) { try { $pname = ([System.Diagnostics.Process]::GetProcessById([int]$ppid)).ProcessName } catch {} }
            [void]$windows.Add([pscustomobject]@{ Hwnd=$h; Title=$t; PID=$ppid; Process=$pname; Visible=$visible })
            return $true
        }, [IntPtr]::Zero) | Out-Null

        if ($ListOnFail -or $PickOnFail) {
            Write-Host "Top-level windows:"; Write-Host "------------------"
            $i = 0
            foreach ($w in ($windows | Sort-Object Title -Unique)) {
                $vis = if ($w.Visible) { "Visible" } else { "Hidden" }
                Write-Host ("[{0}] {1}  (PID {2}, {3}, hWnd=0x{4})" -f $i, $w.Title, $w.PID, $w.Process, ([Convert]::ToString([int]$w.Hwnd,16)))
                $i++
            }
        }

    if ($PickOnFail -and $windows.Count -gt 0) {
            Write-Host ""
            Write-Host "Enter the index of the window to target, or just press Enter to cancel:" -NoNewline
            try { $sel = Read-Host } catch { $sel = "" }
            Write-Host ""
            if ($sel -match '^[0-9]+$') {
                $idx = [int]$sel
                $list = $windows | Sort-Object Title -Unique
                if ($idx -ge 0 -and $idx -lt $list.Count) {
                    $choice = $list[$idx]
                    Write-Host ("Selected: '{0}' (PID {1}, {2})" -f $choice.Title, $choice.PID, $choice.Process)
            $script:foundHwnd = [IntPtr]$choice.Hwnd
                }
            }
        }

    if ($script:foundHwnd -eq [IntPtr]::Zero) { return }
    }

    # Diagnostics: identify target process and check elevation/session
    $winPid = 0
    [void][Win32]::GetWindowThreadProcessId($script:foundHwnd, [ref]$winPid)
    $winPid = [uint32]$winPid

    try {
        $targetProc = [System.Diagnostics.Process]::GetProcessById([int]$winPid)
    } catch {
        Write-Host "Found window handle, but failed to get owning process (PID: $winPid). $_"
        return
    }

    $currentSession = [System.Diagnostics.Process]::GetCurrentProcess().SessionId
    $targetSession = $targetProc.SessionId

    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    $isAdmin = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    $targetElevated = [Win32]::IsProcessElevated($winPid)

    Write-Host "Target window PID: $winPid, Process: $($targetProc.ProcessName), Session: $targetSession, Elevated: $targetElevated"
    Write-Host "Current PowerShell Session: $currentSession, Elevated: $isAdmin"

    if ($currentSession -ne $targetSession) {
        Write-Host "Cannot send window messages across sessions. Please run this script in the same user session as the target app."
        return
    }

    if (-not $isAdmin -and $targetElevated) {
        Write-Host "Target app is elevated; attempting to relaunch this script with Administrator privileges..."
        $scriptPath = $PSCommandPath
        if (-not $scriptPath) { $scriptPath = $MyInvocation.MyCommand.Path }
        if (-not $scriptPath) {
            Write-Host "Cannot determine script path for self-elevation. Please run as Administrator manually."
            return
        }
    $argList = ('-NoExit','-NoProfile','-ExecutionPolicy','Bypass','-File',('"' + $scriptPath + '"'),'-StayOpen','-LaunchedInNewWindow') -join ' '
        try {
            Start-Process -FilePath "powershell.exe" -ArgumentList $argList -Verb RunAs | Out-Null
            return
        } catch {
            Write-Host "Elevation canceled or failed: $_"
            return
        }
    }

    # Show which window we matched
    $matchedTitleLen = [Win32]::GetWindowTextLength($script:foundHwnd)
    $matchedSb = New-Object System.Text.StringBuilder -ArgumentList ($matchedTitleLen + 1)
    [Win32]::GetWindowText($script:foundHwnd, $matchedSb, $matchedSb.Capacity) | Out-Null
    Write-Host "Matched window: '$($matchedSb.ToString())' (hWnd=$script:foundHwnd)"

    $result = [Win32]::PostMessage($script:foundHwnd, $WM_COMMAND, [IntPtr]$commandId, [IntPtr]::Zero)

    if ($result) {
        Write-Host "Command sent successfully."
    } else {
        $err = [Win32]::GetLastError()
        $msg = (New-Object ComponentModel.Win32Exception([int]$err)).Message
        Write-Host "Failed to send command. Win32 error code: $err ($msg)"
        if ($err -eq 5) {
            Write-Host "Hint: Access denied typically means UIPI blocked the message. Attempting elevation..."
            $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
            $principal = New-Object Security.Principal.WindowsPrincipal($identity)
            $isAdmin = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
            if (-not $isAdmin) {
                $scriptPath = $PSCommandPath
                if (-not $scriptPath) { $scriptPath = $MyInvocation.MyCommand.Path }
                if ($scriptPath) {
                    $argList = ('-NoExit','-NoProfile','-ExecutionPolicy','Bypass','-File',('"' + $scriptPath + '"'),'-StayOpen','-LaunchedInNewWindow') -join ' '
                    try {
                        Start-Process -FilePath "powershell.exe" -ArgumentList $argList -Verb RunAs | Out-Null
                        return
                    } catch {
                        Write-Host "Elevation canceled or failed: $_"
                    }
                } else {
                    Write-Host "Cannot determine script path for self-elevation. Please run as Administrator manually."
                }
            }
        }
    }
}

# Initial run
Invoke-ResetAction

# Always offer to run again or close
while ($true) {
    Write-Host ""
    Write-Host "Press 'R' to run again, or any other key to close..." -NoNewline
    try {
        $key = [System.Console]::ReadKey($true)
    } catch {
        Write-Host ""
        break
    }
    Write-Host ""
    if (($key.Key -eq [ConsoleKey]::R) -or ($key.KeyChar -eq 'r') -or ($key.KeyChar -eq 'R')) {
        Invoke-ResetAction
        continue
    } else {
        try {
            Start-Sleep -Milliseconds 50
            Stop-Process -Id $PID -Force
        } catch {
            exit
        }
    }
}