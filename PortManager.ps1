# ---------------------------------------------- #
# Port Manager (v2.0) + Online Check             #
# See ports, trust apps, block with one click.   #
# Runs in the tray and watches in the background #
# ---------------------------------------------- #
param([switch]$Hidden)

Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
Add-Type -AssemblyName System.Data
[System.Windows.Forms.Application]::EnableVisualStyles()

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$isAdmin = (New-Object Security.Principal.WindowsPrincipal $identity).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    $argList = "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$PSCommandPath`""
    if ($Hidden) { $argList += " -Hidden" }
    Start-Process powershell.exe -Verb RunAs -ArgumentList $argList
    exit
}

$createdNew = $false
$mutex = [System.Threading.Mutex]::new($true, "Global\PortManager_v2", [ref]$createdNew)
$showEvent = New-Object System.Threading.EventWaitHandle($false, [System.Threading.EventResetMode]::AutoReset, "Global\PortManager_v2_Show")
if (-not $createdNew) { [void]$showEvent.Set(); exit }

try {

$DataDir = Join-Path $env:ProgramData "PortManager"
New-Item -ItemType Directory -Path $DataDir -Force | Out-Null
$TrustedFile = Join-Path $DataDir "trusted.json"
$BlocksFile = Join-Path $DataDir "blocks.json"
$LearnedFile = Join-Path $DataDir "learned.json"
$SettingsFile = Join-Path $DataDir "settings.json"
$HistoryFile = Join-Path $DataDir "history.csv"
$ErrorLog = Join-Path $DataDir "errors.log"
$RulePrefix = "PortGUI Block"
$AlertCooldownMin = 30
$Intervals = @(1000, 2000, 5000, 10000)

$script:Rows = New-Object System.Collections.ArrayList
$script:FirstCycle = $true
$script:LastSig = $null
$script:PendingSelect = $null
$script:LastAlertKey = $null
$script:BalloonAction = 'alert'
$script:AlertsPaused = $false
$script:Quitting = $false
$script:GridReady = $false
$script:Updating = $false
$script:Note = ''
$script:NoteUntil = [datetime]::MinValue
$script:LearnedDirty = $false
$script:HintShown = $false
$script:IgnoreStart = $false
$script:LearningUntil = $null

function Write-AppLog { param([string]$Message) try { Add-Content $ErrorLog "$(Get-Date -Format s)  $Message" } catch {} }
function Read-Json { param([string]$Path) if (-not (Test-Path $Path)) { return $null }; try { $raw = Get-Content $Path -Raw -ErrorAction Stop; if ($raw) { return ($raw | ConvertFrom-Json) } } catch { Write-AppLog "Read $Path : $($_.Exception.Message)" }; return $null }
function Save-Json { param([string]$Path, $Data) try { ConvertTo-Json -InputObject $Data -Depth 5 | Set-Content $Path -Encoding UTF8 } catch { Write-AppLog "Save $Path : $($_.Exception.Message)" } }

$Settings = @{ LearningUntil = ""; LearnNotified = $true; ResolveNames = $true; RefreshIndex = 1 }
$loadedSettings = Read-Json $SettingsFile
if ($loadedSettings) { foreach ($n in @('LearningUntil','LearnNotified','ResolveNames','RefreshIndex')) { if ($null -ne $loadedSettings.$n) { $Settings[$n] = $loadedSettings.$n } } }
function Save-Settings { Save-Json $SettingsFile $Settings }
if ($Settings.LearningUntil) { try { $script:LearningUntil = [datetime]$Settings.LearningUntil } catch {} }

$Trusted = [ordered]@{}
function Get-TrustKey { param([string]$Name, [string]$Path) if ($Path) { return $Path.ToLower() }; return ("name:" + $Name.ToLower()) }
function Save-Trusted { Save-Json $TrustedFile @($Trusted.Values) }
function Add-Trust { param([string]$Name, [string]$Path) $k = Get-TrustKey $Name $Path; if (-not $Trusted.Contains($k)) { $Trusted[$k] = [pscustomobject]@{ Key=$k; Name=$Name; Path=$Path; Added=(Get-Date).ToString('s') } }; Save-Trusted }
function Remove-Trust { param([string]$Name, [string]$Path) $k = Get-TrustKey $Name $Path; if ($Trusted.Contains($k)) { $Trusted.Remove($k); Save-Trusted; return $true }; return $false }
if (Test-Path $TrustedFile) { foreach ($t in @(Read-Json $TrustedFile)) { if ($t -and $t.Key) { $Trusted[[string]$t.Key] = $t } } } else {
    $defaults = @(
        @{Name='svchost';Path="$env:windir\System32\svchost.exe"}, @{Name='explorer';Path="$env:windir\explorer.exe"},
        @{Name='notepad';Path="$env:windir\System32\notepad.exe"}, @{Name='chrome';Path="$env:ProgramFiles\Google\Chrome\Application\chrome.exe"},
        @{Name='chrome';Path="${env:ProgramFiles(x86)}\Google\Chrome\Application\chrome.exe"}, @{Name='chrome';Path="$env:LOCALAPPDATA\Google\Chrome\Application\chrome.exe"},
        @{Name='tailscaled';Path="$env:ProgramFiles\Tailscale\tailscaled.exe"}, @{Name='AnyDesk';Path="${env:ProgramFiles(x86)}\AnyDesk\AnyDesk.exe"},
        @{Name='AnyDesk';Path="$env:ProgramFiles\AnyDesk\AnyDesk.exe"}
    )
    foreach ($d in $defaults) { Add-Trust $d.Name $d.Path }
}
$Blocks = New-Object System.Collections.ArrayList
foreach ($b in @(Read-Json $BlocksFile)) { if ($b) { [void]$Blocks.Add($b) } }
function Save-Blocks { Save-Json $BlocksFile @($Blocks) }
$Learned = [ordered]@{}
foreach ($l in @(Read-Json $LearnedFile)) { if ($l -and $l.Key) { $Learned[[string]$l.Key] = $l } }
function Save-Learned { Save-Json $LearnedFile @($Learned.Values) }
if ((Test-Path $HistoryFile) -and ((Get-Item $HistoryFile).Length -gt 5MB)) { Move-Item $HistoryFile "$HistoryFile.old" -Force }

$sys32 = "$env:windir\System32\*"
$Expected = @{ svchost=@($sys32); lsass=@($sys32); services=@($sys32); csrss=@($sys32); winlogon=@($sys32); wininit=@($sys32); smss=@($sys32); spoolsv=@($sys32); taskhostw=@($sys32); dllhost=@($sys32,"$env:windir\SysWOW64\*"); conhost=@($sys32); runtimebroker=@($sys32); sihost=@($sys32); ctfmon=@($sys32); cmd=@($sys32,"$env:windir\SysWOW64\*"); explorer=@("$env:windir\explorer.exe"); notepad=@($sys32,"$env:windir\*","$env:ProgramFiles\WindowsApps\*"); chrome=@("$env:ProgramFiles\Google\Chrome\*","${env:ProgramFiles(x86)}\Google\Chrome\*","$env:LOCALAPPDATA\Google\Chrome\*"); msedge=@("${env:ProgramFiles(x86)}\Microsoft\Edge\*","$env:ProgramFiles\Microsoft\Edge\*"); firefox=@("$env:ProgramFiles\Mozilla Firefox\*","${env:ProgramFiles(x86)}\Mozilla Firefox\*") }
function Test-FakeName { param([string]$Name,[string]$Path) if (-not $Path) { return $false }; $k=$Name.ToLower(); if (-not $Expected.ContainsKey($k)) { return $false }; foreach ($pattern in $Expected[$k]) { if ($Path -like $pattern) { return $false } }; return $true }
function Test-PrivateIP { param([string]$Ip) if (-not $Ip -or $Ip -eq '0.0.0.0' -or $Ip -eq '::') { return $true }; if ($Ip -match '^(10\.|127\.|169\.254\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.|100\.(6[4-9]|[7-9][0-9]|1[01][0-9]|12[0-7])\.)') { return $true }; if ($Ip -match '^(fe80|fc|fd)' -or $Ip -eq '::1') { return $true }; return $false }

# Background signature and host-name helpers
$Shared = [hashtable]::Synchronized(@{ Stop=$false })
$SigCache = New-Object 'System.Collections.Concurrent.ConcurrentDictionary[string,string]'
$SigQueue = New-Object 'System.Collections.Concurrent.ConcurrentQueue[string]'
$SigRequested = New-Object 'System.Collections.Generic.HashSet[string]'
$HostCache = New-Object 'System.Collections.Concurrent.ConcurrentDictionary[string,string]'
$DnsQueue = New-Object 'System.Collections.Concurrent.ConcurrentQueue[string]'
$DnsRequested = New-Object 'System.Collections.Generic.HashSet[string]'
$Workers = New-Object System.Collections.ArrayList
function Start-Worker { param([scriptblock]$Code,[hashtable]$Vars) $rs=[runspacefactory]::CreateRunspace(); $rs.Open(); foreach ($k in $Vars.Keys) { $rs.SessionStateProxy.SetVariable($k,$Vars[$k]) }; $ps=[powershell]::Create(); $ps.Runspace=$rs; [void]$ps.AddScript($Code.ToString()); [void]$ps.BeginInvoke(); [void]$Workers.Add($ps) }
$sigCode = { while (-not $Shared.Stop) { $p=$null; if ($SigQueue.TryDequeue([ref]$p)) { $res='Unsigned'; try { $s=Get-AuthenticodeSignature -LiteralPath $p -ErrorAction Stop; if ($s.Status -eq 'Valid') { $res='Signed'; if ($s.SignerCertificate.Subject -match 'CN=(?:"([^"]+)"|([^,]+))') { if ($Matches[1]) { $res=$Matches[1] } else { $res=$Matches[2] } } } elseif ($s.Status -eq 'NotSigned') { $res='Unsigned' } else { $res="Invalid signature ($($s.Status))" } } catch { $res='Unknown' }; $SigCache[$p]=$res } else { Start-Sleep -Milliseconds 200 } } }
$dnsCode = { while (-not $Shared.Stop) { $ip=$null; if ($DnsQueue.TryDequeue([ref]$ip)) { $res='(no name)'; try { $h=[System.Net.Dns]::GetHostEntry($ip).HostName; if ($h) { $res=$h } } catch {}; $HostCache[$ip]=$res } else { Start-Sleep -Milliseconds 250 } } }
Start-Worker $sigCode @{Shared=$Shared;SigQueue=$SigQueue;SigCache=$SigCache}
for ($i=0; $i -lt 3; $i++) { Start-Worker $dnsCode @{Shared=$Shared;DnsQueue=$DnsQueue;HostCache=$HostCache} }

$NetstatRegex = [regex]'^\s*TCP\s+(\S+):(\d+)\s+(\S+):(\d+)\s+(\S+)\s+(\d+)\s*$'
$ProcCache=@{}; $FirstSeen=@{}; $AlertedAt=@{}
function Get-NetstatLines { $psi=New-Object System.Diagnostics.ProcessStartInfo; $psi.FileName="$env:windir\System32\netstat.exe"; $psi.Arguments="-ano"; $psi.UseShellExecute=$false; $psi.RedirectStandardOutput=$true; $psi.CreateNoWindow=$true; $p=[System.Diagnostics.Process]::Start($psi); $out=$p.StandardOutput.ReadToEnd(); $p.WaitForExit(); return ($out -split "`r?`n") }
function Get-ProcPath { param([int]$ProcId,[string]$Name) $c=$ProcCache[$ProcId]; if ($c -and $c.Name -eq $Name) { return $c.Path }; $path=''; try { $path=[string](Get-Process -Id $ProcId -ErrorAction Stop).Path } catch {}; $ProcCache[$ProcId]=@{Name=$Name;Path=$path}; return $path }
function Get-AppStatus { param([string]$Name,[string]$Path,[int]$ProcId,[string]$TrustKey) if ($ProcId -eq $PID -or $ProcId -le 4) { return 'OK' }; if ($Trusted.Contains($TrustKey)) { return 'OK' }; if (Test-FakeName $Name $Path) { return 'DANGER' }; return 'UNTRUSTED' }
function Collect-Data {
    $now=Get-Date; $names=@{}; foreach ($p in [System.Diagnostics.Process]::GetProcesses()) { $names[[int]$p.Id]=$p.ProcessName; $p.Dispose() }; if ($ProcCache.Count -gt 3000) { $ProcCache.Clear() }
    $rows=New-Object System.Collections.ArrayList; $seen=@{}; $resolve=[bool]$chkNames.Checked
    foreach ($line in (Get-NetstatLines)) {
        $m=$NetstatRegex.Match($line); if (-not $m.Success) { continue }; $st=$m.Groups[5].Value
        if ($st -eq 'ESTABLISHED') { $state='Established' } elseif ($st -eq 'LISTENING') { $state='Listen' } else { continue }
        $laddr=$m.Groups[1].Value -replace '^\[|\]$','' -replace '%.*$',''; $raddr=$m.Groups[3].Value -replace '^\[|\]$','' -replace '%.*$',''
        $lport=[int]$m.Groups[2].Value; $rport=[int]$m.Groups[4].Value; $procId=[int]$m.Groups[6].Value; $name=$names[$procId]
        if (-not $name) { if ($procId -eq 0) { $name='System Idle' } else { $name='unknown' } }; $path=''; if ($procId -gt 4) { $path=Get-ProcPath $procId $name }
        $trustKey=Get-TrustKey $name $path; $status=Get-AppStatus $name $path $procId $trustKey
        if ($procId -le 4) { $pub='Windows' } elseif (-not $path) { $pub='' } else { $pub=''; if (-not $SigCache.TryGetValue($path,[ref]$pub)) { $pub='Checking...'; if ($SigRequested.Add($path)) { $SigQueue.Enqueue($path) } } }
        $site=''
        if ($state -eq 'Established' -and $resolve) { if (Test-PrivateIP $raddr) { $site='(local network)' } else { $h=''; if ($HostCache.TryGetValue($raddr,[ref]$h)) { $site=$h } else { $site='...'; if ($DnsRequested.Add($raddr)) { $DnsQueue.Enqueue($raddr) } } } }
        $key="$procId|$lport|$raddr|$rport"; $seen[$key]=$true
        if (-not $FirstSeen.ContainsKey($key)) { $FirstSeen[$key]=@{Time=$now;Initial=$script:FirstCycle} }
        $fs=$FirstSeen[$key]; $isNew=(-not $fs.Initial) -and (($now-$fs.Time).TotalMinutes -lt 2) -and ($state -eq 'Established')
        if ($fs.Initial) { $fsText='before start' } else { $fsText=$fs.Time.ToString('HH:mm:ss') }
        [void]$rows.Add([pscustomobject]@{Key=$key;Name=$name;ProcId=$procId;Path=$path;Publisher=$pub;LocalAddress=$laddr;LocalPort=$lport;RemoteAddress=$raddr;RemotePort=$rport;State=$state;Site=$site;Status=$status;TrustKey=$trustKey;FirstSeenText=$fsText;IsNew=$isNew})
    }
    foreach ($k in @($FirstSeen.Keys)) { if (-not $seen.ContainsKey($k)) { $FirstSeen.Remove($k) } }; $script:FirstCycle=$false; return ,$rows
}

function Test-Learning { return ($null -ne $script:LearningUntil -and (Get-Date) -lt $script:LearningUntil) }
function Add-History { param($r) try { $site=$r.Site; if ($site -eq '...') { $site='' }; $pub=$r.Publisher; if ($pub -eq 'Checking...') { $pub='' }; [pscustomobject]@{Time=(Get-Date -Format 'yyyy-MM-dd HH:mm:ss');Status=$r.Status;App=$r.Name;PID=$r.ProcId;RemoteIP=$r.RemoteAddress;RemoteHost=$site;RemotePort=$r.RemotePort;Publisher=$pub;Path=$r.Path} | Export-Csv $HistoryFile -Append -NoTypeInformation -Encoding UTF8 } catch { Write-AppLog "History: $($_.Exception.Message)" } }
function Learn-App { param($r) $k=$r.TrustKey; $remote=$r.Site; if (-not $remote -or $remote -eq '...') { $remote=$r.RemoteAddress }; if ($Learned.Contains($k)) { $o=$Learned[$k]; $o.Seen=[int]$o.Seen+1; $o.LastRemote=$remote; if ($r.Status -eq 'DANGER') { $o.Status='DANGER' } } else { $Learned[$k]=[pscustomobject]@{Key=$k;Name=$r.Name;Path=$r.Path;Status=$r.Status;FirstSeen=(Get-Date).ToString('s');LastRemote=$remote;Seen=1} }; $script:LearnedDirty=$true }
function Send-Alert {
    param($List) $first=$List[0]; $danger=(@($List|Where-Object {$_.Status -eq 'DANGER'}).Count -gt 0); foreach ($r in $List) { Add-History $r }
    if ($List.Count -eq 1) { if ($first.Status -eq 'DANGER') { $title='DANGER: possible fake system name' } else { $title='Untrusted app is online' }; $text="$($first.Name) -> $($first.RemoteAddress):$($first.RemotePort)" } else { $title="$($List.Count) untrusted connections"; $text=(($List|ForEach-Object {$_.Name}|Select-Object -Unique|Select-Object -First 4) -join ', ') }
    $script:BalloonAction='alert'; $script:LastAlertKey=$first.Key; $notify.BalloonTipTitle=$title; $notify.BalloonTipText=$text; if ($danger) { $notify.BalloonTipIcon='Error' } else { $notify.BalloonTipIcon='Warning' }; $notify.ShowBalloonTip(6000); [System.Media.SystemSounds]::Exclamation.Play(); if ($form.Visible -and $tabs.SelectedIndex -eq 1) { Load-History }
}
function Process-Alerts { param($Rows) $learning=Test-Learning; $alertList=New-Object System.Collections.ArrayList; foreach ($r in $Rows) { if ($r.State -ne 'Established' -or $r.Status -eq 'OK' -or $r.RemoteAddress -in @('127.0.0.1','::1')) { continue }; if ($learning) { Learn-App $r }; if ($learning -and $r.Status -eq 'UNTRUSTED') { continue }; if ($script:AlertsPaused) { continue }; $ak="$($r.TrustKey)|$($r.RemoteAddress)|$($r.RemotePort)"; if ($AlertedAt.ContainsKey($ak) -and ((Get-Date)-$AlertedAt[$ak]).TotalMinutes -lt $AlertCooldownMin) { continue }; $AlertedAt[$ak]=Get-Date; [void]$alertList.Add($r) }; if ($AlertedAt.Count -gt 500) { foreach ($k in @($AlertedAt.Keys)) { if (((Get-Date)-$AlertedAt[$k]).TotalMinutes -gt $AlertCooldownMin) { $AlertedAt.Remove($k) } } }; if ($alertList.Count -gt 0) { Send-Alert $alertList } }

function Show-Info { param([string]$Text) [void][System.Windows.Forms.MessageBox]::Show($Text,"Port Manager","OK","Information") }
function Show-Error { param([string]$Text) [void][System.Windows.Forms.MessageBox]::Show($Text,"Port Manager","OK","Error") }
function Ask-Yes { param([string]$Text,[string]$Icon="Question") return ([System.Windows.Forms.MessageBox]::Show($Text,"Port Manager","YesNo",$Icon) -eq "Yes") }
function Set-Note { param([string]$Text) $script:Note=$Text; $script:NoteUntil=(Get-Date).AddSeconds(8); if ($lblStatus) { $lblStatus.Text=$Text } }
function New-Button { param([string]$Text,[int]$Width=128) $b=New-Object System.Windows.Forms.Button; $b.Text=$Text; $b.Width=$Width; $b.Height=30; return $b }
function New-Check { param([string]$Text,[bool]$Checked=$false) $c=New-Object System.Windows.Forms.CheckBox; $c.Text=$Text; $c.AutoSize=$true; $c.Checked=$Checked; $c.Margin=New-Object System.Windows.Forms.Padding(8,4,0,0); return $c }

$form=New-Object System.Windows.Forms.Form; $form.Text="Port Manager"; $form.Size=New-Object System.Drawing.Size(1180,680); $form.MinimumSize=New-Object System.Drawing.Size(900,500); $form.StartPosition="CenterScreen"
$tabs=New-Object System.Windows.Forms.TabControl; $tabs.Dock="Fill"; $tabLive=New-Object System.Windows.Forms.TabPage "Live ports"; $tabHist=New-Object System.Windows.Forms.TabPage "Alert history"; [void]$tabs.TabPages.Add($tabLive); [void]$tabs.TabPages.Add($tabHist); $form.Controls.Add($tabs)
$grid=New-Object System.Windows.Forms.DataGridView; $grid.Dock="Fill"; $grid.ReadOnly=$true; $grid.AllowUserToAddRows=$false; $grid.AllowUserToDeleteRows=$false; $grid.AllowUserToResizeRows=$false; $grid.SelectionMode="FullRowSelect"; $grid.MultiSelect=$false; $grid.RowHeadersVisible=$false; $grid.BackgroundColor=[System.Drawing.Color]::White
$boldFont=New-Object System.Drawing.Font($grid.Font,[System.Drawing.FontStyle]::Bold)
$top=New-Object System.Windows.Forms.FlowLayoutPanel; $top.Dock="Top"; $top.AutoSize=$true; $top.AutoSizeMode="GrowAndShrink"; $top.WrapContents=$true; $top.Padding=New-Object System.Windows.Forms.Padding(6,6,6,2)
$lblSearch=New-Object System.Windows.Forms.Label; $lblSearch.Text="Search:"; $lblSearch.AutoSize=$true; $lblSearch.Margin=New-Object System.Windows.Forms.Padding(0,6,4,0)
$txtFilter=New-Object System.Windows.Forms.TextBox; $txtFilter.Width=150
$chkUntrusted=New-Check "Only untrusted"; $chkLocal=New-Check "Hide local-only (127.0.0.1)" $true; $chkNames=New-Check "Show website names" ([bool]$Settings.ResolveNames); $chkAuto=New-Check "Auto refresh" $true; $chkPause=New-Check "Pause alerts"; $chkStart=New-Check "Start with Windows"
$cmbInterval=New-Object System.Windows.Forms.ComboBox; $cmbInterval.DropDownStyle="DropDownList"; $cmbInterval.Width=85; [void]$cmbInterval.Items.AddRange(@("1 second","2 seconds","5 seconds","10 seconds")); $idx=[int]$Settings.RefreshIndex; if ($idx -lt 0 -or $idx -ge $Intervals.Count) { $idx=1 }; $cmbInterval.SelectedIndex=$idx
$btnRefresh=New-Button "Refresh now" 100; $btnRefresh.Margin=New-Object System.Windows.Forms.Padding(8,0,0,0)
foreach ($c in @($lblSearch,$txtFilter,$chkUntrusted,$chkLocal,$chkNames,$chkAuto,$cmbInterval,$btnRefresh,$chkPause,$chkStart)) { $top.Controls.Add($c) }
$bottom=New-Object System.Windows.Forms.FlowLayoutPanel; $bottom.Dock="Bottom"; $bottom.AutoSize=$true; $bottom.AutoSizeMode="GrowAndShrink"; $bottom.WrapContents=$true; $bottom.Padding=New-Object System.Windows.Forms.Padding(6,6,6,4)
$btnTrust=New-Button "Trust this app"; $btnUntrust=New-Button "Untrust this app"; $btnBlockApp=New-Button "Block this app..."; $btnBlockIP=New-Button "Block remote IP..."; $btnBlockPort=New-Button "Block this port..."; $btnClose=New-Button "Close this app"; $btnBlockAll=New-Button "Block all untrusted..." 150; $btnTrustList=New-Button "Trusted apps"; $btnManage=New-Button "My blocks"; $btnOnline=New-Button "Check online..." 120; $btnFirewall=New-Button "Firewall setup..." 140; $btnLearn=New-Button "Learning mode"; $btnQuit=New-Button "Quit" 80
foreach ($b in @($btnTrust,$btnUntrust,$btnBlockApp,$btnBlockIP,$btnBlockPort,$btnClose,$btnBlockAll,$btnTrustList,$btnManage,$btnOnline,$btnFirewall,$btnLearn,$btnQuit)) { $bottom.Controls.Add($b) }
$bottom.SetFlowBreak($btnQuit,$true)
$lblStatus=New-Object System.Windows.Forms.Label; $lblStatus.AutoSize=$true; $lblStatus.Text="Select a row, then choose an action. Right-click a row for more."; $lblStatus.Margin=New-Object System.Windows.Forms.Padding(6,6,0,0); $bottom.Controls.Add($lblStatus)
$details=New-Object System.Windows.Forms.TextBox; $details.Dock='Bottom'; $details.Height=82; $details.Multiline=$true; $details.ReadOnly=$true; $details.ScrollBars='Vertical'; $details.BackColor=[System.Drawing.Color]::White; $details.Text='Select a connection to see process, signature, endpoints, and path details.'
$tabLive.Controls.Add($grid); $tabLive.Controls.Add($details); $tabLive.Controls.Add($top); $tabLive.Controls.Add($bottom)
$histGrid=New-Object System.Windows.Forms.DataGridView; $histGrid.Dock="Fill"; $histGrid.ReadOnly=$true; $histGrid.AllowUserToAddRows=$false; $histGrid.AllowUserToDeleteRows=$false; $histGrid.SelectionMode="FullRowSelect"; $histGrid.MultiSelect=$false; $histGrid.RowHeadersVisible=$false; $histGrid.BackgroundColor=[System.Drawing.Color]::White
$histBottom=New-Object System.Windows.Forms.FlowLayoutPanel; $histBottom.Dock="Bottom"; $histBottom.AutoSize=$true; $histBottom.AutoSizeMode="GrowAndShrink"; $histBottom.Padding=New-Object System.Windows.Forms.Padding(6,6,6,4)
$hTrust=New-Button "Trust this app"; $hBlock=New-Button "Block this app..."; $hRefresh=New-Button "Refresh" 90; $hExport=New-Button "Export to CSV" 120; $hClear=New-Button "Clear history" 110
foreach ($b in @($hTrust,$hBlock,$hRefresh,$hExport,$hClear)) { $histBottom.Controls.Add($b) }; $tabHist.Controls.Add($histGrid); $tabHist.Controls.Add($histBottom)
$notify=New-Object System.Windows.Forms.NotifyIcon; $notify.Icon=[System.Drawing.SystemIcons]::Shield; $notify.Text="Port Manager - watching"; $notify.Visible=$true

$script:Dt=New-Object System.Data.DataTable
[void]$script:Dt.Columns.Add("Rank",[int])
foreach ($c in @('Status','New','Process','Publisher')) { [void]$script:Dt.Columns.Add($c) }
[void]$script:Dt.Columns.Add("PID",[int]); [void]$script:Dt.Columns.Add("LocalAddress"); [void]$script:Dt.Columns.Add("LocalPort",[int])
foreach ($c in @('RemoteAddress','Site')) { [void]$script:Dt.Columns.Add($c) }
[void]$script:Dt.Columns.Add("RemotePort",[int]); foreach ($c in @('Direction','State','FirstSeen','Path')) { [void]$script:Dt.Columns.Add($c) }
$script:Dt.DefaultView.Sort="Rank ASC, Process ASC"
function Setup-Grid { if ($script:GridReady) { return }; $grid.DataSource=$script:Dt.DefaultView; if ($grid.Columns.Count -eq 0) { return }; $widths=@{Status=90;New=45;Process=130;Publisher=170;PID=55;LocalPort=75;RemoteAddress=120;Site=210;RemotePort=80;Direction=95;State=85;FirstSeen=95}; foreach ($k in $widths.Keys) { $grid.Columns[$k].Width=$widths[$k] }; $grid.Columns["Rank"].Visible=$false; $grid.Columns["LocalAddress"].Visible=$false; $grid.Columns["Path"].AutoSizeMode="Fill"; $grid.Columns["Path"].MinimumWidth=200; $grid.Columns["LocalPort"].HeaderText="Local port"; $grid.Columns["RemoteAddress"].HeaderText="Remote IP"; $grid.Columns["Site"].HeaderText="Website / host"; $grid.Columns["RemotePort"].HeaderText="Remote port"; $grid.Columns["Direction"].HeaderText="Direction"; $grid.Columns["FirstSeen"].HeaderText="First seen"; $script:GridReady=$true }
function Fill-Grid {
    if (-not $script:GridReady) { Setup-Grid }; if (-not $script:GridReady) { return }
    $text=$txtFilter.Text.Trim().ToLower(); $onlyUntrusted=$chkUntrusted.Checked; $hideLocal=$chkLocal.Checked; $loop=@('127.0.0.1','::1'); $view=New-Object System.Collections.ArrayList
    foreach ($r in $script:Rows) { if ($hideLocal -and (($loop -contains $r.LocalAddress) -or ($loop -contains $r.RemoteAddress))) { continue }; if ($onlyUntrusted -and $r.Status -eq 'OK') { continue }; if ($text) { $line="$($r.Name) $($r.LocalPort) $($r.RemoteAddress) $($r.RemotePort) $($r.Site) $($r.Publisher) $($r.Path)".ToLower(); if (-not $line.Contains($text)) { continue } }; [void]$view.Add($r) }
    $untrustedNow=@($script:Rows|Where-Object {$_.Status -ne 'OK' -and $_.State -eq 'Established'}).Count; $msg="Showing $($view.Count) of $($script:Rows.Count) | untrusted online: $untrustedNow"; if (Test-Learning) { $msg+=" | LEARNING MODE until "+$script:LearningUntil.ToString('HH:mm dd/MM')+" (no alerts)" }; if ($script:AlertsPaused) { $msg+=" | ALERTS PAUSED" }; if ($script:NoteUntil -gt (Get-Date)) { $msg=$script:Note+"    ["+$msg+"]" }; $lblStatus.Text=$msg
    $sig=(($view|ForEach-Object {"$($_.Key)|$($_.Status)|$($_.Publisher)|$($_.Site)|$($_.IsNew)"}) -join ';'); if ($sig -eq $script:LastSig -and -not $script:PendingSelect) { return }; $script:LastSig=$sig
    $selKey=$script:PendingSelect; if (-not $selKey -and $grid.SelectedRows.Count -gt 0) { $sr=$grid.SelectedRows[0]; $selKey="$($sr.Cells['PID'].Value)|$($sr.Cells['LocalPort'].Value)|$($sr.Cells['RemoteAddress'].Value)|$($sr.Cells['RemotePort'].Value)" }
    $scroll=0; try { $scroll=$grid.FirstDisplayedScrollingRowIndex } catch {}; if ($scroll -lt 0) { $scroll=0 }
    $script:Dt.BeginLoadData(); $script:Dt.Rows.Clear(); foreach ($r in $view) { $rank=2; if ($r.Status -eq 'DANGER') { $rank=0 } elseif ($r.Status -eq 'UNTRUSTED') { $rank=1 }; $newText=''; if ($r.IsNew) { $newText='NEW' }; $direction='Established (2-way)'; if ($r.State -eq 'Listen') { $direction='Listening (inbound-ready)' }; [void]$script:Dt.Rows.Add($rank,$r.Status,$newText,$r.Name,$r.Publisher,$r.ProcId,$r.LocalAddress,$r.LocalPort,$r.RemoteAddress,$r.Site,$r.RemotePort,$direction,$r.State,$r.FirstSeenText,$r.Path) }; $script:Dt.EndLoadData()
    try { if ($scroll -lt $grid.RowCount) { $grid.FirstDisplayedScrollingRowIndex=$scroll } } catch {}; $grid.CurrentCell=$null; $grid.ClearSelection()
    if ($selKey) { foreach ($row in $grid.Rows) { $k="$($row.Cells['PID'].Value)|$($row.Cells['LocalPort'].Value)|$($row.Cells['RemoteAddress'].Value)|$($row.Cells['RemotePort'].Value)"; if ($k -eq $selKey) { $row.Selected=$true; if ($script:PendingSelect) { try { $grid.FirstDisplayedScrollingRowIndex=$row.Index } catch {} }; break } } }; $script:PendingSelect=$null
}
function Update-All { param([switch]$Force) if ($script:Updating) { return }; $script:Updating=$true; try { $script:Rows=Collect-Data; Process-Alerts $script:Rows; $visible=$form.Visible -and ($form.WindowState -ne 'Minimized') -and ($tabs.SelectedIndex -eq 0); if ($visible -and ($Force -or $chkAuto.Checked)) { Fill-Grid } } catch { Write-AppLog "Update-All: $($_.Exception.Message) (line $($_.InvocationInfo.ScriptLineNumber))" } finally { $script:Updating=$false } }
function Format-StatusCell { param($sender,$e) if ($e.RowIndex -lt 0) { return }; $row=$sender.Rows[$e.RowIndex]; $st=$row.Cells["Status"].Value; if ($st -eq 'DANGER') { $e.CellStyle.BackColor=[System.Drawing.Color]::DarkRed; $e.CellStyle.ForeColor=[System.Drawing.Color]::White } elseif ($st -eq 'UNTRUSTED') { $e.CellStyle.BackColor=[System.Drawing.Color]::MistyRose }; if ($row.Cells["New"]) { if ($row.Cells["New"].Value -eq 'NEW') { $e.CellStyle.Font=$boldFont } } }
$grid.Add_CellFormatting({param($sender,$e) Format-StatusCell $sender $e}); $histGrid.Add_CellFormatting({param($sender,$e) Format-StatusCell $sender $e})
$grid.Add_CellMouseDown({param($sender,$e) if ($e.Button -eq 'Right' -and $e.RowIndex -ge 0) { $sender.ClearSelection(); $sender.Rows[$e.RowIndex].Selected=$true }})
$grid.Add_SelectionChanged({if (-not $details -or $grid.SelectedRows.Count -eq 0) { return }; $r=Get-Selected; if (-not $r) { return }; $details.Text="Process: $($r.Process)    PID: $($r.ProcId)    Publisher/signature: $($r.Publisher)`r`nConnection: $($r.Direction)    State: $($r.State)    Local: $($r.LocalAddress):$($r.LocalPort)    Remote: $($r.RemoteAddress):$($r.RemotePort)`r`nExecutable: $($r.Path)"})
function Get-Selected { if ($grid.SelectedRows.Count -eq 0) { Show-Info "Please click a row first."; return $null }; $r=$grid.SelectedRows[0]; return [pscustomobject]@{Process=[string]$r.Cells["Process"].Value;ProcId=[int]$r.Cells["PID"].Value;LocalAddress=[string]$r.Cells["LocalAddress"].Value;LocalPort=[int]$r.Cells["LocalPort"].Value;RemoteAddress=[string]$r.Cells["RemoteAddress"].Value;RemotePort=[int]$r.Cells["RemotePort"].Value;Direction=[string]$r.Cells["Direction"].Value;State=[string]$r.Cells["State"].Value;Path=[string]$r.Cells["Path"].Value;Status=[string]$r.Cells["Status"].Value;Publisher=[string]$r.Cells["Publisher"].Value} }
function Get-HistSelected { if ($histGrid.SelectedRows.Count -eq 0) { Show-Info "Please click a row first."; return $null }; $r=$histGrid.SelectedRows[0]; $procId=0; [void][int]::TryParse([string]$r.Cells["PID"].Value,[ref]$procId); $rport=0; [void][int]::TryParse([string]$r.Cells["RemotePort"].Value,[ref]$rport); return [pscustomobject]@{Process=[string]$r.Cells["App"].Value;ProcId=$procId;LocalPort=0;RemoteAddress=[string]$r.Cells["RemoteIP"].Value;RemotePort=$rport;State='Established';Path=[string]$r.Cells["Path"].Value;Status=[string]$r.Cells["Status"].Value;Publisher=[string]$r.Cells["Publisher"].Value} }

# Opens only the selected process name and port; no IP address or file path is sent.
function Show-OnlineCheck {
    param($S)
    if (-not $S) { return }
    $port=[int]$S.RemotePort; $portKind='remote'
    if ($S.State -eq 'Listen' -or $port -le 0) { $port=[int]$S.LocalPort; $portKind='local listening' }
    if ($port -le 0) { Show-Error "This row has no TCP port to check."; return }
    $process=[string]$S.Process
    $portUrl="https://www.speedguide.net/port.php?port=$port"
    $processQuery=[uri]::EscapeDataString("`"$process`" Windows process service")
    $processUrl="https://www.google.com/search?q=$processQuery"
    $combinedQuery=[uri]::EscapeDataString("`"$process`" TCP port $port expected service")
    $combinedUrl="https://www.google.com/search?q=$combinedQuery"
    $menu=New-Object System.Windows.Forms.ContextMenuStrip
    $links=@(@{Text="Check $portKind TCP port $port / usual service";Url=$portUrl},@{Text="Search process: $process";Url=$processUrl},@{Text="Search process + port together";Url=$combinedUrl})
    foreach ($link in $links) { $item=$menu.Items.Add($link.Text); $item.Tag=$link.Url; $item.Add_Click({param($sender,$e) try { Start-Process ([string]$sender.Tag) } catch { Show-Error "Could not open the browser:`n$($_.Exception.Message)" }}) }
    [void]$menu.Items.Add('-'); $note=$menu.Items.Add("Lookups help investigation; they do not prove a connection is safe."); $note.Enabled=$false
    $menu.Show([System.Windows.Forms.Cursor]::Position)
}
function Show-FirewallSetup {
    $d=New-Object System.Windows.Forms.Form; $d.Text='Configure Windows Firewall'; $d.StartPosition='CenterParent'; $d.FormBorderStyle='FixedDialog'; $d.MaximizeBox=$false; $d.MinimizeBox=$false; $d.ShowInTaskbar=$false; $d.ClientSize=New-Object System.Drawing.Size(470,285)
    $intro=New-Object System.Windows.Forms.Label; $intro.Location=New-Object System.Drawing.Point(14,12); $intro.Size=New-Object System.Drawing.Size(440,48); $intro.Text='Set firewall defaults for Domain, Private, and Public profiles, then add TCP port exceptions. This affects all programs on this PC.'
    $inLabel=New-Object System.Windows.Forms.Label; $inLabel.Location=New-Object System.Drawing.Point(16,76); $inLabel.Size=New-Object System.Drawing.Size(270,24); $inLabel.Text='Allow inbound TCP local port:'
    $inPort=New-Object System.Windows.Forms.NumericUpDown; $inPort.Location=New-Object System.Drawing.Point(320,72); $inPort.Width=100; $inPort.Minimum=1; $inPort.Maximum=65535; $inPort.Value=80
    $outLabel=New-Object System.Windows.Forms.Label; $outLabel.Location=New-Object System.Drawing.Point(16,116); $outLabel.Size=New-Object System.Drawing.Size(290,24); $outLabel.Text='Block outbound TCP remote port:'
    $outPort=New-Object System.Windows.Forms.NumericUpDown; $outPort.Location=New-Object System.Drawing.Point(320,112); $outPort.Width=100; $outPort.Minimum=1; $outPort.Maximum=65535; $outPort.Value=25
    $warning=New-Object System.Windows.Forms.Label; $warning.Location=New-Object System.Drawing.Point(16,153); $warning.Size=New-Object System.Drawing.Size(438,48); $warning.ForeColor=[System.Drawing.Color]::DarkRed; $warning.Text='Existing firewall rules remain active and may override these defaults. Check organization-managed policies before changing them.'
    $apply=New-Object System.Windows.Forms.Button; $apply.Text='Apply firewall settings'; $apply.Location=New-Object System.Drawing.Point(174,220); $apply.Size=New-Object System.Drawing.Size(160,32)
    $cancel=New-Object System.Windows.Forms.Button; $cancel.Text='Cancel'; $cancel.Location=New-Object System.Drawing.Point(344,220); $cancel.Size=New-Object System.Drawing.Size(100,32); $cancel.DialogResult=[System.Windows.Forms.DialogResult]::Cancel
    foreach ($c in @($intro,$inLabel,$inPort,$outLabel,$outPort,$warning,$apply,$cancel)) { $d.Controls.Add($c) }; $d.CancelButton=$cancel
    $apply.Add_Click({
        $in=[int]$inPort.Value; $out=[int]$outPort.Value
        $confirm="This will set the default inbound action to Block and outbound action to Allow for all firewall profiles, then allow inbound TCP port $in and block outbound TCP port $out.`n`nThese changes affect every app on this PC. Continue?"
        if (-not (Ask-Yes $confirm 'Warning')) { return }
        try {
            Set-NetFirewallProfile -Profile Domain,Private,Public -Enabled True -DefaultInboundAction Block -DefaultOutboundAction Allow
            $allowName="Port Manager - Allow inbound TCP $in"; $blockName="Port Manager - Block outbound TCP $out"
            Remove-NetFirewallRule -DisplayName $allowName -ErrorAction SilentlyContinue
            Remove-NetFirewallRule -DisplayName $blockName -ErrorAction SilentlyContinue
            New-NetFirewallRule -DisplayName $allowName -Direction Inbound -Action Allow -Enabled True -Protocol TCP -LocalPort $in -Profile Domain,Private,Public | Out-Null
            New-NetFirewallRule -DisplayName $blockName -Direction Outbound -Action Block -Enabled True -Protocol TCP -RemotePort $out -Profile Domain,Private,Public | Out-Null
            Set-Note "Firewall configured: inbound allow TCP $in; outbound block TCP $out"
            [void][System.Windows.Forms.MessageBox]::Show("Firewall settings applied.`n`nDefault inbound: Block`nDefault outbound: Allow`nAllowed inbound TCP port: $in`nBlocked outbound TCP port: $out`n`nExisting rules were not removed.",'Port Manager','OK','Information')
            $d.Close()
        } catch { Show-Error "Could not configure the firewall:`n$($_.Exception.Message)`n`nMake sure Port Manager is running as Administrator." }
    })
    [void]$d.ShowDialog($form)
}
function Do-Trust { param($S) if (-not $S) { return }; if ($S.ProcId -eq $PID -or ($S.ProcId -le 4 -and $S.ProcId -gt 0 -and -not $S.Path)) { Set-Note "$($S.Process) is always trusted."; return }; if ($S.Status -eq 'DANGER') { if (-not (Ask-Yes "WARNING: '$($S.Process)' runs from an unexpected folder:`n$($S.Path)`n`nThis is how fake system apps hide. Trust it anyway?" 'Warning')) { return } }; Add-Trust $S.Process $S.Path; Set-Note "Trusted: $($S.Process)"; Update-All -Force }
function Do-Untrust { param($S) if (-not $S) { return }; if (Remove-Trust $S.Process $S.Path) { Set-Note "Untrusted: $($S.Process)" } else { Set-Note "'$($S.Process)' was not in your trusted list." }; Update-All -Force }

function Show-BlockDialog {
    param([string]$Message,[bool]$ShowClose=$false,[bool]$Warn=$false,[bool]$PortRule=$false,[bool]$HasProcess=$false)
    $d=New-Object System.Windows.Forms.Form; $d.Text="Port Manager - Block"; $d.StartPosition="CenterParent"; $d.FormBorderStyle="FixedDialog"; $d.MaximizeBox=$false; $d.MinimizeBox=$false; $d.ShowInTaskbar=$false; $d.ClientSize=New-Object System.Drawing.Size(500,410)
    $lbl=New-Object System.Windows.Forms.Label; $lbl.Location=New-Object System.Drawing.Point(12,10); $lbl.Size=New-Object System.Drawing.Size(476,75); $lbl.Text=$Message; if ($Warn) { $lbl.ForeColor=[System.Drawing.Color]::DarkRed }
    $protocol=New-Object System.Windows.Forms.ComboBox; $protocol.DropDownStyle='DropDownList'; $protocol.Location=New-Object System.Drawing.Point(155,92); $protocol.Width=120; [void]$protocol.Items.AddRange(@('TCP','UDP')); $protocol.SelectedIndex=0; $protocol.Visible=$PortRule
    $protocolLabel=New-Object System.Windows.Forms.Label; $protocolLabel.Text='Protocol:'; $protocolLabel.Location=New-Object System.Drawing.Point(18,95); $protocolLabel.AutoSize=$true; $protocolLabel.Visible=$PortRule
    $scope=New-Object System.Windows.Forms.ComboBox; $scope.DropDownStyle='DropDownList'; $scope.Location=New-Object System.Drawing.Point(155,124); $scope.Width=300; [void]$scope.Items.Add('All programs (port-wide)'); if ($HasProcess) { [void]$scope.Items.Add('Selected app only'); $scope.SelectedIndex=1 } else { $scope.SelectedIndex=0 }; $scope.Visible=$PortRule
    $scopeLabel=New-Object System.Windows.Forms.Label; $scopeLabel.Text='Applies to:'; $scopeLabel.Location=New-Object System.Drawing.Point(18,127); $scopeLabel.AutoSize=$true; $scopeLabel.Visible=$PortRule
    $grp=New-Object System.Windows.Forms.GroupBox; $grp.Text="How long?"; $grp.Location=New-Object System.Drawing.Point(12,160); $grp.Size=New-Object System.Drawing.Size(476,105)
    $radios=@(); $labels=@("Forever (until I unblock it)","1 hour","1 day","Until I restart the PC")
    for ($i=0; $i -lt 4; $i++) { $rb=New-Object System.Windows.Forms.RadioButton; $rb.Text=$labels[$i]; $rb.AutoSize=$true; $rb.Location=New-Object System.Drawing.Point(14,(20+20*$i)); if ($i -eq 0) { $rb.Checked=$true }; $grp.Controls.Add($rb); $radios+=$rb }
    $chk=New-Object System.Windows.Forms.CheckBox; $chk.Text="Also close the app now"; $chk.AutoSize=$true; $chk.Checked=$true; $chk.Location=New-Object System.Drawing.Point(16,278); $chk.Visible=$ShowClose
    $ok=New-Object System.Windows.Forms.Button; $ok.Text="Block"; $ok.Size=New-Object System.Drawing.Size(100,30); $ok.Location=New-Object System.Drawing.Point(280,360); $ok.DialogResult=[System.Windows.Forms.DialogResult]::OK
    $cancel=New-Object System.Windows.Forms.Button; $cancel.Text="Cancel"; $cancel.Size=New-Object System.Drawing.Size(100,30); $cancel.Location=New-Object System.Drawing.Point(388,360); $cancel.DialogResult=[System.Windows.Forms.DialogResult]::Cancel
    foreach ($c in @($lbl,$protocol,$protocolLabel,$scope,$scopeLabel,$grp,$chk,$ok,$cancel)) { $d.Controls.Add($c) }; $d.AcceptButton=$ok; $d.CancelButton=$cancel
    if ($d.ShowDialog($form) -ne [System.Windows.Forms.DialogResult]::OK) { return $null }; $dur='forever'; if ($radios[1].Checked) { $dur='1h' } elseif ($radios[2].Checked) { $dur='1d' } elseif ($radios[3].Checked) { $dur='restart' }; $selectedScope='All'; if ($PortRule -and $scope.SelectedIndex -eq 1) { $selectedScope='App' }; $selectedProtocol='TCP'; if ($PortRule) { $selectedProtocol=[string]$protocol.SelectedItem }; return [pscustomobject]@{Duration=$dur;Close=($ShowClose -and $chk.Checked);Scope=$selectedScope;Protocol=$selectedProtocol}
}
function New-Block { param([object[]]$RuleSpecs,[string]$Duration) $suffix=''; $expires=$null; switch ($Duration) { '1h' {$expires=(Get-Date).AddHours(1);$suffix=" [until "+$expires.ToString('yyyy-MM-dd HH:mm')+"]"} '1d' {$expires=(Get-Date).AddDays(1);$suffix=" [until "+$expires.ToString('yyyy-MM-dd HH:mm')+"]"} 'restart' {$suffix=" [until restart]"} }; $names=@(); foreach ($spec in $RuleSpecs) { $p=@{}; foreach ($k in $spec.Keys) { if ($k -ne 'Label') { $p[$k]=$spec[$k] } }; $p['DisplayName']="$RulePrefix $($spec['Label'])$suffix"; $p['Action']='Block'; $p['ErrorAction']='Stop'; New-NetFirewallRule @p | Out-Null; $names+=$p['DisplayName'] }; if ($Duration -ne 'forever') { $exp='restart'; if ($expires) { $exp=$expires.ToString('s') }; [void]$Blocks.Add([pscustomobject]@{Names=@($names);Expires=$exp;Created=(Get-Date).ToString('s')}); Save-Blocks } }
function Remove-BlockByName { param([string]$Name) $entry=$null; foreach ($b in $Blocks) { if (@($b.Names) -contains $Name) { $entry=$b; break } }; if ($entry) { foreach ($n in @($entry.Names)) { Remove-NetFirewallRule -DisplayName $n -ErrorAction SilentlyContinue }; $Blocks.Remove($entry); Save-Blocks } else { Remove-NetFirewallRule -DisplayName $Name -ErrorAction SilentlyContinue } }
try { $script:BootTime=(Get-CimInstance Win32_OperatingSystem -ErrorAction Stop).LastBootUpTime } catch { $script:BootTime=[datetime]::MinValue }
function Expire-Blocks { $now=Get-Date; $changed=$false; foreach ($b in @($Blocks)) { $expired=$false; try { if ($b.Expires -eq 'restart') { if ([datetime]$b.Created -lt $script:BootTime) { $expired=$true } } elseif ($b.Expires) { if ([datetime]$b.Expires -lt $now) { $expired=$true } } } catch { $expired=$true }; if ($expired) { foreach ($n in @($b.Names)) { Remove-NetFirewallRule -DisplayName $n -ErrorAction SilentlyContinue }; $Blocks.Remove($b); $changed=$true } }; if ($changed) { Save-Blocks } }
function Close-AppByPath { param([string]$Name,[string]$Path) Get-Process -Name $Name -ErrorAction SilentlyContinue | Where-Object {$_.Id -ne $PID -and $_.Path -eq $Path} | ForEach-Object { try { Stop-Process -Id $_.Id -Force -ErrorAction Stop } catch {} } }
function Do-BlockApp { param($S) if (-not $S) { return }; if ($S.ProcId -eq $PID) { Show-Info "This is Port Manager itself."; return }; if (-not $S.Path) { Show-Error "Windows does not show the file path of '$($S.Process)', so it cannot be blocked by app."; return }; $msg="Block '$($S.Process)' from ALL network traffic (in and out)?`n`n$($S.Path)"; $warn=$false; if ($S.Path -like "$env:windir\*") { $msg+="`n`nWARNING: this is a Windows system file. Blocking it can break internet, updates or Windows itself."; $warn=$true }; $opt=Show-BlockDialog -Message $msg -ShowClose $true -Warn $warn; if (-not $opt) { return }; try { New-Block -Duration $opt.Duration -RuleSpecs @(@{Label="App - $($S.Process) (out)";Direction='Outbound';Program=$S.Path},@{Label="App - $($S.Process) (in)";Direction='Inbound';Program=$S.Path}); if ($opt.Close) { Close-AppByPath $S.Process $S.Path }; Set-Note "Blocked: $($S.Process)"; Update-All -Force } catch { Show-Error "Could not create the rule:`n$($_.Exception.Message)" } }
function Do-BlockIP { param($S) if (-not $S) { return }; if ($S.RemoteAddress -in @("","0.0.0.0","::")) { Show-Error "This row has no remote address (it is a listening port). Use 'Block this port' instead."; return }; $opt=Show-BlockDialog -Message "Block all traffic to and from this address?`n`n$($S.RemoteAddress)`n`nThe live connection stays open until the app closes it. Use 'Close this app' to cut it now."; if (-not $opt) { return }; try { New-Block -Duration $opt.Duration -RuleSpecs @(@{Label="IP - $($S.RemoteAddress) (out)";Direction='Outbound';RemoteAddress=$S.RemoteAddress},@{Label="IP - $($S.RemoteAddress) (in)";Direction='Inbound';RemoteAddress=$S.RemoteAddress}); Set-Note "Blocked IP: $($S.RemoteAddress)" } catch { Show-Error "Could not create the rule:`n$($_.Exception.Message)" } }
function Do-BlockPort { param($S) if (-not $S) { return }; $dir=''; if ($S.State -eq 'Listen') { $dir='Inbound' } else { Show-Info "An established connection carries traffic both ways; Windows netstat does not identify its initiating side. Choose which endpoint's port to block."; $choice=[System.Windows.Forms.MessageBox]::Show("Yes = block local port $($S.LocalPort) for inbound traffic.`nNo = block remote destination port $($S.RemotePort) for outbound traffic.`nCancel = do nothing.",'Choose block direction','YesNoCancel','Question'); if ($choice -eq 'Cancel') { return }; if ($choice -eq 'Yes') { $dir='Inbound' } else { $dir='Outbound' } }; if ($dir -eq 'Inbound') { $port=[int]$S.LocalPort;$param='LocalPort';$msg="Block inbound connections to local port $port?" } else { $dir='Outbound';$port=[int]$S.RemotePort;$param='RemotePort';$msg="Block outbound connections to remote destination port $port?" }; if ($port -le 0) { Show-Error "No port is available for the chosen $dir direction."; return }; $warn=$false; if (@(53,80,443) -contains $port) { $msg+="`n`nWARNING: port $port is used for common internet services. Blocking it can disrupt browsing or name resolution."; $warn=$true }; $opt=Show-BlockDialog -Message $msg -Warn $warn -PortRule $true -HasProcess ([bool]$S.Path); if (-not $opt) { return }; try { $spec=@{Label="Port - $port ($dir) ($($opt.Protocol))";Direction=$dir;Protocol=$opt.Protocol}; $spec[$param]=$port; if ($opt.Scope -eq 'App') { if (-not $S.Path) { Show-Error "Windows did not provide this app's path; cannot create an app-only rule."; return }; $spec['Program']=$S.Path; $spec['Label']="App port - $($S.Process) - $port ($dir) ($($opt.Protocol))" }; New-Block -Duration $opt.Duration -RuleSpecs @($spec); $scopeText='all programs'; if ($opt.Scope -eq 'App') { $scopeText=$S.Process }; Set-Note "Blocked $($opt.Protocol) port $port ($dir; $scopeText)" } catch { Show-Error "Could not create the rule:`n$($_.Exception.Message)" } }
function Do-Close { param($S) if (-not $S) { return }; if ($S.ProcId -eq $PID) { Show-Info "This is Port Manager itself."; return }; if ($S.ProcId -le 4) { Show-Info "This is a Windows system process. It cannot be closed."; return }; if (-not (Ask-Yes "Close '$($S.Process)' (PID $($S.ProcId)) now?`n`nThis only stops it for now. It can start again." 'Warning')) { return }; try { Stop-Process -Id $S.ProcId -Force -ErrorAction Stop; Set-Note "Closed: $($S.Process)"; Update-All -Force } catch { Show-Error "Could not close it:`n$($_.Exception.Message)" } }
function Do-BlockAllUntrusted { $apps=[ordered]@{}; $skipped=@(); foreach ($r in $script:Rows) { if ($r.Status -eq 'OK' -or $r.State -ne 'Established' -or $r.RemoteAddress -in @('127.0.0.1','::1')) { continue }; if (-not $r.Path -or $r.ProcId -eq $PID) { continue }; if ($r.Path -like "$env:windir\*") { if ($skipped -notcontains $r.Name) { $skipped+=$r.Name }; continue }; $apps[$r.Path.ToLower()]=$r }; if ($apps.Count -eq 0) { Show-Info "No untrusted apps with a known file path are online right now."; return }; $list=(($apps.Values|ForEach-Object {"- "+$_.Name}|Select-Object -Unique|Select-Object -First 12) -join "`n"); $msg="Block these $($apps.Count) untrusted app(s) from ALL network traffic?`n`n$list"; if ($skipped.Count -gt 0) { $msg+="`n`n(Skipped Windows files: "+($skipped -join ', ')+")" }; $opt=Show-BlockDialog -Message $msg -ShowClose $true; if (-not $opt) { return }; $done=0; foreach ($r in $apps.Values) { try { New-Block -Duration $opt.Duration -RuleSpecs @(@{Label="App - $($r.Name) (out)";Direction='Outbound';Program=$r.Path},@{Label="App - $($r.Name) (in)";Direction='Inbound';Program=$r.Path}); if ($opt.Close) { Close-AppByPath $r.Name $r.Path }; $done++ } catch { Write-AppLog "BlockAll $($r.Name): $($_.Exception.Message)" } }; Set-Note "Blocked $done app(s)."; Update-All -Force }

function Show-ManageBlocks {
    $f=New-Object System.Windows.Forms.Form; $f.Text="My blocks (made by Port Manager)"; $f.Size=New-Object System.Drawing.Size(640,440); $f.StartPosition="CenterParent"
    $list=New-Object System.Windows.Forms.ListBox; $list.Dock="Fill"; $list.SelectionMode="MultiExtended"; $list.HorizontalScrollbar=$true
    $pnl=New-Object System.Windows.Forms.Panel; $pnl.Dock="Bottom"; $pnl.Height=50
    $btnUn=New-Button "Unblock selected" 150; $btnUn.Location=New-Object System.Drawing.Point(10,8); $btnAll=New-Button "Unblock all" 120; $btnAll.Location=New-Object System.Drawing.Point(170,8); $pnl.Controls.Add($btnUn); $pnl.Controls.Add($btnAll); $f.Controls.Add($list); $f.Controls.Add($pnl)
    $load={$list.Items.Clear(); Get-NetFirewallRule -DisplayName "$RulePrefix*" -ErrorAction SilentlyContinue | Sort-Object DisplayName | ForEach-Object {[void]$list.Items.Add($_.DisplayName)}}; & $load
    $btnUn.Add_Click({if ($list.SelectedItems.Count -eq 0) { Show-Info "Select one or more blocks first."; return }; foreach ($n in @($list.SelectedItems)) { Remove-BlockByName ([string]$n) }; & $load})
    $btnAll.Add_Click({if ($list.Items.Count -eq 0) { return }; if (-not (Ask-Yes "Remove all $($list.Items.Count) blocks made by Port Manager?" 'Warning')) { return }; foreach ($n in @($list.Items)) { Remove-BlockByName ([string]$n) }; & $load})
    [void]$f.ShowDialog($form)
}
function Show-TrustedWindow {
    $f=New-Object System.Windows.Forms.Form; $f.Text="Trusted apps"; $f.Size=New-Object System.Drawing.Size(760,460); $f.StartPosition="CenterParent"
    $list=New-Object System.Windows.Forms.ListBox; $list.Dock="Fill"; $list.SelectionMode="MultiExtended"; $list.HorizontalScrollbar=$true
    $pnl=New-Object System.Windows.Forms.Panel; $pnl.Dock="Bottom"; $pnl.Height=50; $btnRem=New-Button "Make untrusted" 140; $btnRem.Location=New-Object System.Drawing.Point(10,8); $btnAdd=New-Button "Add app file..." 140; $btnAdd.Location=New-Object System.Drawing.Point(160,8); $pnl.Controls.Add($btnRem); $pnl.Controls.Add($btnAdd); $f.Controls.Add($list); $f.Controls.Add($pnl)
    $keys=New-Object System.Collections.ArrayList
    $load={$list.Items.Clear(); $keys.Clear(); foreach ($t in $Trusted.Values) { $where=$t.Path; if (-not $where) { $where="(any location)" }; [void]$list.Items.Add("$($t.Name)   -   $where"); [void]$keys.Add([string]$t.Key) }}; & $load
    $btnRem.Add_Click({if ($list.SelectedIndices.Count -eq 0) { Show-Info "Select one or more apps first."; return }; $remove=@(); foreach ($i in $list.SelectedIndices) { $remove+=$keys[$i] }; foreach ($k in $remove) { $Trusted.Remove($k) }; Save-Trusted; & $load; Update-All -Force})
    $btnAdd.Add_Click({$dlg=New-Object System.Windows.Forms.OpenFileDialog; $dlg.Filter="Programs (*.exe)|*.exe"; if ($dlg.ShowDialog() -eq 'OK') { Add-Trust ([System.IO.Path]::GetFileNameWithoutExtension($dlg.FileName)) $dlg.FileName; & $load; Update-All -Force }})
    [void]$f.ShowDialog($form)
}
function Show-LearnReview {
    if ($Learned.Count -eq 0) { Show-Info "Nothing to review. No untrusted apps were seen during learning."; return }
    $f=New-Object System.Windows.Forms.Form; $f.Text="Learning mode - review"; $f.Size=New-Object System.Drawing.Size(920,520); $f.StartPosition="CenterParent"
    $lbl=New-Object System.Windows.Forms.Label; $lbl.Dock="Top"; $lbl.Height=50; $lbl.Padding=New-Object System.Windows.Forms.Padding(8,8,8,0); $lbl.Text="These apps went online while learning. Tick the ones you know and trust, then click 'Trust ticked apps'. Unticked apps stay untrusted. Signed apps are ticked for you; unsigned ones are not."
    $clb=New-Object System.Windows.Forms.CheckedListBox; $clb.Dock="Fill"; $clb.CheckOnClick=$true; $clb.HorizontalScrollbar=$true
    $pnl=New-Object System.Windows.Forms.Panel; $pnl.Dock="Bottom"; $pnl.Height=50; $btnOk=New-Button "Trust ticked apps" 150; $btnOk.Location=New-Object System.Drawing.Point(10,8); $btnClear=New-Button "Clear this list" 130; $btnClear.Location=New-Object System.Drawing.Point(170,8); $pnl.Controls.Add($btnOk); $pnl.Controls.Add($btnClear); $f.Controls.Add($clb); $f.Controls.Add($pnl); $f.Controls.Add($lbl)
    $keys=New-Object System.Collections.ArrayList
    foreach ($o in $Learned.Values) { $pub=''; if ($o.Path) { $v=''; if ($SigCache.TryGetValue([string]$o.Path,[ref]$v)) { $pub=$v } else { $pub='Checking...'; if ($SigRequested.Add([string]$o.Path)) { $SigQueue.Enqueue([string]$o.Path) } } }; $good=($pub -and $pub -notin @('Unsigned','Unknown','Checking...') -and -not $pub.StartsWith('Invalid') -and $o.Status -ne 'DANGER'); $tag=''; if ($o.Status -eq 'DANGER') { $tag='[FAKE NAME?] ' }; $txt="$tag$($o.Name)  |  $pub  |  seen $($o.Seen)x, last: $($o.LastRemote)  |  $($o.Path)"; [void]$clb.Items.Add($txt,[bool]$good); [void]$keys.Add([string]$o.Key) }
    $btnOk.Add_Click({$count=0; for ($i=0; $i -lt $clb.Items.Count; $i++) { if ($clb.GetItemChecked($i)) { $o=$Learned[$keys[$i]]; if ($o) { Add-Trust $o.Name $o.Path; $Learned.Remove($keys[$i]); $count++ } } }; Save-Learned; Update-All -Force; Show-Info "Trusted $count app(s)."; $f.Close()})
    $btnClear.Add_Click({if (Ask-Yes "Remove all apps from the learning list? (They stay untrusted.)") { $Learned.Clear(); Save-Learned; $f.Close() }})
    [void]$f.ShowDialog($form)
}

function Start-Learning { param([int]$Hours) $script:LearningUntil=(Get-Date).AddHours($Hours); $Settings.LearningUntil=$script:LearningUntil.ToString('s'); $Settings.LearnNotified=$false; Save-Settings; Set-Note "Learning mode ON for $Hours hour(s)."; Show-Info "Learning mode is ON until $($script:LearningUntil.ToString('HH:mm dd/MM')).`n`nUse your PC as normal. No alerts will pop up (fake system names still will). When it ends, you will get a message to review the apps and trust the good ones in one go."; Update-All -Force }
function Stop-Learning { $script:LearningUntil=$null; $Settings.LearningUntil=''; $Settings.LearnNotified=$true; Save-Settings; Save-Learned; Set-Note "Learning mode stopped."; if ($Learned.Count -gt 0 -and (Ask-Yes "Learning stopped. Review the $($Learned.Count) app(s) it saw now?")) { Show-LearnReview } }
function New-LearnMenu { $m=New-Object System.Windows.Forms.ContextMenuStrip; $hdr=$m.Items.Add("Learning mode"); $hdr.Enabled=$false; [void]$m.Items.Add('-'); $i1=$m.Items.Add("Start for 1 hour"); $i1.Add_Click({Start-Learning 1}); $i2=$m.Items.Add("Start for 4 hours"); $i2.Add_Click({Start-Learning 4}); $i3=$m.Items.Add("Start for 24 hours"); $i3.Add_Click({Start-Learning 24}); $i4=$m.Items.Add("Stop now"); $i4.Add_Click({Stop-Learning}); [void]$m.Items.Add('-'); $i5=$m.Items.Add("Review learned apps..."); $i5.Add_Click({Show-LearnReview}); $m.Add_Opening({param($sender,$e) if (Test-Learning) { $sender.Items[0].Text="Learning is ON until "+$script:LearningUntil.ToString('HH:mm dd/MM') } else { $sender.Items[0].Text="Learning is OFF" }; $sender.Items[$sender.Items.Count-1].Text="Review learned apps ($($Learned.Count))..." }); return $m }
function Load-History { $dt=New-Object System.Data.DataTable; foreach ($c in 'Time','Status','App','PID','RemoteIP','RemoteHost','RemotePort','Publisher','Path') { [void]$dt.Columns.Add($c) }; if (Test-Path $HistoryFile) { try { $items=@(Import-Csv $HistoryFile | Select-Object -Last 1000); [array]::Reverse($items); foreach ($i in $items) { [void]$dt.Rows.Add($i.Time,$i.Status,$i.App,$i.PID,$i.RemoteIP,$i.RemoteHost,$i.RemotePort,$i.Publisher,$i.Path) } } catch { Write-AppLog "Load-History: $($_.Exception.Message)" } }; $histGrid.DataSource=$dt; if ($histGrid.Columns["Path"]) { $histGrid.Columns["Path"].AutoSizeMode="Fill" }; if ($histGrid.Columns["Time"]) { $histGrid.Columns["Time"].Width=140 }; if ($histGrid.Columns["Publisher"]) { $histGrid.Columns["Publisher"].Width=160 }; if ($histGrid.Columns["RemoteHost"]) { $histGrid.Columns["RemoteHost"].Width=200 } }
function Test-StartupTask { return [bool](Get-ScheduledTask -TaskName 'PortManager' -ErrorAction SilentlyContinue) }
function Set-StartupTask { param([bool]$On) if ($On) { $user="$env:USERDOMAIN\$env:USERNAME"; $action=New-ScheduledTaskAction -Execute 'powershell.exe' -Argument "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$PSCommandPath`" -Hidden"; $trigger=New-ScheduledTaskTrigger -AtLogOn -User $user; $principal=New-ScheduledTaskPrincipal -UserId $user -LogonType Interactive -RunLevel Highest; $settings=New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable -ExecutionTimeLimit ([TimeSpan]::Zero) -MultipleInstances IgnoreNew -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1); Unregister-ScheduledTask -TaskName 'PortManager' -Confirm:$false -ErrorAction SilentlyContinue; Register-ScheduledTask -TaskName 'PortManager' -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Description 'Port Manager - starts in the tray at logon' | Out-Null; Unregister-ScheduledTask -TaskName 'PortMonitor' -Confirm:$false -ErrorAction SilentlyContinue } else { Unregister-ScheduledTask -TaskName 'PortManager' -Confirm:$false -ErrorAction SilentlyContinue } }
function Show-Window { if (-not $form.Visible) { $form.Show() }; if ($form.WindowState -eq 'Minimized') { $form.WindowState='Normal' }; $form.Activate(); $form.BringToFront(); Update-All -Force }
function Set-Paused { param([bool]$V) $script:AlertsPaused=$V; $chkPause.Checked=$V; $trayPause.Checked=$V }
function Quit-App { $script:Quitting=$true; try { Save-Learned; Save-Settings } catch {}; $Shared.Stop=$true; $notify.Visible=$false; $notify.Dispose(); $form.Close(); $ctx.ExitThread() }
$trayMenu=New-Object System.Windows.Forms.ContextMenuStrip
$tOpen=$trayMenu.Items.Add("Open Port Manager"); $tOpen.Add_Click({Show-Window})
$trayPause=New-Object System.Windows.Forms.ToolStripMenuItem("Pause alerts"); $trayPause.CheckOnClick=$true; [void]$trayMenu.Items.Add($trayPause)
$trayLearn=New-Object System.Windows.Forms.ToolStripMenuItem("Learning mode"); $trayLearn.DropDown=(New-LearnMenu); [void]$trayMenu.Items.Add($trayLearn); [void]$trayMenu.Items.Add('-')
$tQuit=$trayMenu.Items.Add("Quit Port Manager"); $tQuit.Add_Click({Quit-App}); $notify.ContextMenuStrip=$trayMenu
$notify.Add_DoubleClick({Show-Window})
$notify.Add_BalloonTipClicked({if ($script:BalloonAction -eq 'learn') { Show-Window; Show-LearnReview } elseif ($script:BalloonAction -eq 'alert') { $tabs.SelectedIndex=0; $script:PendingSelect=$script:LastAlertKey; Show-Window } else { Show-Window }})

# Right-click menu on the live grid
$ctxMenu=New-Object System.Windows.Forms.ContextMenuStrip
$mi=$ctxMenu.Items.Add("Trust this app"); $mi.Add_Click({Do-Trust (Get-Selected)})
$mi=$ctxMenu.Items.Add("Untrust this app"); $mi.Add_Click({Do-Untrust (Get-Selected)})
[void]$ctxMenu.Items.Add('-')
$mi=$ctxMenu.Items.Add("Block this app..."); $mi.Add_Click({Do-BlockApp (Get-Selected)})
$mi=$ctxMenu.Items.Add("Block remote IP..."); $mi.Add_Click({Do-BlockIP (Get-Selected)})
$mi=$ctxMenu.Items.Add("Block this port..."); $mi.Add_Click({Do-BlockPort (Get-Selected)})
$mi=$ctxMenu.Items.Add("Close this app"); $mi.Add_Click({Do-Close (Get-Selected)})
[void]$ctxMenu.Items.Add('-')
$mi=$ctxMenu.Items.Add("Check online (port / process)..."); $mi.Add_Click({Show-OnlineCheck (Get-Selected)})
[void]$ctxMenu.Items.Add('-')
$mi=$ctxMenu.Items.Add("Copy remote IP"); $mi.Add_Click({$s=Get-Selected; if ($s) { [System.Windows.Forms.Clipboard]::SetText($s.RemoteAddress); Set-Note "Copied $($s.RemoteAddress)" }})
$mi=$ctxMenu.Items.Add("Copy file path"); $mi.Add_Click({$s=Get-Selected; if ($s -and $s.Path) { [System.Windows.Forms.Clipboard]::SetText($s.Path); Set-Note "Copied file path" }})
$mi=$ctxMenu.Items.Add("Open file location"); $mi.Add_Click({$s=Get-Selected; if ($s -and $s.Path) { Start-Process explorer.exe -ArgumentList "/select,`"$($s.Path)`"" }})
$grid.ContextMenuStrip=$ctxMenu

$btnTrust.Add_Click({Do-Trust (Get-Selected)}); $btnUntrust.Add_Click({Do-Untrust (Get-Selected)})
$btnBlockApp.Add_Click({Do-BlockApp (Get-Selected)}); $btnBlockIP.Add_Click({Do-BlockIP (Get-Selected)})
$btnBlockPort.Add_Click({Do-BlockPort (Get-Selected)}); $btnClose.Add_Click({Do-Close (Get-Selected)})
$btnBlockAll.Add_Click({Do-BlockAllUntrusted}); $btnTrustList.Add_Click({Show-TrustedWindow}); $btnManage.Add_Click({Show-ManageBlocks})
$btnOnline.Add_Click({Show-OnlineCheck (Get-Selected)})
$btnFirewall.Add_Click({Show-FirewallSetup})
$learnMenuButton=New-LearnMenu
$btnLearn.Add_Click({$learnMenuButton.Show($btnLearn,(New-Object System.Drawing.Point(0,$btnLearn.Height)))})
$btnQuit.Add_Click({if (Ask-Yes "Quit Port Manager completely?`n`nAlerts will stop until you start it again." 'Warning') { Quit-App }})
$btnRefresh.Add_Click({Update-All -Force}); $txtFilter.Add_TextChanged({$script:LastSig=$null; Fill-Grid})
$chkUntrusted.Add_CheckedChanged({$script:LastSig=$null; Fill-Grid}); $chkLocal.Add_CheckedChanged({$script:LastSig=$null; Fill-Grid})
$chkNames.Add_CheckedChanged({$Settings.ResolveNames=$chkNames.Checked; Save-Settings; Update-All -Force})
$chkPause.Add_CheckedChanged({Set-Paused $chkPause.Checked}); $trayPause.Add_CheckedChanged({Set-Paused $trayPause.Checked})
$chkStart.Checked=(Test-StartupTask)
$chkStart.Add_CheckedChanged({if ($script:IgnoreStart) { return }; try { Set-StartupTask $chkStart.Checked; if ($chkStart.Checked) { Show-Info "Done. Port Manager will start in the tray every time you sign in.`n`nPlease keep this file where it is:`n$PSCommandPath" } } catch { Show-Error "Could not change the startup setting:`n$($_.Exception.Message)"; $script:IgnoreStart=$true; $chkStart.Checked=(Test-StartupTask); $script:IgnoreStart=$false }})
$hTrust.Add_Click({Do-Trust (Get-HistSelected)}); $hBlock.Add_Click({Do-BlockApp (Get-HistSelected)}); $hRefresh.Add_Click({Load-History})
$hExport.Add_Click({if (-not (Test-Path $HistoryFile)) { Show-Info "There is no history yet."; return }; $target=Join-Path ([Environment]::GetFolderPath('Desktop')) ("PortManager-History-"+(Get-Date -Format 'yyyyMMdd-HHmm')+".csv"); Copy-Item $HistoryFile $target -Force; Show-Info "Saved to your Desktop:`n$target`n`nYou can open it with Excel."})
$hClear.Add_Click({if (Test-Path $HistoryFile) { if (Ask-Yes "Delete the whole alert history?" 'Warning') { Remove-Item $HistoryFile -Force; Load-History } }})
$tabs.Add_SelectedIndexChanged({if ($tabs.SelectedIndex -eq 1) { Load-History } else { Update-All -Force }})
$form.Add_FormClosing({param($sender,$e) if (-not $script:Quitting -and $e.CloseReason -eq 'UserClosing') { $e.Cancel=$true; $form.Hide(); if (-not $script:HintShown) { $script:HintShown=$true; $script:BalloonAction='none'; $notify.BalloonTipTitle="Port Manager is still watching"; $notify.BalloonTipText="It runs in the tray. Right-click the icon to quit."; $notify.BalloonTipIcon='Info'; $notify.ShowBalloonTip(4000) } }})

$timer=New-Object System.Windows.Forms.Timer; $timer.Interval=$Intervals[$cmbInterval.SelectedIndex]; $timer.Add_Tick({Update-All})
$cmbInterval.Add_SelectedIndexChanged({$timer.Interval=$Intervals[$cmbInterval.SelectedIndex]; $Settings.RefreshIndex=$cmbInterval.SelectedIndex; Save-Settings})
$showTimer=New-Object System.Windows.Forms.Timer; $showTimer.Interval=500; $showTimer.Add_Tick({if ($showEvent.WaitOne(0)) { Show-Window }})
$houseTimer=New-Object System.Windows.Forms.Timer; $houseTimer.Interval=30000
$houseTimer.Add_Tick({try { if ($Blocks.Count -gt 0) { Expire-Blocks }; if ($script:LearnedDirty) { Save-Learned; $script:LearnedDirty=$false }; if ($script:LearningUntil -and (Get-Date) -ge $script:LearningUntil -and -not $Settings.LearnNotified) { $Settings.LearnNotified=$true; Save-Settings; Save-Learned; $script:BalloonAction='learn'; $notify.BalloonTipTitle="Learning mode finished"; if ($Learned.Count -gt 0) { $notify.BalloonTipText="$($Learned.Count) app(s) seen. Click to review and trust the good ones." } else { $notify.BalloonTipText="No new untrusted apps were seen." }; $notify.BalloonTipIcon='Info'; $notify.ShowBalloonTip(8000) }; if ($HostCache.Count -gt 5000) { $HostCache.Clear(); $DnsRequested.Clear() } } catch { Write-AppLog "Housekeeping: $($_.Exception.Message)" }})

Expire-Blocks
Update-All
$timer.Start(); $showTimer.Start(); $houseTimer.Start()
$ctx=New-Object System.Windows.Forms.ApplicationContext
if (-not $Hidden) { Show-Window }
[System.Windows.Forms.Application]::Run($ctx)
} catch {
    Write-AppLog "FATAL: $($_.Exception.Message) (line $($_.InvocationInfo.ScriptLineNumber))"
    [void][System.Windows.Forms.MessageBox]::Show("Port Manager stopped:`n$($_.Exception.Message)`n`nDetails: $env:ProgramData\PortManager\errors.log","Port Manager","OK","Error")
}

