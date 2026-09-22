param(
  [Parameter(Mandatory=$true)][string]$ExePath,
  [Parameter(Mandatory=$true)][string]$ExpectedSha256,
  [string]$NortonLogPath = 'C:\ProgramData\Norton\Antivirus\log\autosandbox.log',
  [string]$ResultPath = '.\c20r7n-result.json',
  [int]$ObserveSeconds = 12
)
$ErrorActionPreference='Stop'
$start=Get-Date
$resolved=(Resolve-Path -LiteralPath $ExePath).Path
$hash=(Get-FileHash -LiteralPath $resolved -Algorithm SHA256).Hash.ToUpperInvariant()
$size=(Get-Item -LiteralPath $resolved).Length
if($hash -ne $ExpectedSha256.ToUpperInvariant()){ throw "G1_SAMPLE_IDENTITY failed: $hash" }

# Norton log access is evidence collection only. Failure to read it must not erase
# the launch/process/window evidence or make Run 1 disappear.
$logPresent=$false
$logLengthBefore=0
$nortonReadError=$null
try {
  $logPresent=Test-Path -LiteralPath $NortonLogPath -ErrorAction Stop
  if($logPresent){ $logLengthBefore=(Get-Item -LiteralPath $NortonLogPath -ErrorAction Stop).Length }
} catch {
  $nortonReadError=$_.Exception.Message
}

$launchError=$null; $p=$null
try { $p=Start-Process -FilePath $resolved -PassThru -ErrorAction Stop } catch { $launchError=$_.Exception.Message }
$observations=@()
for($i=0;$i -lt $ObserveSeconds;$i++){
  Start-Sleep -Seconds 1
  $matches=@()
  Get-CimInstance Win32_Process -ErrorAction SilentlyContinue | ForEach-Object {
    if($_.ExecutablePath -and ([string]::Equals($_.ExecutablePath,$resolved,[System.StringComparison]::OrdinalIgnoreCase))){
      $gp=Get-Process -Id $_.ProcessId -ErrorAction SilentlyContinue
      $matches += [ordered]@{pid=$_.ProcessId; hwnd=if($gp){[int64]$gp.MainWindowHandle}else{0}; title=if($gp){$gp.MainWindowTitle}else{''}}
    }
  }
  $observations += [ordered]@{at=(Get-Date).ToString('o'); exact_path_count=$matches.Count; processes=$matches}
}
$end=Get-Date
$nortonLines=@(); $nortonDecision='UNKNOWN'
if($logPresent){
  try {
    $fs=[System.IO.File]::Open($NortonLogPath,'Open','Read','ReadWrite')
    $sr=$null
    try {
      if($logLengthBefore -le $fs.Length){$fs.Seek($logLengthBefore,'Begin')|Out-Null}else{$fs.Seek(0,'Begin')|Out-Null}
      $sr=New-Object System.IO.StreamReader($fs)
      $delta=$sr.ReadToEnd()
    } finally {
      if($sr){$sr.Dispose()}elseif($fs){$fs.Dispose()}
    }
    $leaf=[IO.Path]::GetFileName($resolved)
    $nortonLines=@($delta -split "`r?`n" | Where-Object { $_ -and (($_ -like "*$resolved*") -or ($_ -like "*$leaf*")) })
    if($nortonLines -match 'Not sandboxing'){ $nortonDecision='NOT_SANDBOXING' }
    elseif($nortonLines -match 'Sandboxing'){ $nortonDecision='SANDBOXING' }
  } catch {
    $nortonReadError=$_.Exception.Message
    $nortonDecision='UNKNOWN'
  }
}

$maxCount=if($observations.Count){($observations|Measure-Object exact_path_count -Maximum).Maximum}else{0}
$windowSeen=[bool]($observations.processes|Where-Object {$_.hwnd -ne 0})
$osCaption=$null
try { $osCaption=(Get-CimInstance Win32_OperatingSystem -ErrorAction Stop).Caption } catch { $osCaption='UNKNOWN' }
$result=[ordered]@{
 dispatch='V16-T26-R17U-A7-NORTON-CAUSALITY-DISCRIMINATOR-C20R7N';
 started_at=$start.ToString('o'); ended_at=$end.ToString('o');
 os_caption=$osCaption; os_version=[Environment]::OSVersion.Version.ToString();
 exe_path=$resolved; exe_sha256=$hash; exe_size=$size; expected_sha256=$ExpectedSha256.ToUpperInvariant();
 launch_pid=if($p){$p.Id}else{$null}; launch_error=$launchError;
 max_exact_path_count=$maxCount; duplicate_seen=($maxCount -gt 1); window_seen=$windowSeen;
 norton_log_path=$NortonLogPath; norton_log_present=$logPresent; norton_decision=$nortonDecision; norton_log_read_error=$nortonReadError; norton_matching_lines=$nortonLines;
 observations=$observations
}
$result|ConvertTo-Json -Depth 8|Set-Content -LiteralPath $ResultPath -Encoding UTF8
if($p -and -not $p.HasExited){ Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue }
Get-CimInstance Win32_Process -ErrorAction SilentlyContinue | Where-Object { $_.ExecutablePath -and ([string]::Equals($_.ExecutablePath,$resolved,[System.StringComparison]::OrdinalIgnoreCase)) } | ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }
Write-Host "RESULT_PATH=$((Resolve-Path $ResultPath).Path)"
Write-Host "NORTON_DECISION=$nortonDecision"
if($nortonReadError){ Write-Host "NORTON_LOG_READ_ERROR=$nortonReadError" }
Write-Host "MAX_EXACT_PATH_COUNT=$maxCount WINDOW_SEEN=$windowSeen"
