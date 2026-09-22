param([string]$PackageDir=$PSScriptRoot,[switch]$SelfTest)
$ErrorActionPreference='Stop'
$expected='18599C12A9A00E75F13A58F48E355F6F6FF20DBAEE049D8E856373AF5006A358'
$exe=Join-Path $PackageDir 'Abin.exe'; $harness=Join-Path $PackageDir 'c20r7n-norton-discriminator.ps1'
$r1=Join-Path $PackageDir 'c20r7n-run1.json'; $r2=Join-Path $PackageDir 'c20r7n-run2.json'; $summary=Join-Path $PackageDir 'c20r7n-summary.json'; $confirm=Join-Path $PackageDir 'CONFIRMATION_REQUIRED.txt'; $errorFile=Join-Path $PackageDir 'c20r7n-error.txt'
try {
  if(Test-Path $errorFile){Remove-Item $errorFile -Force -ErrorAction SilentlyContinue}
  if(!(Test-Path $exe)-or!(Test-Path $harness)){throw 'PACKAGE_INCOMPLETE'}
  $hash=(Get-FileHash $exe -Algorithm SHA256).Hash.ToUpperInvariant(); if($hash-ne$expected){throw "CANDIDATE_A_IDENTITY_FAILED:$hash"}
  if((Get-Item $exe).Length-ne279552){throw 'CANDIDATE_A_SIZE_FAILED'}
  if($SelfTest){
    $fake1=[ordered]@{exe_sha256=$expected;norton_decision='NOT_SANDBOXING';max_exact_path_count=1;duplicate_seen=$false;window_seen=$true}; $fake2=[ordered]@{exe_sha256=$expected;norton_decision='SANDBOXING';max_exact_path_count=2;duplicate_seen=$true;window_seen=$true}
    $fake1|ConvertTo-Json|Set-Content $r1; $fake2|ConvertTo-Json|Set-Content $r2
  }else{
    if(!(Test-Path $r1)){
      & powershell -NoProfile -ExecutionPolicy Bypass -File $harness -ExePath $exe -ExpectedSha256 $expected -ResultPath $r1
      if($LASTEXITCODE-ne0){throw "RUN1_FAILED_EXIT_$LASTEXITCODE"}
      if(!(Test-Path $r1)){throw 'RUN1_RESULT_MISSING'}
      $a=Get-Content $r1 -Raw|ConvertFrom-Json
      @"
C20R7N requires a controlled counterfactual only if PM/user explicitly approves it.
Run 1 Norton decision: $($a.norton_decision)

STOP HERE. This package will NOT disable Norton and will NOT add/remove exclusions.
To obtain Run 2, PM/user must explicitly approve a minimal reversible Norton change for Abin.exe only, then make that change in Norton manually. Keep this same folder, same Abin.exe, and same launcher. After the approved Norton state differs, double-click c20r7n-run-on-win10.cmd again.
After Run 2, restore the original Norton state.
"@ | Set-Content $confirm -Encoding utf8
      Write-Host 'RUN1_COMPLETE_CONFIRMATION_REQUIRED'; exit 0
    }
    if(!(Test-Path $r2)){
      $a=Get-Content $r1 -Raw|ConvertFrom-Json
      & powershell -NoProfile -ExecutionPolicy Bypass -File $harness -ExePath $exe -ExpectedSha256 $expected -ResultPath $r2
      if($LASTEXITCODE-ne0){throw "RUN2_FAILED_EXIT_$LASTEXITCODE"}
      if(!(Test-Path $r2)){throw 'RUN2_RESULT_MISSING'}
    }
  }
  $a=Get-Content $r1 -Raw|ConvertFrom-Json; $b=Get-Content $r2 -Raw|ConvertFrom-Json
  if($a.exe_sha256-ne$expected-or$b.exe_sha256-ne$expected){throw 'SUMMARY_IDENTITY_MISMATCH'}
  $stateChanged=($a.norton_decision-ne$b.norton_decision)-and($a.norton_decision-ne'UNKNOWN')-and($b.norton_decision-ne'UNKNOWN')
  $behaviorA=[ordered]@{max_exact_path_count=$a.max_exact_path_count;duplicate_seen=$a.duplicate_seen;window_seen=$a.window_seen}
  $behaviorB=[ordered]@{max_exact_path_count=$b.max_exact_path_count;duplicate_seen=$b.duplicate_seen;window_seen=$b.window_seen}
  $behaviorChanged=($a.max_exact_path_count-ne$b.max_exact_path_count)-or($a.duplicate_seen-ne$b.duplicate_seen)-or($a.window_seen-ne$b.window_seen)
  $conclusion=if(-not$stateChanged){'INCONCLUSIVE_NORTON_STATE_NOT_CHANGED'}elseif($behaviorChanged){'CONTROLLED_DIFFERENCE_OBSERVED_REQUIRES_PM_CAUSAL_REVIEW'}else{'NO_BEHAVIOR_DIFFERENCE_OBSERVED_REQUIRES_PM_CAUSAL_REVIEW'}
  [ordered]@{dispatch='V16-T26-R17U-A7-NORTON-CAUSALITY-DISCRIMINATOR-C20R7N';candidate_sha256=$expected;run1_decision=$a.norton_decision;run2_decision=$b.norton_decision;norton_state_changed=$stateChanged;run1_behavior=$behaviorA;run2_behavior=$behaviorB;behavior_changed=$behaviorChanged;tool_conclusion=$conclusion;security_configuration_modified_by_tool=$false;restore_original_norton_state_required=$true}|ConvertTo-Json -Depth 6|Set-Content $summary -Encoding utf8
  if(Test-Path $confirm){Remove-Item $confirm -Force}
  Write-Host "SUMMARY_PATH=$summary"
}catch{
  $detail="C20R7N_HARNESS_ERROR`r`n$($_.Exception.Message)`r`n$($_.InvocationInfo.PositionMessage)"
  $detail|Set-Content $errorFile -Encoding utf8
  Write-Error $detail
  exit 1
}
