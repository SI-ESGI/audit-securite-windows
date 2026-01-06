function Export-AuditResults {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [hashtable]$AuditResults,
        
        [Parameter(Mandatory = $true)]
        [string]$ReportPath
    )
    
    Write-Output "Generation des rapports d'audit..."
    
    try {
        # Export JSON pour analyse ulterieure
        $jsonPath = Join-Path -Path $ReportPath -ChildPath "audit-results.json"
        $AuditResults | ConvertTo-Json -Depth 10 | Set-Content -Path $jsonPath -Force
        
        # Creation du rapport HTML en utilisant le template
        $htmlPath = Join-Path -Path $ReportPath -ChildPath "audit-report.html"
        $templatePath = Join-Path -Path $PSScriptRoot -ChildPath "audit-report-template.html"
        
        # Verification de l'existence du template
        if (-not (Test-Path -Path $templatePath)) {
            Write-Error "Le fichier template $templatePath n'existe pas."
            return $false
        }
        
        # Lecture du template
        $htmlTemplate = Get-Content -Path $templatePath -Raw
        
        # Calcul du score de conformite avant generation des rapports
        # Le calcul est fait dans le fichier principal (windows_auditor.ps1)
        # La fonction Calculate-AuditScore du fichier principal sera utilisee
        
        # Fonction pour gerer les valeurs nulles ou vides
        function Get-SafeValue {
            param($Value, $DefaultValue = "N/A")
            if ($null -eq $Value) {
                Write-Host "DEBUG: Valeur null detectee, retour: $DefaultValue" -ForegroundColor Yellow
                return $DefaultValue
            }
            if ($Value -eq "" -and $Value -is [string]) {
                Write-Host "DEBUG: String vide detectee, retour: $DefaultValue" -ForegroundColor Yellow
                return $DefaultValue
            }
            Write-Host "DEBUG: Valeur trouvee: $Value" -ForegroundColor Green
            return $Value
        }
        
        # Fonction pour determiner la classe CSS basee sur l'etat
        function Get-StatusClass {
            param($Condition, $SuccessClass = "success", $WarningClass = "warning", $DangerClass = "danger")
            if ($Condition) {
                return $SuccessClass
            } else {
                return $DangerClass
            }
        }
        
        # Remplacement des placeholders dans le template
        $replacements = @{
            '{{COMPUTER_NAME}}' = $env:COMPUTERNAME
            '{{REPORT_DATE}}' = Get-Date
            '{{OS_NAME}}' = Get-SafeValue $AuditResults.SystemInfo.OSName
            '{{OS_VERSION}}' = Get-SafeValue $AuditResults.SystemInfo.OSVersion
            
            # Informations systeme
            '{{SYSTEM_HOSTNAME}}' = Get-SafeValue $AuditResults.SystemInfo.Hostname
            '{{SYSTEM_DOMAIN}}' = Get-SafeValue $AuditResults.SystemInfo.Domain
            '{{SYSTEM_MANUFACTURER}}' = Get-SafeValue $AuditResults.SystemInfo.Manufacturer
            '{{SYSTEM_MODEL}}' = Get-SafeValue $AuditResults.SystemInfo.Model
            '{{SYSTEM_BIOS_VERSION}}' = Get-SafeValue $AuditResults.SystemInfo.BIOSVersion
            '{{SYSTEM_OS_NAME}}' = Get-SafeValue $AuditResults.SystemInfo.OSName
            '{{SYSTEM_OS_VERSION}}' = Get-SafeValue $AuditResults.SystemInfo.OSVersion
            '{{SYSTEM_OS_BUILD}}' = Get-SafeValue $AuditResults.SystemInfo.OSBuild
            '{{SYSTEM_OS_ARCHITECTURE}}' = Get-SafeValue $AuditResults.SystemInfo.OSArchitecture
            '{{SYSTEM_LAST_BOOT_TIME}}' = Get-SafeValue $AuditResults.SystemInfo.LastBootTime
            '{{SYSTEM_INSTALL_DATE}}' = Get-SafeValue $AuditResults.SystemInfo.InstallDate
            
            # Utilisateurs et groupes
            '{{USERS_ENABLED_COUNT}}' = Get-SafeValue $AuditResults.UsersAndGroups.EnabledUserCount "0"
            '{{USERS_DISABLED_COUNT}}' = Get-SafeValue $AuditResults.UsersAndGroups.DisabledUserCount "0"
            '{{USERS_LOCAL_GROUPS_COUNT}}' = if ($AuditResults.UsersAndGroups.LocalGroups) { $AuditResults.UsersAndGroups.LocalGroups.Count } else { "0" }
            '{{USERS_ADMIN_GROUP_MEMBERS}}' = if ($AuditResults.UsersAndGroups.AdministratorGroupMembers) { ($AuditResults.UsersAndGroups.AdministratorGroupMembers | Format-Table -AutoSize | Out-String).Trim() } else { "Aucun membre trouve" }
            
            # Authentification
            '{{AUTH_LAPS_CLASS}}' = Get-StatusClass $AuditResults.Authentication.LAPS.Installed "success" "warning" "warning"
            '{{AUTH_LAPS_STATUS}}' = if ($AuditResults.Authentication.LAPS.Installed) { "Installe" } else { "Non installe" }
            '{{AUTH_HELLO_CLASS}}' = Get-StatusClass $AuditResults.Authentication.WindowsHello.EnabledViaGPO "success" "warning" "warning"
            '{{AUTH_HELLO_STATUS}}' = if ($AuditResults.Authentication.WindowsHello.EnabledViaGPO) { "Active" } else { "Desactive ou non configure" }
            '{{AUTH_UAC_CLASS}}' = Get-StatusClass $AuditResults.Authentication.UAC.Enabled "success" "warning" "danger"
            '{{AUTH_UAC_STATUS}}' = if ($AuditResults.Authentication.UAC.Enabled) { "Active" } else { "Desactive" }
            '{{AUTH_JEA_CLASS}}' = Get-StatusClass $AuditResults.Authentication.JEA.ModulesInstalled "success" "info" "info"
            '{{AUTH_JEA_STATUS}}' = if ($AuditResults.Authentication.JEA.ModulesInstalled) { "Modules installes" } else { "Non configure" }
            '{{AUTH_LSASS_CLASS}}' = Get-StatusClass $AuditResults.Authentication.LSASSProtection.Enabled "success" "warning" "danger"
            '{{AUTH_LSASS_STATUS}}' = if ($AuditResults.Authentication.LSASSProtection.Enabled) { "Active" } else { "Desactive" }
            '{{AUTH_WDIGEST_CLASS}}' = Get-StatusClass $AuditResults.Authentication.WDigest.Disabled "success" "warning" "danger"
            '{{AUTH_WDIGEST_STATUS}}' = if ($AuditResults.Authentication.WDigest.Disabled) { "Desactive (securise)" } else { "Active (vulnerable)" }
            '{{AUTH_CREDGUARD_CLASS}}' = Get-StatusClass $AuditResults.Authentication.CredentialGuard.Running "success" "warning" "warning"
            '{{AUTH_CREDGUARD_STATUS}}' = if ($AuditResults.Authentication.CredentialGuard.Running) { "Actif" } else { "Inactif ou non disponible" }
            
            # Services
            '{{SERVICES_RDP_CLASS}}' = Get-StatusClass (-not $AuditResults.ServicesAndProcesses.RDP.Enabled) "success" "warning" "warning"
            '{{SERVICES_RDP_STATUS}}' = if ($AuditResults.ServicesAndProcesses.RDP.Enabled) { 
                $status = "Active"
                if ($AuditResults.ServicesAndProcesses.RDP.NLARequired) { 
                    $status += " (avec NLA)" 
                } else { 
                    $status += " (sans NLA - vulnerable)" 
                }
                $status
            } else { "Desactive" }
            '{{SERVICES_WINRM_CLASS}}' = Get-StatusClass (-not $AuditResults.ServicesAndProcesses.WinRM.Enabled) "success" "warning" "warning"
            '{{SERVICES_WINRM_STATUS}}' = if ($AuditResults.ServicesAndProcesses.WinRM.Enabled) { "Active" } else { "Desactive" }
            '{{SERVICES_RUNNING_COUNT}}' = if ($AuditResults.ServicesAndProcesses.RunningServices) { $AuditResults.ServicesAndProcesses.RunningServices.Count } else { "0" }
            '{{SERVICES_STOPPED_AUTO_COUNT}}' = if ($AuditResults.ServicesAndProcesses.StoppedAutoServices) { $AuditResults.ServicesAndProcesses.StoppedAutoServices.Count } else { "0" }
            
            # Reseau
            '{{NETWORK_IP_CONFIG}}' = if ($AuditResults.Network.IPConfiguration) { ($AuditResults.Network.IPConfiguration | Format-Table -AutoSize | Out-String).Trim() } else { "Aucune configuration trouvee" }
            '{{NETWORK_FIREWALL_PROFILES}}' = if ($AuditResults.Network.FirewallProfiles) { ($AuditResults.Network.FirewallProfiles | Format-Table -AutoSize | Out-String).Trim() } else { "Aucun profil trouve" }
            '{{NETWORK_SMBV1_CLASS}}' = Get-StatusClass (-not $AuditResults.Network.SMBv1.Enabled) "success" "warning" "danger"
            '{{NETWORK_SMBV1_STATUS}}' = if ($AuditResults.Network.SMBv1.Enabled) { "Active (vulnerable)" } else { "Desactive (securise)" }
            '{{NETWORK_SMB_SHARES_COUNT}}' = if ($AuditResults.Network.SMBShares) { $AuditResults.Network.SMBShares.Count } else { "0" }
            '{{NETWORK_LISTENING_PORTS_COUNT}}' = if ($AuditResults.Network.ListeningPorts) { $AuditResults.Network.ListeningPorts.Count } else { "0" }
            
            # Logiciels et securite
            '{{SOFTWARE_TOTAL_APPS_COUNT}}' = Get-SafeValue $AuditResults.SoftwareAndSecurity.TotalInstalledAppsCount "0"
            '{{SOFTWARE_DEFENDER_STATUS_CLASS}}' = Get-StatusClass $AuditResults.SoftwareAndSecurity.WindowsDefender.Enabled "success" "warning" "danger"
            '{{SOFTWARE_DEFENDER_STATUS}}' = if ($AuditResults.SoftwareAndSecurity.WindowsDefender.Enabled) { "Active" } else { "Desactive" }
            '{{SOFTWARE_DEFENDER_REALTIME_CLASS}}' = Get-StatusClass ($AuditResults.SoftwareAndSecurity.WindowsDefender.RealTimeProtection -eq $true) "success" "warning" "danger"
            '{{SOFTWARE_DEFENDER_REALTIME_STATUS}}' = if ($AuditResults.SoftwareAndSecurity.WindowsDefender.RealTimeProtection -eq $true) { "Activee" } else { "Desactivee" }
            '{{SOFTWARE_DEFENDER_ENGINE_VERSION}}' = Get-SafeValue $AuditResults.SoftwareAndSecurity.WindowsDefender.EngineVersion
            '{{SOFTWARE_DEFENDER_SIGNATURE_VERSION}}' = Get-SafeValue $AuditResults.SoftwareAndSecurity.WindowsDefender.SignatureVersion
            '{{SOFTWARE_DEFENDER_SIGNATURE_AGE_CLASS}}' = if ($AuditResults.SoftwareAndSecurity.WindowsDefender.SignatureAge -ne "Inconnu" -and $AuditResults.SoftwareAndSecurity.WindowsDefender.SignatureAge -le 7) { "success" } elseif ($AuditResults.SoftwareAndSecurity.WindowsDefender.SignatureAge -ne "Inconnu" -and $AuditResults.SoftwareAndSecurity.WindowsDefender.SignatureAge -le 14) { "warning" } elseif ($AuditResults.SoftwareAndSecurity.WindowsDefender.SignatureAge -ne "Inconnu") { "danger" } else { "warning" }
            '{{SOFTWARE_DEFENDER_SIGNATURE_AGE}}' = Get-SafeValue $AuditResults.SoftwareAndSecurity.WindowsDefender.SignatureAge
            '{{SOFTWARE_APPLOCKER_CLASS}}' = Get-StatusClass $AuditResults.SoftwareAndSecurity.AppLocker.Enabled "success" "warning" "warning"
            '{{SOFTWARE_APPLOCKER_STATUS}}' = if ($AuditResults.SoftwareAndSecurity.AppLocker.Enabled) { "Active" } else { "Desactive ou non configure" }
            '{{SOFTWARE_DEVICEGUARD_CLASS}}' = if ($AuditResults.SoftwareAndSecurity.DeviceGuard.VirtualizationBasedSecurityStatus -eq 2) { "success" } else { "warning" }
            '{{SOFTWARE_DEVICEGUARD_STATUS}}' = if ($AuditResults.SoftwareAndSecurity.DeviceGuard.VirtualizationBasedSecurityStatus -eq 2) { "Active et fonctionnel" } elseif ($AuditResults.SoftwareAndSecurity.DeviceGuard.VirtualizationBasedSecurityStatus -eq 1) { "Active mais pas fonctionnel" } else { "Desactive ou non disponible" }
            '{{SOFTWARE_EXPLOITGUARD_FOLDER_CLASS}}' = Get-StatusClass $AuditResults.SoftwareAndSecurity.ExploitGuard.ControlledFolderAccess "success" "warning" "warning"
            '{{SOFTWARE_EXPLOITGUARD_FOLDER_STATUS}}' = if ($AuditResults.SoftwareAndSecurity.ExploitGuard.ControlledFolderAccess) { "Active" } else { "Desactive" }
            '{{SOFTWARE_EXPLOITGUARD_NETWORK_CLASS}}' = Get-StatusClass $AuditResults.SoftwareAndSecurity.ExploitGuard.NetworkProtection "success" "warning" "warning"
            '{{SOFTWARE_EXPLOITGUARD_NETWORK_STATUS}}' = if ($AuditResults.SoftwareAndSecurity.ExploitGuard.NetworkProtection) { "Active" } else { "Desactive" }
            '{{SOFTWARE_PS_LANGUAGE_MODE_CLASS}}' = Get-StatusClass ($AuditResults.SoftwareAndSecurity.PowerShellLanguageMode -eq "ConstrainedLanguage") "success" "warning" "warning"
            '{{SOFTWARE_PS_LANGUAGE_MODE}}' = Get-SafeValue $AuditResults.SoftwareAndSecurity.PowerShellLanguageMode
            '{{SOFTWARE_PS_EXECUTION_POLICY_CLASS}}' = if ($AuditResults.SoftwareAndSecurity.PowerShellExecutionPolicy -eq "Restricted" -or $AuditResults.SoftwareAndSecurity.PowerShellExecutionPolicy -eq "AllSigned") { "success" } elseif ($AuditResults.SoftwareAndSecurity.PowerShellExecutionPolicy -eq "RemoteSigned") { "warning" } else { "danger" }
            '{{SOFTWARE_PS_EXECUTION_POLICY}}' = Get-SafeValue $AuditResults.SoftwareAndSecurity.PowerShellExecutionPolicy
            
            # Stockage
            '{{STORAGE_VOLUMES}}' = if ($AuditResults.Storage.Volumes) { ($AuditResults.Storage.Volumes | Format-Table -AutoSize | Out-String).Trim() } else { "Aucun volume trouve" }
            '{{STORAGE_AUTORUN_CLASS}}' = Get-StatusClass $AuditResults.Storage.AutoRun.DisabledForAll "success" "warning" "warning"
            '{{STORAGE_AUTORUN_STATUS}}' = if ($AuditResults.Storage.AutoRun.DisabledForAll) { "Oui (securise)" } else { "Non (potentiellement vulnerable)" }
            
            # Journalisation
            '{{LOGGING_EVENT_LOGS}}' = if ($AuditResults.LoggingAndAudit.EventLogs) { ($AuditResults.LoggingAndAudit.EventLogs | Format-Table -AutoSize | Out-String).Trim() } else { "Aucun journal trouve" }
            '{{LOGGING_EVENT_FORWARDING_CLASS}}' = Get-StatusClass $AuditResults.LoggingAndAudit.EventForwarding.Enabled "success" "warning" "warning"
            '{{LOGGING_EVENT_FORWARDING_STATUS}}' = if ($AuditResults.LoggingAndAudit.EventForwarding.Enabled) { "Active" } else { "Desactive ou non configure" }
            '{{LOGGING_SYSMON_CLASS}}' = Get-StatusClass $AuditResults.LoggingAndAudit.Sysmon.Installed "success" "warning" "warning"
            '{{LOGGING_SYSMON_STATUS}}' = if ($AuditResults.LoggingAndAudit.Sysmon.Installed) { "Installe ($($AuditResults.LoggingAndAudit.Sysmon.Status))" } else { "Non installe" }
            '{{LOGGING_PS_SCRIPT_BLOCK_CLASS}}' = Get-StatusClass $AuditResults.LoggingAndAudit.PowerShellScriptBlockLogging.Enabled "success" "warning" "warning"
            '{{LOGGING_PS_SCRIPT_BLOCK_STATUS}}' = if ($AuditResults.LoggingAndAudit.PowerShellScriptBlockLogging.Enabled) { "Active" } else { "Desactive ou non configure" }
            '{{LOGGING_PS_TRANSCRIPTION_CLASS}}' = Get-StatusClass $AuditResults.LoggingAndAudit.PowerShellTranscription.Enabled "success" "warning" "warning"
            '{{LOGGING_PS_TRANSCRIPTION_STATUS}}' = if ($AuditResults.LoggingAndAudit.PowerShellTranscription.Enabled) { "Active" } else { "Desactive ou non configure" }
            
            # Score et resume de conformite
            '{{AUDIT_SCORE}}' = if ($AuditResults.Summary -and $AuditResults.Summary.Score -ne 'N/A') { $AuditResults.Summary.Score } else { "N/A" }
            '{{AUDIT_RATING}}' = if ($AuditResults.Summary) { $AuditResults.Summary.Rating } else { "Indetermine" }
            '{{AUDIT_OK_COUNT}}' = if ($AuditResults.Summary) { $AuditResults.Summary.Counts.OK } else { "0" }
            '{{AUDIT_WARN_COUNT}}' = if ($AuditResults.Summary) { $AuditResults.Summary.Counts.WARN } else { "0" }
            '{{AUDIT_FAIL_COUNT}}' = if ($AuditResults.Summary) { $AuditResults.Summary.Counts.FAIL } else { "0" }
            '{{AUDIT_GENERATED_DATE}}' = if ($AuditResults.Summary) { $AuditResults.Summary.GeneratedAt } else { Get-Date }
        }
        
        # Gestion speciale pour les volumes BitLocker
        $bitlockerVolumesHtml = ""
        if ($AuditResults.Storage.BitLocker.Volumes) {
            foreach ($volume in $AuditResults.Storage.BitLocker.Volumes) {
                $volumeStatus = if ($volume.VolumeStatus -eq "FullyEncrypted") { "success" } elseif ($volume.VolumeStatus -eq "EncryptionInProgress") { "warning" } else { "danger" }
                $protectionStatus = if ($volume.ProtectionStatus -eq "On") { "success" } else { "danger" }
                
                $bitlockerVolumesHtml += "<tr><td>$($volume.MountPoint)</td><td class=`"$volumeStatus`">$($volume.VolumeStatus)</td><td>$($volume.EncryptionMethod)</td><td class=`"$protectionStatus`">$($volume.ProtectionStatus)</td></tr>"
            }
        } else {
            $bitlockerVolumesHtml = "<tr><td colspan='4'>Aucune information BitLocker disponible</td></tr>"
        }
        $replacements['{{STORAGE_BITLOCKER_VOLUMES}}'] = $bitlockerVolumesHtml
        
        # Gestion speciale pour les principales constatations
        $topFindingsHtml = ""
        if ($AuditResults.Summary -and $AuditResults.Summary.TopFindings -and $AuditResults.Summary.TopFindings.Count -gt 0) {
            $topFindingsHtml = "<ul>"
            foreach ($finding in $AuditResults.Summary.TopFindings) {
                $statusClass = switch ($finding.Status) {
                    'FAIL' { 'status-fail' }
                    'WARN' { 'status-warn' }
                    'OK'   { 'status-ok' }
                    default { 'status-warn' }
                }
                $topFindingsHtml += "<li><span class=`"$statusClass`">$($finding.Status)</span> <strong>$($finding.Check)</strong> - $($finding.Recommendation)</li>"
            }
            $topFindingsHtml += "</ul>"
        } else {
            $topFindingsHtml = "<ul><li>Aucun constat prioritaire ou recommandations non generees.</li></ul>"
        }
        $replacements['{{AUDIT_TOP_FINDINGS}}'] = $topFindingsHtml
        
        # Generation du tableau des recommandations
        $recommendationsTableHtml = ""
        $allRecommendations = Get-AllAuditRecommendations -AuditResults $AuditResults
        if ($allRecommendations -and $allRecommendations.Count -gt 0) {
            foreach ($rec in $allRecommendations) {
                $statusClass = "status-" + ($rec.Status.ToLower())
                $linkHtml = if ($rec.Link) { "<a href='$($rec.Link)' target='_blank' rel='noopener'>Lien</a>" } else { "" }
                $recommendationsTableHtml += "<tr><td>$($rec.Category)</td><td>$($rec.Check)</td><td class='$statusClass'>$($rec.Status)</td><td>$($rec.Severity)</td><td>$($rec.Recommendation)</td><td>$linkHtml</td></tr>`n"
            }
        } else {
            $recommendationsTableHtml = "<tr><td colspan='6'>Aucune recommandation generee</td></tr>"
        }
        $replacements['{{AUDIT_RECOMMENDATIONS_TABLE}}'] = $recommendationsTableHtml
        
        # Application des remplacements
        $htmlContent = $htmlTemplate
        foreach ($placeholder in $replacements.Keys) {
            $htmlContent = $htmlContent -replace [regex]::Escape($placeholder), $replacements[$placeholder]
        }
        
        Set-Content -Path $htmlPath -Value $htmlContent -Force
        
        # Creation du rapport texte de resume
        $summaryPath = Join-Path -Path $ReportPath -ChildPath "audit-summary.txt"
        # Nouvelle version du rapport resume complètement sans accents ni caracteres speciaux
        $summaryContent = @"
==========================================================================
             RESUME D'AUDIT DE SECURITE WINDOWS
==========================================================================
Machine: $($env:COMPUTERNAME)
Date: $(Get-Date)
Systeme: $($AuditResults.SystemInfo.OSName) $($AuditResults.SystemInfo.OSVersion)

RESULTATS PRINCIPAUX
==========================================================================

## SYSTEME
- Nom de l'ordinateur: $($AuditResults.SystemInfo.Hostname)
- Domaine: $($AuditResults.SystemInfo.Domain)
- Dernier demarrage: $($AuditResults.SystemInfo.LastBootTime)

## AUTHENTIFICATION
- LAPS: $(if ($AuditResults.Authentication.LAPS.Installed) { "Installe" } else { "Non installe" })
- UAC: $(if ($AuditResults.Authentication.UAC.Enabled) { "Active" } else { "Desactive" })
- Protection LSASS: $(if ($AuditResults.Authentication.LSASSProtection.Enabled) { "Activee" } else { "Desactivee" })
- WDigest: $(if ($AuditResults.Authentication.WDigest.Disabled) { "Desactive (securise)" } else { "Active (vulnerable)" })
- Credential Guard: $(if ($AuditResults.Authentication.CredentialGuard.Running) { "Actif" } else { "Inactif ou non disponible" })

## UTILISATEURS
- Utilisateurs actives: $($AuditResults.UsersAndGroups.EnabledUserCount)
- Utilisateurs desactives: $($AuditResults.UsersAndGroups.DisabledUserCount)

## RESEAU
- RDP: $(if ($AuditResults.ServicesAndProcesses.RDP.Enabled) { "Active" } else { "Desactive" })$(if ($AuditResults.ServicesAndProcesses.RDP.Enabled -and $AuditResults.ServicesAndProcesses.RDP.NLARequired) { " (avec NLA)" } elseif ($AuditResults.ServicesAndProcesses.RDP.Enabled) { " (sans NLA - vulnerable)" })
- WinRM: $(if ($AuditResults.ServicesAndProcesses.WinRM.Enabled) { "Active" } else { "Desactive" })
- SMBv1: $(if ($AuditResults.Network.SMBv1.Enabled) { "Active (vulnerable)" } else { "Desactive (securise)" })
- Pare-feu: $(if (($AuditResults.Network.FirewallProfiles | Where-Object { $_.Enabled -eq $false }).Count -eq 0) { "Tous les profils actives" } else { "Certains profils desactives" })

## SECURITE
- Windows Defender: $(if ($AuditResults.SoftwareAndSecurity.WindowsDefender.Enabled) { "Active" } else { "Desactive" })
- Protection temps reel: $(if ($AuditResults.SoftwareAndSecurity.WindowsDefender.RealTimeProtection -eq $true) { "Activee" } else { "Desactivee" })
- AppLocker: $(if ($AuditResults.SoftwareAndSecurity.AppLocker.Enabled) { "Active" } else { "Desactive ou non configure" })
- Device Guard: $(if ($AuditResults.SoftwareAndSecurity.DeviceGuard.VirtualizationBasedSecurityStatus -eq 2) { "Active et fonctionnel" } elseif ($AuditResults.SoftwareAndSecurity.DeviceGuard.VirtualizationBasedSecurityStatus -eq 1) { "Active mais pas fonctionnel" } else { "Desactive ou non disponible" })
- PowerShell Script Block Logging: $(if ($AuditResults.LoggingAndAudit.PowerShellScriptBlockLogging.Enabled) { "Active" } else { "Desactive" })

## STOCKAGE  
- BitLocker: $(
    $encryptedVolumes = $AuditResults.Storage.BitLocker.Volumes | Where-Object { $_.VolumeStatus -eq "FullyEncrypted" -and $_.ProtectionStatus -eq "On" }
    $totalVolumes = ($AuditResults.Storage.Volumes | Where-Object { $_.DriveLetter }).Count
    if ($encryptedVolumes -and $encryptedVolumes.Count -eq $totalVolumes) { 
        "Tous les volumes chiffres et proteges" 
    } elseif ($encryptedVolumes) { 
        "$($encryptedVolumes.Count)/$totalVolumes volumes chiffres et proteges" 
    } else { 
        "Aucun volume chiffre" 
    }
)
- AutoRun desactive: $(if ($AuditResults.Storage.AutoRun.DisabledForAll) { "Oui (securise)" } else { "Non (potentiellement vulnerable)" })

## JOURNALISATION
- Sysmon: $(if ($AuditResults.LoggingAndAudit.Sysmon.Installed) { "Installe" } else { "Non installe" })
- Redirection des evenements: $(if ($AuditResults.LoggingAndAudit.EventForwarding.Enabled) { "Activee" } else { "Desactivee" })

==========================================================================
      Consultez le rapport HTML pour des informations detaillees:
               $htmlPath
==========================================================================
"@

        Set-Content -Path $summaryPath -Value $summaryContent -Force
        
        Write-Output "Rapport d'audit HTML cree: $htmlPath"
        Write-Output "Resume d'audit cree: $summaryPath"
        Write-Output "Donnees brutes JSON: $jsonPath"
        
        return $true
    }
    catch {
        Write-Error "Erreur lors de la generation des rapports: $_"
        return $false
    }
}

function Get-AllAuditRecommendations {
    <#
    .SYNOPSIS
    Recupere toutes les recommandations d'audit depuis les resultats d'audit.
    
    .DESCRIPTION
    Cette fonction parcourt tous les resultats d'audit et collecte toutes les recommandations
    stockees dans les differents modules d'audit.
    
    .PARAMETER AuditResults
    Les resultats d'audit a parcourir pour extraire les recommandations.
    
    .EXAMPLE
    $recommendations = Get-AllAuditRecommendations -AuditResults $auditData
    
    .OUTPUTS
    Array des recommandations d'audit
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [hashtable]$AuditResults
    )

    $all = @()
    if (-not $AuditResults) { return $all }

    foreach ($k in $AuditResults.Keys) {
        try {
            $v = $AuditResults[$k]
            if ($v -is [hashtable] -and $v.ContainsKey('Recommendations') -and $v.Recommendations) {
                $all += $v.Recommendations
            }
        } catch { }
    }
    return $all
}
