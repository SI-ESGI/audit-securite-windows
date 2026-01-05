
function Export-AuditResults {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [hashtable]$AuditResults,
        
        [Parameter(Mandatory = $true)]
        [string]$ReportPath
    )
    
    Write-Output "Génération des rapports d'audit..."
    
    try {
        # Export JSON pour analyse ultérieure
        $jsonPath = Join-Path -Path $ReportPath -ChildPath "audit-results.json"
        $AuditResults | ConvertTo-Json -Depth 10 | Set-Content -Path $jsonPath -Force
        
        # Création du rapport HTML en utilisant le template
        $htmlPath = Join-Path -Path $ReportPath -ChildPath "audit-report.html"
        $templatePath = Join-Path -Path $PSScriptRoot -ChildPath "audit-report-template.html"
        
        # Vérification de l'existence du template
        if (-not (Test-Path -Path $templatePath)) {
            Write-Error "Le fichier template $templatePath n'existe pas."
            return $false
        }
        
        # Lecture du template
        $htmlTemplate = Get-Content -Path $templatePath -Raw
        
        # Fonction pour gérer les valeurs nulles ou vides
        function Get-SafeValue {
            param($Value, $DefaultValue = "N/A")
            if ($null -eq $Value) {
                Write-Host "DEBUG: Valeur null détectée, retour: $DefaultValue" -ForegroundColor Yellow
                return $DefaultValue
            }
            if ($Value -eq "" -and $Value -is [string]) {
                Write-Host "DEBUG: String vide détectée, retour: $DefaultValue" -ForegroundColor Yellow
                return $DefaultValue
            }
            Write-Host "DEBUG: Valeur trouvée: $Value" -ForegroundColor Green
            return $Value
        }
        
        # Fonction pour déterminer la classe CSS basée sur l'état
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
            
            # Informations système
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
            '{{USERS_ADMIN_GROUP_MEMBERS}}' = if ($AuditResults.UsersAndGroups.AdministratorGroupMembers) { ($AuditResults.UsersAndGroups.AdministratorGroupMembers | Format-Table -AutoSize | Out-String).Trim() } else { "Aucun membre trouvé" }
            
            # Authentification
            '{{AUTH_LAPS_CLASS}}' = Get-StatusClass $AuditResults.Authentication.LAPS.Installed "success" "warning" "warning"
            '{{AUTH_LAPS_STATUS}}' = if ($AuditResults.Authentication.LAPS.Installed) { "Installé" } else { "Non installé" }
            '{{AUTH_HELLO_CLASS}}' = Get-StatusClass $AuditResults.Authentication.WindowsHello.EnabledViaGPO "success" "warning" "warning"
            '{{AUTH_HELLO_STATUS}}' = if ($AuditResults.Authentication.WindowsHello.EnabledViaGPO) { "Activé" } else { "Désactivé ou non configuré" }
            '{{AUTH_UAC_CLASS}}' = Get-StatusClass $AuditResults.Authentication.UAC.Enabled "success" "warning" "danger"
            '{{AUTH_UAC_STATUS}}' = if ($AuditResults.Authentication.UAC.Enabled) { "Activé" } else { "Désactivé" }
            '{{AUTH_JEA_CLASS}}' = Get-StatusClass $AuditResults.Authentication.JEA.ModulesInstalled "success" "info" "info"
            '{{AUTH_JEA_STATUS}}' = if ($AuditResults.Authentication.JEA.ModulesInstalled) { "Modules installés" } else { "Non configuré" }
            '{{AUTH_LSASS_CLASS}}' = Get-StatusClass $AuditResults.Authentication.LSASSProtection.Enabled "success" "warning" "danger"
            '{{AUTH_LSASS_STATUS}}' = if ($AuditResults.Authentication.LSASSProtection.Enabled) { "Activé" } else { "Désactivé" }
            '{{AUTH_WDIGEST_CLASS}}' = Get-StatusClass $AuditResults.Authentication.WDigest.Disabled "success" "warning" "danger"
            '{{AUTH_WDIGEST_STATUS}}' = if ($AuditResults.Authentication.WDigest.Disabled) { "Désactivé (sécurisé)" } else { "Activé (vulnérable)" }
            '{{AUTH_CREDGUARD_CLASS}}' = Get-StatusClass $AuditResults.Authentication.CredentialGuard.Running "success" "warning" "warning"
            '{{AUTH_CREDGUARD_STATUS}}' = if ($AuditResults.Authentication.CredentialGuard.Running) { "Actif" } else { "Inactif ou non disponible" }
            
            # Services
            '{{SERVICES_RDP_CLASS}}' = Get-StatusClass (-not $AuditResults.ServicesAndProcesses.RDP.Enabled) "success" "warning" "warning"
            '{{SERVICES_RDP_STATUS}}' = if ($AuditResults.ServicesAndProcesses.RDP.Enabled) { 
                $status = "Activé"
                if ($AuditResults.ServicesAndProcesses.RDP.NLARequired) { 
                    $status += " (avec NLA)" 
                } else { 
                    $status += " (sans NLA - vulnérable)" 
                }
                $status
            } else { "Désactivé" }
            '{{SERVICES_WINRM_CLASS}}' = Get-StatusClass (-not $AuditResults.ServicesAndProcesses.WinRM.Enabled) "success" "warning" "warning"
            '{{SERVICES_WINRM_STATUS}}' = if ($AuditResults.ServicesAndProcesses.WinRM.Enabled) { "Activé" } else { "Désactivé" }
            '{{SERVICES_RUNNING_COUNT}}' = if ($AuditResults.ServicesAndProcesses.RunningServices) { $AuditResults.ServicesAndProcesses.RunningServices.Count } else { "0" }
            '{{SERVICES_STOPPED_AUTO_COUNT}}' = if ($AuditResults.ServicesAndProcesses.StoppedAutoServices) { $AuditResults.ServicesAndProcesses.StoppedAutoServices.Count } else { "0" }
            
            # Réseau
            '{{NETWORK_IP_CONFIG}}' = if ($AuditResults.Network.IPConfiguration) { ($AuditResults.Network.IPConfiguration | Format-Table -AutoSize | Out-String).Trim() } else { "Aucune configuration trouvée" }
            '{{NETWORK_FIREWALL_PROFILES}}' = if ($AuditResults.Network.FirewallProfiles) { ($AuditResults.Network.FirewallProfiles | Format-Table -AutoSize | Out-String).Trim() } else { "Aucun profil trouvé" }
            '{{NETWORK_SMBV1_CLASS}}' = Get-StatusClass (-not $AuditResults.Network.SMBv1.Enabled) "success" "warning" "danger"
            '{{NETWORK_SMBV1_STATUS}}' = if ($AuditResults.Network.SMBv1.Enabled) { "Activé (vulnérable)" } else { "Désactivé (sécurisé)" }
            '{{NETWORK_SMB_SHARES_COUNT}}' = if ($AuditResults.Network.SMBShares) { $AuditResults.Network.SMBShares.Count } else { "0" }
            '{{NETWORK_LISTENING_PORTS_COUNT}}' = if ($AuditResults.Network.ListeningPorts) { $AuditResults.Network.ListeningPorts.Count } else { "0" }
            
            # Logiciels et sécurité
            '{{SOFTWARE_TOTAL_APPS_COUNT}}' = Get-SafeValue $AuditResults.SoftwareAndSecurity.TotalInstalledAppsCount "0"
            '{{SOFTWARE_DEFENDER_STATUS_CLASS}}' = Get-StatusClass $AuditResults.SoftwareAndSecurity.WindowsDefender.Enabled "success" "warning" "danger"
            '{{SOFTWARE_DEFENDER_STATUS}}' = if ($AuditResults.SoftwareAndSecurity.WindowsDefender.Enabled) { "Activé" } else { "Désactivé" }
            '{{SOFTWARE_DEFENDER_REALTIME_CLASS}}' = Get-StatusClass ($AuditResults.SoftwareAndSecurity.WindowsDefender.RealTimeProtection -eq $true) "success" "warning" "danger"
            '{{SOFTWARE_DEFENDER_REALTIME_STATUS}}' = if ($AuditResults.SoftwareAndSecurity.WindowsDefender.RealTimeProtection -eq $true) { "Activée" } else { "Désactivée" }
            '{{SOFTWARE_DEFENDER_ENGINE_VERSION}}' = Get-SafeValue $AuditResults.SoftwareAndSecurity.WindowsDefender.EngineVersion
            '{{SOFTWARE_DEFENDER_SIGNATURE_VERSION}}' = Get-SafeValue $AuditResults.SoftwareAndSecurity.WindowsDefender.SignatureVersion
            '{{SOFTWARE_DEFENDER_SIGNATURE_AGE_CLASS}}' = if ($AuditResults.SoftwareAndSecurity.WindowsDefender.SignatureAge -ne "Inconnu" -and $AuditResults.SoftwareAndSecurity.WindowsDefender.SignatureAge -le 7) { "success" } elseif ($AuditResults.SoftwareAndSecurity.WindowsDefender.SignatureAge -ne "Inconnu" -and $AuditResults.SoftwareAndSecurity.WindowsDefender.SignatureAge -le 14) { "warning" } elseif ($AuditResults.SoftwareAndSecurity.WindowsDefender.SignatureAge -ne "Inconnu") { "danger" } else { "warning" }
            '{{SOFTWARE_DEFENDER_SIGNATURE_AGE}}' = Get-SafeValue $AuditResults.SoftwareAndSecurity.WindowsDefender.SignatureAge
            '{{SOFTWARE_APPLOCKER_CLASS}}' = Get-StatusClass $AuditResults.SoftwareAndSecurity.AppLocker.Enabled "success" "warning" "warning"
            '{{SOFTWARE_APPLOCKER_STATUS}}' = if ($AuditResults.SoftwareAndSecurity.AppLocker.Enabled) { "Activé" } else { "Désactivé ou non configuré" }
            '{{SOFTWARE_DEVICEGUARD_CLASS}}' = if ($AuditResults.SoftwareAndSecurity.DeviceGuard.VirtualizationBasedSecurityStatus -eq 2) { "success" } else { "warning" }
            '{{SOFTWARE_DEVICEGUARD_STATUS}}' = if ($AuditResults.SoftwareAndSecurity.DeviceGuard.VirtualizationBasedSecurityStatus -eq 2) { "Activé et fonctionnel" } elseif ($AuditResults.SoftwareAndSecurity.DeviceGuard.VirtualizationBasedSecurityStatus -eq 1) { "Activé mais pas fonctionnel" } else { "Désactivé ou non disponible" }
            '{{SOFTWARE_EXPLOITGUARD_FOLDER_CLASS}}' = Get-StatusClass $AuditResults.SoftwareAndSecurity.ExploitGuard.ControlledFolderAccess "success" "warning" "warning"
            '{{SOFTWARE_EXPLOITGUARD_FOLDER_STATUS}}' = if ($AuditResults.SoftwareAndSecurity.ExploitGuard.ControlledFolderAccess) { "Activé" } else { "Désactivé" }
            '{{SOFTWARE_EXPLOITGUARD_NETWORK_CLASS}}' = Get-StatusClass $AuditResults.SoftwareAndSecurity.ExploitGuard.NetworkProtection "success" "warning" "warning"
            '{{SOFTWARE_EXPLOITGUARD_NETWORK_STATUS}}' = if ($AuditResults.SoftwareAndSecurity.ExploitGuard.NetworkProtection) { "Activé" } else { "Désactivé" }
            '{{SOFTWARE_PS_LANGUAGE_MODE_CLASS}}' = Get-StatusClass ($AuditResults.SoftwareAndSecurity.PowerShellLanguageMode -eq "ConstrainedLanguage") "success" "warning" "warning"
            '{{SOFTWARE_PS_LANGUAGE_MODE}}' = Get-SafeValue $AuditResults.SoftwareAndSecurity.PowerShellLanguageMode
            '{{SOFTWARE_PS_EXECUTION_POLICY_CLASS}}' = if ($AuditResults.SoftwareAndSecurity.PowerShellExecutionPolicy -eq "Restricted" -or $AuditResults.SoftwareAndSecurity.PowerShellExecutionPolicy -eq "AllSigned") { "success" } elseif ($AuditResults.SoftwareAndSecurity.PowerShellExecutionPolicy -eq "RemoteSigned") { "warning" } else { "danger" }
            '{{SOFTWARE_PS_EXECUTION_POLICY}}' = Get-SafeValue $AuditResults.SoftwareAndSecurity.PowerShellExecutionPolicy
            
            # Stockage
            '{{STORAGE_VOLUMES}}' = if ($AuditResults.Storage.Volumes) { ($AuditResults.Storage.Volumes | Format-Table -AutoSize | Out-String).Trim() } else { "Aucun volume trouvé" }
            '{{STORAGE_AUTORUN_CLASS}}' = Get-StatusClass $AuditResults.Storage.AutoRun.DisabledForAll "success" "warning" "warning"
            '{{STORAGE_AUTORUN_STATUS}}' = if ($AuditResults.Storage.AutoRun.DisabledForAll) { "Oui (sécurisé)" } else { "Non (potentiellement vulnérable)" }
            
            # Journalisation
            '{{LOGGING_EVENT_LOGS}}' = if ($AuditResults.LoggingAndAudit.EventLogs) { ($AuditResults.LoggingAndAudit.EventLogs | Format-Table -AutoSize | Out-String).Trim() } else { "Aucun journal trouvé" }
            '{{LOGGING_EVENT_FORWARDING_CLASS}}' = Get-StatusClass $AuditResults.LoggingAndAudit.EventForwarding.Enabled "success" "warning" "warning"
            '{{LOGGING_EVENT_FORWARDING_STATUS}}' = if ($AuditResults.LoggingAndAudit.EventForwarding.Enabled) { "Activé" } else { "Désactivé ou non configuré" }
            '{{LOGGING_SYSMON_CLASS}}' = Get-StatusClass $AuditResults.LoggingAndAudit.Sysmon.Installed "success" "warning" "warning"
            '{{LOGGING_SYSMON_STATUS}}' = if ($AuditResults.LoggingAndAudit.Sysmon.Installed) { "Installé ($($AuditResults.LoggingAndAudit.Sysmon.Status))" } else { "Non installé" }
            '{{LOGGING_PS_SCRIPT_BLOCK_CLASS}}' = Get-StatusClass $AuditResults.LoggingAndAudit.PowerShellScriptBlockLogging.Enabled "success" "warning" "warning"
            '{{LOGGING_PS_SCRIPT_BLOCK_STATUS}}' = if ($AuditResults.LoggingAndAudit.PowerShellScriptBlockLogging.Enabled) { "Activé" } else { "Désactivé ou non configuré" }
            '{{LOGGING_PS_TRANSCRIPTION_CLASS}}' = Get-StatusClass $AuditResults.LoggingAndAudit.PowerShellTranscription.Enabled "success" "warning" "warning"
            '{{LOGGING_PS_TRANSCRIPTION_STATUS}}' = if ($AuditResults.LoggingAndAudit.PowerShellTranscription.Enabled) { "Activé" } else { "Désactivé ou non configuré" }
        }
        
        # Gestion spéciale pour les volumes BitLocker
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
        
        # Application des remplacements
        $htmlContent = $htmlTemplate
        foreach ($placeholder in $replacements.Keys) {
            $htmlContent = $htmlContent -replace [regex]::Escape($placeholder), $replacements[$placeholder]
        }
        
        Set-Content -Path $htmlPath -Value $htmlContent -Force
        
        # Création du rapport texte de résumé
        $summaryPath = Join-Path -Path $ReportPath -ChildPath "audit-summary.txt"
        $summaryContent = @"
==========================================================================
             RÉSUMÉ D'AUDIT DE SÉCURITÉ WINDOWS
==========================================================================
Machine: $($env:COMPUTERNAME)
Date: $(Get-Date)
Système: $($AuditResults.SystemInfo.OSName) $($AuditResults.SystemInfo.OSVersion)

RÉSULTATS PRINCIPAUX
==========================================================================

## SYSTÈME
- Nom de l'ordinateur: $($AuditResults.SystemInfo.Hostname)
- Domaine: $($AuditResults.SystemInfo.Domain)
- Dernier démarrage: $($AuditResults.SystemInfo.LastBootTime)

## AUTHENTIFICATION
- LAPS: $(if ($AuditResults.Authentication.LAPS.Installed) { "Installé" } else { "Non installé" })
- UAC: $(if ($AuditResults.Authentication.UAC.Enabled) { "Activé" } else { "Désactivé" })
- Protection LSASS: $(if ($AuditResults.Authentication.LSASSProtection.Enabled) { "Activée" } else { "Désactivée" })
- WDigest (stockage en clair): $(if ($AuditResults.Authentication.WDigest.Disabled) { "Désactivé (sécurisé)" } else { "Activé (vulnérable)" })
- Credential Guard: $(if ($AuditResults.Authentication.CredentialGuard.Running) { "Actif" } else { "Inactif ou non disponible" })

## UTILISATEURS
- Utilisateurs activés: $($AuditResults.UsersAndGroups.EnabledUserCount)
- Utilisateurs désactivés: $($AuditResults.UsersAndGroups.DisabledUserCount)

## RÉSEAU
- RDP: $(if ($AuditResults.ServicesAndProcesses.RDP.Enabled) { "Activé" } else { "Désactivé" })$(if ($AuditResults.ServicesAndProcesses.RDP.Enabled -and $AuditResults.ServicesAndProcesses.RDP.NLARequired) { " (avec NLA)" } elseif ($AuditResults.ServicesAndProcesses.RDP.Enabled) { " (sans NLA - vulnérable)" })
- WinRM: $(if ($AuditResults.ServicesAndProcesses.WinRM.Enabled) { "Activé" } else { "Désactivé" })
- SMBv1: $(if ($AuditResults.Network.SMBv1.Enabled) { "Activé (vulnérable)" } else { "Désactivé (sécurisé)" })
- Pare-feu: $(if (($AuditResults.Network.FirewallProfiles | Where-Object { $_.Enabled -eq $false }).Count -eq 0) { "Tous les profils activés" } else { "Certains profils désactivés" })

## SÉCURITÉ
- Windows Defender: $(if ($AuditResults.SoftwareAndSecurity.WindowsDefender.Enabled) { "Activé" } else { "Désactivé" })
- Protection en temps réel: $(if ($AuditResults.SoftwareAndSecurity.WindowsDefender.RealTimeProtection -eq $true) { "Activée" } else { "Désactivée" })
- AppLocker: $(if ($AuditResults.SoftwareAndSecurity.AppLocker.Enabled) { "Activé" } else { "Désactivé ou non configuré" })
- Device Guard: $(if ($AuditResults.SoftwareAndSecurity.DeviceGuard.VirtualizationBasedSecurityStatus -eq 2) { "Activé et fonctionnel" } elseif ($AuditResults.SoftwareAndSecurity.DeviceGuard.VirtualizationBasedSecurityStatus -eq 1) { "Activé mais pas fonctionnel" } else { "Désactivé ou non disponible" })
- PowerShell Script Block Logging: $(if ($AuditResults.LoggingAndAudit.PowerShellScriptBlockLogging.Enabled) { "Activé" } else { "Désactivé" })

## STOCKAGE
- BitLocker: $(
    $encryptedVolumes = $AuditResults.Storage.BitLocker.Volumes | Where-Object { $_.VolumeStatus -eq "FullyEncrypted" -and $_.ProtectionStatus -eq "On" }
    $totalVolumes = ($AuditResults.Storage.Volumes | Where-Object { $_.DriveLetter }).Count
    if ($encryptedVolumes -and $encryptedVolumes.Count -eq $totalVolumes) { 
        "Tous les volumes chiffrés et protégés" 
    } elseif ($encryptedVolumes) { 
        "$($encryptedVolumes.Count)/$totalVolumes volumes chiffrés et protégés" 
    } else { 
        "Aucun volume chiffré" 
    }
)
- AutoRun désactivé: $(if ($AuditResults.Storage.AutoRun.DisabledForAll) { "Oui (sécurisé)" } else { "Non (potentiellement vulnérable)" })

## JOURNALISATION
- Sysmon: $(if ($AuditResults.LoggingAndAudit.Sysmon.Installed) { "Installé" } else { "Non installé" })
- Redirection des événements: $(if ($AuditResults.LoggingAndAudit.EventForwarding.Enabled) { "Activée" } else { "Désactivée" })

==========================================================================
      Consultez le rapport HTML pour des informations détaillées:
               $htmlPath
==========================================================================
"@

        Set-Content -Path $summaryPath -Value $summaryContent -Force
        
        Write-Output "Rapport d'audit HTML créé: $htmlPath"
        Write-Output "Résumé d'audit créé: $summaryPath"
        Write-Output "Données brutes JSON: $jsonPath"
        
        return $true
    }
    catch {
        Write-Error "Erreur lors de la génération des rapports: $_"
        return $false
    }
}
