
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
        
        # Création du rapport HTML
        $htmlPath = Join-Path -Path $ReportPath -ChildPath "audit-report.html"
        $htmlContent = @"
<!DOCTYPE html>
<html lang="fr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Rapport d'audit de sécurité Windows - $($env:COMPUTERNAME)</title>
    <style>
        body { 
            font-family: Arial, sans-serif; 
            margin: 20px; 
            line-height: 1.5;
            color: #333;
        }
        h1 { 
            color: #003366; 
            border-bottom: 2px solid #003366;
            padding-bottom: 10px;
        }
        h2 { 
            color: #0066cc; 
            margin-top: 30px; 
            border-bottom: 1px solid #ddd;
            padding-bottom: 5px;
        }
        h3 {
            color: #0099cc;
            margin-top: 20px;
        }
        pre { 
            background-color: #f5f5f5; 
            padding: 10px; 
            border-radius: 5px; 
            overflow: auto;
            font-family: Consolas, monospace;
            font-size: 14px;
        }
        table {
            border-collapse: collapse;
            width: 100%;
            margin-bottom: 20px;
        }
        th, td {
            border: 1px solid #ddd;
            padding: 8px;
            text-align: left;
        }
        th {
            background-color: #f2f2f2;
            font-weight: bold;
        }
        tr:nth-child(even) {
            background-color: #f9f9f9;
        }
        .section { 
            margin-bottom: 30px; 
            background-color: #fff;
            padding: 15px;
            border-radius: 5px;
            box-shadow: 0 1px 3px rgba(0,0,0,0.1);
        }
        .success { color: green; }
        .warning { color: orange; }
        .danger { color: red; }
        .info { 
            background-color: #e6f7ff; 
            border-left: 4px solid #1890ff;
            padding: 10px;
            margin: 10px 0;
        }
        .summary {
            background-color: #f8f8f8;
            padding: 15px;
            border-radius: 5px;
            margin-bottom: 20px;
        }
        footer {
            margin-top: 30px;
            border-top: 1px solid #ddd;
            padding-top: 10px;
            font-size: 12px;
            color: #666;
        }
    </style>
</head>
<body>
    <h1>Rapport d'audit de sécurité Windows</h1>
    <div class="summary">
        <p><strong>Machine:</strong> $($env:COMPUTERNAME)</p>
        <p><strong>Date:</strong> $(Get-Date)</p>
        <p><strong>Système d'exploitation:</strong> $($AuditResults.SystemInfo.OSName)</p>
        <p><strong>Version:</strong> $($AuditResults.SystemInfo.OSVersion)</p>
    </div>
"@

        # Table des matières
        $htmlContent += @"
    <h2>Table des matières</h2>
    <ul>
        <li><a href="#system-info">Informations système</a></li>
        <li><a href="#group-policy">Stratégies de groupe</a></li>
        <li><a href="#users-groups">Utilisateurs et groupes</a></li>
        <li><a href="#authentication">Authentification</a></li>
        <li><a href="#services-processes">Services et processus</a></li>
        <li><a href="#network">Réseau</a></li>
        <li><a href="#software-security">Logiciels et sécurité</a></li>
        <li><a href="#storage">Stockage</a></li>
        <li><a href="#logging-audit">Journalisation et audit</a></li>
    </ul>
"@

        # Informations système
        $htmlContent += @"
    <h2 id="system-info">Informations système</h2>
    <div class="section">
        <table>
            <tr><th>Propriété</th><th>Valeur</th></tr>
            <tr><td>Nom de l'ordinateur</td><td>$($AuditResults.SystemInfo.Hostname)</td></tr>
            <tr><td>Domaine</td><td>$($AuditResults.SystemInfo.Domain)</td></tr>
            <tr><td>Fabricant</td><td>$($AuditResults.SystemInfo.Manufacturer)</td></tr>
            <tr><td>Modèle</td><td>$($AuditResults.SystemInfo.Model)</td></tr>
            <tr><td>Version BIOS</td><td>$($AuditResults.SystemInfo.BIOSVersion)</td></tr>
            <tr><td>Système d'exploitation</td><td>$($AuditResults.SystemInfo.OSName)</td></tr>
            <tr><td>Version</td><td>$($AuditResults.SystemInfo.OSVersion)</td></tr>
            <tr><td>Build</td><td>$($AuditResults.SystemInfo.OSBuild)</td></tr>
            <tr><td>Architecture</td><td>$($AuditResults.SystemInfo.OSArchitecture)</td></tr>
            <tr><td>Dernier démarrage</td><td>$($AuditResults.SystemInfo.LastBootTime)</td></tr>
            <tr><td>Date d'installation</td><td>$($AuditResults.SystemInfo.InstallDate)</td></tr>
        </table>
        
        <h3>Fichiers détaillés</h3>
        <ul>
            <li><a href="systeminfo.txt">Informations système complètes</a></li>
        </ul>
    </div>
"@

        # Stratégies de groupe
        $htmlContent += @"
    <h2 id="group-policy">Stratégies de groupe</h2>
    <div class="section">
        <h3>Fichiers détaillés</h3>
        <ul>
            <li><a href="gpo-report.html">Rapport GPO complet</a></li>
            <li><a href="secpol.cfg">Configuration de la politique de sécurité</a></li>
        </ul>
    </div>
"@

        # Utilisateurs et groupes
        $htmlContent += @"
    <h2 id="users-groups">Utilisateurs et groupes</h2>
    <div class="section">
        <h3>Résumé des utilisateurs</h3>
        <table>
            <tr><th>Type</th><th>Nombre</th></tr>
            <tr><td>Utilisateurs activés</td><td>$($AuditResults.UsersAndGroups.EnabledUserCount)</td></tr>
            <tr><td>Utilisateurs désactivés</td><td>$($AuditResults.UsersAndGroups.DisabledUserCount)</td></tr>
            <tr><td>Total des groupes locaux</td><td>$(($AuditResults.UsersAndGroups.LocalGroups).Count)</td></tr>
        </table>
        
        <h3>Membres du groupe Administrateurs</h3>
        <pre>
$(($AuditResults.UsersAndGroups.AdministratorGroupMembers | Format-Table -AutoSize | Out-String).Trim())
        </pre>
        
        <h3>Fichiers détaillés</h3>
        <ul>
            <li><a href="user-rights.txt">Droits utilisateur spéciaux</a></li>
        </ul>
    </div>
"@

        # Authentification
        $htmlContent += @"
    <h2 id="authentication">Authentification</h2>
    <div class="section">
        <h3>Solutions d'authentification</h3>
        <table>
            <tr><th>Mécanisme</th><th>État</th></tr>
            <tr>
                <td>LAPS (Local Administrator Password Solution)</td>
                <td class="$(if ($AuditResults.Authentication.LAPS.Installed) { "success" } else { "warning" })">
                    $(if ($AuditResults.Authentication.LAPS.Installed) { "Installé" } else { "Non installé" })
                </td>
            </tr>
            <tr>
                <td>Windows Hello for Business (GPO)</td>
                <td class="$(if ($AuditResults.Authentication.WindowsHello.EnabledViaGPO) { "success" } else { "warning" })">
                    $(if ($AuditResults.Authentication.WindowsHello.EnabledViaGPO) { "Activé" } else { "Désactivé ou non configuré" })
                </td>
            </tr>
            <tr>
                <td>UAC (User Account Control)</td>
                <td class="$(if ($AuditResults.Authentication.UAC.Enabled) { "success" } else { "danger" })">
                    $(if ($AuditResults.Authentication.UAC.Enabled) { "Activé" } else { "Désactivé" })
                </td>
            </tr>
            <tr>
                <td>JEA (Just Enough Administration)</td>
                <td class="$(if ($AuditResults.Authentication.JEA.ModulesInstalled) { "success" } else { "info" })">
                    $(if ($AuditResults.Authentication.JEA.ModulesInstalled) { "Modules installés" } else { "Non configuré" })
                </td>
            </tr>
        </table>
        
        <h3>Protection des identifiants</h3>
        <table>
            <tr><th>Protection</th><th>État</th></tr>
            <tr>
                <td>Protection LSASS (RunAsPPL)</td>
                <td class="$(if ($AuditResults.Authentication.LSASSProtection.Enabled) { "success" } else { "danger" })">
                    $(if ($AuditResults.Authentication.LSASSProtection.Enabled) { "Activé" } else { "Désactivé" })
                </td>
            </tr>
            <tr>
                <td>WDigest (stockage en clair des mots de passe)</td>
                <td class="$(if ($AuditResults.Authentication.WDigest.Disabled) { "success" } else { "danger" })">
                    $(if ($AuditResults.Authentication.WDigest.Disabled) { "Désactivé (sécurisé)" } else { "Activé (vulnérable)" })
                </td>
            </tr>
            <tr>
                <td>Credential Guard</td>
                <td class="$(if ($AuditResults.Authentication.CredentialGuard.Running) { "success" } else { "warning" })">
                    $(if ($AuditResults.Authentication.CredentialGuard.Running) { "Actif" } else { "Inactif ou non disponible" })
                </td>
            </tr>
        </table>
    </div>
"@

        # Services et processus
        $htmlContent += @"
    <h2 id="services-processes">Services et processus</h2>
    <div class="section">
        <h3>Services critiques</h3>
        <table>
            <tr><th>Service</th><th>État</th></tr>
            <tr>
                <td>RDP (Remote Desktop Protocol)</td>
                <td class="$(if ($AuditResults.ServicesAndProcesses.RDP.Enabled) { "warning" } else { "success" })">
                    $(if ($AuditResults.ServicesAndProcesses.RDP.Enabled) { "Activé" } else { "Désactivé" })
                    $(if ($AuditResults.ServicesAndProcesses.RDP.Enabled -and $AuditResults.ServicesAndProcesses.RDP.NLARequired) { " (avec NLA)" } elseif ($AuditResults.ServicesAndProcesses.RDP.Enabled) { " (sans NLA - vulnérable)" })
                </td>
            </tr>
            <tr>
                <td>WinRM (Windows Remote Management)</td>
                <td class="$(if ($AuditResults.ServicesAndProcesses.WinRM.Enabled) { "warning" } else { "success" })">
                    $(if ($AuditResults.ServicesAndProcesses.WinRM.Enabled) { "Activé" } else { "Désactivé" })
                </td>
            </tr>
        </table>
        
        <h3>Statistiques des services</h3>
        <p>Nombre de services en cours d'exécution: $(($AuditResults.ServicesAndProcesses.RunningServices).Count)</p>
        <p>Nombre de services automatiques arrêtés: $(($AuditResults.ServicesAndProcesses.StoppedAutoServices).Count)</p>
        
        <h3>Fichiers détaillés</h3>
        <ul>
            <li><a href="winrm-config.txt">Configuration WinRM</a></li>
        </ul>
    </div>
"@

        # Réseau
        $htmlContent += @"
    <h2 id="network">Réseau</h2>
    <div class="section">
        <h3>Configuration de base</h3>
        <pre>
$(($AuditResults.Network.IPConfiguration | Format-Table -AutoSize | Out-String).Trim())
        </pre>
        
        <h3>Pare-feu Windows</h3>
        <pre>
$(($AuditResults.Network.FirewallProfiles | Format-Table -AutoSize | Out-String).Trim())
        </pre>
        
        <h3>Configurations SMB</h3>
        <table>
            <tr><th>Élément</th><th>État</th></tr>
            <tr>
                <td>SMBv1 (version vulnérable)</td>
                <td class="$(if ($AuditResults.Network.SMBv1.Enabled) { "danger" } else { "success" })">
                    $(if ($AuditResults.Network.SMBv1.Enabled) { "Activé (vulnérable)" } else { "Désactivé (sécurisé)" })
                </td>
            </tr>
            <tr>
                <td>Nombre de partages SMB</td>
                <td>$(($AuditResults.Network.SMBShares).Count)</td>
            </tr>
        </table>
        
        <h3>Ports en écoute</h3>
        <p>Nombre de ports en écoute: $(($AuditResults.Network.ListeningPorts).Count)</p>
        
        <h3>Fichiers détaillés</h3>
        <ul>
            <li><a href="ipconfig.txt">Configuration IP complète</a></li>
            <li><a href="firewall-rules.txt">Règles de pare-feu détaillées</a></li>
            <li><a href="netstat.txt">Connexions réseau actives</a></li>
        </ul>
    </div>
"@

        # Logiciels et sécurité
        $htmlContent += @"
    <h2 id="software-security">Logiciels et sécurité</h2>
    <div class="section">
        <h3>Applications installées</h3>
        <p>Nombre total d'applications installées: $($AuditResults.SoftwareAndSecurity.TotalInstalledAppsCount)</p>
        
        <h3>Windows Defender</h3>
        <table>
            <tr><th>Paramètre</th><th>Valeur</th></tr>
            <tr>
                <td>Statut</td>
                <td class="$(if ($AuditResults.SoftwareAndSecurity.WindowsDefender.Enabled) { "success" } else { "danger" })">
                    $(if ($AuditResults.SoftwareAndSecurity.WindowsDefender.Enabled) { "Activé" } else { "Désactivé" })
                </td>
            </tr>
            <tr>
                <td>Protection en temps réel</td>
                <td class="$(if ($AuditResults.SoftwareAndSecurity.WindowsDefender.RealTimeProtection -eq $true) { "success" } else { "danger" })">
                    $(if ($AuditResults.SoftwareAndSecurity.WindowsDefender.RealTimeProtection -eq $true) { "Activée" } else { "Désactivée" })
                </td>
            </tr>
            <tr><td>Version du moteur</td><td>$($AuditResults.SoftwareAndSecurity.WindowsDefender.EngineVersion)</td></tr>
            <tr><td>Version des signatures</td><td>$($AuditResults.SoftwareAndSecurity.WindowsDefender.SignatureVersion)</td></tr>
            <tr>
                <td>Âge des signatures (jours)</td>
                <td class="$(if ($AuditResults.SoftwareAndSecurity.WindowsDefender.SignatureAge -le 7) { "success" } elseif ($AuditResults.SoftwareAndSecurity.WindowsDefender.SignatureAge -le 14) { "warning" } else { "danger" })">
                    $($AuditResults.SoftwareAndSecurity.WindowsDefender.SignatureAge)
                </td>
            </tr>
        </table>
        
        <h3>Protections avancées</h3>
        <table>
            <tr><th>Protection</th><th>État</th></tr>
            <tr>
                <td>AppLocker</td>
                <td class="$(if ($AuditResults.SoftwareAndSecurity.AppLocker.Enabled) { "success" } else { "warning" })">
                    $(if ($AuditResults.SoftwareAndSecurity.AppLocker.Enabled) { "Activé" } else { "Désactivé ou non configuré" })
                </td>
            </tr>
            <tr>
                <td>Device Guard</td>
                <td class="$(if ($AuditResults.SoftwareAndSecurity.DeviceGuard.VirtualizationBasedSecurityStatus -eq 2) { "success" } else { "warning" })">
                    $(if ($AuditResults.SoftwareAndSecurity.DeviceGuard.VirtualizationBasedSecurityStatus -eq 2) { "Activé et fonctionnel" } elseif ($AuditResults.SoftwareAndSecurity.DeviceGuard.VirtualizationBasedSecurityStatus -eq 1) { "Activé mais pas fonctionnel" } else { "Désactivé ou non disponible" })
                </td>
            </tr>
            <tr>
                <td>Exploit Guard - Protection des dossiers contrôlés</td>
                <td class="$(if ($AuditResults.SoftwareAndSecurity.ExploitGuard.ControlledFolderAccess) { "success" } else { "warning" })">
                    $(if ($AuditResults.SoftwareAndSecurity.ExploitGuard.ControlledFolderAccess) { "Activé" } else { "Désactivé" })
                </td>
            </tr>
            <tr>
                <td>Exploit Guard - Protection réseau</td>
                <td class="$(if ($AuditResults.SoftwareAndSecurity.ExploitGuard.NetworkProtection) { "success" } else { "warning" })">
                    $(if ($AuditResults.SoftwareAndSecurity.ExploitGuard.NetworkProtection) { "Activé" } else { "Désactivé" })
                </td>
            </tr>
        </table>
        
        <h3>PowerShell</h3>
        <table>
            <tr><th>Paramètre</th><th>Valeur</th></tr>
            <tr>
                <td>Mode de langage</td>
                <td class="$(if ($AuditResults.SoftwareAndSecurity.PowerShellLanguageMode -eq "ConstrainedLanguage") { "success" } else { "warning" })">
                    $($AuditResults.SoftwareAndSecurity.PowerShellLanguageMode)
                </td>
            </tr>
            <tr>
                <td>Stratégie d'exécution</td>
                <td class="$(if ($AuditResults.SoftwareAndSecurity.PowerShellExecutionPolicy -eq "Restricted" -or $AuditResults.SoftwareAndSecurity.PowerShellExecutionPolicy -eq "AllSigned") { "success" } elseif ($AuditResults.SoftwareAndSecurity.PowerShellExecutionPolicy -eq "RemoteSigned") { "warning" } else { "danger" })">
                    $($AuditResults.SoftwareAndSecurity.PowerShellExecutionPolicy)
                </td>
            </tr>
        </table>
        
        <h3>Fichiers détaillés</h3>
        <ul>
            <li><a href="applocker-policy.xml">Politique AppLocker</a></li>
            <li><a href="ps-executionpolicy.txt">Configuration détaillée des stratégies d'exécution PowerShell</a></li>
        </ul>
    </div>
"@

        # Stockage
        $htmlContent += @"
    <h2 id="storage">Stockage</h2>
    <div class="section">
        <h3>Disques et volumes</h3>
        <pre>
$(($AuditResults.Storage.Volumes | Format-Table -AutoSize | Out-String).Trim())
        </pre>
        
        <h3>BitLocker</h3>
        <table>
            <tr><th>Volume</th><th>État</th><th>Méthode de chiffrement</th><th>État de protection</th></tr>
$(
    if ($AuditResults.Storage.BitLocker.Volumes) {
        $AuditResults.Storage.BitLocker.Volumes | ForEach-Object {
            $volumeStatus = if ($_.VolumeStatus -eq "FullyEncrypted") { "success" } elseif ($_.VolumeStatus -eq "EncryptionInProgress") { "warning" } else { "danger" }
            $protectionStatus = if ($_.ProtectionStatus -eq "On") { "success" } else { "danger" }
            
            "<tr><td>$($_.MountPoint)</td><td class=`"$volumeStatus`">$($_.VolumeStatus)</td><td>$($_.EncryptionMethod)</td><td class=`"$protectionStatus`">$($_.ProtectionStatus)</td></tr>"
        }
    } else {
        "<tr><td colspan='4'>Aucune information BitLocker disponible</td></tr>"
    }
)
        </table>
        
        <h3>Protection des disques amovibles</h3>
        <table>
            <tr><th>Protection</th><th>État</th></tr>
            <tr>
                <td>AutoRun désactivé pour tous les lecteurs</td>
                <td class="$(if ($AuditResults.Storage.AutoRun.DisabledForAll) { "success" } else { "warning" })">
                    $(if ($AuditResults.Storage.AutoRun.DisabledForAll) { "Oui (sécurisé)" } else { "Non (potentiellement vulnérable)" })
                </td>
            </tr>
        </table>
        
        <h3>Fichiers détaillés</h3>
        <ul>
            <li><a href="windows-folder-acl.txt">ACL du dossier Windows</a></li>
            <li><a href="bitlocker-status.txt">État détaillé de BitLocker</a></li>
            <li><a href="ntfs-info.txt">Configuration NTFS</a></li>
        </ul>
    </div>
"@

        # Journalisation et audit
        $htmlContent += @"
    <h2 id="logging-audit">Journalisation et audit</h2>
    <div class="section">
        <h3>Configuration des journaux d'événements</h3>
        <pre>
$(($AuditResults.LoggingAndAudit.EventLogs | Format-Table -AutoSize | Out-String).Trim())
        </pre>
        
        <h3>Solutions de journalisation avancées</h3>
        <table>
            <tr><th>Solution</th><th>État</th></tr>
            <tr>
                <td>Redirection des événements (Event Forwarding)</td>
                <td class="$(if ($AuditResults.LoggingAndAudit.EventForwarding.Enabled) { "success" } else { "warning" })">
                    $(if ($AuditResults.LoggingAndAudit.EventForwarding.Enabled) { "Activé" } else { "Désactivé ou non configuré" })
                </td>
            </tr>
            <tr>
                <td>Sysmon</td>
                <td class="$(if ($AuditResults.LoggingAndAudit.Sysmon.Installed) { "success" } else { "warning" })">
                    $(if ($AuditResults.LoggingAndAudit.Sysmon.Installed) { "Installé ($($AuditResults.LoggingAndAudit.Sysmon.Status))" } else { "Non installé" })
                </td>
            </tr>
            <tr>
                <td>PowerShell Script Block Logging</td>
                <td class="$(if ($AuditResults.LoggingAndAudit.PowerShellScriptBlockLogging.Enabled) { "success" } else { "warning" })">
                    $(if ($AuditResults.LoggingAndAudit.PowerShellScriptBlockLogging.Enabled) { "Activé" } else { "Désactivé ou non configuré" })
                </td>
            </tr>
            <tr>
                <td>PowerShell Transcription</td>
                <td class="$(if ($AuditResults.LoggingAndAudit.PowerShellTranscription.Enabled) { "success" } else { "warning" })">
                    $(if ($AuditResults.LoggingAndAudit.PowerShellTranscription.Enabled) { "Activé" } else { "Désactivé ou non configuré" })
                </td>
            </tr>
        </table>
        
        <h3>Fichiers détaillés</h3>
        <ul>
            <li><a href="audit-policy.txt">Politique d'audit complète</a></li>
        </ul>
    </div>
"@

        # Pied de page
        $htmlContent += @"
    <footer>
        <p>Rapport généré le $(Get-Date) sur $($env:COMPUTERNAME)</p>
        <p>Script d'audit de sécurité Windows - Version 1.0</p>
    </footer>
</body>
</html>
"@

        Set-Content -Path $htmlPath -Value $htmlContent -Force
        
        # Création du rapport texte de résumé
        $summaryPath = Join-Path -Path $script:reportPath -ChildPath "audit-summary.txt"
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
