<#
vérifier les droits d'administrateur et la politique d'exécution
#>
#Requires -RunAsAdministrator 

<#
.SYNOPSIS
    Script d'audit de sécurité Windows complet et modulaire.
    
.DESCRIPTION
    Ce script effectue un audit approfondi des paramètres de sécurité sur une machine Windows,
    vérifiant les GPO, utilisateurs, configurations de sécurité, services, et bien plus.
    Les résultats sont exportés dans des rapports détaillés aux formats HTML, JSON et TXT.
    
#>

#------------------------------------------------------------
# Définition des fonctions du module principal
#------------------------------------------------------------

function Initialize-AuditEnvironment {
    [CmdletBinding()]
    param()
    
    try {
        # Création du dossier pour les résultats
        $script:timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
        $script:reportPath = Join-Path -Path $env:USERPROFILE -ChildPath "Desktop\WindowsAudit-$timestamp"
        
        if (-not (Test-Path -Path $reportPath)) {
            New-Item -ItemType Directory -Path $reportPath -Force | Out-Null
        }
        
        # Initialisation de l'objet de résultats
        $script:auditResults = @{
            SystemInfo = @{}
            GroupPolicy = @{}
            UsersAndGroups = @{}
            Authentication = @{}
            ServicesAndProcesses = @{}
            Network = @{}
            SoftwareAndSecurity = @{}
            Storage = @{}
            LoggingAndAudit = @{}
        }
        
        Write-Output "Audit de sécurité Windows démarré - $(Get-Date)"
        Write-Output "Les résultats seront sauvegardés dans: $reportPath"
        
        return $true
    }
    catch {
        Write-Error "Erreur lors de l'initialisation de l'environnement d'audit: $_"
        return $false
    }
}

#------------------------------------------------------------
# Module: Information système
#------------------------------------------------------------

function Get-SystemInfoAudit {
    [CmdletBinding()]
    param()
    
    Write-Output "Collecte des informations système..."
    
    try {
        # Informations de base sur le système
        $osInfo = Get-CimInstance -ClassName Win32_OperatingSystem
        $computerSystem = Get-CimInstance -ClassName Win32_ComputerSystem
        $bios = Get-CimInstance -ClassName Win32_BIOS
        
        $script:auditResults.SystemInfo.Hostname = $env:COMPUTERNAME
        $script:auditResults.SystemInfo.Domain = $computerSystem.Domain
        $script:auditResults.SystemInfo.Manufacturer = $computerSystem.Manufacturer
        $script:auditResults.SystemInfo.Model = $computerSystem.Model
        $script:auditResults.SystemInfo.BIOSVersion = $bios.SMBIOSBIOSVersion
        $script:auditResults.SystemInfo.BIOSDate = $bios.ReleaseDate
        $script:auditResults.SystemInfo.OSName = $osInfo.Caption
        $script:auditResults.SystemInfo.OSVersion = $osInfo.Version
        $script:auditResults.SystemInfo.OSBuild = $osInfo.BuildNumber
        $script:auditResults.SystemInfo.OSArchitecture = $osInfo.OSArchitecture
        $script:auditResults.SystemInfo.LastBootTime = $osInfo.LastBootUpTime
        $script:auditResults.SystemInfo.InstallDate = $osInfo.InstallDate
        
        # Fonctionnalités Windows installées
        $windowsFeatures = Get-WindowsOptionalFeature -Online | Where-Object { $_.State -eq 'Enabled' } | Select-Object -Property FeatureName
        $script:auditResults.SystemInfo.EnabledWindowsFeatures = $windowsFeatures
        
        # Obtenir des informations système complètes et les sauvegarder dans un fichier
        $systemInfoPath = Join-Path -Path $script:reportPath -ChildPath "systeminfo.txt"
        systeminfo | Out-File -FilePath $systemInfoPath -Force
        $script:auditResults.SystemInfo.SystemInfoDetailFile = $systemInfoPath
        
        return $true
    }
    catch {
        $script:auditResults.SystemInfo.Error = "Erreur lors de la collecte des informations système: $_"
        Write-Warning "Erreur lors de la collecte des informations système: $_"
        return $false
    }
}

#------------------------------------------------------------
# Module: Stratégies de groupe (GPO)
#------------------------------------------------------------

function Get-GroupPolicyAudit {
    [CmdletBinding()]
    param()
    
    Write-Output "Audit des stratégies de groupe..."
    
    try {
        # Exporter les résultats GPO en HTML
        $gpoReportPath = Join-Path -Path $script:reportPath -ChildPath "gpo-report.html"
        Start-Process -FilePath "gpresult.exe" -ArgumentList "/h `"$gpoReportPath`"" -NoNewWindow -Wait
        $script:auditResults.GroupPolicy.GPOReportFile = $gpoReportPath
        
        # Extraire la configuration locale de sécurité
        $secpolPath = Join-Path -Path $script:reportPath -ChildPath "secpol.cfg"
        Start-Process -FilePath "secedit.exe" -ArgumentList "/export /cfg `"$secpolPath`"" -NoNewWindow -Wait
        $script:auditResults.GroupPolicy.SecurityPolicyFile = $secpolPath
        
        # Obtenir toutes les GPO si nous sommes sur un contrôleur de domaine ou avec les outils RSAT installés
        try {
            $allGPOs = Get-GPO -All -ErrorAction Stop
            $script:auditResults.GroupPolicy.AllGPOs = $allGPOs | Select-Object DisplayName, ID, CreationTime, ModificationTime
        }
        catch {
            $script:auditResults.GroupPolicy.AllGPOsInfo = "Non disponible - probablement pas un contrôleur de domaine ou RSAT non installé"
        }
        
        return $true
    }
    catch {
        $script:auditResults.GroupPolicy.Error = "Erreur lors de l'audit des stratégies de groupe: $_"
        Write-Warning "Erreur lors de l'audit des stratégies de groupe: $_"
        return $false
    }
}

#------------------------------------------------------------
# Module: Utilisateurs et groupes
#------------------------------------------------------------

function Get-UsersAndGroupsAudit {
    [CmdletBinding()]
    param()
    
    Write-Output "Audit des utilisateurs et groupes..."
    
    try {
        # Obtenir les utilisateurs locaux
        $localUsers = Get-LocalUser | Select-Object Name, Enabled, LastLogon, PasswordRequired, PasswordLastSet, Description, SID
        $script:auditResults.UsersAndGroups.LocalUsers = $localUsers
        
        # Compter les utilisateurs locaux par état
        $script:auditResults.UsersAndGroups.EnabledUserCount = ($localUsers | Where-Object { $_.Enabled -eq $true }).Count
        $script:auditResults.UsersAndGroups.DisabledUserCount = ($localUsers | Where-Object { $_.Enabled -eq $false }).Count
        
        # Obtenir les groupes locaux
        $localGroups = Get-LocalGroup | Select-Object Name, SID, Description
        $script:auditResults.UsersAndGroups.LocalGroups = $localGroups
        
        # Membres du groupe Administrateurs
        try {
            # Essayer d'abord avec le nom français
            $adminGroupMembers = Get-LocalGroupMember -Group "Administrateurs" -ErrorAction Stop
        }
        catch {
            try {
                # Essayer avec le nom anglais
                $adminGroupMembers = Get-LocalGroupMember -Group "Administrators" -ErrorAction Stop
            }
            catch {
                $adminGroupMembers = "Impossible d'obtenir les membres du groupe Administrateurs"
            }
        }
        
        $script:auditResults.UsersAndGroups.AdministratorGroupMembers = $adminGroupMembers | Select-Object Name, SID, PrincipalSource
        
        # Vérifier les comptes avec des droits spéciaux
        $specialRights = @{
            "SeBackupPrivilege" = "Droit de sauvegarde"
            "SeDebugPrivilege" = "Droit de déboguer des programmes"
            "SeTakeOwnershipPrivilege" = "Droit de s'approprier des fichiers"
            "SeImpersonatePrivilege" = "Droit d'emprunter l'identité d'un client"
        }
        
        $specialRightsPath = Join-Path -Path $script:reportPath -ChildPath "user-rights.txt"
        Start-Process -FilePath "whoami.exe" -ArgumentList "/priv" -NoNewWindow -Wait -RedirectStandardOutput $specialRightsPath
        $script:auditResults.UsersAndGroups.UserRightsFile = $specialRightsPath
        
        return $true
    }
    catch {
        $script:auditResults.UsersAndGroups.Error = "Erreur lors de l'audit des utilisateurs et groupes: $_"
        Write-Warning "Erreur lors de l'audit des utilisateurs et groupes: $_"
        return $false
    }
}

#------------------------------------------------------------
# Module: Authentification
#------------------------------------------------------------

function Get-AuthenticationAudit {
    [CmdletBinding()]
    param()
    
    Write-Output "Audit des mécanismes d'authentification..."
    
    try {
        # Vérification LAPS
        $lapsInstalled = Test-Path -Path "C:\Program Files\LAPS\CSE"
        $lapsRegistry = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*" -ErrorAction SilentlyContinue | 
                       Where-Object { $_.DisplayName -like "*Local Administrator Password Solution*" }
        
        $script:auditResults.Authentication.LAPS = @{
            Installed = ($lapsInstalled -or ($lapsRegistry -ne $null))
            Installation_Path = if ($lapsInstalled) { "C:\Program Files\LAPS\CSE" } else { "Non trouvé" }
            Version = if ($lapsRegistry) { $lapsRegistry.DisplayVersion } else { "Non installé" }
        }
        
        # Windows Hello for Business
        $whfbGPO = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\PassportForWork" -Name "Enabled" -ErrorAction SilentlyContinue
        $whfbCSP = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Policies\PassportForWork" -Name "UsePassportForWork" -ErrorAction SilentlyContinue
        
        $script:auditResults.Authentication.WindowsHello = @{
            EnabledViaGPO = if ($whfbGPO -and $whfbGPO.Enabled -eq 1) { $true } else { $false }
            EnabledViaCSP = if ($whfbCSP -and $whfbCSP.UsePassportForWork -eq 1) { $true } else { $false }
        }
        
        # UAC Configuration
        $uacSettings = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -ErrorAction SilentlyContinue
        
        $script:auditResults.Authentication.UAC = @{
            Enabled = if ($uacSettings.EnableLUA -eq 1) { $true } else { $false }
            PromptLevel = $uacSettings.ConsentPromptBehaviorAdmin
            SecureDesktop = if ($uacSettings.PromptOnSecureDesktop -eq 1) { $true } else { $false }
        }
        
        # JEA (Just Enough Administration)
        $psSessionConfigurations = Get-PSSessionConfiguration -ErrorAction SilentlyContinue
        $jeaModulesExist = Test-Path -Path "C:\Program Files\WindowsPowerShell\Modules\JEA\"
        
        $script:auditResults.Authentication.JEA = @{
            ModulesInstalled = $jeaModulesExist
            SessionConfigurations = $psSessionConfigurations | Select-Object Name, PSVersion, Permission
        }
        
        # Protection LSASS
        $lsassProtection = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "RunAsPPL" -ErrorAction SilentlyContinue
        
        $script:auditResults.Authentication.LSASSProtection = @{
            Enabled = if ($lsassProtection -and ($lsassProtection.RunAsPPL -eq 1 -or $lsassProtection.RunAsPPL -eq 2)) { $true } else { $false }
            Value = if ($lsassProtection) { $lsassProtection.RunAsPPL } else { "Non configuré" }
        }
        
        # WDigest
        $wdigest = Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\SecurityProviders\WDigest" -Name "UseLogonCredential" -ErrorAction SilentlyContinue
        
        $script:auditResults.Authentication.WDigest = @{
            Disabled = if ($wdigest -and $wdigest.UseLogonCredential -eq 0) { $true } else { $false }
            Value = if ($wdigest) { $wdigest.UseLogonCredential } else { "Non configuré" }
        }
        
        # Credential Guard
        $credentialGuard = Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard -ErrorAction SilentlyContinue
        
        $script:auditResults.Authentication.CredentialGuard = @{
            Available = if ($credentialGuard -and $credentialGuard.SecurityServicesConfigured -contains 1) { $true } else { $false }
            Running = if ($credentialGuard -and $credentialGuard.SecurityServicesRunning -contains 1) { $true } else { $false }
        }
        
        return $true
    }
    catch {
        $script:auditResults.Authentication.Error = "Erreur lors de l'audit d'authentification: $_"
        Write-Warning "Erreur lors de l'audit d'authentification: $_"
        return $false
    }
}

#------------------------------------------------------------
# Module: Services et processus
#------------------------------------------------------------

function Get-ServicesAndProcessesAudit {
    [CmdletBinding()]
    param()
    
    Write-Output "Audit des services et processus..."
    
    try {
        # Liste des services en cours d'exécution
        $runningServices = Get-Service | Where-Object { $_.Status -eq "Running" } | 
                           Select-Object Name, DisplayName, StartType, Status
        $script:auditResults.ServicesAndProcesses.RunningServices = $runningServices
        
        # Services automatiques mais non démarrés
        $stoppedAutoServices = Get-Service | Where-Object { $_.Status -eq "Stopped" -and $_.StartType -eq "Automatic" } | 
                              Select-Object Name, DisplayName, StartType, Status
        $script:auditResults.ServicesAndProcesses.StoppedAutoServices = $stoppedAutoServices
        
        # Top processus par utilisation CPU
        $topCpuProcesses = Get-Process | Sort-Object -Property CPU -Descending | 
                          Select-Object -First 15 -Property ProcessName, Id, CPU, WorkingSet, Path
        $script:auditResults.ServicesAndProcesses.TopCPUProcesses = $topCpuProcesses
        
        # Configuration RDP
        try {
            $rdpConfig = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -ErrorAction SilentlyContinue
            $rdpEnabled = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections" -ErrorAction SilentlyContinue
            
            $script:auditResults.ServicesAndProcesses.RDP = @{
                Enabled = if ($rdpEnabled -and $rdpEnabled.fDenyTSConnections -eq 0) { $true } else { $false }
                NLARequired = if ($rdpConfig -and $rdpConfig.UserAuthentication -eq 1) { $true } else { $false }
                SecurityLayer = if ($rdpConfig) { $rdpConfig.SecurityLayer } else { "Non configuré" }
            }
        }
        catch {
            $script:auditResults.ServicesAndProcesses.RDP = "Impossible de déterminer la configuration RDP"
        }
        
        # Configuration WinRM
        $winrmService = Get-Service -Name WinRM -ErrorAction SilentlyContinue
        
        $script:auditResults.ServicesAndProcesses.WinRM = @{
            Enabled = if ($winrmService -and $winrmService.Status -eq "Running") { $true } else { $false }
            StartType = if ($winrmService) { $winrmService.StartType } else { "Non disponible" }
        }
        
        if ($winrmService -and $winrmService.Status -eq "Running") {
            $winrmConfigPath = Join-Path -Path $script:reportPath -ChildPath "winrm-config.txt"
            winrm get winrm/config | Out-File -FilePath $winrmConfigPath -Force
            $script:auditResults.ServicesAndProcesses.WinRMConfigFile = $winrmConfigPath
        }
        
        # Liste des démarrages automatiques
        $startupApps = Get-CimInstance -ClassName Win32_StartupCommand | 
                      Select-Object Name, Command, Location, User
        $script:auditResults.ServicesAndProcesses.StartupItems = $startupApps
        
        # Services tiers vs. Microsoft
        $nonMsServices = Get-WmiObject -Class Win32_Service | 
                        Where-Object { $_.PathName -notlike "*system32*" -and $_.PathName -notlike "*Program Files*\Windows *" } | 
                        Select-Object Name, DisplayName, StartMode, State, PathName
        $script:auditResults.ServicesAndProcesses.ThirdPartyServices = $nonMsServices
        
        return $true
    }
    catch {
        $script:auditResults.ServicesAndProcesses.Error = "Erreur lors de l'audit des services et processus: $_"
        Write-Warning "Erreur lors de l'audit des services et processus: $_"
        return $false
    }
}

#------------------------------------------------------------
# Module: Réseau
#------------------------------------------------------------

function Get-NetworkAudit {
    [CmdletBinding()]
    param()
    
    Write-Output "Audit de la configuration réseau..."
    
    try {
        # Configuration IP
        $netIPConfig = Get-NetIPConfiguration | Select-Object InterfaceAlias, InterfaceDescription, IPv4Address, IPv6Address, DNSServer
        $script:auditResults.Network.IPConfiguration = $netIPConfig
        
        # Détails complets de la configuration IP
        $ipConfigPath = Join-Path -Path $script:reportPath -ChildPath "ipconfig.txt"
        ipconfig /all | Out-File -FilePath $ipConfigPath -Force
        $script:auditResults.Network.IPConfigDetailFile = $ipConfigPath
        
        # Configuration pare-feu
        $firewallProfiles = Get-NetFirewallProfile | Select-Object Name, Enabled, DefaultInboundAction, DefaultOutboundAction, LogAllowed, LogBlocked, LogIgnored
        $script:auditResults.Network.FirewallProfiles = $firewallProfiles
        
        # Règles de pare-feu entrantes autorisant le trafic
        $inboundRules = Get-NetFirewallRule -Direction Inbound -Enabled True -Action Allow | 
                       Select-Object DisplayName, Enabled, Direction, Action, Profile | 
                       Sort-Object -Property DisplayName
        $script:auditResults.Network.InboundAllowRules = $inboundRules
        
        # Sauvegarde des règles de pare-feu complètes
        $firewallRulesPath = Join-Path -Path $script:reportPath -ChildPath "firewall-rules.txt"
        netsh advfirewall firewall show rule name=all | Out-File -FilePath $firewallRulesPath -Force
        $script:auditResults.Network.FirewallRulesFile = $firewallRulesPath
        
        # Connexions actives
        $netStatPath = Join-Path -Path $script:reportPath -ChildPath "netstat.txt"
        netstat -ano | Out-File -FilePath $netStatPath -Force
        $script:auditResults.Network.ActiveConnectionsFile = $netStatPath
        
        # État des ports en écoute
        $listeningPorts = Get-NetTCPConnection -State Listen | 
                         Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, State, OwningProcess
        $script:auditResults.Network.ListeningPorts = $listeningPorts
        
        # Mappage processus-ports
        $portToProcess = @()
        foreach ($port in $listeningPorts) {
            try {
                $process = Get-Process -Id $port.OwningProcess -ErrorAction SilentlyContinue
                $portToProcess += [PSCustomObject]@{
                    Port = $port.LocalPort
                    ProcessId = $port.OwningProcess
                    ProcessName = if ($process) { $process.ProcessName } else { "Unknown" }
                    Path = if ($process -and $process.Path) { $process.Path } else { "N/A" }
                }
            }
            catch {
                # Ignorer les erreurs individuelles
            }
        }
        $script:auditResults.Network.ProcessPortMapping = $portToProcess
        
        # État SMB
        try {
            $smbv1Status = Get-WindowsOptionalFeature -Online -FeatureName "SMB1Protocol" -ErrorAction SilentlyContinue
            $script:auditResults.Network.SMBv1 = @{
                Enabled = if ($smbv1Status -and $smbv1Status.State -eq "Enabled") { $true } else { $false }
                State = if ($smbv1Status) { $smbv1Status.State } else { "Non disponible" }
            }
        }
        catch {
            $script:auditResults.Network.SMBv1 = "Impossible de déterminer l'état de SMBv1"
        }
        
        # Partages SMB
        $smbShares = Get-SmbShare -ErrorAction SilentlyContinue | Select-Object Name, Path, Description
        $script:auditResults.Network.SMBShares = $smbShares
        
        # Accès aux partages SMB
        $smbShareAccess = @()
        foreach ($share in $smbShares) {
            try {
                $access = Get-SmbShareAccess -Name $share.Name -ErrorAction SilentlyContinue | 
                         Select-Object @{Name="Share"; Expression={$share.Name}}, AccountName, AccessRight
                $smbShareAccess += $access
            }
            catch {
                # Ignorer les erreurs individuelles
            }
        }
        $script:auditResults.Network.SMBShareAccessRights = $smbShareAccess
        
        return $true
    }
    catch {
        $script:auditResults.Network.Error = "Erreur lors de l'audit réseau: $_"
        Write-Warning "Erreur lors de l'audit réseau: $_"
        return $false
    }
}

#------------------------------------------------------------
# Module: Logiciels et sécurité
#------------------------------------------------------------

function Get-SoftwareAndSecurityAudit {
    [CmdletBinding()]
    param()
    
    Write-Output "Audit des logiciels et de la sécurité..."
    
    try {
        # Applications installées (limitées aux 50 plus récentes pour éviter un rapport trop volumineux)
        $installedApps = Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* | 
                        Where-Object { $_.DisplayName } |
                        Select-Object DisplayName, DisplayVersion, Publisher, InstallDate |
                        Sort-Object -Property InstallDate -Descending | 
                        Select-Object -First 50
        $script:auditResults.SoftwareAndSecurity.RecentInstalledApps = $installedApps
        
        # Nombre total d'applications installées
        $totalAppsCount = (Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* | 
                          Where-Object { $_.DisplayName }).Count
        $script:auditResults.SoftwareAndSecurity.TotalInstalledAppsCount = $totalAppsCount
        
        # Mises à jour Windows
        try {
            $windowsUpdateServer = Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate" -Name "WUServer" -ErrorAction SilentlyContinue
            $auSettings = Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\AU" -ErrorAction SilentlyContinue
            
            $script:auditResults.SoftwareAndSecurity.WindowsUpdate = @{
                Server = if ($windowsUpdateServer) { $windowsUpdateServer.WUServer } else { "Non configuré" }
                AutoUpdateSettings = if ($auSettings) { $auSettings | Select-Object AUOptions, ScheduledInstallDay, ScheduledInstallTime } else { "Non configuré" }
            }
            
            # Liste des mises à jour installées (limitées aux 50 plus récentes)
            $hotfixes = Get-HotFix | Sort-Object -Property InstalledOn -Descending | Select-Object -First 50 HotFixID, Description, InstalledOn
            $script:auditResults.SoftwareAndSecurity.RecentHotfixes = $hotfixes
        }
        catch {
            $script:auditResults.SoftwareAndSecurity.WindowsUpdateError = "Erreur lors de la vérification des mises à jour Windows: $_"
        }
        
        # AppLocker
        try {
            $appLockerPolicy = Get-AppLockerPolicy -Effective -Xml -ErrorAction SilentlyContinue
            $appLockerPath = Join-Path -Path $script:reportPath -ChildPath "applocker-policy.xml"
            
            if ($appLockerPolicy) {
                Set-Content -Path $appLockerPath -Value $appLockerPolicy -Force
                $script:auditResults.SoftwareAndSecurity.AppLocker = @{
                    Enabled = $true
                    PolicyFile = $appLockerPath
                }
            }
            else {
                $script:auditResults.SoftwareAndSecurity.AppLocker = @{
                    Enabled = $false
                    PolicyFile = "Non disponible"
                }
            }
        }
        catch {
            $script:auditResults.SoftwareAndSecurity.AppLocker = "Impossible de déterminer la configuration AppLocker"
        }
        
        # Windows Defender
        try {
            $defenderStatus = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows Defender\" -ErrorAction SilentlyContinue
            $defenderSignature = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows Defender\Signature Updates\" -ErrorAction SilentlyContinue
            $mpComputerStatus = Get-MpComputerStatus -ErrorAction SilentlyContinue
            
            $script:auditResults.SoftwareAndSecurity.WindowsDefender = @{
                Enabled = if ($defenderStatus -and $defenderStatus.IsServiceRunning -eq 1 -and 
                               $defenderStatus.DisableAntiSpyware -ne 1 -and 
                               $defenderStatus.DisableAntiVirus -ne 1) { $true } else { $false }
                RealTimeProtection = if ($mpComputerStatus) { $mpComputerStatus.RealTimeProtectionEnabled } else { "Inconnu" }
                EngineVersion = if ($defenderSignature) { $defenderSignature.EngineVersion } else { "Inconnu" }
                SignatureVersion = if ($mpComputerStatus) { $mpComputerStatus.AntivirusSignatureVersion } else { "Inconnu" }
                SignatureAge = if ($mpComputerStatus) { $mpComputerStatus.AntivirusSignatureAge } else { "Inconnu" }
            }
        }
        catch {
            $script:auditResults.SoftwareAndSecurity.WindowsDefender = "Impossible de déterminer l'état de Windows Defender"
        }
        
        # Device Guard
        try {
            $deviceGuard = Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard -ErrorAction SilentlyContinue
            
            $script:auditResults.SoftwareAndSecurity.DeviceGuard = @{
                VirtualizationBasedSecurityStatus = if ($deviceGuard) { $deviceGuard.VirtualizationBasedSecurityStatus } else { "Non disponible" }
                SecurityServicesRunning = if ($deviceGuard) { $deviceGuard.SecurityServicesRunning } else { "Non disponible" }
                SecurityServicesConfigured = if ($deviceGuard) { $deviceGuard.SecurityServicesConfigured } else { "Non disponible" }
            }
        }
        catch {
            $script:auditResults.SoftwareAndSecurity.DeviceGuard = "Impossible de déterminer l'état de Device Guard"
        }
        
        # Exploit Guard - Protection des dossiers contrôlés
        try {
            $mpPreference = Get-MpPreference -ErrorAction SilentlyContinue
            
            $script:auditResults.SoftwareAndSecurity.ExploitGuard = @{
                ControlledFolderAccess = if ($mpPreference -and $mpPreference.EnableControlledFolderAccess -eq 1) { $true } else { $false }
                NetworkProtection = if ($mpPreference -and $mpPreference.EnableNetworkProtection -eq 1) { $true } else { $false }
                ExploitProtection = if ($mpPreference -and $mpPreference.EnableExploitProtection -eq 1) { $true } else { $false }
            }
        }
        catch {
            $script:auditResults.SoftwareAndSecurity.ExploitGuard = "Impossible de déterminer la configuration d'Exploit Guard"
        }
        
        # Mode de langage PowerShell
        $script:auditResults.SoftwareAndSecurity.PowerShellLanguageMode = $ExecutionContext.SessionState.LanguageMode
        
        # Stratégie d'exécution PowerShell
        $policyPath = Join-Path -Path $script:reportPath -ChildPath "ps-executionpolicy.txt"
        Get-ExecutionPolicy -List | Out-File -FilePath $policyPath -Force
        $script:auditResults.SoftwareAndSecurity.PowerShellExecutionPolicy = Get-ExecutionPolicy
        $script:auditResults.SoftwareAndSecurity.PowerShellExecutionPolicyFile = $policyPath
        
        return $true
    }
    catch {
        $script:auditResults.SoftwareAndSecurity.Error = "Erreur lors de l'audit des logiciels et de la sécurité: $_"
        Write-Warning "Erreur lors de l'audit des logiciels et de la sécurité: $_"
        return $false
    }
}

#------------------------------------------------------------
# Module: Stockage
#------------------------------------------------------------

function Get-StorageAudit {
    [CmdletBinding()]
    param()
    
    Write-Output "Audit du stockage et du chiffrement..."
    
    try {
        # Informations sur les disques
        $disks = Get-Disk | Select-Object Number, FriendlyName, HealthStatus, OperationalStatus, Size, PartitionStyle
        $script:auditResults.Storage.Disks = $disks
        
        # Informations sur les volumes
        $volumes = Get-Volume | Where-Object { $_.DriveLetter } | 
                  Select-Object DriveLetter, FileSystemLabel, FileSystem, DriveType, HealthStatus, SizeRemaining, Size
        $script:auditResults.Storage.Volumes = $volumes
        
        # Vérification des ACL NTFS sur les dossiers système critiques
        $criticalFolders = @(
            "C:\Windows",
            "C:\Windows\System32",
            "C:\Program Files",
            "C:\Program Files (x86)"
        )
        
        $folderAcls = @()
        foreach ($folder in $criticalFolders) {
            if (Test-Path -Path $folder) {
                try {
                    $acl = Get-Acl -Path $folder -ErrorAction SilentlyContinue
                    $folderAcls += [PSCustomObject]@{
                        Path = $folder
                        Owner = $acl.Owner
                        AccessCount = $acl.Access.Count
                        FullControlForEveryone = ($acl.Access | Where-Object { 
                            $_.IdentityReference -eq "Everyone" -and 
                            $_.FileSystemRights -match "FullControl" -and 
                            $_.AccessControlType -eq "Allow" 
                        }) -ne $null
                    }
                }
                catch {
                    $folderAcls += [PSCustomObject]@{
                        Path = $folder
                        Owner = "Erreur: $_"
                        AccessCount = 0
                        FullControlForEveryone = "Erreur"
                    }
                }
            }
        }
        $script:auditResults.Storage.CriticalFolderACLs = $folderAcls
        
        # Export des ACL détaillées pour C:\Windows
        $windowsAclPath = Join-Path -Path $script:reportPath -ChildPath "windows-folder-acl.txt"
        try {
            $acl = Get-Acl -Path "C:\Windows" -ErrorAction SilentlyContinue
            $acl.Access | Format-Table -AutoSize | Out-File -FilePath $windowsAclPath -Force
            $script:auditResults.Storage.WindowsFolderACLFile = $windowsAclPath
        }
        catch {
            $script:auditResults.Storage.WindowsFolderACLError = "Impossible d'obtenir les ACL pour C:\Windows: $_"
        }
        
        # Lecteurs amovibles
        try {
            $autoRunSetting = Get-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoDriveTypeAutoRun" -ErrorAction SilentlyContinue
            
            $script:auditResults.Storage.AutoRun = @{
                DisabledForAll = if ($autoRunSetting -and $autoRunSetting.NoDriveTypeAutoRun -eq 255) { $true } else { $false }
                Value = if ($autoRunSetting) { $autoRunSetting.NoDriveTypeAutoRun } else { "Non configuré" }
            }
        }
        catch {
            $script:auditResults.Storage.AutoRun = "Impossible de déterminer la configuration AutoRun"
        }
        
        # BitLocker
        try {
            $bitlockerVolumes = Get-BitLockerVolume -ErrorAction SilentlyContinue
            $script:auditResults.Storage.BitLocker = @{
                Volumes = $bitlockerVolumes | Select-Object MountPoint, VolumeStatus, EncryptionMethod, ProtectionStatus
            }
            
            # Export des détails BitLocker
            $bitlockerPath = Join-Path -Path $script:reportPath -ChildPath "bitlocker-status.txt"
            manage-bde -status | Out-File -FilePath $bitlockerPath -Force
            $script:auditResults.Storage.BitLockerStatusFile = $bitlockerPath
        }
        catch {
            $script:auditResults.Storage.BitLocker = "Impossible d'obtenir les informations BitLocker"
        }
        
        # Configuration NTFS sur les lecteurs principaux
        $ntfsConfig = @()
        foreach ($volume in $volumes) {
            if ($volume.FileSystem -eq "NTFS" -and $volume.DriveLetter) {
                try {
                    $fsutilInfo = fsutil fsinfo ntfsinfo $($volume.DriveLetter):
                    $ntfsConfig += [PSCustomObject]@{
                        DriveLetter = $volume.DriveLetter
                        Info = $fsutilInfo -join "`n"
                    }
                }
                catch {
                    $ntfsConfig += [PSCustomObject]@{
                        DriveLetter = $volume.DriveLetter
                        Info = "Erreur: $_"
                    }
                }
            }
        }
        
        # Sauvegarde des informations NTFS
        $ntfsPath = Join-Path -Path $script:reportPath -ChildPath "ntfs-info.txt"
        $ntfsConfig | ForEach-Object { "=== Lecteur $($_.DriveLetter): ===`n$($_.Info)`n`n" } | Out-File -FilePath $ntfsPath -Force
        $script:auditResults.Storage.NTFSConfigFile = $ntfsPath
        
        return $true
    }
    catch {
        $script:auditResults.Storage.Error = "Erreur lors de l'audit du stockage: $_"
        Write-Warning "Erreur lors de l'audit du stockage: $_"
        return $false
    }
}

#------------------------------------------------------------
# Module: Journalisation et audit
#------------------------------------------------------------

function Get-LoggingAndAuditAudit {
    [CmdletBinding()]
    param()
    
    Write-Output "Audit de la journalisation et des événements..."
    
    try {
        # Politique d'audit
        $auditPolicyPath = Join-Path -Path $script:reportPath -ChildPath "audit-policy.txt"
        auditpol.exe /get /category:* | Out-File -FilePath $auditPolicyPath -Force
        $script:auditResults.LoggingAndAudit.AuditPolicyFile = $auditPolicyPath
        
        # Configuration des journaux d'événements Windows
        $eventLogs = Get-WinEvent -ListLog "Application", "System", "Security" -ErrorAction SilentlyContinue | 
                    Select-Object LogName, LogMode, MaximumSizeInBytes, IsEnabled, RecordCount
        $script:auditResults.LoggingAndAudit.EventLogs = $eventLogs
        
        # Vérification de la redirection des journaux
        try {
            $forwardingLog = Get-WinEvent -ListLog "Microsoft-Windows-Forwarding/Operational" -ErrorAction SilentlyContinue
            
            $script:auditResults.LoggingAndAudit.EventForwarding = @{
                Enabled = if ($forwardingLog -and $forwardingLog.IsEnabled) { $true } else { $false }
                LogMode = if ($forwardingLog) { $forwardingLog.LogMode } else { "Non disponible" }
                MaxSizeInBytes = if ($forwardingLog) { $forwardingLog.MaximumSizeInBytes } else { 0 }
            }
            
            if ($forwardingLog -and $forwardingLog.IsEnabled) {
                try {
                    $forwardingEvents = Get-WinEvent -FilterHashtable @{ LogName = 'Microsoft-Windows-Forwarding/Operational'; Id = 104; } -MaxEvents 5 -ErrorAction SilentlyContinue |
                                       Select-Object TimeCreated, Id, Message
                    $script:auditResults.LoggingAndAudit.RecentForwardingEvents = $forwardingEvents
                }
                catch {
                    $script:auditResults.LoggingAndAudit.RecentForwardingEvents = "Aucun événement récent trouvé ou erreur lors de la récupération"
                }
            }
        }
        catch {
            $script:auditResults.LoggingAndAudit.EventForwarding = "Impossible de déterminer la configuration de redirection des journaux"
        }
        
        # Vérification de Sysmon
        $sysmonService = Get-Service -Name Sysmon -ErrorAction SilentlyContinue
        
        $script:auditResults.LoggingAndAudit.Sysmon = @{
            Installed = if ($sysmonService) { $true } else { $false }
            Status = if ($sysmonService) { $sysmonService.Status } else { "Non installé" }
            StartType = if ($sysmonService) { $sysmonService.StartType } else { "N/A" }
        }
        
        if ($sysmonService) {
            try {
                $sysmonEvents = Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -MaxEvents 5 -ErrorAction SilentlyContinue |
                              Select-Object TimeCreated, Id, Message
                $script:auditResults.LoggingAndAudit.RecentSysmonEvents = $sysmonEvents
            }
            catch {
                $script:auditResults.LoggingAndAudit.SysmonEventsError = "Impossible d'obtenir les événements Sysmon: $_"
            }
        }
        
        # Script Block Logging
        try {
            $psLoggingPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"
            $scriptBlockLogging = Get-ItemProperty -Path $psLoggingPath -Name "EnableScriptBlockLogging" -ErrorAction SilentlyContinue
            
            $script:auditResults.LoggingAndAudit.PowerShellScriptBlockLogging = @{
                Enabled = if ($scriptBlockLogging -and $scriptBlockLogging.EnableScriptBlockLogging -eq 1) { $true } else { $false }
                Value = if ($scriptBlockLogging) { $scriptBlockLogging.EnableScriptBlockLogging } else { "Non configuré" }
            }
        }
        catch {
            $script:auditResults.LoggingAndAudit.PowerShellScriptBlockLogging = "Impossible de déterminer la configuration de Script Block Logging"
        }
        
        # Transcription PowerShell
        try {
            $psTranscriptionPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription"
            $transcription = Get-ItemProperty -Path $psTranscriptionPath -ErrorAction SilentlyContinue
            
            $script:auditResults.LoggingAndAudit.PowerShellTranscription = @{
                Enabled = if ($transcription -and $transcription.EnableTranscripting -eq 1) { $true } else { $false }
                OutputDirectory = if ($transcription -and $transcription.OutputDirectory) { $transcription.OutputDirectory } else { "Non configuré" }
                EnableInvocationHeader = if ($transcription -and $transcription.EnableInvocationHeader -eq 1) { $true } else { $false }
            }
        }
        catch {
            $script:auditResults.LoggingAndAudit.PowerShellTranscription = "Impossible de déterminer la configuration de transcription PowerShell"
        }
        
        return $true
    }
    catch {
        $script:auditResults.LoggingAndAudit.Error = "Erreur lors de l'audit de la journalisation: $_"
        Write-Warning "Erreur lors de l'audit de la journalisation: $_"
        return $false
    }
}

#------------------------------------------------------------
# Module: Génération des rapports
#------------------------------------------------------------

function Export-AuditResults {
    [CmdletBinding()]
    param()
    
    Write-Output "Génération des rapports d'audit..."
    
    try {
        # Export JSON pour analyse ultérieure
        $jsonPath = Join-Path -Path $script:reportPath -ChildPath "audit-results.json"
        $script:auditResults | ConvertTo-Json -Depth 10 | Set-Content -Path $jsonPath -Force
        
        # Création du rapport HTML
        $htmlPath = Join-Path -Path $script:reportPath -ChildPath "audit-report.html"
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
        <p><strong>Système d'exploitation:</strong> $($script:auditResults.SystemInfo.OSName)</p>
        <p><strong>Version:</strong> $($script:auditResults.SystemInfo.OSVersion)</p>
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
            <tr><td>Nom de l'ordinateur</td><td>$($script:auditResults.SystemInfo.Hostname)</td></tr>
            <tr><td>Domaine</td><td>$($script:auditResults.SystemInfo.Domain)</td></tr>
            <tr><td>Fabricant</td><td>$($script:auditResults.SystemInfo.Manufacturer)</td></tr>
            <tr><td>Modèle</td><td>$($script:auditResults.SystemInfo.Model)</td></tr>
            <tr><td>Version BIOS</td><td>$($script:auditResults.SystemInfo.BIOSVersion)</td></tr>
            <tr><td>Système d'exploitation</td><td>$($script:auditResults.SystemInfo.OSName)</td></tr>
            <tr><td>Version</td><td>$($script:auditResults.SystemInfo.OSVersion)</td></tr>
            <tr><td>Build</td><td>$($script:auditResults.SystemInfo.OSBuild)</td></tr>
            <tr><td>Architecture</td><td>$($script:auditResults.SystemInfo.OSArchitecture)</td></tr>
            <tr><td>Dernier démarrage</td><td>$($script:auditResults.SystemInfo.LastBootTime)</td></tr>
            <tr><td>Date d'installation</td><td>$($script:auditResults.SystemInfo.InstallDate)</td></tr>
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
            <tr><td>Utilisateurs activés</td><td>$($script:auditResults.UsersAndGroups.EnabledUserCount)</td></tr>
            <tr><td>Utilisateurs désactivés</td><td>$($script:auditResults.UsersAndGroups.DisabledUserCount)</td></tr>
            <tr><td>Total des groupes locaux</td><td>$(($script:auditResults.UsersAndGroups.LocalGroups).Count)</td></tr>
        </table>
        
        <h3>Membres du groupe Administrateurs</h3>
        <pre>
$(($script:auditResults.UsersAndGroups.AdministratorGroupMembers | Format-Table -AutoSize | Out-String).Trim())
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
                <td class="$(if ($script:auditResults.Authentication.LAPS.Installed) { "success" } else { "warning" })">
                    $(if ($script:auditResults.Authentication.LAPS.Installed) { "Installé" } else { "Non installé" })
                </td>
            </tr>
            <tr>
                <td>Windows Hello for Business (GPO)</td>
                <td class="$(if ($script:auditResults.Authentication.WindowsHello.EnabledViaGPO) { "success" } else { "warning" })">
                    $(if ($script:auditResults.Authentication.WindowsHello.EnabledViaGPO) { "Activé" } else { "Désactivé ou non configuré" })
                </td>
            </tr>
            <tr>
                <td>UAC (User Account Control)</td>
                <td class="$(if ($script:auditResults.Authentication.UAC.Enabled) { "success" } else { "danger" })">
                    $(if ($script:auditResults.Authentication.UAC.Enabled) { "Activé" } else { "Désactivé" })
                </td>
            </tr>
            <tr>
                <td>JEA (Just Enough Administration)</td>
                <td class="$(if ($script:auditResults.Authentication.JEA.ModulesInstalled) { "success" } else { "info" })">
                    $(if ($script:auditResults.Authentication.JEA.ModulesInstalled) { "Modules installés" } else { "Non configuré" })
                </td>
            </tr>
        </table>
        
        <h3>Protection des identifiants</h3>
        <table>
            <tr><th>Protection</th><th>État</th></tr>
            <tr>
                <td>Protection LSASS (RunAsPPL)</td>
                <td class="$(if ($script:auditResults.Authentication.LSASSProtection.Enabled) { "success" } else { "danger" })">
                    $(if ($script:auditResults.Authentication.LSASSProtection.Enabled) { "Activé" } else { "Désactivé" })
                </td>
            </tr>
            <tr>
                <td>WDigest (stockage en clair des mots de passe)</td>
                <td class="$(if ($script:auditResults.Authentication.WDigest.Disabled) { "success" } else { "danger" })">
                    $(if ($script:auditResults.Authentication.WDigest.Disabled) { "Désactivé (sécurisé)" } else { "Activé (vulnérable)" })
                </td>
            </tr>
            <tr>
                <td>Credential Guard</td>
                <td class="$(if ($script:auditResults.Authentication.CredentialGuard.Running) { "success" } else { "warning" })">
                    $(if ($script:auditResults.Authentication.CredentialGuard.Running) { "Actif" } else { "Inactif ou non disponible" })
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
                <td class="$(if ($script:auditResults.ServicesAndProcesses.RDP.Enabled) { "warning" } else { "success" })">
                    $(if ($script:auditResults.ServicesAndProcesses.RDP.Enabled) { "Activé" } else { "Désactivé" })
                    $(if ($script:auditResults.ServicesAndProcesses.RDP.Enabled -and $script:auditResults.ServicesAndProcesses.RDP.NLARequired) { " (avec NLA)" } elseif ($script:auditResults.ServicesAndProcesses.RDP.Enabled) { " (sans NLA - vulnérable)" })
                </td>
            </tr>
            <tr>
                <td>WinRM (Windows Remote Management)</td>
                <td class="$(if ($script:auditResults.ServicesAndProcesses.WinRM.Enabled) { "warning" } else { "success" })">
                    $(if ($script:auditResults.ServicesAndProcesses.WinRM.Enabled) { "Activé" } else { "Désactivé" })
                </td>
            </tr>
        </table>
        
        <h3>Statistiques des services</h3>
        <p>Nombre de services en cours d'exécution: $(($script:auditResults.ServicesAndProcesses.RunningServices).Count)</p>
        <p>Nombre de services automatiques arrêtés: $(($script:auditResults.ServicesAndProcesses.StoppedAutoServices).Count)</p>
        
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
$(($script:auditResults.Network.IPConfiguration | Format-Table -AutoSize | Out-String).Trim())
        </pre>
        
        <h3>Pare-feu Windows</h3>
        <pre>
$(($script:auditResults.Network.FirewallProfiles | Format-Table -AutoSize | Out-String).Trim())
        </pre>
        
        <h3>Configurations SMB</h3>
        <table>
            <tr><th>Élément</th><th>État</th></tr>
            <tr>
                <td>SMBv1 (version vulnérable)</td>
                <td class="$(if ($script:auditResults.Network.SMBv1.Enabled) { "danger" } else { "success" })">
                    $(if ($script:auditResults.Network.SMBv1.Enabled) { "Activé (vulnérable)" } else { "Désactivé (sécurisé)" })
                </td>
            </tr>
            <tr>
                <td>Nombre de partages SMB</td>
                <td>$(($script:auditResults.Network.SMBShares).Count)</td>
            </tr>
        </table>
        
        <h3>Ports en écoute</h3>
        <p>Nombre de ports en écoute: $(($script:auditResults.Network.ListeningPorts).Count)</p>
        
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
        <p>Nombre total d'applications installées: $($script:auditResults.SoftwareAndSecurity.TotalInstalledAppsCount)</p>
        
        <h3>Windows Defender</h3>
        <table>
            <tr><th>Paramètre</th><th>Valeur</th></tr>
            <tr>
                <td>Statut</td>
                <td class="$(if ($script:auditResults.SoftwareAndSecurity.WindowsDefender.Enabled) { "success" } else { "danger" })">
                    $(if ($script:auditResults.SoftwareAndSecurity.WindowsDefender.Enabled) { "Activé" } else { "Désactivé" })
                </td>
            </tr>
            <tr>
                <td>Protection en temps réel</td>
                <td class="$(if ($script:auditResults.SoftwareAndSecurity.WindowsDefender.RealTimeProtection -eq $true) { "success" } else { "danger" })">
                    $(if ($script:auditResults.SoftwareAndSecurity.WindowsDefender.RealTimeProtection -eq $true) { "Activée" } else { "Désactivée" })
                </td>
            </tr>
            <tr><td>Version du moteur</td><td>$($script:auditResults.SoftwareAndSecurity.WindowsDefender.EngineVersion)</td></tr>
            <tr><td>Version des signatures</td><td>$($script:auditResults.SoftwareAndSecurity.WindowsDefender.SignatureVersion)</td></tr>
            <tr>
                <td>Âge des signatures (jours)</td>
                <td class="$(if ($script:auditResults.SoftwareAndSecurity.WindowsDefender.SignatureAge -le 7) { "success" } elseif ($script:auditResults.SoftwareAndSecurity.WindowsDefender.SignatureAge -le 14) { "warning" } else { "danger" })">
                    $($script:auditResults.SoftwareAndSecurity.WindowsDefender.SignatureAge)
                </td>
            </tr>
        </table>
        
        <h3>Protections avancées</h3>
        <table>
            <tr><th>Protection</th><th>État</th></tr>
            <tr>
                <td>AppLocker</td>
                <td class="$(if ($script:auditResults.SoftwareAndSecurity.AppLocker.Enabled) { "success" } else { "warning" })">
                    $(if ($script:auditResults.SoftwareAndSecurity.AppLocker.Enabled) { "Activé" } else { "Désactivé ou non configuré" })
                </td>
            </tr>
            <tr>
                <td>Device Guard</td>
                <td class="$(if ($script:auditResults.SoftwareAndSecurity.DeviceGuard.VirtualizationBasedSecurityStatus -eq 2) { "success" } else { "warning" })">
                    $(if ($script:auditResults.SoftwareAndSecurity.DeviceGuard.VirtualizationBasedSecurityStatus -eq 2) { "Activé et fonctionnel" } elseif ($script:auditResults.SoftwareAndSecurity.DeviceGuard.VirtualizationBasedSecurityStatus -eq 1) { "Activé mais pas fonctionnel" } else { "Désactivé ou non disponible" })
                </td>
            </tr>
            <tr>
                <td>Exploit Guard - Protection des dossiers contrôlés</td>
                <td class="$(if ($script:auditResults.SoftwareAndSecurity.ExploitGuard.ControlledFolderAccess) { "success" } else { "warning" })">
                    $(if ($script:auditResults.SoftwareAndSecurity.ExploitGuard.ControlledFolderAccess) { "Activé" } else { "Désactivé" })
                </td>
            </tr>
            <tr>
                <td>Exploit Guard - Protection réseau</td>
                <td class="$(if ($script:auditResults.SoftwareAndSecurity.ExploitGuard.NetworkProtection) { "success" } else { "warning" })">
                    $(if ($script:auditResults.SoftwareAndSecurity.ExploitGuard.NetworkProtection) { "Activé" } else { "Désactivé" })
                </td>
            </tr>
        </table>
        
        <h3>PowerShell</h3>
        <table>
            <tr><th>Paramètre</th><th>Valeur</th></tr>
            <tr>
                <td>Mode de langage</td>
                <td class="$(if ($script:auditResults.SoftwareAndSecurity.PowerShellLanguageMode -eq "ConstrainedLanguage") { "success" } else { "warning" })">
                    $($script:auditResults.SoftwareAndSecurity.PowerShellLanguageMode)
                </td>
            </tr>
            <tr>
                <td>Stratégie d'exécution</td>
                <td class="$(if ($script:auditResults.SoftwareAndSecurity.PowerShellExecutionPolicy -eq "Restricted" -or $script:auditResults.SoftwareAndSecurity.PowerShellExecutionPolicy -eq "AllSigned") { "success" } elseif ($script:auditResults.SoftwareAndSecurity.PowerShellExecutionPolicy -eq "RemoteSigned") { "warning" } else { "danger" })">
                    $($script:auditResults.SoftwareAndSecurity.PowerShellExecutionPolicy)
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
$(($script:auditResults.Storage.Volumes | Format-Table -AutoSize | Out-String).Trim())
        </pre>
        
        <h3>BitLocker</h3>
        <table>
            <tr><th>Volume</th><th>État</th><th>Méthode de chiffrement</th><th>État de protection</th></tr>
$(
    if ($script:auditResults.Storage.BitLocker.Volumes) {
        $script:auditResults.Storage.BitLocker.Volumes | ForEach-Object {
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
                <td class="$(if ($script:auditResults.Storage.AutoRun.DisabledForAll) { "success" } else { "warning" })">
                    $(if ($script:auditResults.Storage.AutoRun.DisabledForAll) { "Oui (sécurisé)" } else { "Non (potentiellement vulnérable)" })
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
$(($script:auditResults.LoggingAndAudit.EventLogs | Format-Table -AutoSize | Out-String).Trim())
        </pre>
        
        <h3>Solutions de journalisation avancées</h3>
        <table>
            <tr><th>Solution</th><th>État</th></tr>
            <tr>
                <td>Redirection des événements (Event Forwarding)</td>
                <td class="$(if ($script:auditResults.LoggingAndAudit.EventForwarding.Enabled) { "success" } else { "warning" })">
                    $(if ($script:auditResults.LoggingAndAudit.EventForwarding.Enabled) { "Activé" } else { "Désactivé ou non configuré" })
                </td>
            </tr>
            <tr>
                <td>Sysmon</td>
                <td class="$(if ($script:auditResults.LoggingAndAudit.Sysmon.Installed) { "success" } else { "warning" })">
                    $(if ($script:auditResults.LoggingAndAudit.Sysmon.Installed) { "Installé ($($script:auditResults.LoggingAndAudit.Sysmon.Status))" } else { "Non installé" })
                </td>
            </tr>
            <tr>
                <td>PowerShell Script Block Logging</td>
                <td class="$(if ($script:auditResults.LoggingAndAudit.PowerShellScriptBlockLogging.Enabled) { "success" } else { "warning" })">
                    $(if ($script:auditResults.LoggingAndAudit.PowerShellScriptBlockLogging.Enabled) { "Activé" } else { "Désactivé ou non configuré" })
                </td>
            </tr>
            <tr>
                <td>PowerShell Transcription</td>
                <td class="$(if ($script:auditResults.LoggingAndAudit.PowerShellTranscription.Enabled) { "success" } else { "warning" })">
                    $(if ($script:auditResults.LoggingAndAudit.PowerShellTranscription.Enabled) { "Activé" } else { "Désactivé ou non configuré" })
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
Système: $($script:auditResults.SystemInfo.OSName) $($script:auditResults.SystemInfo.OSVersion)

RÉSULTATS PRINCIPAUX
==========================================================================

## SYSTÈME
- Nom de l'ordinateur: $($script:auditResults.SystemInfo.Hostname)
- Domaine: $($script:auditResults.SystemInfo.Domain)
- Dernier démarrage: $($script:auditResults.SystemInfo.LastBootTime)

## AUTHENTIFICATION
- LAPS: $(if ($script:auditResults.Authentication.LAPS.Installed) { "Installé" } else { "Non installé" })
- UAC: $(if ($script:auditResults.Authentication.UAC.Enabled) { "Activé" } else { "Désactivé" })
- Protection LSASS: $(if ($script:auditResults.Authentication.LSASSProtection.Enabled) { "Activée" } else { "Désactivée" })
- WDigest (stockage en clair): $(if ($script:auditResults.Authentication.WDigest.Disabled) { "Désactivé (sécurisé)" } else { "Activé (vulnérable)" })
- Credential Guard: $(if ($script:auditResults.Authentication.CredentialGuard.Running) { "Actif" } else { "Inactif ou non disponible" })

## UTILISATEURS
- Utilisateurs activés: $($script:auditResults.UsersAndGroups.EnabledUserCount)
- Utilisateurs désactivés: $($script:auditResults.UsersAndGroups.DisabledUserCount)

## RÉSEAU
- RDP: $(if ($script:auditResults.ServicesAndProcesses.RDP.Enabled) { "Activé" } else { "Désactivé" })$(if ($script:auditResults.ServicesAndProcesses.RDP.Enabled -and $script:auditResults.ServicesAndProcesses.RDP.NLARequired) { " (avec NLA)" } elseif ($script:auditResults.ServicesAndProcesses.RDP.Enabled) { " (sans NLA - vulnérable)" })
- WinRM: $(if ($script:auditResults.ServicesAndProcesses.WinRM.Enabled) { "Activé" } else { "Désactivé" })
- SMBv1: $(if ($script:auditResults.Network.SMBv1.Enabled) { "Activé (vulnérable)" } else { "Désactivé (sécurisé)" })
- Pare-feu: $(if (($script:auditResults.Network.FirewallProfiles | Where-Object { $_.Enabled -eq $false }).Count -eq 0) { "Tous les profils activés" } else { "Certains profils désactivés" })

## SÉCURITÉ
- Windows Defender: $(if ($script:auditResults.SoftwareAndSecurity.WindowsDefender.Enabled) { "Activé" } else { "Désactivé" })
- Protection en temps réel: $(if ($script:auditResults.SoftwareAndSecurity.WindowsDefender.RealTimeProtection -eq $true) { "Activée" } else { "Désactivée" })
- AppLocker: $(if ($script:auditResults.SoftwareAndSecurity.AppLocker.Enabled) { "Activé" } else { "Désactivé ou non configuré" })
- Device Guard: $(if ($script:auditResults.SoftwareAndSecurity.DeviceGuard.VirtualizationBasedSecurityStatus -eq 2) { "Activé et fonctionnel" } elseif ($script:auditResults.SoftwareAndSecurity.DeviceGuard.VirtualizationBasedSecurityStatus -eq 1) { "Activé mais pas fonctionnel" } else { "Désactivé ou non disponible" })
- PowerShell Script Block Logging: $(if ($script:auditResults.LoggingAndAudit.PowerShellScriptBlockLogging.Enabled) { "Activé" } else { "Désactivé" })

## STOCKAGE
- BitLocker: $(
    $encryptedVolumes = $script:auditResults.Storage.BitLocker.Volumes | Where-Object { $_.VolumeStatus -eq "FullyEncrypted" -and $_.ProtectionStatus -eq "On" }
    $totalVolumes = ($script:auditResults.Storage.Volumes | Where-Object { $_.DriveLetter }).Count
    if ($encryptedVolumes -and $encryptedVolumes.Count -eq $totalVolumes) { 
        "Tous les volumes chiffrés et protégés" 
    } elseif ($encryptedVolumes) { 
        "$($encryptedVolumes.Count)/$totalVolumes volumes chiffrés et protégés" 
    } else { 
        "Aucun volume chiffré" 
    }
)
- AutoRun désactivé: $(if ($script:auditResults.Storage.AutoRun.DisabledForAll) { "Oui (sécurisé)" } else { "Non (potentiellement vulnérable)" })

## JOURNALISATION
- Sysmon: $(if ($script:auditResults.LoggingAndAudit.Sysmon.Installed) { "Installé" } else { "Non installé" })
- Redirection des événements: $(if ($script:auditResults.LoggingAndAudit.EventForwarding.Enabled) { "Activée" } else { "Désactivée" })

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

#------------------------------------------------------------
# Fonction principale d'audit
#------------------------------------------------------------

function Start-WindowsSecurityAudit {
    [CmdletBinding()]
    param()
    
    Write-Output "=================================="
    Write-Output "  AUDIT DE SÉCURITÉ WINDOWS"
    Write-Output "=================================="
    
    # Initialisation de l'environnement
    $initResult = Initialize-AuditEnvironment
    if (-not $initResult) {
        Write-Error "Échec de l'initialisation de l'environnement. Arrêt de l'audit."
        return
    }
    
    # Exécution des modules d'audit
    $modules = @(
        @{ Name = "Informations système"; Function = "Get-SystemInfoAudit" },
        @{ Name = "Stratégies de groupe"; Function = "Get-GroupPolicyAudit" },
        @{ Name = "Utilisateurs et groupes"; Function = "Get-UsersAndGroupsAudit" },
        @{ Name = "Authentification"; Function = "Get-AuthenticationAudit" },
        @{ Name = "Services et processus"; Function = "Get-ServicesAndProcessesAudit" },
        @{ Name = "Réseau"; Function = "Get-NetworkAudit" },
        @{ Name = "Logiciels et sécurité"; Function = "Get-SoftwareAndSecurityAudit" },
        @{ Name = "Stockage"; Function = "Get-StorageAudit" },
        @{ Name = "Journalisation et audit"; Function = "Get-LoggingAndAuditAudit" }
    )
    
    foreach ($module in $modules) {
        Write-Output "`n== Module: $($module.Name) =="
        try {
            & $module.Function
        }
        catch {
            Write-Error "Erreur lors de l'exécution du module $($module.Name): $_"
        }
    }
    
    # Génération des rapports
    Export-AuditResults
    
    Write-Output "`n=================================="
    Write-Output "  AUDIT DE SÉCURITÉ TERMINÉ"
    Write-Output "=================================="
    Write-Output "Les résultats ont été sauvegardés dans: $script:reportPath"
    Write-Output "Rapport HTML: $script:reportPath\audit-report.html"
    Write-Output "Résumé texte: $script:reportPath\audit-summary.txt"
}

# Point d'entrée du script
Start-WindowsSecurityAudit