<#
verifier les droits d'administrateur et la politique d'execution
#>
#Requires -RunAsAdministrator 

# Correction de l'encodage pour l'affichage console
$OutputEncoding = [System.Text.Encoding]::UTF8
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8

<#
.SYNOPSIS
    Script d'audit de securite Windows complet et modulaire.
    
.DESCRIPTION
    Ce script effectue un audit approfondi des parametres de securite sur une machine Windows,
    verifiant les GPO, utilisateurs, configurations de securite, services, et bien plus.
    Les resultats sont exportes dans des rapports detailles aux formats HTML, JSON et TXT.
    
#>

# Import de la fonction Export-AuditResults
. "$PSScriptRoot\Export-AuditResults.ps1"

#------------------------------------------------------------
# Fonctions utilitaires pour les recommandations
#------------------------------------------------------------

function Add-AuditRecommendation {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)][string]$Category,
        [Parameter(Mandatory=$true)][string]$Check,
        [Parameter(Mandatory=$true)][ValidateSet('OK','WARN','FAIL')][string]$Status,
        [Parameter(Mandatory=$true)][ValidateSet('Low','Medium','High','Critical')][string]$Severity,
        [Parameter(Mandatory=$true)][string]$Recommendation,
        [Parameter(Mandatory=$false)][string]$Link,
        [Parameter(Mandatory=$false)][string]$Rationale
    )

    if (-not $script:auditResults) { return }
    if (-not $script:auditResults.ContainsKey($Category)) { $script:auditResults[$Category] = @{} }
    if (-not ($script:auditResults[$Category] -is [hashtable])) { $script:auditResults[$Category] = @{} }
    if (-not $script:auditResults[$Category].ContainsKey('Recommendations')) { $script:auditResults[$Category].Recommendations = @() }

    $script:auditResults[$Category].Recommendations += [pscustomobject]@{
        Category       = $Category
        Check          = $Check
        Status         = $Status
        Severity       = $Severity
        Recommendation = $Recommendation
        Link           = $Link
        Rationale      = $Rationale
    }
}

function Initialize-RecommendationBuckets {
    [CmdletBinding()]
    param()

    if (-not $script:auditResults) { return }

    foreach ($cat in $script:auditResults.Keys) {
        if (-not ($script:auditResults[$cat] -is [hashtable])) { $script:auditResults[$cat] = @{} }
        if (-not $script:auditResults[$cat].ContainsKey('Recommendations')) {
            $script:auditResults[$cat].Recommendations = @()
        }
    }
}

#------------------------------------------------------------
# Definition des fonctions du module principal
#------------------------------------------------------------

function Initialize-AuditEnvironment {
    [CmdletBinding()]
    param()
    
    try {
        # Creation du dossier pour les resultats
        $script:timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
        $script:reportPath = Join-Path -Path $env:USERPROFILE -ChildPath "Desktop\WindowsAudit-$timestamp"
        
        if (-not (Test-Path -Path $reportPath)) {
            New-Item -ItemType Directory -Path $reportPath -Force | Out-Null
        }
        
        # Initialisation de l'objet de resultats
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
        
        Write-Output "Audit de securite Windows demarre - $(Get-Date)"
        Write-Output "Les resultats seront sauvegardes dans: $reportPath"
        
        # Initialisation des buckets de recommandations
        Initialize-RecommendationBuckets
        
        return $true
    }
    catch {
        Write-Error "Erreur lors de l'initialisation de l'environnement d'audit: $_"
        return $false
    }
}

#------------------------------------------------------------
# Module: Information systeme
#------------------------------------------------------------

function Get-SystemInfoAudit {
    [CmdletBinding()]
    param()
    
    Write-Output "Collecte des informations systeme..."
    
    try {
        # Informations de base sur le systeme
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
        
        # Fonctionnalites Windows installees
        $windowsFeatures = Get-WindowsOptionalFeature -Online | Where-Object { $_.State -eq 'Enabled' } | Select-Object -Property FeatureName
        $script:auditResults.SystemInfo.EnabledWindowsFeatures = $windowsFeatures
        
        # Obtenir des informations systeme completes et les sauvegarder dans un fichier
        $systemInfoPath = Join-Path -Path $script:reportPath -ChildPath "systeminfo.txt"
        systeminfo | Out-File -FilePath $systemInfoPath -Force
        $script:auditResults.SystemInfo.SystemInfoDetailFile = $systemInfoPath
        
        # --- Recommandations (Informations systeme) ---
        $osVersion = [Version]$script:auditResults.SystemInfo.OSVersion
        if ($osVersion.Major -lt 10 -or ($osVersion.Major -eq 10 -and $osVersion.Build -lt 19041)) {
            Add-AuditRecommendation -Category "SystemInfo" -Check "Version OS" -Status "WARN" -Severity "High" `
                -Recommendation "Version Windows obsolete ou non supportee. Mettre a jour vers une version supportee pour recevoir les correctifs de securite." `
                -Link "https://learn.microsoft.com/lifecycle/products/windows-10-home-and-pro"
        } else {
            Add-AuditRecommendation -Category "SystemInfo" -Check "Version OS" -Status "OK" -Severity "Low" `
                -Recommendation "Version Windows recente. Maintenir les mises a jour regulieres." `
                -Link "https://learn.microsoft.com/windows/deployment/update/"
        }

        $daysSinceLastBoot = (Get-Date) - $script:auditResults.SystemInfo.LastBootTime
        if ($daysSinceLastBoot.Days -gt 30) {
            Add-AuditRecommendation -Category "SystemInfo" -Check "Redemarrage systeme" -Status "WARN" -Severity "Medium" `
                -Recommendation "Le systeme n'a pas redemarre depuis $($daysSinceLastBoot.Days) jours. Planifier des redemarrages reguliers pour appliquer les mises a jour." `
                -Link "https://learn.microsoft.com/windows/deployment/update/waas-restart"
        } else {
            Add-AuditRecommendation -Category "SystemInfo" -Check "Redemarrage systeme" -Status "OK" -Severity "Low" `
                -Recommendation "Redemarrage recent du systeme. Maintenir des redemarrages reguliers." `
                -Link "https://learn.microsoft.com/windows/deployment/update/waas-restart"
        }
        
        return $true
    }
    catch {
        $script:auditResults.SystemInfo.Error = "Erreur lors de la collecte des informations systeme: $_"
        Write-Warning "Erreur lors de la collecte des informations systeme: $_"
        return $false
    }
}

#------------------------------------------------------------
# Module: Strategies de groupe (GPO)
#------------------------------------------------------------

function Get-GroupPolicyAudit {
    [CmdletBinding()]
    param()
    
    Write-Output "Audit des strategies de groupe..."
    
    try {
        # Exporter les resultats GPO en HTML
        $gpoReportPath = Join-Path -Path $script:reportPath -ChildPath "gpo-report.html"
        Start-Process -FilePath "gpresult.exe" -ArgumentList "/h `"$gpoReportPath`"" -NoNewWindow -Wait
        $script:auditResults.GroupPolicy.GPOReportFile = $gpoReportPath
        
        # Extraire la configuration locale de securite
        $secpolPath = Join-Path -Path $script:reportPath -ChildPath "secpol.cfg"
        Start-Process -FilePath "secedit.exe" -ArgumentList "/export /cfg `"$secpolPath`"" -NoNewWindow -Wait
        $script:auditResults.GroupPolicy.SecurityPolicyFile = $secpolPath
        
        # Obtenir toutes les GPO si nous sommes sur un controleur de domaine ou avec les outils RSAT installes
        try {
            $allGPOs = Get-GPO -All -ErrorAction Stop
            $script:auditResults.GroupPolicy.AllGPOs = $allGPOs | Select-Object DisplayName, ID, CreationTime, ModificationTime
        }
        catch {
            $script:auditResults.GroupPolicy.AllGPOsInfo = "Non disponible - probablement pas un controleur de domaine ou RSAT non installe"
        }
        
        # --- Recommandations (Strategies de groupe) ---
        Add-AuditRecommendation -Category "GroupPolicy" -Check "Configuration GPO" -Status "OK" -Severity "Low" `
            -Recommendation "Les strategies de groupe ont ete exportees pour analyse. Verifier les configurations de securite dans secpol.cfg et le rapport HTML." `
            -Link "https://learn.microsoft.com/windows/security/threat-protection/security-policy-settings/"

        if ($script:auditResults.GroupPolicy.AllGPOsInfo -like "*Non disponible*") {
            Add-AuditRecommendation -Category "GroupPolicy" -Check "Outils de gestion GPO" -Status "WARN" -Severity "Medium" `
                -Recommendation "Les outils RSAT ne sont pas installes ou il ne s'agit pas d'un controleur de domaine. Installer les outils pour une gestion complete." `
                -Link "https://learn.microsoft.com/windows-server/remote/remote-server-administration-tools"
        } else {
            Add-AuditRecommendation -Category "GroupPolicy" -Check "Outils de gestion GPO" -Status "OK" -Severity "Low" `
                -Recommendation "Les outils de gestion GPO sont disponibles. Surveiller les modifications et la coherence des strategies." `
                -Link "https://learn.microsoft.com/windows-server/identity/ad-ds/manage/group-policy/"
        }
        
        return $true
    }
    catch {
        $script:auditResults.GroupPolicy.Error = "Erreur lors de l'audit des strategies de groupe: $_"
        Write-Warning "Erreur lors de l'audit des strategies de groupe: $_"
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
        
        # Compter les utilisateurs locaux par etat
        $script:auditResults.UsersAndGroups.EnabledUserCount = ($localUsers | Where-Object { $_.Enabled -eq $true }).Count
        $script:auditResults.UsersAndGroups.DisabledUserCount = ($localUsers | Where-Object { $_.Enabled -eq $false }).Count
        
        # Obtenir les groupes locaux
        $localGroups = Get-LocalGroup | Select-Object Name, SID, Description
        $script:auditResults.UsersAndGroups.LocalGroups = $localGroups
        
        # Membres du groupe Administrateurs
        try {
            # Essayer d'abord avec le nom francais
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
        
        # Verifier les comptes avec des droits speciaux
        $specialRights = @{
            "SeBackupPrivilege" = "Droit de sauvegarde"
            "SeDebugPrivilege" = "Droit de deboguer des programmes"
            "SeTakeOwnershipPrivilege" = "Droit de s'approprier des fichiers"
            "SeImpersonatePrivilege" = "Droit d'emprunter l'identite d'un client"
        }
        
        $specialRightsPath = Join-Path -Path $script:reportPath -ChildPath "user-rights.txt"
        Start-Process -FilePath "whoami.exe" -ArgumentList "/priv" -NoNewWindow -Wait -RedirectStandardOutput $specialRightsPath
        $script:auditResults.UsersAndGroups.UserRightsFile = $specialRightsPath
        
        # --- Recommandations (Utilisateurs et groupes) ---
        $adminCount = ($script:auditResults.UsersAndGroups.AdministratorGroupMembers | Measure-Object).Count
        if ($adminCount -gt 2) {
            Add-AuditRecommendation -Category "UsersAndGroups" -Check "Membres administrateurs" -Status "WARN" -Severity "High" `
                -Recommendation "Trop d'utilisateurs ont des privileges administrateur ($adminCount membres). Limiter aux comptes strictement necessaires." `
                -Link "https://learn.microsoft.com/windows/security/identity-protection/access-control/local-accounts"
        } else {
            Add-AuditRecommendation -Category "UsersAndGroups" -Check "Membres administrateurs" -Status "OK" -Severity "Low" `
                -Recommendation "Nombre approprie d'administrateurs ($adminCount membres). Continuer a surveiller les modifications." `
                -Link "https://learn.microsoft.com/windows/security/identity-protection/access-control/local-accounts"
        }

        $disabledRatio = if ($script:auditResults.UsersAndGroups.EnabledUserCount -gt 0) { 
            $script:auditResults.UsersAndGroups.DisabledUserCount / ($script:auditResults.UsersAndGroups.EnabledUserCount + $script:auditResults.UsersAndGroups.DisabledUserCount) 
        } else { 0 }
        
        if ($disabledRatio -gt 0.3) {
            Add-AuditRecommendation -Category "UsersAndGroups" -Check "Comptes desactives" -Status "WARN" -Severity "Medium" `
                -Recommendation "Trop de comptes desactives ($($script:auditResults.UsersAndGroups.DisabledUserCount)). Nettoyer les comptes inutiles." `
                -Link "https://learn.microsoft.com/windows/security/identity-protection/access-control/local-accounts"
        } else {
            Add-AuditRecommendation -Category "UsersAndGroups" -Check "Comptes desactives" -Status "OK" -Severity "Low" `
                -Recommendation "Ratio acceptable de comptes desactives. Continuer le nettoyage regulier." `
                -Link "https://learn.microsoft.com/windows/security/identity-protection/access-control/local-accounts"
        }
        
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
    
    Write-Output "Audit des mecanismes d'authentification..."
    
    try {
        # Verification LAPS
        $lapsInstalled = Test-Path -Path "C:\Program Files\LAPS\CSE"
        $lapsRegistry = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*" -ErrorAction SilentlyContinue | 
                       Where-Object { $_.DisplayName -like "*Local Administrator Password Solution*" }
        
        $script:auditResults.Authentication.LAPS = @{
            Installed = ($lapsInstalled -or ($lapsRegistry -ne $null))
            Installation_Path = if ($lapsInstalled) { "C:\Program Files\LAPS\CSE" } else { "Non trouve" }
            Version = if ($lapsRegistry) { $lapsRegistry.DisplayVersion } else { "Non installe" }
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
            Value = if ($lsassProtection) { $lsassProtection.RunAsPPL } else { "Non configure" }
        }
        
        # WDigest
        $wdigest = Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\SecurityProviders\WDigest" -Name "UseLogonCredential" -ErrorAction SilentlyContinue
        
        $script:auditResults.Authentication.WDigest = @{
            Disabled = if ($wdigest -and $wdigest.UseLogonCredential -eq 0) { $true } else { $false }
            Value = if ($wdigest) { $wdigest.UseLogonCredential } else { "Non configure" }
        }
        
        # Credential Guard
        $credentialGuard = Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard -ErrorAction SilentlyContinue
        
        $script:auditResults.Authentication.CredentialGuard = @{
            Available = if ($credentialGuard -and $credentialGuard.SecurityServicesConfigured -contains 1) { $true } else { $false }
            Running = if ($credentialGuard -and $credentialGuard.SecurityServicesRunning -contains 1) { $true } else { $false }
        }
        
        # --- Recommandations (Authentification) ---
        if ($script:auditResults.Authentication.LAPS -and -not $script:auditResults.Authentication.LAPS.Installed) {
            Add-AuditRecommendation -Category "Authentication" -Check "LAPS" -Status "FAIL" -Severity "High" `
                -Recommendation "Deployer Windows LAPS pour gerer et faire tourner automatiquement les mots de passe des comptes administrateur locaux." `
                -Link "https://learn.microsoft.com/windows-server/identity/laps/laps-overview" `
                -Rationale "Reduit fortement le risque de reutilisation/vol de mots de passe admin local (mouvements lateraux)."
        } elseif ($script:auditResults.Authentication.LAPS -and $script:auditResults.Authentication.LAPS.Installed) {
            Add-AuditRecommendation -Category "Authentication" -Check "LAPS" -Status "OK" -Severity "Low" `
                -Recommendation "Windows LAPS est present. Verifier la rotation, l'archivage (AD/Entra ID) et le controle d'acces aux mots de passe." `
                -Link "https://learn.microsoft.com/windows-server/identity/laps/laps-scenarios-windows-server-active-directory"
        }

        if ($script:auditResults.Authentication.UAC -and -not $script:auditResults.Authentication.UAC.Enabled) {
            Add-AuditRecommendation -Category "Authentication" -Check "UAC" -Status "FAIL" -Severity "High" `
                -Recommendation "Activer l'UAC (Admin Approval Mode) et conserver le Secure Desktop pour les invites." `
                -Link "https://learn.microsoft.com/windows/security/application-security/application-control/user-account-control/" `
                -Rationale "Limite l'execution automatique en contexte administrateur."
        } elseif ($script:auditResults.Authentication.UAC -and $script:auditResults.Authentication.UAC.Enabled) {
            Add-AuditRecommendation -Category "Authentication" -Check "UAC" -Status "OK" -Severity "Low" `
                -Recommendation "UAC est active. Verifier les parametres de securite (Secure Desktop, niveau d'invite)." `
                -Link "https://learn.microsoft.com/windows/security/application-security/application-control/user-account-control/"
        }

        if ($script:auditResults.Authentication.LSASSProtection -and -not $script:auditResults.Authentication.LSASSProtection.Enabled) {
            Add-AuditRecommendation -Category "Authentication" -Check "LSASS protection (RunAsPPL)" -Status "WARN" -Severity "High" `
                -Recommendation "Activer la protection renforcee de LSASS (RunAsPPL) pour reduire l'injection et le vol d'identifiants en memoire." `
                -Link "https://learn.microsoft.com/windows-server/security/credentials-protection-and-management/configuring-additional-lsa-protection"
        } elseif ($script:auditResults.Authentication.LSASSProtection -and $script:auditResults.Authentication.LSASSProtection.Enabled) {
            Add-AuditRecommendation -Category "Authentication" -Check "LSASS protection (RunAsPPL)" -Status "OK" -Severity "Low" `
                -Recommendation "Protection LSASS activee. Surveiller les tentatives de contournement dans les journaux." `
                -Link "https://learn.microsoft.com/windows-server/security/credentials-protection-and-management/configuring-additional-lsa-protection"
        }

        if ($script:auditResults.Authentication.WDigest -and -not $script:auditResults.Authentication.WDigest.Disabled) {
            Add-AuditRecommendation -Category "Authentication" -Check "WDigest" -Status "FAIL" -Severity "Critical" `
                -Recommendation "Desactiver le stockage de mots de passe en clair via WDigest (UseLogonCredential=0) et s'assurer que les correctifs adequats sont appliques." `
                -Link "https://support.microsoft.com/topic/microsoft-security-advisory-update-to-improve-credentials-protection-and-management-may-13-2014-93434251-04ac-b7f3-52aa-9f951c14b649"
        } elseif ($script:auditResults.Authentication.WDigest -and $script:auditResults.Authentication.WDigest.Disabled) {
            Add-AuditRecommendation -Category "Authentication" -Check "WDigest" -Status "OK" -Severity "Low" `
                -Recommendation "WDigest est desactive. Maintenir cette configuration pour eviter le stockage en clair des mots de passe." `
                -Link "https://support.microsoft.com/topic/microsoft-security-advisory-update-to-improve-credentials-protection-and-management-may-13-2014-93434251-04ac-b7f3-52aa-9f951c14b649"
        }

        if ($script:auditResults.Authentication.CredentialGuard) {
            if (-not $script:auditResults.Authentication.CredentialGuard.Running) {
                Add-AuditRecommendation -Category "Authentication" -Check "Credential Guard" -Status "WARN" -Severity "High" `
                    -Recommendation "Activer Microsoft Defender Credential Guard (VBS) lorsque compatible, notamment sur les VMs supportees." `
                    -Link "https://learn.microsoft.com/windows/security/identity-protection/credential-guard/configure"
            } else {
                Add-AuditRecommendation -Category "Authentication" -Check "Credential Guard" -Status "OK" -Severity "Low" `
                    -Recommendation "Credential Guard est actif. Verifier les prerequis VBS/Secure Boot selon votre hyperviseur." `
                    -Link "https://learn.microsoft.com/windows/security/identity-protection/credential-guard/"
            }
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
        # Liste des services en cours d'execution
        $runningServices = Get-Service | Where-Object { $_.Status -eq "Running" } | 
                           Select-Object Name, DisplayName, StartType, Status
        $script:auditResults.ServicesAndProcesses.RunningServices = $runningServices
        
        # Services automatiques mais non demarres
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
                SecurityLayer = if ($rdpConfig) { $rdpConfig.SecurityLayer } else { "Non configure" }
            }
        }
        catch {
            $script:auditResults.ServicesAndProcesses.RDP = "Impossible de determiner la configuration RDP"
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
        
        # Liste des demarrages automatiques
        $startupApps = Get-CimInstance -ClassName Win32_StartupCommand | 
                      Select-Object Name, Command, Location, User
        $script:auditResults.ServicesAndProcesses.StartupItems = $startupApps
        
        # Services tiers vs. Microsoft
        $nonMsServices = Get-WmiObject -Class Win32_Service | 
                        Where-Object { $_.PathName -notlike "*system32*" -and $_.PathName -notlike "*Program Files*\Windows *" } | 
                        Select-Object Name, DisplayName, StartMode, State, PathName
        $script:auditResults.ServicesAndProcesses.ThirdPartyServices = $nonMsServices
        
        # --- Recommandations (Services et Processus) ---
        if ($script:auditResults.ServicesAndProcesses.RDP -and $script:auditResults.ServicesAndProcesses.RDP.Enabled) {
            if ($script:auditResults.ServicesAndProcesses.RDP.NLARequired) {
                Add-AuditRecommendation -Category "ServicesAndProcesses" -Check "Configuration RDP" -Status "OK" -Severity "Medium" `
                    -Recommendation "RDP est active avec NLA (Network Level Authentication). Verifier les utilisateurs autorises et considerer l'utilisation d'un VPN." `
                    -Link "https://learn.microsoft.com/windows/security/operating-system-security/network-security/windows-firewall/best-practices-configuring"
            } else {
                Add-AuditRecommendation -Category "ServicesAndProcesses" -Check "Configuration RDP" -Status "WARN" -Severity "High" `
                    -Recommendation "RDP est active mais NLA n'est pas requis. Activer NLA et limiter l'acces aux utilisateurs autorises." `
                    -Link "https://learn.microsoft.com/windows-server/remote/remote-desktop-services/clients/remote-desktop-allow-access"
            }
        } elseif ($script:auditResults.ServicesAndProcesses.RDP -and -not $script:auditResults.ServicesAndProcesses.RDP.Enabled) {
            Add-AuditRecommendation -Category "ServicesAndProcesses" -Check "Configuration RDP" -Status "OK" -Severity "Low" `
                -Recommendation "RDP est desactive. Si l'acces distant est necessaire, utiliser des solutions plus securisees comme SSH ou VPN." `
                -Link "https://learn.microsoft.com/windows/security/operating-system-security/network-security/windows-firewall/best-practices-configuring"
        }

        if ($script:auditResults.ServicesAndProcesses.WinRM -and $script:auditResults.ServicesAndProcesses.WinRM.Enabled) {
            Add-AuditRecommendation -Category "ServicesAndProcesses" -Check "WinRM" -Status "WARN" -Severity "Medium" `
                -Recommendation "WinRM est active. Verifier la configuration HTTPS, l'authentification et limiter les connexions aux hotes autorises." `
                -Link "https://learn.microsoft.com/powershell/module/microsoft.powershell.core/about/about_remote_requirements"
        } else {
            Add-AuditRecommendation -Category "ServicesAndProcesses" -Check "WinRM" -Status "OK" -Severity "Low" `
                -Recommendation "WinRM est desactive. Si PowerShell Remoting est necessaire, configurer HTTPS et authentification forte." `
                -Link "https://learn.microsoft.com/powershell/module/microsoft.powershell.core/about/about_remote_requirements"
        }

        if ($script:auditResults.ServicesAndProcesses.StoppedAutoServices -and $script:auditResults.ServicesAndProcesses.StoppedAutoServices.Count -gt 5) {
            Add-AuditRecommendation -Category "ServicesAndProcesses" -Check "Services automatiques arretes" -Status "WARN" -Severity "Medium" `
                -Recommendation "Plusieurs services configures en demarrage automatique sont arretes. Verifier si cela est intentionnel." `
                -Link "https://learn.microsoft.com/troubleshoot/windows-server/performance/optimize-windows-server-performance"
        } else {
            Add-AuditRecommendation -Category "ServicesAndProcesses" -Check "Services automatiques arretes" -Status "OK" -Severity "Low" `
                -Recommendation "Nombre acceptable de services automatiques arretes. Continuer a surveiller regulierement." `
                -Link "https://learn.microsoft.com/troubleshoot/windows-server/performance/optimize-windows-server-performance"
        }
        
        return $true
    }
    catch {
        $script:auditResults.ServicesAndProcesses.Error = "Erreur lors de l'audit des services et processus: $_"
        Write-Warning "Erreur lors de l'audit des services et processus: $_"
        return $false
    }
}

#------------------------------------------------------------
# Module: Reseau
#------------------------------------------------------------

function Get-NetworkAudit {
    [CmdletBinding()]
    param()
    
    Write-Output "Audit de la configuration reseau..."
    
    try {
        # Configuration IP
        $netIPConfig = Get-NetIPConfiguration | Select-Object InterfaceAlias, InterfaceDescription, IPv4Address, IPv6Address, DNSServer
        $script:auditResults.Network.IPConfiguration = $netIPConfig
        
        # Details complets de la configuration IP
        $ipConfigPath = Join-Path -Path $script:reportPath -ChildPath "ipconfig.txt"
        ipconfig /all | Out-File -FilePath $ipConfigPath -Force
        $script:auditResults.Network.IPConfigDetailFile = $ipConfigPath
        
        # Configuration pare-feu
        $firewallProfiles = Get-NetFirewallProfile | Select-Object Name, Enabled, DefaultInboundAction, DefaultOutboundAction, LogAllowed, LogBlocked, LogIgnored
        $script:auditResults.Network.FirewallProfiles = $firewallProfiles
        
        # Regles de pare-feu entrantes autorisant le trafic
        $inboundRules = Get-NetFirewallRule -Direction Inbound -Enabled True -Action Allow | 
                       Select-Object DisplayName, Enabled, Direction, Action, Profile | 
                       Sort-Object -Property DisplayName
        $script:auditResults.Network.InboundAllowRules = $inboundRules
        
        # Sauvegarde des regles de pare-feu completes
        $firewallRulesPath = Join-Path -Path $script:reportPath -ChildPath "firewall-rules.txt"
        netsh advfirewall firewall show rule name=all | Out-File -FilePath $firewallRulesPath -Force
        $script:auditResults.Network.FirewallRulesFile = $firewallRulesPath
        
        # Connexions actives
        $netStatPath = Join-Path -Path $script:reportPath -ChildPath "netstat.txt"
        netstat -ano | Out-File -FilePath $netStatPath -Force
        $script:auditResults.Network.ActiveConnectionsFile = $netStatPath
        
        # État des ports en ecoute
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
            $script:auditResults.Network.SMBv1 = "Impossible de determiner l'etat de SMBv1"
        }
        
        # Partages SMB
        $smbShares = Get-SmbShare -ErrorAction SilentlyContinue | Select-Object Name, Path, Description
        $script:auditResults.Network.SMBShares = $smbShares
        
        # Acces aux partages SMB
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
        
        # --- Recommandations (Reseau) ---
        if ($script:auditResults.Network.SMBv1 -and $script:auditResults.Network.SMBv1.Enabled) {
            Add-AuditRecommendation -Category "Network" -Check "SMBv1" -Status "FAIL" -Severity "Critical" `
                -Recommendation "SMBv1 est active. Desactiver immediatement SMBv1 car il presente des vulnerabilites critiques (WannaCry, EternalBlue)." `
                -Link "https://learn.microsoft.com/windows-server/storage/file-server/troubleshoot/detect-enable-and-disable-smbv1-v2-v3"
        } else {
            Add-AuditRecommendation -Category "Network" -Check "SMBv1" -Status "OK" -Severity "Low" `
                -Recommendation "SMBv1 est desactive. Maintenir cette configuration et utiliser SMBv3 uniquement." `
                -Link "https://learn.microsoft.com/windows-server/storage/file-server/troubleshoot/detect-enable-and-disable-smbv1-v2-v3"
        }

        $publicProfileEnabled = $script:auditResults.Network.FirewallProfiles | Where-Object { $_.Name -eq "Public" -and $_.Enabled -eq $true }
        if ($publicProfileEnabled) {
            Add-AuditRecommendation -Category "Network" -Check "Pare-feu Public" -Status "OK" -Severity "Medium" `
                -Recommendation "Le pare-feu est active pour le profil Public. Verifier les regles autorisees et minimiser les exceptions." `
                -Link "https://learn.microsoft.com/windows/security/operating-system-security/network-security/windows-firewall/best-practices-configuring"
        } else {
            Add-AuditRecommendation -Category "Network" -Check "Pare-feu Public" -Status "FAIL" -Severity "High" `
                -Recommendation "Le pare-feu n'est pas active pour le profil Public. Activer immediatement le pare-feu Windows." `
                -Link "https://learn.microsoft.com/windows/security/operating-system-security/network-security/windows-firewall/best-practices-configuring"
        }

        $suspiciousPorts = $script:auditResults.Network.ListeningPorts | Where-Object { $_.LocalPort -in @(23, 135, 139, 445, 1433, 3389) }
        if ($suspiciousPorts -and $suspiciousPorts.Count -gt 2) {
            Add-AuditRecommendation -Category "Network" -Check "Ports sensibles" -Status "WARN" -Severity "High" `
                -Recommendation "Plusieurs ports sensibles sont ouverts (Telnet, RPC, NetBIOS, SMB, SQL, RDP). Fermer les ports inutiles." `
                -Link "https://learn.microsoft.com/windows-server/networking/technologies/netsh/netsh-contexts"
        } else {
            Add-AuditRecommendation -Category "Network" -Check "Ports sensibles" -Status "OK" -Severity "Low" `
                -Recommendation "Nombre acceptable de ports sensibles ouverts. Continuer a surveiller regulierement." `
                -Link "https://learn.microsoft.com/windows-server/networking/technologies/netsh/netsh-contexts"
        }
        
        return $true
    }
    catch {
        $script:auditResults.Network.Error = "Erreur lors de l'audit reseau: $_"
        Write-Warning "Erreur lors de l'audit reseau: $_"
        return $false
    }
}

#------------------------------------------------------------
# Module: Logiciels et securite
#------------------------------------------------------------

function Get-SoftwareAndSecurityAudit {
    [CmdletBinding()]
    param()
    
    Write-Output "Audit des logiciels et de la securite..."
    
    try {
        # Applications installees (limitees aux 50 plus recentes pour eviter un rapport trop volumineux)
        $installedApps = Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* | 
                        Where-Object { $_.DisplayName } |
                        Select-Object DisplayName, DisplayVersion, Publisher, InstallDate |
                        Sort-Object -Property InstallDate -Descending | 
                        Select-Object -First 50
        $script:auditResults.SoftwareAndSecurity.RecentInstalledApps = $installedApps
        
        # Nombre total d'applications installees
        $totalAppsCount = (Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* | 
                          Where-Object { $_.DisplayName }).Count
        $script:auditResults.SoftwareAndSecurity.TotalInstalledAppsCount = $totalAppsCount
        
        # Mises a jour Windows
        try {
            $windowsUpdateServer = Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate" -Name "WUServer" -ErrorAction SilentlyContinue
            $auSettings = Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\AU" -ErrorAction SilentlyContinue
            
            $script:auditResults.SoftwareAndSecurity.WindowsUpdate = @{
                Server = if ($windowsUpdateServer) { $windowsUpdateServer.WUServer } else { "Non configure" }
                AutoUpdateSettings = if ($auSettings) { $auSettings | Select-Object AUOptions, ScheduledInstallDay, ScheduledInstallTime } else { "Non configure" }
            }
            
            # Liste des mises a jour installees (limitees aux 50 plus recentes)
            $hotfixes = Get-HotFix | Sort-Object -Property InstalledOn -Descending | Select-Object -First 50 HotFixID, Description, InstalledOn
            $script:auditResults.SoftwareAndSecurity.RecentHotfixes = $hotfixes
        }
        catch {
            $script:auditResults.SoftwareAndSecurity.WindowsUpdateError = "Erreur lors de la verification des mises a jour Windows: $_"
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
            $script:auditResults.SoftwareAndSecurity.AppLocker = "Impossible de determiner la configuration AppLocker"
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
            $script:auditResults.SoftwareAndSecurity.WindowsDefender = "Impossible de determiner l'etat de Windows Defender"
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
            $script:auditResults.SoftwareAndSecurity.DeviceGuard = "Impossible de determiner l'etat de Device Guard"
        }
        
        # Exploit Guard - Protection des dossiers controles
        try {
            $mpPreference = Get-MpPreference -ErrorAction SilentlyContinue
            
            $script:auditResults.SoftwareAndSecurity.ExploitGuard = @{
                ControlledFolderAccess = if ($mpPreference -and $mpPreference.EnableControlledFolderAccess -eq 1) { $true } else { $false }
                NetworkProtection = if ($mpPreference -and $mpPreference.EnableNetworkProtection -eq 1) { $true } else { $false }
                ExploitProtection = if ($mpPreference -and $mpPreference.EnableExploitProtection -eq 1) { $true } else { $false }
            }
        }
        catch {
            $script:auditResults.SoftwareAndSecurity.ExploitGuard = "Impossible de determiner la configuration d'Exploit Guard"
        }
        
        # Mode de langage PowerShell
        $script:auditResults.SoftwareAndSecurity.PowerShellLanguageMode = $ExecutionContext.SessionState.LanguageMode
        
        # Strategie d'execution PowerShell
        $policyPath = Join-Path -Path $script:reportPath -ChildPath "ps-executionpolicy.txt"
        Get-ExecutionPolicy -List | Out-File -FilePath $policyPath -Force
        $script:auditResults.SoftwareAndSecurity.PowerShellExecutionPolicy = Get-ExecutionPolicy
        $script:auditResults.SoftwareAndSecurity.PowerShellExecutionPolicyFile = $policyPath
        
        # --- Recommandations (Logiciels et Securite) ---
        if ($script:auditResults.SoftwareAndSecurity.WindowsDefender -and -not $script:auditResults.SoftwareAndSecurity.WindowsDefender.Enabled) {
            Add-AuditRecommendation -Category "SoftwareAndSecurity" -Check "Windows Defender" -Status "FAIL" -Severity "Critical" `
                -Recommendation "Windows Defender n'est pas active. Activer la protection antivirus ou installer une solution tierce." `
                -Link "https://learn.microsoft.com/windows/security/operating-system-security/system-security/windows-defender-antivirus/"
        } elseif ($script:auditResults.SoftwareAndSecurity.WindowsDefender -and $script:auditResults.SoftwareAndSecurity.WindowsDefender.Enabled) {
            Add-AuditRecommendation -Category "SoftwareAndSecurity" -Check "Windows Defender" -Status "OK" -Severity "Low" `
                -Recommendation "Windows Defender est active. Verifier la frequence de mise a jour des signatures et la protection temps reel." `
                -Link "https://learn.microsoft.com/windows/security/operating-system-security/system-security/windows-defender-antivirus/"
        }

        if ($script:auditResults.SoftwareAndSecurity.ExploitGuard -and -not $script:auditResults.SoftwareAndSecurity.ExploitGuard.ControlledFolderAccess) {
            Add-AuditRecommendation -Category "SoftwareAndSecurity" -Check "Exploit Guard - Controle d'acces aux dossiers" -Status "WARN" -Severity "High" `
                -Recommendation "L'acces controle aux dossiers n'est pas active. Activer cette protection contre les ransomwares." `
                -Link "https://learn.microsoft.com/windows/security/operating-system-security/system-security/windows-defender-exploit-guard/controlled-folders"
        } else {
            Add-AuditRecommendation -Category "SoftwareAndSecurity" -Check "Exploit Guard - Controle d'acces aux dossiers" -Status "OK" -Severity "Low" `
                -Recommendation "L'acces controle aux dossiers est active. Surveiller les alertes et ajuster les exceptions si necessaire." `
                -Link "https://learn.microsoft.com/windows/security/operating-system-security/system-security/windows-defender-exploit-guard/controlled-folders"
        }

        if ($script:auditResults.SoftwareAndSecurity.PowerShellLanguageMode -ne "ConstrainedLanguage") {
            Add-AuditRecommendation -Category "SoftwareAndSecurity" -Check "PowerShell Language Mode" -Status "WARN" -Severity "Medium" `
                -Recommendation "PowerShell fonctionne en mode FullLanguage. Considerer le mode ConstrainedLanguage avec AppLocker/Device Guard." `
                -Link "https://learn.microsoft.com/powershell/module/microsoft.powershell.core/about/about_language_modes"
        } else {
            Add-AuditRecommendation -Category "SoftwareAndSecurity" -Check "PowerShell Language Mode" -Status "OK" -Severity "Low" `
                -Recommendation "PowerShell fonctionne en mode ConstrainedLanguage. Maintenir cette configuration securisee." `
                -Link "https://learn.microsoft.com/powershell/module/microsoft.powershell.core/about/about_language_modes"
        }

        if ($script:auditResults.SoftwareAndSecurity.PowerShellExecutionPolicy -eq "Unrestricted" -or $script:auditResults.SoftwareAndSecurity.PowerShellExecutionPolicy -eq "Bypass") {
            Add-AuditRecommendation -Category "SoftwareAndSecurity" -Check "PowerShell Execution Policy" -Status "FAIL" -Severity "High" `
                -Recommendation "La politique d'execution PowerShell est trop permissive (Unrestricted/Bypass). Utiliser RemoteSigned ou AllSigned." `
                -Link "https://learn.microsoft.com/powershell/module/microsoft.powershell.core/about/about_execution_policies"
        } else {
            Add-AuditRecommendation -Category "SoftwareAndSecurity" -Check "PowerShell Execution Policy" -Status "OK" -Severity "Low" `
                -Recommendation "La politique d'execution PowerShell est appropriee. Maintenir cette configuration." `
                -Link "https://learn.microsoft.com/powershell/module/microsoft.powershell.core/about/about_execution_policies"
        }
        
        return $true
    }
    catch {
        $script:auditResults.SoftwareAndSecurity.Error = "Erreur lors de l'audit des logiciels et de la securite: $_"
        Write-Warning "Erreur lors de l'audit des logiciels et de la securite: $_"
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
        
        # Verification des ACL NTFS sur les dossiers systeme critiques
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
        
        # Export des ACL detaillees pour C:\Windows
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
                Value = if ($autoRunSetting) { $autoRunSetting.NoDriveTypeAutoRun } else { "Non configure" }
            }
        }
        catch {
            $script:auditResults.Storage.AutoRun = "Impossible de determiner la configuration AutoRun"
        }
        
        # BitLocker
        try {
            $bitlockerVolumes = Get-BitLockerVolume -ErrorAction SilentlyContinue
            $script:auditResults.Storage.BitLocker = @{
                Volumes = $bitlockerVolumes | Select-Object MountPoint, VolumeStatus, EncryptionMethod, ProtectionStatus
            }
            
            # Export des details BitLocker
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
        
        # --- Recommandations (Stockage) ---
        $unencryptedVolumes = @()
        if ($script:auditResults.Storage.BitLocker -and $script:auditResults.Storage.BitLocker.Volumes) {
            $unencryptedVolumes = $script:auditResults.Storage.BitLocker.Volumes | Where-Object { 
                $_.VolumeStatus -ne "FullyEncrypted" -and $_.MountPoint -like "*:" 
            }
        }
        
        if ($unencryptedVolumes.Count -gt 0) {
            Add-AuditRecommendation -Category "Storage" -Check "BitLocker" -Status "FAIL" -Severity "High" `
                -Recommendation "Des volumes ne sont pas chiffres avec BitLocker. Activer le chiffrement sur tous les volumes sensibles." `
                -Link "https://learn.microsoft.com/windows/security/operating-system-security/data-protection/bitlocker/"
        } else {
            Add-AuditRecommendation -Category "Storage" -Check "BitLocker" -Status "OK" -Severity "Low" `
                -Recommendation "BitLocker est configure sur les volumes principaux. Verifier la sauvegarde des cles de recuperation." `
                -Link "https://learn.microsoft.com/windows/security/operating-system-security/data-protection/bitlocker/"
        }

        $folderWithEveryoneFullControl = $script:auditResults.Storage.CriticalFolderACLs | Where-Object { $_.FullControlForEveryone -eq $true }
        if ($folderWithEveryoneFullControl) {
            Add-AuditRecommendation -Category "Storage" -Check "ACL dossiers critiques" -Status "FAIL" -Severity "Critical" `
                -Recommendation "Des dossiers critiques donnent un controle total au groupe 'Everyone'. Restreindre immediatement les permissions." `
                -Link "https://learn.microsoft.com/windows/security/operating-system-security/data-protection/configuring-file-system-permissions"
        } else {
            Add-AuditRecommendation -Category "Storage" -Check "ACL dossiers critiques" -Status "OK" -Severity "Low" `
                -Recommendation "Les permissions sur les dossiers critiques semblent appropriees. Continuer a surveiller." `
                -Link "https://learn.microsoft.com/windows/security/operating-system-security/data-protection/configuring-file-system-permissions"
        }

        if ($script:auditResults.Storage.AutoRun -and -not $script:auditResults.Storage.AutoRun.DisabledForAll) {
            Add-AuditRecommendation -Category "Storage" -Check "AutoRun" -Status "WARN" -Severity "Medium" `
                -Recommendation "L'execution automatique n'est pas completement desactivee. Desactiver AutoRun pour tous les types de lecteurs." `
                -Link "https://support.microsoft.com/topic/how-to-disable-the-autorun-functionality-in-windows-6f7b0c43-3e56-d2b3-4c3d-c44fe38c8c2e"
        } else {
            Add-AuditRecommendation -Category "Storage" -Check "AutoRun" -Status "OK" -Severity "Low" `
                -Recommendation "AutoRun est desactive pour tous les types de lecteurs. Maintenir cette configuration." `
                -Link "https://support.microsoft.com/topic/how-to-disable-the-autorun-functionality-in-windows-6f7b0c43-3e56-d2b3-4c3d-c44fe38c8c2e"
        }
        
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
    
    Write-Output "Audit de la journalisation et des evenements..."
    
    try {
        # Politique d'audit
        $auditPolicyPath = Join-Path -Path $script:reportPath -ChildPath "audit-policy.txt"
        auditpol.exe /get /category:* | Out-File -FilePath $auditPolicyPath -Force
        $script:auditResults.LoggingAndAudit.AuditPolicyFile = $auditPolicyPath
        
        # Configuration des journaux d'evenements Windows
        $eventLogs = Get-WinEvent -ListLog "Application", "System", "Security" -ErrorAction SilentlyContinue | 
                    Select-Object LogName, LogMode, MaximumSizeInBytes, IsEnabled, RecordCount
        $script:auditResults.LoggingAndAudit.EventLogs = $eventLogs
        
        # Verification de la redirection des journaux
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
                    $script:auditResults.LoggingAndAudit.RecentForwardingEvents = "Aucun evenement recent trouve ou erreur lors de la recuperation"
                }
            }
        }
        catch {
            $script:auditResults.LoggingAndAudit.EventForwarding = "Impossible de determiner la configuration de redirection des journaux"
        }
        
        # Verification de Sysmon
        $sysmonService = Get-Service -Name Sysmon -ErrorAction SilentlyContinue
        
        $script:auditResults.LoggingAndAudit.Sysmon = @{
            Installed = if ($sysmonService) { $true } else { $false }
            Status = if ($sysmonService) { $sysmonService.Status } else { "Non installe" }
            StartType = if ($sysmonService) { $sysmonService.StartType } else { "N/A" }
        }
        
        if ($sysmonService) {
            try {
                $sysmonEvents = Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -MaxEvents 5 -ErrorAction SilentlyContinue |
                              Select-Object TimeCreated, Id, Message
                $script:auditResults.LoggingAndAudit.RecentSysmonEvents = $sysmonEvents
            }
            catch {
                $script:auditResults.LoggingAndAudit.SysmonEventsError = "Impossible d'obtenir les evenements Sysmon: $_"
            }
        }
        
        # Script Block Logging
        try {
            $psLoggingPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"
            $scriptBlockLogging = Get-ItemProperty -Path $psLoggingPath -Name "EnableScriptBlockLogging" -ErrorAction SilentlyContinue
            
            $script:auditResults.LoggingAndAudit.PowerShellScriptBlockLogging = @{
                Enabled = if ($scriptBlockLogging -and $scriptBlockLogging.EnableScriptBlockLogging -eq 1) { $true } else { $false }
                Value = if ($scriptBlockLogging) { $scriptBlockLogging.EnableScriptBlockLogging } else { "Non configure" }
            }
        }
        catch {
            $script:auditResults.LoggingAndAudit.PowerShellScriptBlockLogging = "Impossible de determiner la configuration de Script Block Logging"
        }
        
        # Transcription PowerShell
        try {
            $psTranscriptionPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription"
            $transcription = Get-ItemProperty -Path $psTranscriptionPath -ErrorAction SilentlyContinue
            
            $script:auditResults.LoggingAndAudit.PowerShellTranscription = @{
                Enabled = if ($transcription -and $transcription.EnableTranscripting -eq 1) { $true } else { $false }
                OutputDirectory = if ($transcription -and $transcription.OutputDirectory) { $transcription.OutputDirectory } else { "Non configure" }
                EnableInvocationHeader = if ($transcription -and $transcription.EnableInvocationHeader -eq 1) { $true } else { $false }
            }
        }
        catch {
            $script:auditResults.LoggingAndAudit.PowerShellTranscription = "Impossible de determiner la configuration de transcription PowerShell"
        }
        
        # --- Recommandations (Journalisation et audit) ---
        if ($script:auditResults.LoggingAndAudit.Sysmon -and -not $script:auditResults.LoggingAndAudit.Sysmon.Installed) {
            Add-AuditRecommendation -Category "LoggingAndAudit" -Check "Sysmon" -Status "WARN" -Severity "High" `
                -Recommendation "Sysmon n'est pas installe. Deployer Sysmon pour une journalisation avancee des evenements systeme." `
                -Link "https://learn.microsoft.com/sysinternals/downloads/sysmon"
        } else {
            Add-AuditRecommendation -Category "LoggingAndAudit" -Check "Sysmon" -Status "OK" -Severity "Low" `
                -Recommendation "Sysmon est installe. Verifier la configuration et la rotation des logs." `
                -Link "https://learn.microsoft.com/sysinternals/downloads/sysmon"
        }

        if ($script:auditResults.LoggingAndAudit.PowerShellScriptBlockLogging -and -not $script:auditResults.LoggingAndAudit.PowerShellScriptBlockLogging.Enabled) {
            Add-AuditRecommendation -Category "LoggingAndAudit" -Check "PowerShell Script Block Logging" -Status "WARN" -Severity "Medium" `
                -Recommendation "La journalisation des blocs de script PowerShell n'est pas activee. Activer pour detecter les activites malveillantes." `
                -Link "https://learn.microsoft.com/powershell/module/microsoft.powershell.core/about/about_logging"
        } else {
            Add-AuditRecommendation -Category "LoggingAndAudit" -Check "PowerShell Script Block Logging" -Status "OK" -Severity "Low" `
                -Recommendation "La journalisation PowerShell est activee. Surveiller les evenements dans les logs Windows." `
                -Link "https://learn.microsoft.com/powershell/module/microsoft.powershell.core/about/about_logging"
        }

        if ($script:auditResults.LoggingAndAudit.PowerShellTranscription -and -not $script:auditResults.LoggingAndAudit.PowerShellTranscription.Enabled) {
            Add-AuditRecommendation -Category "LoggingAndAudit" -Check "PowerShell Transcription" -Status "WARN" -Severity "Medium" `
                -Recommendation "La transcription PowerShell n'est pas activee. Activer pour enregistrer toutes les sessions PowerShell." `
                -Link "https://learn.microsoft.com/powershell/module/microsoft.powershell.core/about/about_logging"
        } else {
            Add-AuditRecommendation -Category "LoggingAndAudit" -Check "PowerShell Transcription" -Status "OK" -Severity "Low" `
                -Recommendation "La transcription PowerShell est activee. Verifier l'emplacement et la retention des fichiers." `
                -Link "https://learn.microsoft.com/powershell/module/microsoft.powershell.core/about/about_logging"
        }

        $securityLogMaxSize = ($script:auditResults.LoggingAndAudit.EventLogs | Where-Object { $_.LogName -eq "Security" }).MaximumSizeInBytes
        if ($securityLogMaxSize -lt 104857600) {  # 100 MB
            Add-AuditRecommendation -Category "LoggingAndAudit" -Check "Taille log Security" -Status "WARN" -Severity "Medium" `
                -Recommendation "Le journal Security est configure avec une taille maximale insuffisante. Augmenter a au moins 100 MB." `
                -Link "https://learn.microsoft.com/windows-server/identity/ad-ds/plan/security-best-practices/audit-policy-recommendations"
        } else {
            Add-AuditRecommendation -Category "LoggingAndAudit" -Check "Taille log Security" -Status "OK" -Severity "Low" `
                -Recommendation "Le journal Security a une taille appropriee. Surveiller la rotation et l'archivage." `
                -Link "https://learn.microsoft.com/windows-server/identity/ad-ds/plan/security-best-practices/audit-policy-recommendations"
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
# Module: Generation des rapports
#------------------------------------------------------------

# Note: La fonction Export-AuditResults est importee depuis Export-AuditResults.ps1

#------------------------------------------------------------
# Module: Calcul du score d'audit et recommandations
#------------------------------------------------------------

function Calculate-AuditScore {
    [CmdletBinding()]
    param()
    
    Write-Output "Calcul du score de conformite et generation du resume..."
    
    try {
        # Collecte de toutes les recommandations
        $allRecommendations = @()
        foreach ($category in $script:auditResults.Keys) {
            if ($script:auditResults[$category] -is [hashtable] -and $script:auditResults[$category].Recommendations) {
                $allRecommendations += $script:auditResults[$category].Recommendations
            }
        }
        
        # Calcul du score base principalement sur les vulnerabilites critiques
        $totalChecks = $allRecommendations.Count
        if ($totalChecks -gt 0) {
            # Comptage par statut et criticite
            $okCount = ($allRecommendations | Where-Object { $_.Status -eq "OK" }).Count
            $warnCount = ($allRecommendations | Where-Object { $_.Status -eq "WARN" }).Count
            $failCount = ($allRecommendations | Where-Object { $_.Status -eq "FAIL" }).Count
            
            # Analyse des vulnerabilites par criticite
            $criticalFailures = ($allRecommendations | Where-Object { $_.Status -eq "FAIL" -and $_.Severity -eq "Critical" }).Count
            $highFailures = ($allRecommendations | Where-Object { $_.Status -eq "FAIL" -and $_.Severity -eq "High" }).Count
            $mediumFailures = ($allRecommendations | Where-Object { $_.Status -eq "FAIL" -and $_.Severity -eq "Medium" }).Count
            $lowFailures = ($allRecommendations | Where-Object { $_.Status -eq "FAIL" -and $_.Severity -eq "Low" }).Count
            
            $criticalWarnings = ($allRecommendations | Where-Object { $_.Status -eq "WARN" -and $_.Severity -eq "Critical" }).Count
            $highWarnings = ($allRecommendations | Where-Object { $_.Status -eq "WARN" -and $_.Severity -eq "High" }).Count
            $mediumWarnings = ($allRecommendations | Where-Object { $_.Status -eq "WARN" -and $_.Severity -eq "Medium" }).Count
            
            # Nouveau calcul base sur les penalites par criticite
            $baseScore = 100.0
            
            # Penalites severes pour les vulnerabilites critiques
            $baseScore -= ($criticalFailures * 40)      # -40 points par FAIL critique
            $baseScore -= ($criticalWarnings * 25)      # -25 points par WARN critique
            
            # Penalites importantes pour les vulnerabilites High
            $baseScore -= ($highFailures * 15)          # -15 points par FAIL high
            $baseScore -= ($highWarnings * 8)           # -8 points par WARN high
            
            # Penalites moderees pour Medium
            $baseScore -= ($mediumFailures * 5)         # -5 points par FAIL medium  
            $baseScore -= ($mediumWarnings * 3)         # -3 points par WARN medium
            
            # Penalites legeres pour Low
            $baseScore -= ($lowFailures * 2)            # -2 points par FAIL low
            
            # Le score ne peut pas être negatif
            $score = [math]::Max(0, [math]::Round($baseScore, 1))
            
            # Determination de l'appreciation basee sur les vulnerabilites critiques
            if ($criticalFailures -gt 0) {
                $rating = "CRITIQUE - $criticalFailures vulnerabilite(s) critique(s)"
                $score = [math]::Min($score, 25)  # Score max de 25% avec des vulns critiques
            } elseif ($highFailures -ge 3) {
                $rating = "RISQUE ELEVE - $highFailures vulnerabilites majeures"  
                $score = [math]::Min($score, 40)  # Score max de 40% avec 3+ vulns high
            } elseif ($highFailures -gt 0) {
                $rating = "RISQUE MODERE - $highFailures vulnerabilite(s) majeure(s)"
                $score = [math]::Min($score, 60)  # Score max de 60% avec des vulns high
            } else {
                # Appreciation normale basee sur le score
                $rating = if ($score -ge 90) { "Excellent" }
                         elseif ($score -ge 80) { "Conforme" } 
                         elseif ($score -ge 65) { "Partiellement conforme" }
                         elseif ($score -ge 50) { "Insuffisant" }
                         else { "Non conforme" }
            }
            
            # Top findings (problemes prioritaires avec ponderation)
            $topFindings = $allRecommendations | 
                          Where-Object { $_.Status -in @("FAIL", "WARN") } |
                          Sort-Object @{Expression={if($_.Status -eq "FAIL") {0} else {1}}}, 
                                     @{Expression={switch($_.Severity) {"Critical" {0} "High" {1} "Medium" {2} "Low" {3} default {4}}}} |
                          Select-Object -First 5
            
            # Stockage du resume avec metriques detaillees
            $script:auditResults.Summary = @{
                Score = $score
                Rating = $rating
                Counts = @{
                    OK = $okCount
                    WARN = $warnCount
                    FAIL = $failCount
                    Total = $totalChecks
                }
                VulnerabilitiesBySeverity = @{
                    Critical = @{ FAIL = $criticalFailures; WARN = $criticalWarnings }
                    High = @{ FAIL = $highFailures; WARN = $highWarnings }
                    Medium = @{ FAIL = $mediumFailures; WARN = $mediumWarnings }
                    Low = @{ FAIL = $lowFailures; WARN = ($allRecommendations | Where-Object { $_.Status -eq "WARN" -and $_.Severity -eq "Low" }).Count }
                }
                ScoringMethod = @{
                    BaseScore = 100
                    CriticalPenalties = ($criticalFailures * 40 + $criticalWarnings * 25)
                    HighPenalties = ($highFailures * 15 + $highWarnings * 8)  
                    MediumPenalties = ($mediumFailures * 5 + $mediumWarnings * 3)
                    LowPenalties = ($lowFailures * 2)
                }
                TopFindings = $topFindings
            }
        } else {
            $script:auditResults.Summary = @{
                Score = "N/A"
                Rating = "Aucune recommandation generee"
                Counts = @{ OK = 0; WARN = 0; FAIL = 0 }
                TopFindings = @()
            }
        }
        
        return $true
    }
    catch {
        Write-Warning "Erreur lors du calcul du score: $_"
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
        Write-Error "Échec de l'initialisation de l'environnement. Arret de l'audit."
        return
    }
    
    # Execution des modules d'audit
    $modules = @(
        @{ Name = "Informations systeme"; Function = "Get-SystemInfoAudit" },
        @{ Name = "Strategies de groupe"; Function = "Get-GroupPolicyAudit" },
        @{ Name = "Utilisateurs et groupes"; Function = "Get-UsersAndGroupsAudit" },
        @{ Name = "Authentification"; Function = "Get-AuthenticationAudit" },
        @{ Name = "Services et processus"; Function = "Get-ServicesAndProcessesAudit" },
        @{ Name = "Reseau"; Function = "Get-NetworkAudit" },
        @{ Name = "Logiciels et securite"; Function = "Get-SoftwareAndSecurityAudit" },
        @{ Name = "Stockage"; Function = "Get-StorageAudit" },
        @{ Name = "Journalisation et audit"; Function = "Get-LoggingAndAuditAudit" }
    )
    
    foreach ($module in $modules) {
        Write-Output "`n== Module: $($module.Name) =="
        try {
            $result = & $module.Function
            Write-Host "Module $($module.Name) termine avec succes (resultat: $result)" -ForegroundColor Green
        }
        catch {
            Write-Error "Erreur lors de l'execution du module $($module.Name): $_"
            Write-Host "Details de l'erreur: $($_.ScriptStackTrace)" -ForegroundColor Red
        }
    }
    
    # Calcul du score et generation des recommandations
    try { 
        Calculate-AuditScore 
    } catch { 
        Write-Warning "Erreur lors du calcul du score: $_"
    }
    
    # ===== CODE DE DEBOGAGE =====
    Write-Host "`n=== DIAGNOSTIC AVANT EXPORT ===" -ForegroundColor Yellow
    Write-Host "Nombre total de categories: $($script:auditResults.Count)" -ForegroundColor Cyan
    
    foreach ($category in $script:auditResults.Keys) {
        Write-Host "`n--- Categorie: $category ---" -ForegroundColor Green
        
        if ($script:auditResults[$category] -is [hashtable]) {
            Write-Host "  Proprietes disponibles: $($script:auditResults[$category].Keys.Count)" -ForegroundColor Gray
            
            # Afficher les cles principales
            foreach ($key in $script:auditResults[$category].Keys) {
                if ($key -eq "Recommendations") {
                    $recCount = if ($script:auditResults[$category].Recommendations) { $script:auditResults[$category].Recommendations.Count } else { 0 }
                    Write-Host "    - $key : $recCount recommandations" -ForegroundColor White
                } else {
                    $value = $script:auditResults[$category][$key]
                    $valueType = if ($value -eq $null) { "null" } elseif ($value -is [string]) { "string" } elseif ($value -is [array]) { "array[$($value.Count)]" } elseif ($value -is [hashtable]) { "hashtable[$($value.Keys.Count)]" } else { $value.GetType().Name }
                    Write-Host "    - $key : $valueType" -ForegroundColor Gray
                }
            }
        } else {
            Write-Host "  Type: $($script:auditResults[$category].GetType().Name)" -ForegroundColor Red
        }
    }
    
    # Verifier les recommandations globales
    $allRecs = @()
    foreach ($cat in $script:auditResults.Keys) {
        if ($script:auditResults[$cat] -is [hashtable] -and $script:auditResults[$cat].Recommendations) {
            $allRecs += $script:auditResults[$cat].Recommendations
        }
    }
    
    Write-Host "`n--- RÉSUMÉ RECOMMANDATIONS ---" -ForegroundColor Magenta
    Write-Host "Total recommandations: $($allRecs.Count)" -ForegroundColor White
    if ($allRecs.Count -gt 0) {
        $okCount = ($allRecs | Where-Object { $_.Status -eq 'OK' }).Count
        $warnCount = ($allRecs | Where-Object { $_.Status -eq 'WARN' }).Count
        $failCount = ($allRecs | Where-Object { $_.Status -eq 'FAIL' }).Count
        Write-Host "  OK: $okCount | WARN: $warnCount | FAIL: $failCount" -ForegroundColor White
        
        # Analyse par criticite
        Write-Host "`nVulnerabilites par criticite:" -ForegroundColor Cyan
        $criticalFail = ($allRecs | Where-Object { $_.Status -eq 'FAIL' -and $_.Severity -eq 'Critical' }).Count
        $highFail = ($allRecs | Where-Object { $_.Status -eq 'FAIL' -and $_.Severity -eq 'High' }).Count
        $mediumFail = ($allRecs | Where-Object { $_.Status -eq 'FAIL' -and $_.Severity -eq 'Medium' }).Count
        $lowFail = ($allRecs | Where-Object { $_.Status -eq 'FAIL' -and $_.Severity -eq 'Low' }).Count
        
        if ($criticalFail -gt 0) { Write-Host "  [CRITICAL]: $criticalFail vulnerabilites" -ForegroundColor Red }
        if ($highFail -gt 0) { Write-Host "  [HIGH]: $highFail vulnerabilites" -ForegroundColor DarkRed }
        if ($mediumFail -gt 0) { Write-Host "  [MEDIUM]: $mediumFail vulnerabilites" -ForegroundColor Yellow }
        if ($lowFail -gt 0) { Write-Host "  [LOW]: $lowFail vulnerabilites" -ForegroundColor Green }
        
        # Score calcule si disponible
        if ($script:auditResults.Summary -and $script:auditResults.Summary.Score) {
            Write-Host "`nScore de securite: $($script:auditResults.Summary.Score)% - $($script:auditResults.Summary.Rating)" -ForegroundColor $(if($script:auditResults.Summary.Score -ge 80) {'Green'} elseif($script:auditResults.Summary.Score -ge 60) {'Yellow'} else {'Red'})
        }
        
        # Afficher les vulnerabilites les plus critiques
        Write-Host "`nVulnerabilites prioritaires:" -ForegroundColor Red
        $criticalIssues = $allRecs | Where-Object { $_.Status -eq 'FAIL' } | Sort-Object @{Expression={switch($_.Severity) {"Critical" {0} "High" {1} "Medium" {2} "Low" {3}}}} | Select-Object -First 3
        $criticalIssues | ForEach-Object {
            $color = switch($_.Severity) { "Critical" {"Red"} "High" {"DarkRed"} "Medium" {"Yellow"} default {"Gray"} }
            Write-Host "  [$($_.Severity)] $($_.Category): $($_.Check)" -ForegroundColor $color
        }
    }
    
    Write-Host "`n================================`n" -ForegroundColor Yellow
    # ===== FIN CODE DE DEBOGAGE =====
    
    # Generation des rapports
    Write-Output "Generation des rapports d'audit..."
    
    # Forcer le rechargement de la fonction Export-AuditResults
    . "$PSScriptRoot\Export-AuditResults.ps1"
    
    # Debug: Verifier la signature de la fonction
    $func = Get-Command Export-AuditResults
    Write-Output "DEBUG: Signature de la fonction:"
    Write-Output $func.Parameters.Keys
    
    Export-AuditResults -AuditResults $script:auditResults -ReportPath $script:reportPath
    
    Write-Output "`n=================================="
    Write-Output "  AUDIT DE SÉCURITÉ TERMINÉ"
    Write-Output "=================================="
    Write-Output "Les resultats ont ete sauvegardes dans: $script:reportPath"
    Write-Output "Rapport HTML: $script:reportPath\audit-report.html"
    Write-Output "Resume texte: $script:reportPath\audit-summary.txt"
}

# Point d'entree du script
Start-WindowsSecurityAudit