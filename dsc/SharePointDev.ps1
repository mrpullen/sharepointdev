Configuration SharePointDev {
    
    param
    (
        [Parameter(Mandatory=$true)] [ValidateNotNullOrEmpty()][System.String]$DomainName,
        [Parameter(Mandatory=$false)][System.String]$ProductKey = 'JVF76-6TMPY-98BXW-76B7Q-TCGTV',
        [Parameter(Mandatory=$true)] [ValidateNotNullOrEmpty()][PSCredential]$DomainCredential,
        [Parameter(Mandatory=$true)] [ValidateNotNullOrEmpty()][PSCredential]$safeModePassword,
        [Parameter(Mandatory=$true)] [ValidateNotNullorEmpty()] [PSCredential] $FarmAccount,
        [Parameter(Mandatory=$true)] [ValidateNotNullorEmpty()] [PSCredential] $SQLServerAccount,
        [Parameter(Mandatory=$true)] [ValidateNotNullorEmpty()] [PSCredential] $SPSetupAccount,
        [Parameter(Mandatory=$true)] [ValidateNotNullorEmpty()] [PSCredential] $WebPoolManagedAccount,
        [Parameter(Mandatory=$true)] [ValidateNotNullorEmpty()] [PSCredential] $ServicePoolManagedAccount,
        [Parameter(Mandatory=$true)] [ValidateNotNullorEmpty()] [PSCredential] $Passphrase
    )
    
    Import-DscResource -ModuleName PSDesiredStateConfiguration
    Import-DscResource -ModuleName SharePointDsc
    Import-DscResource -ModuleName ActiveDirectoryDSC
    Import-DscResource -ModuleName cChoco
    Import-DscResource -ModuleName xSQLServer
    Import-DscResource -ModuleName SqlServerDsc
    Import-DSCResource -ModuleName NetworkingDsc
    Import-DSCResource  -ModuleName StorageDsc

   

    Node 'localhost' {


        LocalConfigurationManager {
            ActionAfterReboot = 'ContinueConfiguration'
            ConfigurationMode = 'ApplyOnly'
            RebootNodeIfNeeded = $true

        }
        Set-Item -Path WSMan:\localhost\MaxEnvelopeSizeKb -Value 2048
        
        #region Staging Directories
        File ConfigFiles {
            DestinationPath = "C:\Config"
            Type            = "Directory"
            Ensure          = "Present"
        }
        #endregion

        #region WindowsFeatures

        WindowsFeature ADDSInstall {
            Ensure = 'Present'
            Name = 'AD-Domain-Services'
        }

        WindowsFeature AADSTools {
            Ensure = 'Present'
            Name   = 'RSAT-ADDS'
        }

        #endregion

        #region Active Directory

        ADDomain CreateDomainController             
        {             
            DomainName                    = $DomainName        
            Credential                    = $DomainCredential             
            SafemodeAdministratorPassword = $safeModePassword            
            ForestMode                    = 'WinThreshold'       
            DependsOn = "[WindowsFeature]ADDSInstall"     
        }   
        
        $ldapUsersPath = (($DomainName.Split('.') | ForEach-Object { "DC=$($_)" }) -join ",")
       
        ADOrganizationalUnit ServiceAccounts {
            Name = "ServiceAccounts"
            Path = $ldapUsersPath
            ProtectedFromAccidentalDeletion = $true
            Description = "OU for Service Accounts"
            Ensure = "Present"
            Credential = $DomainCredential
            DependsOn = "[ADDomain]CreateDomainController"
            
        
        }  

        $ldapServiceAccountPath = "OU=ServiceAccounts," + (($DomainName.Split('.') | ForEach-Object { "DC=$($_)" }) -join ",")
        
        $domain = $DomainName.split(".")[0]

        ADUser SQLAccount {
            DomainName = $domain
            UserName   = $SQLServerAccount.UserName.Split("\")[1]
            Password   = $SQLServerAccount
            Path       = $ldapServiceAccountPath
            ChangePasswordAtLogon = $false
            PasswordNeverExpires = $true
            CannotChangePassword = $true
            Credential = $DomainCredential
            DependsOn = "[ADOrganizationalUnit]ServiceAccounts"
        }
        ADUser FarmAccount {
            DomainName = $domain
            UserName   = $FarmAccount.UserName.Split("\")[1]
            Password   = $FarmAccount
            Path       = $ldapServiceAccountPath
            ChangePasswordAtLogon = $false
            PasswordNeverExpires = $true
            CannotChangePassword = $true
            Credential = $DomainCredential
            DependsOn = "[ADOrganizationalUnit]ServiceAccounts"
        }
        ADUser SPSetupAccount {
            DomainName = $domain
            UserName   = $SPSetupAccount.UserName.Split("\")[1]
            Password   = $SPSetupAccount
            Path       = $ldapServiceAccountPath
            ChangePasswordAtLogon = $false
            PasswordNeverExpires = $true
            CannotChangePassword = $true
            Credential = $DomainCredential
            DependsOn = "[ADOrganizationalUnit]ServiceAccounts"
        }
        ADUser WebPoolManagedAccount {
            DomainName = $domain
            UserName   = $WebPoolManagedAccount.UserName.Split("\")[1]
            Password   = $WebPoolManagedAccount
            Path       = $ldapServiceAccountPath
            ChangePasswordAtLogon = $false
            PasswordNeverExpires = $true
            CannotChangePassword = $true
            Credential = $DomainCredential
            DependsOn = "[ADOrganizationalUnit]ServiceAccounts"
        }
        ADUser ServicePoolManagedAccount {
            DomainName = $domain
            UserName   = $ServicePoolManagedAccount.UserName.Split("\")[1]
            Password   = $ServicePoolManagedAccount
            Path       = $ldapServiceAccountPath
            ChangePasswordAtLogon = $false
            PasswordNeverExpires = $true
            CannotChangePassword = $true
            Credential = $DomainCredential
            DependsOn = "[ADOrganizationalUnit]ServiceAccounts"
        }
        ADUser SP_SuperReader {
            DomainName = $domain
            UserName   = "SP_SuperReader"
            Password   = $Passphrase
            Path       = $ldapServiceAccountPath
            ChangePasswordAtLogon = $false
            PasswordNeverExpires = $true
            CannotChangePassword = $true
            Credential = $DomainCredential
            DependsOn = "[ADOrganizationalUnit]ServiceAccounts"
        }
        ADUser SP_SuperUser {
        DomainName = $domain
            UserName   = "SP_SuperUser"
            Password   = $Passphrase
            Path       = $ldapServiceAccountPath
            ChangePasswordAtLogon = $false
            PasswordNeverExpires = $true
            CannotChangePassword = $true
            Credential = $DomainCredential
            DependsOn = "[ADOrganizationalUnit]ServiceAccounts"
        }

         ADGroup AddFarmAccountToAdmins
        {
            GroupName   = "Domain Admins"
            MembersToInclude = @($FarmAccount.UserName.Split("\")[1], $SPSetupAccount.UserName.Split("\")[1], $SQLServerAccount.UserName.Split("\")[1])
            Ensure      = 'Present'
        }

        Reboot

        #endregion
    

        #region SQLServerInstall
        Script DownloadSQLServer2017DeveloperISO {
            
               GetScript = {
                @{ Result = (Test-Path "C:\config\SQLServer2017-x64-ENU-Dev.iso")}    
            }
            SetScript = {
                Invoke-WebRequest -OutFile "C:\config\SQLServer2017-x64-ENU-Dev.iso" -Uri "https://download.microsoft.com/download/E/F/2/EF23C21D-7860-4F05-88CE-39AA114B014B/SQLServer2017-x64-ENU-Dev.iso"
            }
            TestScript = {
                Test-Path "C:\config\SQLServer2017-x64-ENU-Dev.iso"
            }
        
        }

        MountImage MountSQLServerDev2017ISO {
           ImagePath = "C:\config\SQLServer2017-x64-ENU-Dev.iso"
            DriveLetter = "T"
            Ensure = "Present"
            DependsOn ="[Script]DownloadSQLServer2017DeveloperISO"

        }

      
        SqlSetup InstallSQLServerDev2017SP
        {
            InstanceName          = 'SP'
            Features              = 'SQLENGINE'
            SQLCollation          = 'SQL_Latin1_General_CP1_CI_AS'
            SQLSvcAccount         = $SQLServerAccount
            AgtSvcAccount         = $SQLServerAccount
            SQLSysAdminAccounts   = $DomainCredential.UserName, $SPSetupAccount.UserName
            InstallSharedDir      = 'C:\SQL'
            InstallSharedWOWDir   = 'C:\SQLx86'
            InstanceDir           = 'C:\SQL\SP'
            InstallSQLDataDir     = 'C:\SQL\SP\MSSQL\Data'
            SQLUserDBDir          = 'C:\SQL\SP\MSSQL\Data'
            SQLUserDBLogDir       = 'C:\SQL\SP\MSSQL\Data'
            SQLTempDBDir          = 'C:\SQL\SP\MSSQL\Data'
            SQLTempDBLogDir       = 'C:\SQL\SP\MSSQL\Data'
            SQLBackupDir          = 'C:\SQL\SP\MSSQL\Backup'
            SourcePath            = 'T:\'
            UpdateEnabled         = 'False'
            ForceReboot           = $false
            BrowserSvcStartupType = 'Automatic'

            PsDscRunAsCredential  = $SPSetupAccount

            DependsOn             = '[MountImage]MountSQLServerDev2017ISO'
        }

        $SQLServerName = $env:COMPUTERNAME
        
        SqlServerMaxDop 'Set_SQLServerMaxDop_ToOne'
        {
            Ensure               = 'Present'
            DynamicAlloc         = $false
            MaxDop               = 1
            ServerName           = $SQLServerName
            InstanceName         = 'SP'
            PsDscRunAsCredential = $SPSetupAccount
            DependsOn        = "[SqlSetup]InstallSQLServerDev2017SP"
        }

        SqlServerNetwork 'ChangeTcpIpOnDefaultInstance'
        {
            InstanceName         = 'SP'
            ProtocolName         = 'Tcp'
            IsEnabled            = $true
            TCPDynamicPort       = $false
            TCPPort              = 1433
            RestartService       = $true

            PsDscRunAsCredential = $SPSetupAccount
            DependsOn        = "[SqlSetup]InstallSQLServerDev2017SP"
        }

        #endregion

        #region chocoPackages
        
        cChocoInstaller installChoco
        {
            InstallDir = "c:\config\"
        }
        
      
        cChocoPackageInstaller installSSMS
        {
            Name        = "sql-server-management-studio"
            DependsOn   = "[cChocoInstaller]installChoco"
            #This will automatically try to upgrade if available, only if a version is not explicitly specified.
            AutoUpgrade = $True
        }
        <# 
        #Removed - as it was unreliable
        cChocoPackageInstaller installSQL2017
        {
            Name        = "sql-server-2017"
            DependsOn   = "[cChocoInstaller]installChoco"
            Params      = $sqlParams
            #This will automatically try to upgrade if available, only if a version is not explicitly specified.
            AutoUpgrade = $True
            PsDscRunAsCredential = $SPSetupAccount        
        }
        #>

        cChocoPackageInstaller installVS2017 
        {
            Name        = "visualstudio2017community"
            DependsOn   = "[cChocoInstaller]installChoco"
            AutoUpgrade = $true

        }
        
        cChocoPackageInstaller installVS2017OfficeWorkload 
        {
            Name        = "visualstudio2017-workload-office"
            DependsOn   = @("[cChocoInstaller]installChoco", "[cChocoPackageInstaller]installVS2017")
            AutoUpgrade = $true
        }

        cChocoPackageInstaller installSharePointDesigner 
        {
            Name        = "sharepointdesigner2013x64"
            DependsOn   = "[cChocoInstaller]installChoco"
            AutoUpgrade = $true
        }
       
        cChocoPackageInstaller installulsviewer 
        {
            Name        = "ulsviewer"
            DependsOn   = "[cChocoInstaller]installChoco"
            AutoUpgrade = $true
        }
        

        cChocoPackageInstaller installNodeJS 
        {
            Name        = "nodejs"
            DependsOn   = "[cChocoInstaller]installChoco"
            AutoUpgrade = $true

        }

        cChocoPackageInstaller installYeoman
        {
            Name        = "yo"
            DependsOn   = "[cChocoInstaller]installChoco"
            AutoUpgrade = $true

        }


        cChocoPackageInstaller installGit 
        {
            Name        = "git"
            DependsOn   = "[cChocoInstaller]installChoco"
            AutoUpgrade = $true

        }

        cChocoPackageInstaller installGitforWindows
        {
            Name        = "git.install"
            DependsOn   = "[cChocoInstaller]installChoco"
            AutoUpgrade = $true

        }

        cChocoPackageInstaller installGitCredentialManager
        {
            Name        = "git-credential-manager-for-windows"
            DependsOn   = "[cChocoInstaller]installChoco"
            AutoUpgrade = $true

        }

        cChocoPackageInstaller installVSCode
        {
            Name        = "vscode"
            DependsOn   = "[cChocoInstaller]installChoco"
            AutoUpgrade = $true

        }

        cChocoPackageInstaller installVSCodeAzRepos
        {
            Name        = "vscode-azurerepos"
            DependsOn   = "[cChocoInstaller]installChoco"
            AutoUpgrade = $true

        }

        cChocoPackageInstaller installVSCodePowerShellExt
        {
            Name        = "vscode-powershell"
            DependsOn   = "[cChocoInstaller]installChoco"
            AutoUpgrade = $true

        }
        #endregion
        
        #region SharePointInstall     
        Script Download2016ISO {
            GetScript = {
                @{ Result = (Test-Path "C:\config\officeserver.iso")}    
            }
            SetScript = {
                Invoke-WebRequest -OutFile "C:\config\officeserver.iso" -Uri "https://download.microsoft.com/download/0/0/4/004EE264-7043-45BF-99E3-3F74ECAE13E5/officeserver.img"
            }
            TestScript = {
                Test-Path "C:\config\officeserver.iso"
            }
        
        }

        MountImage MountSharePointISO {
            ImagePath = "C:\config\officeserver.iso"
            DriveLetter = "S"
            Ensure = "Present"
        }

        
         SPInstallPrereqs InstallPrereqs {
            IsSingleInstance  = "Yes"
            Ensure            = "Present"
            InstallerPath     = "S:\prerequisiteinstaller.exe"
            OnlineMode        = $true
            DependsOn         = @("[MountImage]MountSharePointISO","[ADDomain]CreateDomainController")
           
        }
        
        SPInstall InstallSharePoint {
            IsSingleInstance  = "Yes"
            Ensure            = "Present"
            BinaryDir         = "S:\"
            ProductKey        = $ProductKey
            DependsOn         = "[SPInstallPrereqs]InstallPrereqs"
        }
        


        #**********************************************************
        # Basic farm configuration
        #
        # This section creates the new SharePoint farm object, and
        # provisions generic services and components used by the
        # whole farm
        #**********************************************************
        

        SPFarm CreateSPFarm
        {
            IsSingleInstance         = "Yes"
            Ensure                   = "Present"
            DatabaseServer           = "$($SQLServerName)\SP"
            FarmConfigDatabaseName   = "SP_Config"
            Passphrase               = $Passphrase
            FarmAccount              = $FarmAccount
            PsDscRunAsCredential     = $SPSetupAccount
            AdminContentDatabaseName = "SP_AdminContent"
            RunCentralAdmin          = $true
            DependsOn                = @("[ADUser]FarmAccount","[ADUser]SPSetupAccount")
        }

        SPManagedAccount ServicePoolManagedAccount
        {
            AccountName          = $ServicePoolManagedAccount.UserName
            Account              = $ServicePoolManagedAccount
            PsDscRunAsCredential = $SPSetupAccount
            DependsOn            = "[SPFarm]CreateSPFarm"
        }
        
        SPManagedAccount WebPoolManagedAccount
        {
            AccountName          = $WebPoolManagedAccount.UserName
            Account              = $WebPoolManagedAccount
            PsDscRunAsCredential = $SPSetupAccount
            DependsOn            = "[SPFarm]CreateSPFarm"
        }
        
        SPDiagnosticLoggingSettings ApplyDiagnosticLogSettings
        {
            IsSingleInstance                            = "Yes"
            PsDscRunAsCredential                        = $SPSetupAccount
            LogPath                                     = "C:\ULS"
            LogSpaceInGB                                = 5
            AppAnalyticsAutomaticUploadEnabled          = $false
            CustomerExperienceImprovementProgramEnabled = $true
            DaysToKeepLogs                              = 7
            DownloadErrorReportingUpdatesEnabled        = $false
            ErrorReportingAutomaticUploadEnabled        = $false
            ErrorReportingEnabled                       = $false
            EventLogFloodProtectionEnabled              = $true
            EventLogFloodProtectionNotifyInterval       = 5
            EventLogFloodProtectionQuietPeriod          = 2
            EventLogFloodProtectionThreshold            = 5
            EventLogFloodProtectionTriggerPeriod        = 2
            LogCutInterval                              = 15
            LogMaxDiskSpaceUsageEnabled                 = $true
            ScriptErrorReportingDelay                   = 30
            ScriptErrorReportingEnabled                 = $true
            ScriptErrorReportingRequireAuth             = $true
            DependsOn                                   = "[SPFarm]CreateSPFarm"
        }
        
        SPUsageApplication UsageApplication
        {
            Name                  = "Usage Service Application"
            DatabaseName          = "SP_Usage"
            UsageLogCutTime       = 5
            UsageLogLocation      = "C:\UsageLogs"
            UsageLogMaxFileSizeKB = 1024
            PsDscRunAsCredential  = $SPSetupAccount
            DependsOn             = "[SPFarm]CreateSPFarm"
        }
        
        SPStateServiceApp StateServiceApp
        {
            Name                 = "State Service Application"
            DatabaseName         = "SP_State"
            PsDscRunAsCredential = $SPSetupAccount
            DependsOn            = "[SPFarm]CreateSPFarm"
        }
        
        SPDistributedCacheService EnableDistributedCache
        {
            Name                 = "AppFabricCachingService"
            Ensure               = "Present"
            CacheSizeInMB        = 1024
            ServiceAccount       = $ServicePoolManagedAccount.UserName
            PsDscRunAsCredential = $SPSetupAccount
            CreateFirewallRules  = $true
            DependsOn            = @('[SPFarm]CreateSPFarm','[SPManagedAccount]ServicePoolManagedAccount')
        }

        #**********************************************************
        # Web applications
        #
        # This section creates the web applications in the
        # SharePoint farm, as well as managed paths and other web
        # application settings
        #**********************************************************
        $serverName = $env:COMPUTERNAME
        $sharePointHostHeader = "$($serverName).$($DomainName)"
        $sharePointUrl = "http://$($serverName).$($DomainName)"
        SPWebApplication SharePointSites
        {
            Name                   = "SharePoint Sites"
            ApplicationPool        = "SharePoint Sites"
            ApplicationPoolAccount = $WebPoolManagedAccount.UserName
            AllowAnonymous         = $false
            DatabaseName           = "SP_Content"
            WebAppUrl              = "$($sharePointUrl)"
            HostHeader             = "$($sharePointHostHeader)"
            Port                   = 80
            PsDscRunAsCredential   = $SPSetupAccount
            DependsOn              = "[SPManagedAccount]WebPoolManagedAccount"
        }

        $domain = $DomainName.split(".")[0].ToUpper()

        SPCacheAccounts WebAppCacheAccounts
        {
            WebAppUrl              = "$($sharePointUrl)"
            SuperUserAlias         = "$($domain)\SP_SuperUser"
            SuperReaderAlias       = "$($domain)\SP_SuperReader"
            PsDscRunAsCredential   = $SPSetupAccount
            DependsOn              = "[SPWebApplication]SharePointSites"
        }

        SPSite TeamSite
        {
            Url                      = "$($sharePointUrl)"
            OwnerAlias               = $SPSetupAccount.UserName
            Name                     = "DSC Demo Site"
            Template                 = "STS#0"
            PsDscRunAsCredential     = $SPSetupAccount
            DependsOn                = "[SPWebApplication]SharePointSites"
        }


        #**********************************************************
        # Service instances
        #
        # This section describes which services should be running
        # and not running on the server
        #**********************************************************

        SPServiceInstance ClaimsToWindowsTokenServiceInstance
        {
            Name                 = "Claims to Windows Token Service"
            Ensure               = "Present"
            PsDscRunAsCredential = $SPSetupAccount
            DependsOn            = "[SPFarm]CreateSPFarm"
        }

        SPServiceInstance SecureStoreServiceInstance
        {
            Name                 = "Secure Store Service"
            Ensure               = "Present"
            PsDscRunAsCredential = $SPSetupAccount
            DependsOn            = "[SPFarm]CreateSPFarm"
        }

        SPServiceInstance ManagedMetadataServiceInstance
        {
            Name                 = "Managed Metadata Web Service"
            Ensure               = "Present"
            PsDscRunAsCredential = $SPSetupAccount
            DependsOn            = "[SPFarm]CreateSPFarm"
        }

        SPServiceInstance BCSServiceInstance
        {
            Name                 = "Business Data Connectivity Service"
            Ensure               = "Present"
            PsDscRunAsCredential = $SPSetupAccount
            DependsOn            = "[SPFarm]CreateSPFarm"
        }

        SPServiceInstance SearchServiceInstance
        {
            Name                 = "SharePoint Server Search"
            Ensure               = "Present"
            PsDscRunAsCredential = $SPSetupAccount
            DependsOn            = "[SPFarm]CreateSPFarm"
        }

        #**********************************************************
        # Service applications
        #
        # This section creates service applications and required
        # dependencies
        #**********************************************************

        $serviceAppPoolName = "SharePoint Service Applications"
        SPServiceAppPool MainServiceAppPool
        {
            Name                 = $serviceAppPoolName
            ServiceAccount       = $ServicePoolManagedAccount.UserName
            PsDscRunAsCredential = $SPSetupAccount
            DependsOn            = "[SPFarm]CreateSPFarm"
        }

        SPSecureStoreServiceApp SecureStoreServiceApp
        {
            Name                  = "Secure Store Service Application"
            ApplicationPool       = $serviceAppPoolName
            AuditingEnabled       = $true
            AuditlogMaxSize       = 30
            DatabaseName          = "SP_SecureStore"
            PsDscRunAsCredential  = $SPSetupAccount
            DependsOn             = "[SPServiceAppPool]MainServiceAppPool"
        }

        SPManagedMetaDataServiceApp ManagedMetadataServiceApp
        {
            Name                 = "Managed Metadata Service Application"
            PsDscRunAsCredential = $SPSetupAccount
            ApplicationPool      = $serviceAppPoolName
            DatabaseName         = "SP_MMS"
            DependsOn            = "[SPServiceAppPool]MainServiceAppPool"
        }

        SPBCSServiceApp BCSServiceApp
        {
            Name                  = "BCS Service Application"
            ApplicationPool       = $serviceAppPoolName
            DatabaseName          = "SP_BCS"
            DatabaseServer        = "$($SQLServerName)\SP"
            PsDscRunAsCredential  = $SPSetupAccount
            DependsOn             = @('[SPServiceAppPool]MainServiceAppPool', '[SPSecureStoreServiceApp]SecureStoreServiceApp')
        }

        SPSearchServiceApp SearchServiceApp
        {
            Name                  = "Search Service Application"
            DatabaseName          = "SP_Search"
            ApplicationPool       = $serviceAppPoolName
            PsDscRunAsCredential  = $SPSetupAccount
            DependsOn             = "[SPServiceAppPool]MainServiceAppPool"
        }   

        #endregion

        #region WindowsFirewall
          Firewall OpenSQLServerPort1433
        {
            Name                  = 'SQLServerTCP'
            DisplayName           = 'SQL Server 1433, 1434'
            Group                 = 'SharePointDev'
            Ensure                = 'Present'
            Enabled               = 'True'
            Profile               = ('Domain', 'Private')
            Direction             = 'InBound'
            LocalPort             = ('1433','1434')
            Protocol              = 'TCP'
            Description           = 'Open SQL Server Port'
            DependsOn             = '[SqlServerNetwork]ChangeTcpIpOnDefaultInstance'

        }

          Firewall OpenSharePointIISPort80
        {
            Name                  = 'SharePointTCP'
            DisplayName           = 'SharePoint Server 80,9999'
            Group                 = 'SharePointDev'
            Ensure                = 'Present'
            Enabled               = 'True'
            Profile               = ('Domain', 'Private')
            Direction             = 'InBound'
            LocalPort             = ('80','9999')
            Protocol              = 'TCP'
            Description           = 'Open SharePoint Server Port'
            DependsOn             = @('[SPWebApplication]SharePointSites','[SPFarm]CreateSPFarm')

        }

        
        #endregion
    }


}



$ConfigurationData = @{
    AllNodes = @(
        @{
            NodeName = "localhost"
            PSDscAllowPlainTextPassword = $true 
            PSDscAllowDomainUser = $true
        }
    )
}
<#
$password = [System.Web.Security.Membership]::GeneratePassword(12,2)

Write-Host "Remember this password : $($password)"

$secpasswd                  = ConvertTo-SecureString $password -AsPlainText -Force
$domainCredential           = New-Object System.Management.Automation.PSCredential ("DEV\mrpullen", $secpasswd)
$safeModePassword           = New-Object System.Management.Automation.PSCredential ("smp", $secpasswd)
$farmAccount                = New-Object System.Management.Automation.PSCredential ("DEV\sa-spfarm", $secpasswd)
$spSetupAccount             = New-Object System.Management.Automation.PSCredential ("DEV\sa-spSetup", $secpasswd)
$webPoolManagedAccount      = New-Object System.Management.Automation.PSCredential ("DEV\sa-spweb", $secpasswd)
$servicePoolManagedACcount  = New-Object System.Management.Automation.PSCredential ("DEV\sa-spsvc", $secpasswd)
$sqlServerAccount           = New-Object System.Management.Automation.PSCredential ("DEV\sa-spsql", $secpasswd)
$passphrase                 = New-Object System.Management.Automation.PSCredential ("DEV\sa-sp", $secpasswd)


SharePointDev -DomainName "DEV.LOC" -DomainCredential $domainCredential -FarmAccount $farmAccount -SPSetupAccount $spSetupAccount -SQLServerAccount $sqlServerAccount `
-WebPoolManagedAccount $webPoolManagedAccount -ServicePoolManagedAccount $servicePoolManagedACcount -Passphrase $passphrase -safeModePassword $safeModePassword `
-ConfigurationData $ConfigurationData

Start-DscConfiguration -Path .\SharePointDev -Wait -Force 
#>
#SharePointDev -domainName dev.loc -safeModePassword $safeModeCred -credential $credential -ConfigurationData $configData