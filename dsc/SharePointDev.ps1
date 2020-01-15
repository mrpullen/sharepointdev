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

    $configIni = @"
;SQL Server 2017 Configuration File
[OPTIONS]
; By specifying this parameter and accepting Microsoft R Open and Microsoft R Server terms, you acknowledge that you have read and understood the terms of use. 
IACCEPTPYTHONLICENSETERMS="False"
; Specifies a Setup work flow, like INSTALL, UNINSTALL, or UPGRADE. This is a required parameter. 
ACTION="Install"
; Specifies that SQL Server Setup should not display the privacy statement when ran from the command line. 
SUPPRESSPRIVACYSTATEMENTNOTICE="False"
; By specifying this parameter and accepting Microsoft R Open and Microsoft R Server terms, you acknowledge that you have read and understood the terms of use. 
IACCEPTROPENLICENSETERMS="False"
; Use the /ENU parameter to install the English version of SQL Server on your localized Windows operating system. 
ENU="True"
; Setup will not display any user interface. 
QUIET="True"
; Setup will display progress only, without any user interaction. 
QUIETSIMPLE="False"
; Parameter that controls the user interface behavior. Valid values are Normal for the full UI,AutoAdvance for a simplied UI, and EnableUIOnServerCore for bypassing Server Core setup GUI block. 
UIMODE="Normal"
; Specify whether SQL Server Setup should discover and include product updates. The valid values are True and False or 1 and 0. By default SQL Server Setup will include updates that are found. 
UpdateEnabled="False"
; If this parameter is provided, then this computer will use Microsoft Update to check for updates. 
USEMICROSOFTUPDATE="True"
; Specify the location where SQL Server Setup will obtain product updates. The valid values are "MU" to search Microsoft Update, a valid folder path, a relative path such as .\MyUpdates or a UNC share. By default SQL Server Setup will search Microsoft Update or a Windows Update service through the Window Server Update Services. 
UpdateSource="MU"
; Specifies features to install, uninstall, or upgrade. The list of top-level features include SQL, AS, IS, MDS, and Tools. The SQL feature will install the Database Engine, Replication, Full-Text, and Data Quality Services (DQS) server. The Tools feature will install shared components. 
FEATURES=SQLENGINE
; Displays the command line parameters usage 
HELP="False"
; Specifies that the detailed Setup log should be piped to the console. 
INDICATEPROGRESS="False"
; Specifies that Setup should install into WOW64. This command line argument is not supported on an IA64 or a 32-bit system. 
X86="False"
; Specify a default or named instance. MSSQLSERVER is the default instance for non-Express editions and SQLExpress for Express editions. This parameter is required when installing the SQL Server Database Engine (SQL), or Analysis Services (AS). 
INSTANCENAME="SP"
; Specify the root installation directory for shared components.  This directory remains unchanged after shared components are already installed. 
INSTALLSHAREDDIR="C:\Program Files\Microsoft SQL Server"
; Specify the root installation directory for the WOW64 shared components.  This directory remains unchanged after WOW64 shared components are already installed. 
INSTALLSHAREDWOWDIR="C:\Program Files (x86)\Microsoft SQL Server"
; Specify the Instance ID for the SQL Server features you have specified. SQL Server directory structure, registry structure, and service names will incorporate the instance ID of the SQL Server instance. 
INSTANCEID="SP"
; TelemetryUserNameConfigDescription 
SQLTELSVCACCT="NT Service\SQLTELEMETRY"
; TelemetryStartupConfigDescription 
SQLTELSVCSTARTUPTYPE="Automatic"
; Specify the installation directory. 
INSTANCEDIR="C:\Program Files\Microsoft SQL Server"
; Agent account name 
AGTSVCACCOUNT="NT Service\SQLSERVERAGENT"
; Auto-start service after installation.  
AGTSVCSTARTUPTYPE="Manual"
; CM brick TCP communication port 
COMMFABRICPORT="0"
; How matrix will use private networks 
COMMFABRICNETWORKLEVEL="0"
; How inter brick communication will be protected 
COMMFABRICENCRYPTION="0"
; TCP port used by the CM brick 
MATRIXCMBRICKCOMMPORT="0"
; Startup type for the SQL Server service. 
SQLSVCSTARTUPTYPE="Automatic"
; Level to enable FILESTREAM feature at (0, 1, 2 or 3). 
FILESTREAMLEVEL="0"
; Set to "1" to enable RANU for SQL Server Express. 
ENABLERANU="False"
; Specifies a Windows collation or an SQL collation to use for the Database Engine. 
SQLCOLLATION="SQL_Latin1_General_CP1_CI_AS"
; Account for SQL Server service: Domain\User or system account. 
SQLSVCACCOUNT="$($SQLServerAccount.UserName)"
; Set to "True" to enable instant file initialization for SQL Server service. If enabled, Setup will grant Perform Volume Maintenance Task privilege to the Database Engine Service SID. This may lead to information disclosure as it could allow deleted content to be accessed by an unauthorized principal. 
SQLSVCINSTANTFILEINIT="False"
; Windows account(s) to provision as SQL Server system administrators. 
SQLSYSADMINACCOUNTS="Administrators"
; The number of Database Engine TempDB files. 
SQLTEMPDBFILECOUNT="4"
; Specifies the initial size of a Database Engine TempDB data file in MB. 
SQLTEMPDBFILESIZE="8"
; Specifies the automatic growth increment of each Database Engine TempDB data file in MB. 
SQLTEMPDBFILEGROWTH="64"
; Specifies the initial size of the Database Engine TempDB log file in MB. 
SQLTEMPDBLOGFILESIZE="8"
; Specifies the automatic growth increment of the Database Engine TempDB log file in MB. 
SQLTEMPDBLOGFILEGROWTH="64"
; Provision current user as a Database Engine system administrator for %SQL_PRODUCT_SHORT_NAME% Express. 
ADDCURRENTUSERASSQLADMIN="True"
; Specify 0 to disable or 1 to enable the TCP/IP protocol. 
TCPENABLED="1"
; Specify 0 to disable or 1 to enable the Named Pipes protocol. 
NPENABLED="0"
; Startup type for Browser Service. 
BROWSERSVCSTARTUPTYPE="Disabled"
"@

    Node 'localhost' {


        LocalConfigurationManager {
            ActionAfterReboot = 'ContinueConfiguration'
            ConfigurationMode = 'ApplyOnly'
            RebootNodeIfNeeded = $true

        }

        File ConfigFiles {
            DestinationPath = "C:\Config"
            Type            = "Directory"
            Ensure          = "Present"
        }

        WindowsFeature ADDSInstall {
            Ensure = 'Present'
            Name = 'AD-Domain-Services'
        }

        WindowsFeature AADSTools {
            Ensure = 'Present'
            Name   = 'RSAT-ADDS'
        }

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
            Password   = $SQLServerAccountv
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
            MembersToInclude = @($FarmAccount.UserName.Split("\")[1], $SPSetupAccount.UserName.Split("\")[1])
            Ensure      = 'Present'
        }

        

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

        Script ConfigurationFile {
            GetScript = { @{ Result=(Get-Content "C:\config\configurationFile.ini") } }
            SetScript = {
                $configIni | Out-File "C:\config\configurationFile.ini"
            }
            TestScript = { 
                Test-Path "C:\Config\configurationFile.ini"
            }
        }

        $sqlParameters = @(
            "ConfigurationFile=""C:\Config\configurationFile.ini"""
            "SQLSVCPASSWORD=""$($SQLServerAccount.GetNetworkCredential().Password)"""
        )
        $sqlParams = (($sqlParameters | foreach-object { "/$($_) " }) -join "").trim()
        
        cChocoPackageInstaller installSQL2017
        {
            Name        = "sql-server-2017"
            DependsOn   = "[cChocoInstaller]installChoco"
            Params      = $sqlParams
            #This will automatically try to upgrade if available, only if a version is not explicitly specified.
            AutoUpgrade = $True
        }

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

        Script Extract2016ISO {
            GetScript = {
                @{ Result = (Test-Path "C:\config\spinstall") }
            }
            SetScript = {
                $mountResult = Mount-DiskImage -ImagePath "C:\config\officeserver.iso"
                $driveLetter = ($mountResult | Get-Volume).DriveLetter
                Copy-Item -LiteralPath "$($driveLetter):\" -Destination C:\config\spinstall -Recurse 
            }
            TestScript = {
                Test-Path "C:\config\spinstall"
            }
            DependsOn = "[Script]Download2016ISO"
        }


        
         SPInstallPrereqs InstallPrereqs {
            IsSingleInstance  = "Yes"
            Ensure            = "Present"
            InstallerPath     = "C:\config\spinstall\prerequisiteinstaller.exe"
            OnlineMode        = $true
            DependsOn         = @("[Script]Extract2016ISO","[ADDomain]CreateDomainController")
           
        }
        
        SPInstall InstallSharePoint {
            IsSingleInstance  = "Yes"
            Ensure            = "Present"
            BinaryDir         = "C:\config\spinstall\"
            ProductKey        = $ProductKey
            DependsOn         = "[SPInstallPrereqs]InstallPrereqs"
        }
        #>

        xSQLServerMaxDop SetMAXDOP {
            Ensure          = "Present"
            SQLInstanceName = "SP"
            DynamicAlloc    = $false
            MaxDop          = 1
        }

        SqlServerNetwork 'ChangeTcpIpOnDefaultInstance'
        {
            InstanceName         = 'MSSQLSERVER'
            ProtocolName         = 'Tcp'
            IsEnabled            = $true
            TCPDynamicPort       = $false
            TCPPort              = 1433
            RestartService       = $true
             PsDscRunAsCredential     = $SPSetupAccount
        }

        Firewall AddFirewallRule
        {
            Name                  = 'SQLFirewallRule'
            DisplayName           = 'Firewall Rule for SQLServer'
            Group                 = 'SQL Firewall Rule Group'
            Ensure                = 'Present'
            Enabled               = 'True'
            Profile               = ('Domain', 'Private')
            Direction             = 'InBound'
            LocalPort             = ('1433', '1434')
            Protocol              = 'TCP'
            Description           = 'Firewall Rule for Notepad.exe'
        }


        #**********************************************************
        # Basic farm configuration
        #
        # This section creates the new SharePoint farm object, and
        # provisions generic services and components used by the
        # whole farm
        #**********************************************************
        $SQLServerName = $env:COMPUTERNAME

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

    }


}

<#
$ConfigurationData = @{
    AllNodes = @(
        @{
            NodeName = "localhost"
            PSDscAllowPlainTextPassword = $true 
            PSDscAllowDomainUser = $true
        }
    )
}

$password                   = [System.Web.Security.Membership]::GeneratePassword(12,2)
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

Start-DscConfiguration -Path .\SharePointDev -Wait -Force -Verbose 
#>
#SharePointDev -domainName dev.loc -safeModePassword $safeModeCred -credential $credential -ConfigurationData $configData