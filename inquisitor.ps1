<#

.SYNOPSIS
    ▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▒
    ▓                                                                                              ▒
    ▓    ######\                               ##\           ##\   ##\                             ▒ 
    ▓    \_##  _|                              \__|          \__|  ## |                            ▒
    ▓      ## |  #######\   ######\  ##\   ##\ ##\  #######\ ##\ ######\    ######\   ######\      ▒
    ▓      ## |  ##  __##\ ##  __##\ ## |  ## |## |##  _____|## |\_##  _|  ##  __##\ ##  __##\     ▒
    ▓      ## |  ## |  ## |## /  ## |## |  ## |## |\######\  ## |  ## |    ## /  ## |## |  \__|    ▒
    ▓      ## |  ## |  ## |## |  ## |## |  ## |## | \____##\ ## |  ## |##\ ## |  ## |## |          ▒
    ▓    ######\ ## |  ## |\####### |\######  |## |#######  |## |  \####  |\######  |## |          ▒
    ▓    \______|\__|  \__| \____## | \______/ \__|\_______/ \__|   \____/  \______/ \__|          ▒
    ▓                            ## |                                                              ▒
    ▓                            ## |                                                              ▒
    ▓                            \__|                           By:      f4d0                      ▒
    ▓                                                           Version: 0.7                       ▒ 
    ▓                                                                                              ▒
    ▓▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒



.DESCRIPTION
    Script in powershell to collect evidence from windows machines.

.EXAMPLE
    .\inquisitor.ps1 -SOURCE c: DESTINY d: -ALL -RAM -SFI -FormatType Zeros

    In this example, the c: is chosen as source drive and the d: as destiny drive.
    All the the evidences that inquisitor can collect are set to true: "ALL", "RAM" "SFI" (signed files)
    Before start, the destiny driver will be formated setting all the bits to 0.

.EXAMPLE   
    .\inquisitor.ps1 -SOURCE c: DESTINY d: -HIV -EVT

    Inquisitor only collects HIVE and EVTX files.
    
.EXAMPLE
    .\inquisitor.ps1 -GUI 

    Starts Inquisitor in graphical mode.

.EXAMPLE
    .\inquisitor_v0.4.ps1 -PER -Source c: -Destiny e: -FormatType No

    Collects information from drive C: about persistence in the machine, outputing the results to E: and not formating the destiny drive. 


.NOTES

    Third-party software dependencies:
        - RawCopy.exe - Allow to copy blocked files x86
        - RawCopy64.exe - Allow to copy blocked files x64
        - sigcheck.exe - Hashes Files x86 option to check with VirusTotal 
        - sigcheck64.exe - Hashes Files x64 option to check with VirusTotal 
        - psloglist.exe - Parses EVTX files, in our case to an CSV file with basic info
        - autorunsc.exe - Exports a CSV with info about the auto run executables, with hashes and VT info
        - winpmem_1.6.2.exe - Used to dump memory

    Considerations:
        - PSLOGLIST - it only works with 3 EVTXs Application, Security and System

    References:
        - CIR_CODE\obtain_evidences.ps1 de Jaime Ferrer 
        - https://es.wikipedia.org/wiki/Windows_Server
        - https://www.fwhibbit.es/windows-registry-prepare-the-coffeemaker
        - https://docs.microsoft.com/en-us/windows/desktop/SysInfo/about-the-registry
        - https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/wevtutil
        - https://www.sans.org/cyber-security-summit/archives/file/summit-archive-1544032916.pdf

    For better performance and avoid errors, execute in "NT AUTHORITY\SYSTEM"
        .\bin\PsExec64.exe -i -s powershell.exe

    To Activate the execution of Scripts:
        # Set-ExecutionPolicy -ExecutionPolicy Bypass
        
        More info:
        - https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.security/set-executionpolicy?view=powershell-6
        - https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_execution_policies?view=powershell-6


.LINK

#>

<############ INPUT PARAMETERS ############>
param(
    
    <# Start in Graphic mode.#>
    [switch]$GUI=$false,
      
    <# Define the SOURCE drive.#>
    [String]$Source="",             
    
    <# Define the DESTINY drive.#>
    [String]$Destiny="",            
    
    <# DEVELOPMENT mode to help the developer. #>
    [parameter(DontShow)][switch]$DevMode=$false,     
    
    <# This option allows the user to format the DESTINY drive before start to collect data to it. 
There are 3 options:
- No -> It does not format. (default)
- Quick -> Quick Format
- Zeros -> Formats the driver and sets all the bits to 0.#>
    [ValidateSet("No","Quick","Zeros")][string]$FormatType="No",    
    
    <# Defines if the SOURCE drive is mounted. 
If the SOURCE drive is mounted the way to collect the evidences change slightly, so this is a crucial parameter to use in this cases. 
If the drive unit is different from C the script will detect and ask the user to confirm that it's a mounted drive.#>
    [switch]$Live=$true,      

    
    <# Enables the collection of all the posible evidences by Inquisitor.
Exceptions are: "Signed Files" and "RAM"
"Signed Files" is time consuming task
"RAM is a collecting that might not allawys be needed and it's also a time consuming task" #>
    [switch]$All=$false,         

##### LIVE
   
    <# Collects RAM Memory - Be sure to have enough space in the destiny drive/folder #>
    [switch]$RAM=$false,   
        
    <# Collects Information about network. #>
    [switch]$NET=$false, 
       
    <# Collects Information about Services and Processes. #>
    [switch]$SAP=$false, 
    
    <# Collects Information about Scheduled Tasks and Jobs. #>
    [switch]$STJ=$false, 
    
    <# Collects Information about Command Line and PowerShell history. #>
    [switch]$CPH=$false, 
    
    <# Collects Information about Installed Software. #>
    [switch]$INS=$false, 
    
    <# Collects Information about Users and Groups. #>
    [switch]$UGR=$false, 
    
    <# Collects Information about Persistence on the system. #>
    [switch]$PER=$false, 
    
    <# Collects Information about USB devices. #>
    [switch]$USB=$false, 
    
    <# Collects Information about Devices from the OS. #>
    [switch]$DEV=$false, 
    
    <# Collects Information about Security configuration of the system. #>
    [switch]$SEC=$false, 
         
    <# Collects Information about Shell Folders. #>
    [switch]$SFO=$false, 
    
    <# Collects Information about Environment variables. #>
    [switch]$ENV=$false, 
    

    <# Collects Information about Most Recent Used registries. #>
    [switch]$MRU=$false, 
    
    <# Collects Information about AppCompact more known as Shimcache. #>
    [switch]$SHI=$false, 
    
    <# Collects Information about Jump Lists. #>
    [switch]$JLI=$false,      
    
    <# Collects Information about Background Activity Moderator. #>
    [switch]$BAM=$false, 
    

    <# Collects Information about the Timeline. #>
    [switch]$TLH=$false, 
    
    <# Collects Information about Recent Apps. #>
    [switch]$RAP=$false,      
    
    <# Collects Information about System Information. #>
    [switch]$SYS=$false, 



    <# Collects Information about User Assist. #>
    [switch]$UAS=$false,         
    
    <# Sign Files
This goes over all the files in "c:\windows" and "c:\windows\system32" calculates hashes and checks with Virus Total for infections.  
TIME CONSUMING: Depending on the computer and disk can go easly over 20 minutes. #>
    [switch]$SFI=$false,          
    
    <# Collects Information about Last Activity. #>
    [switch]$LAC=$false,         

    <# Collects Information about Autorun Files. #> <# TIME CONSUMING #>
    [switch]$AFI=$false,         
    
        
##### OFFLINE  

    <# Collects HIVE files #>
    [switch]$HIV=$false,          
    
    <# Collects EVTX Files #>
    [switch]$EVT=$false,         
    
    <# Collects Information about all the files in the system orderer by different dates. #>
    [switch]$FIL=$false,         
    
    <# Collects Prefectch Files #>
    [switch]$PRF=$false,         
    
    <# Collects Windows Search database file. #>
    [switch]$WSE=$false,          
    
    <# Collects ETW and ETL Files #>
    [switch]$EET=$false,         
    
    <# Collects Thumcache files from the system. #>
    [switch]$THC=$false,          
    
    <# Collects Iconcache files from the system. #>
    [switch]$ICO=$false,          
    
    <# Collects some root files: $MFT, $UsnJrnl and $LogFile #>
    [switch]$MUL=$false,         
    
    <# Collects some system files: Hiberfil.sys, Pagefile.sys, Swapfile.sys #>
    [switch]$HPS=$false,          
    
    <# Collects all the files from the system with "Dangerous" extensions #>
    [switch]$DEX=$false,          
    
    <# Collects info stored in the Text Harvester. #>
    [switch]$THA=$false,

    <# Collects info about System Resource Usage Monitoring #>
    [switch]$SRU=$false,

    <# Collects Credentials stored in the system. #>
    [switch]$CRE=$false,


    <# Collects Data from conversations using SKYPE. #>
    [switch]$SKY=$false,


    <# Collects Browsing data from Chrome Web Browser. #>
    [switch]$CHR=$false,

    <# Collects Browsing data from Firefox Web Browser. #>
    [switch]$MFI=$false,

    <# Collects Browsing data from Internet Explorer Web Browser. #>
    [switch]$IEX=$false,

    <# Collects Browsing data from Edge Web Browser. #>
    [switch]$EDG=$false,

    <# Collects Browsing data from Safari Web Browser. #>
    [switch]$SAF=$false,

    <# Collects Browsing data from Opera Web Browser. #>
    [switch]$OPE=$false,

    <# Collects Browsing data from TOR Web Browser. #>
    [switch]$TOR=$false,


    <# Collects emails storage file from OUTLOOK. #>
    [switch]$OUT=$false,


    <# Collects logs from OneDrive cloud app. #>
    [switch]$COD=$false,

    <# Collects logs from Google Drive cloud app. #>
    [switch]$CGD=$false,
    
    <# Collects logs from DropBox cloud app. #>
    [switch]$CDB=$false
)



<# The Global variables that are almost a mirror of the inut parameters, but needed it we need to change then on runtime #>
$Global:Source=$Source
$Global:Destiny=$Destiny
$Global:FormatType=$FormatType
$Global:Live=$Live
$Global:All=$All

##### LIVE
   
$Global:RAM=$RAM,

$Global:NET=$NET, 
$Global:SAP=$SAP, 
$Global:STJ=$STJ, 
$Global:CPH=$CPH, 
$Global:INS=$INS, 
$Global:UGR=$UGR, 
$Global:PER=$PER, 
$Global:USB=$USB, 
$Global:DEV=$DEV, 
$Global:SEC=$SEC, 
$Global:SFO=$SFO, 
$Global:ENV=$ENV, 
 
$Global:MRU=$MRU, 
$Global:SHI=$SHI, 
$Global:JLI=$JLI,      
$Global:BAM=$BAM,

$Global:TLH=$TLH, 
$Global:RAP=$RAP,      
$Global:SYS=$SYS,

$Global:UAS=$UAS,         
$Global:SFI=$SFI,          
$Global:LAC=$LAC,         
$Global:AFI=$AFI,         
    
        
##### OFFLINE  

$Global:HIV=$HIV,          
$Global:EVT=$EVT,         
$Global:FIL=$FIL,         
$Global:PRF=$PRF,         
$Global:WSE=$WSE,          
$Global:EET=$EET,         
$Global:THC=$THC,          
$Global:ICO=$ICO,          
$Global:MUL=$MUL,         
$Global:HPS=$HPS,          
$Global:DEX=$DEX,          
$Global:THA=$THA,
$Global:SRU=$SRU,
$Global:CRE=$CRE,

$Global:SKY=$SKY,

$Global:CHR=$CHR,
$Global:MFI=$MFI,
$Global:IEX=$IEX,
$Global:EDG=$EDG,
$Global:SAF=$SAF,
$Global:OPE=$OPE,
$Global:TOR=$TOR,

$Global:OUT=$OUT,

$Global:COD=$COD,
$Global:CGD=$CGD,
$Global:CDB=$CDB


<##################################################################################################################################>
<############  GENERAL CONFIGURATIONS AND SETUPS  ####################################>
<##################################################################################################################################>

<# GLOBAL VARIABLES #>
$HOSTNAME = hostname
$OS = ((Get-CimInstance win32_operatingsystem).name).split(" ")[2] <# Intead of collecting the windows version: XP, Vista, 7, 10, ... should be according to the core #>
$USERS = Get-LocalUser | ? { $_.Enabled } | Select-Object -ExpandProperty Name
$SIDS = Get-ChildItem "REGISTRY::HKEY_USERS" | ForEach-Object { ($_.Name).Split("\")[1] } # list of user SIDs
$ARCH = $env:PROCESSOR_ARCHITECTURE
$SCRIPTPATH = split-path -parent $MyInvocation.MyCommand.Definition
    
<# defines according to architecture which version of Rawcpoy and SigCheck to use #>
if($ARCH -eq "AMD64") {
    $RAW_EXE = "$SCRIPTPATH\bin\RawCopy64.exe"
    $SIG_EXE = "$SCRIPTPATH\bin\sigcheck64.exe"
    $SQL_DBX_EXE = "$SCRIPTPATH\bin\sqlite-dbx-win64.exe"
    $OPEN_SAVED_FILES_VIEW = "$SCRIPTPATH\bin\opensavefilesview-x64\OpenSaveFilesView.exe" # not used
    
} else {
    $RAW_EXE = "$SCRIPTPATH\bin\RawCopy.exe"
    $SIG_EXE = "$SCRIPTPATH\bin\sigcheck.exe"
    $SQL_DBX_EXE = "$SCRIPTPATH\bin\sqlite-dbx-win32.exe"
    $OPEN_SAVED_FILES_VIEW = "$SCRIPTPATH\bin\opensavefilesview\OpenSaveFilesView.exe"
    
}

$UsedParameters = $PSBoundParameters.Keys <# TODO: Will use this variable to check which parameters were inserted in the command line and therefore don't need confirmation #>


<##################################################################################################################################>
<############ E V I D E N C E   C O L L E C T I O N ###############################################################################>
<##################################################################################################################################>

<##################################################################################################################################>
<############  LIVE SYSTEM  /  VOLATILE ###########################################################################################>
<##################################################################################################################################>

<########### S Y S T E M   T I M E #################> # TIM
Function Collect-Time {
    
    if ( -Not ( Test-Path $Global:Destiny\$HOSTNAME\System_Info\ ) ) { New-Item -ItemType directory -Path $Global:Destiny\$HOSTNAME\System_Info\ > $null }

    Write-Host "[+] Collecting Date and Timezone ..." -ForegroundColor Green
    try
    {
        Get-Date > "$Global:Destiny\$HOSTNAME\System_Info\Date_Time_TimeZone.txt"  # Other options: cmd.exe /c Write-Host %DATE% %TIME% OR  cmd.exe /c "date /t & time /t"
        Get-TimeZone >> "$Global:Destiny\$HOSTNAME\System_Info\Date_Time_TimeZone.txt"
    }
    catch
    {
        Report-Error -evidence "Date or Timezone"
    }
}

<########### M E M O R Y   D U M P #################> # RAM
Function Collect-Memory-Dump {

    Write-Host "[+] Collecting Memory Dump ..." -ForegroundColor Green

    if ( -Not ( Test-Path "$Global:Destiny\$HOSTNAME\MEMORY_DUMP" ) ) { New-Item -ItemType directory -Path "$Global:Destiny\$HOSTNAME\MEMORY_DUMP" > $null }
    
    try {
        cmd.exe /c $SCRIPTPATH\bin\winpmem_1.6.2.exe $Global:Destiny\$HOSTNAME\MEMORY_DUMP\"$HOSTNAME".raw > $null
        Write-Host "`t└>Successfully collected" -ForegroundColor DarkGreen
    } catch {
        Report-Error -evidence "Memory Dump"
    }
} 


<########### N E T W O R K #########################> # NET
Function Collect-Network-Information {
    
    if ( -Not ( Test-Path "$Global:Destiny\$HOSTNAME\Network" ) ) { New-Item -ItemType directory -Path "$Global:Destiny\$HOSTNAME\Network" > $null }
    
    Write-Host "[+] Collecting TCP Connections ..." -ForegroundColor Green
    try
    {
        Get-NetTCPConnection | ? {($_.State -eq "Established")} | Sort-Object -Property RemoteAddress | Select-Object CreationTime, LocalAddress, LocalPort, RemoteAddress, RemotePort, State, AppliedSetting, OwningProcess, @{Name="Process";Expression={(Get-Process -Id $_.OwningProcess).ProcessName }}, @{Name="Proc. Path:";Expression={(Get-Process -Id $_.OwningProcess).Path }}, @{Name="CMD Line:";Expression={(Get-CimInstance -ClassName Win32_Process | where ProcessID -eq $_.OwningProcess).CommandLine }} | Export-Csv "$Global:Destiny\$HOSTNAME\Network\TCP_Connections_Established.csv"
        Get-NetTCPConnection | ? {($_.State -eq "Bound")} | Sort-Object -Property RemoteAddress | Select-Object CreationTime, LocalAddress, LocalPort, RemoteAddress, RemotePort, State, AppliedSetting, OwningProcess, @{Name="Process";Expression={(Get-Process -Id $_.OwningProcess).ProcessName }},@{Name="Proc. Path:";Expression={(Get-Process -Id $_.OwningProcess).Path }}, @{Name="CMD Line:";Expression={(Get-CimInstance -ClassName Win32_Process | where ProcessID -eq $_.OwningProcess).CommandLine }} | Export-Csv "$Global:Destiny\$HOSTNAME\Network\TCP_Connections_Bound.csv"
        Get-NetTCPConnection | ? {($_.State -eq "Listen")} | Sort-Object -Property RemoteAddress | Select-Object CreationTime, LocalAddress, LocalPort, RemoteAddress, RemotePort, State, AppliedSetting, OwningProcess, @{Name="Process";Expression={(Get-Process -Id $_.OwningProcess).ProcessName }},@{Name="Proc. Path:";Expression={(Get-Process -Id $_.OwningProcess).Path }}, @{Name="CMD Line:";Expression={(Get-CimInstance -ClassName Win32_Process | where ProcessID -eq $_.OwningProcess).CommandLine }} | Export-Csv "$Global:Destiny\$HOSTNAME\Network\TCP_Connections_Listen.csv"
        Get-NetTCPConnection | ? {($_.State -eq "TimeWait")} | Sort-Object -Property RemoteAddress | Select-Object CreationTime, LocalAddress, LocalPort, RemoteAddress, RemotePort, State, AppliedSetting, OwningProcess, @{Name="Process";Expression={(Get-Process -Id $_.OwningProcess).ProcessName }},@{Name="Proc. Path:";Expression={(Get-Process -Id $_.OwningProcess).Path }}, @{Name="CMD Line:";Expression={(Get-CimInstance -ClassName Win32_Process | where ProcessID -eq $_.OwningProcess).CommandLine }} | Export-Csv "$Global:Destiny\$HOSTNAME\Network\TCP_Connections_TimeWait.csv"
        Get-NetTCPConnection | ? {($_.State -eq "SynSent")} | Sort-Object -Property RemoteAddress | Select-Object CreationTime, LocalAddress, LocalPort, RemoteAddress, RemotePort, State, AppliedSetting, OwningProcess, @{Name="Process";Expression={(Get-Process -Id $_.OwningProcess).ProcessName }},@{Name="Proc. Path:";Expression={(Get-Process -Id $_.OwningProcess).Path }}, @{Name="CMD Line:";Expression={(Get-CimInstance -ClassName Win32_Process | where ProcessID -eq $_.OwningProcess).CommandLine }} | Export-Csv "$Global:Destiny\$HOSTNAME\Network\TCP_Connections_SynSent.csv"
        Get-NetTCPConnection | Select-Object *, @{Name="Process";Expression={(Get-Process -Id $_.OwningProcess).ProcessName }},@{Name="Proc. Path:";Expression={(Get-Process -Id $_.OwningProcess).Path }}, @{Name="CMD Line:";Expression={(Get-CimInstance -ClassName Win32_Process | where ProcessID -eq $_.OwningProcess).CommandLine }} | Export-Csv "$Global:Destiny\$HOSTNAME\Network\TCP_Connections_All.csv"
    }
    catch
    {
        Report-Error -evidence "TCP Connections"
    }


    Write-Host "[+] Collecting UDP Connections ..." -ForegroundColor Green
    try
    {
        Get-NetUDPEndpoint | Select-Object *, @{Name="Process";Expression={(Get-Process -Id $_.OwningProcess).ProcessName }},@{Name="Proc. Path:";Expression={(Get-Process -Id $_.OwningProcess).Path }}, @{Name="CMD Line:";Expression={(Get-CimInstance -ClassName Win32_Process | where ProcessID -eq $_.OwningProcess).CommandLine }} | Export-Csv "$Global:Destiny\$HOSTNAME\Network\UDP_Connections.csv" 
    }
    catch
    {
        Report-Error -evidence "UDP Connections"
    }
    
    
    Write-Host "[+] Collecting NetBIOS Active Connections ..." -ForegroundColor Green
    try
    {
        cmd.exe /c nbtstat -S > "$Global:Destiny\$HOSTNAME\Network\NetBIOS_Active_Connections.txt"
    }
    catch
    {
        Report-Error -evidence "NetBIOS Active Connections"
    }

    
    Write-Host "[+] Collecting Remote Established Sessions ..." -ForegroundColor Green    
    try
    {
    
        cmd.exe /c net sessions > "$Global:Destiny\$HOSTNAME\Network\LAN_Established_Sessions.txt"
    }
    catch
    {
        Report-Error -evidence "Remote Established Sessions"
    }

    
    Write-Host "[+] Collecting Info of Remotely Open/Locked files ..." -ForegroundColor Green
    try
    {
        cmd.exe /c net file > "$Global:Destiny\$HOSTNAME\Network\LAN_Open_Locked_Files.txt"
    }
    catch
    {
        Report-Error -evidence "Remotely Open/Locked files"
    }


    Write-Host "[+] Collecting Network Configuration ..." -ForegroundColor Green
    try
    {
        if ( -Not ( Test-Path "$Global:Destiny\$HOSTNAME\Network\Raw_Files" ) ) { New-Item -ItemType directory -Path "$Global:Destiny\$HOSTNAME\Network\Raw_Files" > $null }
           
        Get-NetAdapter | Select-Object * | Export-Csv "$Global:Destiny\$HOSTNAME\Network\Network_Visible_Adapters_Complete.csv"
        Get-NetAdapter | Select-Object ComponentID, CreationClassName, DeviceID, DriverDescription, DriverFileName, DriverInformation, DriverName, Hidden, ifAlias, ifDesc, LinkLayerAddress | Export-Csv "$Global:Destiny\$HOSTNAME\Network\Network_Visible_Adapters_Resume.csv"
        # Get-CimInstance Win32_NetworkAdapterConfiguration | Select-Object * | Export-Csv "$Global:Destiny\$HOSTNAME\Network\Network_All_Adapters_Complete.csv"
        # Get-CimInstance Win32_NetworkAdapterConfiguration | Export-Csv "$Global:Destiny\$HOSTNAME\Network\Network_All_Adapters_Resume.csv"
        
        cmd.exe /c type "$Global:Source\windows\system32\drivers\etc\hosts" > "$Global:Destiny\$HOSTNAME\Network\Raw_Files\hosts_file"

        Get-CimInstance Win32_MappedLogicalDisk | select Name, ProviderName, FileSystem, Size, FreeSpace | Export-Csv "$Global:Destiny\$HOSTNAME\Network\Mapped_Drives_ps.csv" # cmd.exe /c net use > "$Global:Destiny\$HOSTNAME\Network\Mapped_Drives_cmd.txt"
        Get-SmbShare | Export-Csv "$Global:Destiny\$HOSTNAME\Network\Shared_Folders.csv" #  Get-CimInstance Win32_Share || cmd.exe /c net share > "$Global:Destiny\$HOSTNAME\Network\Shared_Folders.txt"
    }
    catch
    {
        Report-Error -evidence "Network Configuration"
    }


    Write-Host "[+] Collecting DNS Cache ..." -ForegroundColor Green
    try
    {
        Get-DnsClientCache > "$Global:Destiny\$HOSTNAME\Network\DNS_Cache.csv"
    }
    catch
    {
        Report-Error -evidence "DNS Cache"
    }


    Write-Host "[+] Collecting ARP Cache ..." -ForegroundColor Green
    try
    {
        cmd.exe /c arp -a > "$Global:Destiny\$HOSTNAME\Network\ARPCache.txt"
    }
    catch
    {
        Report-Error -evidence "ARP Cache"
    }


    Write-Host "[+] Collecting Info from WIFI Network ..." -ForegroundColor Green
    try
    {
        cmd.exe /c netsh wlan show profiles > "$Global:Destiny\$HOSTNAME\Network\WIFI_Profiles.txt"
        cmd.exe /c netsh wlan show all > "$Global:Destiny\$HOSTNAME\Network\WIFI_All_Configuration.txt"
        cmd.exe /c netsh wlan export profile folder=$Global:Destiny\$HOSTNAME\Network\ > $null

        cmd.exe /c netsh wlan show profiles | Select-String "All User Profile" | ForEach {
             $bla = netsh wlan show profiles name=$(($_ -split ":")[1].Trim()) key="clear"
             $SSID = ((($bla | Select-String "SSID Name") -split ":")[1].Trim())
             $KEY = ((($bla | Select-string "Key Content") -split ":")[1].Trim())
             Write-Host "SSID: $SSID | Key: $KEY" -ForegroundColor Green # create the object
        }
        
    } 
    catch 
    {
        Report-Error -evidence "WIFI Info"
    }



}

<########### S E R V I C E S   P R O C E S S E S ###> # SAP
Function Collect-Services-and-Processes {
    
    if ( -Not ( Test-Path $Global:Destiny\$HOSTNAME\Services_Processes\ ) ) { New-Item -ItemType directory -Path $Global:Destiny\$HOSTNAME\Services_Processes\ > $null }


    Write-Host "[+] Collecting Services ..." -ForegroundColor Green
    try
    {
        Get-Service | Where-Object {$_.Status -eq "Running"} >> "$Global:Destiny\$HOSTNAME\Services_Processes\3.Services.txt"
        Get-Service | Where-Object {$_.Status -eq "Stopped"} >> "$Global:Destiny\$HOSTNAME\Services_Processes\3.Services.txt"
        Get-CimInstance -ClassName Win32_Service | Select-Object Name, DisplayName, StartMode, State, PathName, StartName, ServiceType >> "$Global:Destiny\$HOSTNAME\Services_Processes\3.Services.txt"
        echo "Details for each " >> "$Global:Destiny\$HOSTNAME\Services_Processes\3.Services.txt"
        Get-CimInstance -ClassName Win32_Service | Select-Object * >> "$Global:Destiny\$HOSTNAME\Services_Processes\3.Services.txt"
        Get-Service | Select-Object * >> "$Global:Destiny\$HOSTNAME\Services_Processes\3.Services.txt"
    }
    catch
    {
        Report-Error -evidence "Services"
    }

    
    Write-Host "[+] Collecting Processes ..." -ForegroundColor Green
    try
    {
        echo "Resume 1: " > $Global:Destiny\$HOSTNAME\Services_Processes\"4.Processes.txt"
        Get-Process | Sort-Object -Property id >> $Global:Destiny\$HOSTNAME\Services_Processes\"4.Processes.txt"
        echo "Resume 2: " >> $Global:Destiny\$HOSTNAME\"4.Processes.txt"
        Get-CimInstance -ClassName Win32_Process | Sort-Object ProcessId >> $Global:Destiny\$HOSTNAME\Services_Processes\"4.Processes.txt"
        echo "Details 1: " >> $Global:Destiny\$HOSTNAME\"4.Processes.txt"
        Get-Process | Sort-Object -Property id | Select-Object * >> $Global:Destiny\$HOSTNAME\Services_Processes\"4.Processes.txt"
        echo "Details 2: " >> $Global:Destiny\$HOSTNAME\"4.Processes.txt"
        Get-CimInstance -ClassName Win32_Process | Select-Object * >> $Global:Destiny\$HOSTNAME\Services_Processes\"4.Processes.txt"
        <# using cpu using in descending order: Get-Process | Sort-Object -Property cpu -Descending > .\004.Processes.txt #>
        <# otra opcion: Get-Process | Select-Object Name, Path, Company, CPU, Product, TotalProcessorTime, StartTime, PagedSystemMemorySize #>
        <# TODO: Analize the above results and decide which to use. Compare them with the below code, that crosses parent process with child process:
        
            $runningProcesses = Get-CimInstance -ClassName Win32_Process |
                Select-Object CreationDate, ProcessName, ProcessId, CommandLine, ParentProcessId

            for($i=0; $i -le $runningProcesses.count; $i++)
            {
                $runningProcesses[$i]

                Write-Host("Parent:")`                (Get-CimInstance -ClassName Win32_Process | where ProcessId -eq $runningProcesses[$i].ParentProcessId).ProcessName
                Write-Host("Parent CmdLine:")`                (Get-CimInstance -ClassName Win32_Process | where ProcessId -eq $runningProcesses[$i].ParentProcessId).CommandLine
                Write-Host("--------------------")
            }
        #>
    }
    catch
    {
        Report-Error -evidence "Processes"
    }
}

<########### S C H E D U L E D   T A S K S #########> # STJ
# TODO: Copy the folder with tasks: C:\Windows\System32\Tasks - https://attack.mitre.org/techniques/T1053/
Function Collect-Scheduled-Tasks-Jobs {

    if ( -Not ( Test-Path $Global:Destiny\$HOSTNAME\Tasks_Jobs ) ) { New-Item -ItemType directory -Path $Global:Destiny\$HOSTNAME\Tasks_Jobs > $null }
    
    Write-Host "[+] Collecting Scheduled Tasks ..." -ForegroundColor Green    
    try
    {
        cmd.exe /c schtasks > "$Global:Destiny\$HOSTNAME\Tasks_Jobs\_RESUME_LIST_1.txt"
        Get-ScheduledTask | Select-Object TaskName, TaskPath, Date, Author, Actions, Triggers, Description,State | where Author -NotLike "Microsoft*" | where Author -NotLike "*SystemRoot*" | where Author -ne $null > "$Global:Destiny\$HOSTNAME\Tasks_Jobs\_RESUME_LIST_2.txt"
    }
    catch
    {
        Report-Error -evidence "Scheduled Tasks"
    }
    
    try 
    {
        Get-ScheduledTask | where Author -NotLike "Microsoft*" | where Author -NotLike "*SystemRoot*" | where Author -ne $null |  foreach {
             Export-ScheduledTask -TaskName $_.TaskName -TaskPath $_.TaskPath |
             Out-File (Join-Path "$Global:Destiny\$HOSTNAME\Tasks_Jobs" "$($_.TaskName).xml") #-WhatIf
             # cmd /c schtasks /query /tn "\Microsoft\Windows\WCM\WiFiTask" /xml
        }  
    } 
    catch 
    {
        Report-Error -evidence "Scheduled Tasks"
    }


    Write-Host "[+] Collecting Scheduled Tasks ..." -ForegroundColor Green    
    try
    {
        Get-ScheduledJob > $Global:Destiny\$HOSTNAME\Tasks_Jobs\Scheduled_jobs.txt
    }
    catch
    {
        Report-Error -evidence "Scheduled Jobs"
    }
}

<########### C O M M A N D   H I S T O R Y #########> # CPH
Function Collect-Command-History {
    
    if ( -Not ( Test-Path $Global:Destiny\$HOSTNAME\CMD_HISTORY ) ) { New-Item -ItemType directory -Path $Global:Destiny\$HOSTNAME\CMD_HISTORY > $null }
    
    foreach($u in $USERS)
    {
        if(Test-Path -Path "$Global:Source\Users\$u\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt")
        {
            try
            {
                New-Item -ItemType directory -Path $Global:Destiny\$HOSTNAME\CMD_HISTORY\$u > $null
                type "$Global:Source\Users\$u\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt" > "$Global:Destiny\$HOSTNAME\CMD_HISTORY\$u\ConsoleHost_history.txt"
            }
            catch
            {
                Report-Error -evidence "Command History"    
            }
        }
    }

    
    Write-Host "[+] Collecting CMD_History, Scheduled Progams and Environment Variables ... " -ForegroundColor Green
    try
    {
        cmd.exe /c doskey /history > "$Global:Destiny\$HOSTNAME\CMD_HISTORY\CL_CMD_History.txt"
        type (Get-PSReadlineOption).HistorySavePath > "$Global:Destiny\$HOSTNAME\CMD_HISTORY\PS_CMD_History.txt" <#TODO: Check if the above code for each user always works, maybe the path may change for different OS and Powershell versions. #>
    } 
    catch 
    {
        Report-Error -evidence "CL Command History"
    }

}

<########### I N S T A L L E D   S O F T W A R E ###> # INS
Function Collect-Installed-Software {

    if ( -Not ( Test-Path $Global:Destiny\$HOSTNAME\Software ) ) { New-Item -ItemType directory -Path $Global:Destiny\$HOSTNAME\Software > $null }

    Write-Host "[+] Collecting List of Installed Software ..." -ForegroundColor Green
    try
    {
        # cmd.exe /c reg export "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Uninstall" "$Global:Destiny\$HOSTNAME\Software\5.InstalledSoftware.reg" > $null
        Get-ChildItem "$Global:Source\Program Files" | ?{$_.PSIsContainer} >> "$Global:Destiny\$HOSTNAME\Software\5.InstalledSoftware.txt"
        Get-ChildItem "$Global:Source\Program Files (x86)" | ?{$_.PSIsContainer} >> "$Global:Destiny\$HOSTNAME\Software\5.InstalledSoftware.txt"
        Get-CimInstance -ClassName Win32_Product | Select-Object Name, Version, Vendor, InstallDate, InstallSource, PackageName, LocalPackage >> "$Global:Destiny\$HOSTNAME\Software\5.InstalledSoftware.txt"
        Get-ItemProperty "HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*" >> "$Global:Destiny\$HOSTNAME\Software\5.InstalledSoftware.txt"
        Get-ItemProperty "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*" >> "$Global:Destiny\$HOSTNAME\Software\5.InstalledSoftware.txt"

    } 
    catch 
    {
        Report-Error -evidence "List of Installed Software"
    }
}

<########### U S E R S   A N D   G R O U P S #######> # UGR
Function Collect-Users-Groups {
    
    if ( -Not ( Test-Path $Global:Destiny\$HOSTNAME\Users_Groups ) ) { New-Item -ItemType directory -Path $Global:Destiny\$HOSTNAME\Users_Groups > $null }
    
    Write-Host "[+] Collecting Users and Groups" -ForegroundColor Green
    try
    {
        Get-LocalUser                        > "$Global:Destiny\$HOSTNAME\Users_Groups\10.Users_And_Groups.txt"
        Get-LocalGroup                      >> "$Global:Destiny\$HOSTNAME\Users_Groups\10.Users_And_Groups.txt"
        Get-LocalGroupMember Administrators >> "$Global:Destiny\$HOSTNAME\Users_Groups\10.Users_And_Groups.txt"
        echo "Detail info about Users: "    >> "$Global:Destiny\$HOSTNAME\Users_Groups\10.Users_And_Groups.txt"
        Get-LocalUser | Select-Object *     >> "$Global:Destiny\$HOSTNAME\Users_Groups\10.Users_And_Groups.txt" # Alternative: Get-WmiObject -ClassName Win32_UserAccount | Select-Object *
    }
    catch
    {
        Report-Error -evidence "Users and Groups"
    }
}

<########### P E R S I S T E N C E #################> # PER
Function Collect-Persistence { 
    
    if ( -Not ( Test-Path $Global:Destiny\$HOSTNAME\Persistence ) ) { New-Item -ItemType directory -Path $Global:Destiny\$HOSTNAME\Persistence > $null }
    
    try{
        Write-Host "[+] Collecting Persistence " -ForegroundColor Green
        
        echo "Notes: Look for Strange Executables"                                                                              >> "$Global:Destiny\$HOSTNAME\Persistence\Persistence_RegistryRunKeys.txt"
        echo "More information: https://attack.mitre.org/techniques/T1060/"                                                     >> "$Global:Destiny\$HOSTNAME\Persistence\Persistence_RegistryRunKeys.txt"
        echo ""                                                                                                                 >> "$Global:Destiny\$HOSTNAME\Persistence\Persistence_RegistryRunKeys.txt" 
        
        # OLD - cmd.exe /c reg export "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run" "$Global:Destiny\$HOSTNAME\PERSISTENCE\HKCU_Run.reg" > $null
        Get-Item -Path "REGISTRY::HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run"                              >> "$Global:Destiny\$HOSTNAME\Persistence\Persistence_RegistryRunKeys.txt"

        # OLD - cmd.exe /c reg export "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\RunOnce" "$Global:Destiny\$HOSTNAME\PERSISTENCE\HKCU_RunOnce.reg" > $null
        Get-Item -Path "REGISTRY::HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\RunOnce"                          >> "$Global:Destiny\$HOSTNAME\Persistence\Persistence_RegistryRunKeys.txt"

        # OLD - cmd.exe /c reg export "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\RunOnce" "$Global:Destiny\$HOSTNAME\PERSISTENCE\HKCU_RunOnce.reg" > $null
        Get-Item -Path "REGISTRY::HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\RunOnceEx"                        >> "$Global:Destiny\$HOSTNAME\Persistence\Persistence_RegistryRunKeys.txt" 2> $null

        # OLD - cmd.exe /c reg export "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run" "$Global:Destiny\$HOSTNAME\PERSISTENCE\HKLM_Run.reg" > $null 
        Get-Item -Path "REGISTRY::HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run"                             >> "$Global:Destiny\$HOSTNAME\Persistence\Persistence_RegistryRunKeys.txt"

        # OLD - cmd.exe /c reg export "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunOnce" "$Global:Destiny\$HOSTNAME\PERSISTENCE\HKLM_RunOnce.reg" > $null 
        Get-Item -Path "REGISTRY::HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunOnce"                         >> "$Global:Destiny\$HOSTNAME\Persistence\Persistence_RegistryRunKeys.txt"
        
        # OLD - cmd.exe /c reg export "HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run" "$Global:Destiny\$HOSTNAME\PERSISTENCE\HKLM_WOW6432_Run.reg" > $null
        Get-Item -Path "REGISTRY::HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run"                 >> "$Global:Destiny\$HOSTNAME\Persistence\Persistence_RegistryRunKeys.txt"

        # OLD - cmd.exe /c reg export "HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce" "$Global:Destiny\$HOSTNAME\PERSISTENCE\HKLM_WOW6432_RunOnce.reg" > $null
        Get-Item -Path "REGISTRY::HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce"             >> "$Global:Destiny\$HOSTNAME\Persistence\Persistence_RegistryRunKeys.txt"

        # OLD - cmd.exe /c reg export "HKEY_USERS\.DEFAULT\Software\Microsoft\Windows\CurrentVersion\Run" "$Global:Destiny\$HOSTNAME\PERSISTENCE\HKU_Run.reg" > $null
        Get-Item -Path "REGISTRY::HKEY_USERS\.DEFAULT\Software\Microsoft\Windows\CurrentVersion\Run"                            >> "$Global:Destiny\$HOSTNAME\Persistence\Persistence_RegistryRunKeys.txt"

        # OLD - cmd.exe /c reg export "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunServices" "$Global:Destiny\$HOSTNAME\PERSISTENCE\HKLM_RunServices.reg" > $null
        if(Test-Path "REGISTRY::HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunServices") {
            Get-Item -Path "REGISTRY::HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunServices"                 >> "$Global:Destiny\$HOSTNAME\Persistence\Persistence_RegistryRunKeys.txt"
        }

        # OLD - cmd.exe /c reg export "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce" "$Global:Destiny\$HOSTNAME\PERSISTENCE\HKLM_RunServicesOnce.reg" > $null
        if(Test-Path "REGISTRY::HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce") {
            Get-Item -Path "REGISTRY::HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce"             >> "$Global:Destiny\$HOSTNAME\Persistence\Persistence_RegistryRunKeys.txt"
        }

        # OLD - cmd.exe /c reg export "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\Userinit" "$Global:Destiny\$HOSTNAME\PERSISTENCE\HKLM_Userinit.reg" > $null
        if(Test-Path "REGISTRY::HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\Userinit") {
            Get-Item -Path "REGISTRY::HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\Userinit"        >> "$Global:Destiny\$HOSTNAME\Persistence\Persistence_RegistryRunKeys.txt"
        }

        # OLD - cmd.exe /c reg export "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\RunServices" "$Global:Destiny\$HOSTNAME\PERSISTENCE\HKCU_RunServices.reg" > $null
        if(Test-Path "REGISTRY::HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\RunServices") {
            Get-Item -Path "REGISTRY::HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\RunServices"                  >> "$Global:Destiny\$HOSTNAME\Persistence\Persistence_RegistryRunKeys.txt"
        }

        # OLD - cmd.exe /c reg export "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce" "$Global:Destiny\$HOSTNAME\PERSISTENCE\HKCU_RunServicesOnce.reg" > $null
        if(Test-Path "REGISTRY::HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce") {
            Get-Item -Path "REGISTRY::HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce"              >> "$Global:Destiny\$HOSTNAME\Persistence\Persistence_RegistryRunKeys.txt"
        }

        # OLD - cmd.exe /c reg export "HKEY_CURRENT_USER\Software\Microsoft\Windows NT\CurrentVersion\Windows" "$Global:Destiny\$HOSTNAME\PERSISTENCE\HKCU_Windows.reg" > $null
        if(Test-Path "REGISTRY::HKEY_CURRENT_USER\Software\Microsoft\Windows NT\CurrentVersion\Windows") {
            Get-Item -Path "REGISTRY::HKEY_CURRENT_USER\Software\Microsoft\Windows NT\CurrentVersion\Windows"                   >> "$Global:Destiny\$HOSTNAME\Persistence\Persistence_RegistryRunKeys.txt"
        }

        # Winlogon Helper DLL - https://attack.mitre.org/techniques/T1004/
        if(Test-Path "REGISTRY::HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Winlogon") {
            echo "Notes: "                                                                                                       > "$Global:Destiny\$HOSTNAME\Persistence\Persistence_WinlogonHalperDLL.txt"
            echo "    Winlogon\Notify - points to notification package DLLs that handle Winlogon events"                        >> "$Global:Destiny\$HOSTNAME\Persistence\Persistence_WinlogonHalperDLL.txt"
            echo "    Winlogon\Userinit - points to userinit.exe, the user initialization program executed when a user logs on" >> "$Global:Destiny\$HOSTNAME\Persistence\Persistence_WinlogonHalperDLL.txt"
            echo "    Winlogon\Shell - points to explorer.exe, the system shell executed when a user logs on"                   >> "$Global:Destiny\$HOSTNAME\Persistence\Persistence_WinlogonHalperDLL.txt"
            echo ""                                                                                                             >> "$Global:Destiny\$HOSTNAME\Persistence\Persistence_WinlogonHalperDLL.txt"
            echo "More information: https://attack.mitre.org/techniques/T1004/"                                                 >> "$Global:Destiny\$HOSTNAME\Persistence\Persistence_WinlogonHalperDLL.txt"
            echo ""                                                                                                             >> "$Global:Destiny\$HOSTNAME\Persistence\Persistence_WinlogonHalperDLL.txt"
            
            Get-Item -Path "REGISTRY::HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Winlogon"     >> "$Global:Destiny\$HOSTNAME\Persistence\Persistence_WinlogonHalperDLL.txt"
        }
        if(Test-Path "REGISTRY::HKEY_CURRENT_USER\Software\Microsoft\Windows NT\CurrentVersion\Winlogon") {
            Get-Item -Path "REGISTRY::HKEY_CURRENT_USER\Software\Microsoft\Windows NT\CurrentVersion\Winlogon"                  >> "$Global:Destiny\$HOSTNAME\Persistence\Persistence_WinlogonHalperDLL.txt"
        }

        # Time Providers - https://attack.mitre.org/techniques/T1209/
        if(Test-Path "REGISTRY::HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\W32Time\TimeProviders\") {
            echo "Notes: Look for Strange DLLs"                                                                             >> "$Global:Destiny\$HOSTNAME\Persistence\Persistence_TimeProviders.txt"
            echo "More information: https://attack.mitre.org/techniques/T1209/"                                             >> "$Global:Destiny\$HOSTNAME\Persistence\Persistence_TimeProviders.txt"
            echo ""                                                                                                         >> "$Global:Destiny\$HOSTNAME\Persistence\Persistence_TimeProviders.txt" 
            Get-Item -Path "REGISTRY::HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\W32Time\TimeProviders\*"         >> "$Global:Destiny\$HOSTNAME\Persistence\Persistence_TimeProviders.txt"
        }

        # SIP and Trust Provider Hijacking - https://attack.mitre.org/techniques/T1198/
        # TODO - Hash the DLL's and send them to virustotal and receive the results
        # HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Microsoft\Cryptography\OID\EncodingType 0\CryptSIPDllVerifyIndirectData
        if(Test-Path "REGISTRY::HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Microsoft\Cryptography\OID\EncodingType 0\CryptSIPDllVerifyIndirectData") {
            echo "Notes: Look for Strange DLLs"                                                                                                          >> "$Global:Destiny\$HOSTNAME\Persistence\Persistence_SIP&TrustProviderHijacking.txt"
            echo "More information: https://attack.mitre.org/techniques/T1198/"                                                                          >> "$Global:Destiny\$HOSTNAME\Persistence\Persistence_SIP&TrustProviderHijacking.txt"
            echo ""                                                                                                                                      >> "$Global:Destiny\$HOSTNAME\Persistence\Persistence_SIP&TrustProviderHijacking.txt"   
            Get-Item -Path "REGISTRY::HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Microsoft\Cryptography\OID\EncodingType 0\CryptSIPDllVerifyIndirectData\*" >> "$Global:Destiny\$HOSTNAME\Persistence\Persistence_SIP&TrustProviderHijacking.txt"
        }
        # HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Microsoft\Cryptography\OID\EncodingType 0\CryptSIPDllGetSignedDataMsg
        if(Test-Path "REGISTRY::HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Microsoft\Cryptography\OID\EncodingType 0\CryptSIPDllGetSignedDataMsg") {
            Get-Item -Path "REGISTRY::HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Microsoft\Cryptography\OID\EncodingType 0\CryptSIPDllGetSignedDataMsg\*" >> "$Global:Destiny\$HOSTNAME\Persistence\Persistence_SIP&TrustProviderHijacking.txt"
        }
        # HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Microsoft\Cryptography\Providers\Trust\FinalPolicy
        if(Test-Path "REGISTRY::HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Microsoft\Cryptography\Providers\Trust\FinalPolicy") {
            Get-Item -Path "REGISTRY::HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Microsoft\Cryptography\Providers\Trust\FinalPolicy\*" >> "$Global:Destiny\$HOSTNAME\Persistence\Persistence_SIP&TrustProviderHijacking.txt"
        }
        # HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Cryptography\OID\EncodingType 0\CryptSIPDllVerifyIndirectData
        if(Test-Path "REGISTRY::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Cryptography\OID\EncodingType 0\CryptSIPDllVerifyIndirectData") {
            Get-Item -Path "REGISTRY::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Cryptography\OID\EncodingType 0\CryptSIPDllVerifyIndirectData\*" >> "$Global:Destiny\$HOSTNAME\Persistence\Persistence_SIP&TrustProviderHijacking.txt"
        }
        # HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Cryptography\OID\EncodingType 0\CryptSIPDllGetSignedDataMsg
        if(Test-Path "REGISTRY::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Cryptography\OID\EncodingType 0\CryptSIPDllGetSignedDataMsg") {
            Get-Item -Path "REGISTRY::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Cryptography\OID\EncodingType 0\CryptSIPDllGetSignedDataMsg\*" >> "$Global:Destiny\$HOSTNAME\Persistence\Persistence_SIP&TrustProviderHijacking.txt"
        }
        # HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Cryptography\Providers\Trust\FinalPolicy
        if(Test-Path "REGISTRY::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Cryptography\Providers\Trust\FinalPolicy") {
            Get-Item -Path "REGISTRY::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Cryptography\Providers\Trust\FinalPolicy\*" >> "$Global:Destiny\$HOSTNAME\Persistence\Persistence_SIP&TrustProviderHijacking.txt"
        }


        # Security Support Provider (SSP) - Local Security Authority (LSA) - https://attack.mitre.org/techniques/T1101/
        if(Test-Path "REGISTRY::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa") {
            echo "Notes: Check Security Packages configuration   "                                            >> "$Global:Destiny\$HOSTNAME\Persistence\Persistence_SSP-LSA.txt"
            echo "More information: https://attack.mitre.org/techniques/T1101/"                               >> "$Global:Destiny\$HOSTNAME\Persistence\Persistence_SSP-LSA.txt"
            echo ""                                                                                           >> "$Global:Destiny\$HOSTNAME\Persistence\Persistence_SSP-LSA.txt"
            Get-Item -Path "REGISTRY::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa\"               >> "$Global:Destiny\$HOSTNAME\Persistence\Persistence_SSP-LSA.txt"
        }
        if(Test-Path "REGISTRY::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa\OSConfig") {
            Get-Item -Path "REGISTRY::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa\OSConfig\"      >> "$Global:Destiny\$HOSTNAME\Persistence\Persistence_SSP-LSA.txt"
        }

        # Port Monitors - https://attack.mitre.org/techniques/T1013/
        if(Test-Path "REGISTRY::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Print\Monitors") {
            echo "Notes: Check DLLs of: Local Port, Standard TCP/IP Port, USB Monitor, WSD Port"              >> "$Global:Destiny\$HOSTNAME\Persistence\Persistence_PortMonitors.txt"
            echo "More information: https://attack.mitre.org/techniques/T1013/"                               >> "$Global:Destiny\$HOSTNAME\Persistence\Persistence_PortMonitors.txt"
            echo ""                                                                                           >> "$Global:Destiny\$HOSTNAME\Persistence\Persistence_PortMonitors.txt"
            Get-Item -Path "REGISTRY::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Print\Monitors\*"   >> "$Global:Destiny\$HOSTNAME\Persistence\Persistence_PortMonitors.txt"
        }

        # Office Test - https://attack.mitre.org/techniques/T1137/
        if(Test-Path "REGISTRY::HKEY_CURRENT_USER\Software\Microsoft\Office test\Special\Perf") {
            echo "More information: https://attack.mitre.org/techniques/T1137/"                               >> "$Global:Destiny\$HOSTNAME\Persistence\Persistence_OfficeTest.txt"
            echo ""                                                                                           >> "$Global:Destiny\$HOSTNAME\Persistence\Persistence_OfficeTest.txt"
            Get-Item -Path "REGISTRY::HKEY_CURRENT_USER\Software\Microsoft\Office test\Special\Perf\"         >> "$Global:Destiny\$HOSTNAME\Persistence\Persistence_OfficeTest.txt"
            Get-Item -Path "REGISTRY::HKEY_CURRENT_USER\Software\Microsoft\Office test\Special\Perf\*"        >> "$Global:Destiny\$HOSTNAME\Persistence\Persistence_OfficeTest.txt"
        }


        # Change Default File Association - https://attack.mitre.org/techniques/T1042/
        if(Test-Path "REGISTRY::HKEY_CLASSES_ROOT\batfile\shell\open\command") {
            echo "BAT files:"                                                                                      > "$Global:Destiny\$HOSTNAME\Persistence\Persistence_FileAssociation.txt"
            Get-Item -Path "REGISTRY::HKEY_CLASSES_ROOT\batfile\shell\open\command"                               >> "$Global:Destiny\$HOSTNAME\Persistence\Persistence_FileAssociation.txt"
            Get-Item -Path "REGISTRY::HKEY_CLASSES_ROOT\batfile\shell\print\command"                               >> "$Global:Destiny\$HOSTNAME\Persistence\Persistence_FileAssociation.txt"
        }
        if(Test-Path "REGISTRY::HKEY_LOCAL_MACHINE\software\Classes\batfile\shell\open\command") {
            echo "BAT file:"                                                                                      >> "$Global:Destiny\$HOSTNAME\Persistence\Persistence_FileAssociation.txt"
            Get-Item -Path "REGISTRY::HKEY_LOCAL_MACHINE\software\Classes\batfile\shell\open\command"             >> "$Global:Destiny\$HOSTNAME\Persistence\Persistence_FileAssociation.txt"
            Get-Item -Path "REGISTRY::HKEY_LOCAL_MACHINE\software\Classes\batfile\shell\print\command"             >> "$Global:Destiny\$HOSTNAME\Persistence\Persistence_FileAssociation.txt"
        }
        if(Test-Path "REGISTRY::HKEY_CLASSES_ROOT\cmdfile\shell\open\command") {
            echo "CMD files:"                                                                                     >> "$Global:Destiny\$HOSTNAME\Persistence\Persistence_FileAssociation.txt"
            Get-Item -Path "REGISTRY::HKEY_CLASSES_ROOT\cmdfile\shell\open\command"                               >> "$Global:Destiny\$HOSTNAME\Persistence\Persistence_FileAssociation.txt"
            Get-Item -Path "REGISTRY::HKEY_CLASSES_ROOT\cmdfile\shell\print\command"                               >> "$Global:Destiny\$HOSTNAME\Persistence\Persistence_FileAssociation.txt"
        }
        if(Test-Path "REGISTRY::HKEY_CLASSES_ROOT\comfile\shell\open\command") {
            echo "COM files:"                                                                                     >> "$Global:Destiny\$HOSTNAME\Persistence\Persistence_FileAssociation.txt"
            Get-Item -Path "REGISTRY::HKEY_CLASSES_ROOT\comfile\shell\open\command"                               >> "$Global:Destiny\$HOSTNAME\Persistence\Persistence_FileAssociation.txt"
            Get-Item -Path "REGISTRY::HKEY_CLASSES_ROOT\comfile\shell\print\command"                               >> "$Global:Destiny\$HOSTNAME\Persistence\Persistence_FileAssociation.txt"
        }
        if(Test-Path "REGISTRY::HKEY_LOCAL_MACHINE\software\Classes\comfile\shell\open\command") {
            echo "COM file:"                                                                                      >> "$Global:Destiny\$HOSTNAME\Persistence\Persistence_FileAssociation.txt"
            Get-Item -Path "REGISTRY::HKEY_LOCAL_MACHINE\software\Classes\comfile\shell\open\command"             >> "$Global:Destiny\$HOSTNAME\Persistence\Persistence_FileAssociation.txt"
            Get-Item -Path "REGISTRY::HKEY_LOCAL_MACHINE\software\Classes\comfile\shell\print\command"             >> "$Global:Destiny\$HOSTNAME\Persistence\Persistence_FileAssociation.txt"
        }
        if(Test-Path "REGISTRY::HKEY_CLASSES_ROOT\exefile\shell\open\command") {
            echo "EXE files:"                                                                                     >> "$Global:Destiny\$HOSTNAME\Persistence\Persistence_FileAssociation.txt"
            Get-Item -Path "REGISTRY::HKEY_CLASSES_ROOT\exefile\shell\open\command"                               >> "$Global:Destiny\$HOSTNAME\Persistence\Persistence_FileAssociation.txt"
            Get-Item -Path "REGISTRY::HKEY_CLASSES_ROOT\exefile\shell\print\command"                               >> "$Global:Destiny\$HOSTNAME\Persistence\Persistence_FileAssociation.txt"
        }
        if(Test-Path "REGISTRY::HKEY_LOCAL_MACHINE\software\Classes\exefile\shell\open\command") {
            echo "EXE file:"                                                                                      >> "$Global:Destiny\$HOSTNAME\Persistence\Persistence_FileAssociation.txt"
            Get-Item -Path "REGISTRY::HKEY_LOCAL_MACHINE\software\Classes\exefile\shell\open\command"             >> "$Global:Destiny\$HOSTNAME\Persistence\Persistence_FileAssociation.txt"
            Get-Item -Path "REGISTRY::HKEY_LOCAL_MACHINE\software\Classes\exefile\shell\print\command"             >> "$Global:Destiny\$HOSTNAME\Persistence\Persistence_FileAssociation.txt"
        }
        if(Test-Path "REGISTRY::HKEY_CLASSES_ROOT\htafile\shell\open\command") {
            echo "HTA files:"                                                                                     >> "$Global:Destiny\$HOSTNAME\Persistence\Persistence_FileAssociation.txt"
            Get-Item -Path "REGISTRY::HKEY_CLASSES_ROOT\htafile\shell\open\command"                               >> "$Global:Destiny\$HOSTNAME\Persistence\Persistence_FileAssociation.txt"
            Get-Item -Path "REGISTRY::HKEY_CLASSES_ROOT\htafile\shell\print\command"                               >> "$Global:Destiny\$HOSTNAME\Persistence\Persistence_FileAssociation.txt"
        }
        if(Test-Path "REGISTRY::HKEY_CLASSES_ROOT\https\shell\open\command") {
            echo "HTTPS:"                                                                                         >> "$Global:Destiny\$HOSTNAME\Persistence\Persistence_FileAssociation.txt"
            Get-Item -Path "REGISTRY::HKEY_CLASSES_ROOT\https\shell\open\command"                                 >> "$Global:Destiny\$HOSTNAME\Persistence\Persistence_FileAssociation.txt"
            Get-Item -Path "REGISTRY::HKEY_CLASSES_ROOT\https\shell\print\command"                                 >> "$Global:Destiny\$HOSTNAME\Persistence\Persistence_FileAssociation.txt"
        }
        if(Test-Path "REGISTRY::HKEY_CLASSES_ROOT\JSEfile\shell\open\command") {
            echo "JSE file:"                                                                                      >> "$Global:Destiny\$HOSTNAME\Persistence\Persistence_FileAssociation.txt"
            Get-Item -Path "REGISTRY::HKEY_CLASSES_ROOT\JSEfile\shell\open\command"                               >> "$Global:Destiny\$HOSTNAME\Persistence\Persistence_FileAssociation.txt"
            Get-Item -Path "REGISTRY::HKEY_CLASSES_ROOT\JSEfile\shell\print\command"                               >> "$Global:Destiny\$HOSTNAME\Persistence\Persistence_FileAssociation.txt"
        }
        if(Test-Path "REGISTRY::HKEY_CLASSES_ROOT\piffile\shell\open\command") {
            echo "PIF file:"                                                                                      >> "$Global:Destiny\$HOSTNAME\Persistence\Persistence_FileAssociation.txt"
            Get-Item -Path "REGISTRY::HKEY_CLASSES_ROOT\piffile\shell\open\command"                               >> "$Global:Destiny\$HOSTNAME\Persistence\Persistence_FileAssociation.txt"
            Get-Item -Path "REGISTRY::HKEY_CLASSES_ROOT\piffile\shell\print\command"                               >> "$Global:Destiny\$HOSTNAME\Persistence\Persistence_FileAssociation.txt"
        }
        if(Test-Path "REGISTRY::HKEY_LOCAL_MACHINE\software\Classes\piffile\shell\open\command") {
            echo "PIF file:"                                                                                      >> "$Global:Destiny\$HOSTNAME\Persistence\Persistence_FileAssociation.txt"
            Get-Item -Path "REGISTRY::HKEY_LOCAL_MACHINE\software\Classes\piffile\shell\open\command"             >> "$Global:Destiny\$HOSTNAME\Persistence\Persistence_FileAssociation.txt"
            Get-Item -Path "REGISTRY::HKEY_LOCAL_MACHINE\software\Classes\piffile\shell\print\command"             >> "$Global:Destiny\$HOSTNAME\Persistence\Persistence_FileAssociation.txt"
        }
        if(Test-Path "REGISTRY::HKEY_CLASSES_ROOT\regfile\shell\open\command") {
            echo "REG file:"                                                                                      >> "$Global:Destiny\$HOSTNAME\Persistence\Persistence_FileAssociation.txt"
            Get-Item -Path "REGISTRY::HKEY_CLASSES_ROOT\regfile\shell\open\command"                               >> "$Global:Destiny\$HOSTNAME\Persistence\Persistence_FileAssociation.txt"
            Get-Item -Path "REGISTRY::HKEY_CLASSES_ROOT\regfile\shell\print\command"                               >> "$Global:Destiny\$HOSTNAME\Persistence\Persistence_FileAssociation.txt"
        }
        if(Test-Path "REGISTRY::HKEY_CLASSES_ROOT\srcfile\shell\open\command") {
            echo "SRC file:"                                                                                      >> "$Global:Destiny\$HOSTNAME\Persistence\Persistence_FileAssociation.txt"
            Get-Item -Path "REGISTRY::HKEY_CLASSES_ROOT\srcfile\shell\open\command"                               >> "$Global:Destiny\$HOSTNAME\Persistence\Persistence_FileAssociation.txt"
            Get-Item -Path "REGISTRY::HKEY_CLASSES_ROOT\srcfile\shell\print\command"                               >> "$Global:Destiny\$HOSTNAME\Persistence\Persistence_FileAssociation.txt"
        }
        if(Test-Path "REGISTRY::HKEY_CLASSES_ROOT\txtfile\shell\open\command") {
            echo "TXT file:"                                                                                      >> "$Global:Destiny\$HOSTNAME\Persistence\Persistence_FileAssociation.txt"
            Get-Item -Path "REGISTRY::HKEY_CLASSES_ROOT\txtfile\shell\open\command"                               >> "$Global:Destiny\$HOSTNAME\Persistence\Persistence_FileAssociation.txt"
            Get-Item -Path "REGISTRY::HKEY_CLASSES_ROOT\txtfile\shell\print\command"                               >> "$Global:Destiny\$HOSTNAME\Persistence\Persistence_FileAssociation.txt"
        }
        if(Test-Path "REGISTRY::HKEY_CLASSES_ROOT\VBSfile\shell\open\command") {
            echo "VBS file:"                                                                                      >> "$Global:Destiny\$HOSTNAME\Persistence\Persistence_FileAssociation.txt"
            Get-Item -Path "REGISTRY::HKEY_CLASSES_ROOT\vbsfile\shell\open\command"                               >> "$Global:Destiny\$HOSTNAME\Persistence\Persistence_FileAssociation.txt"
            Get-Item -Path "REGISTRY::HKEY_CLASSES_ROOT\vbsfile\shell\print\command"                               >> "$Global:Destiny\$HOSTNAME\Persistence\Persistence_FileAssociation.txt"
        }
        if(Test-Path "REGISTRY::HKEY_CLASSES_ROOT\WSFfile\shell\open\command") {
            echo "WSF file:"                                                                                      >> "$Global:Destiny\$HOSTNAME\Persistence\Persistence_FileAssociation.txt"
            Get-Item -Path "REGISTRY::HKEY_CLASSES_ROOT\wsffile\shell\open\command"                               >> "$Global:Destiny\$HOSTNAME\Persistence\Persistence_FileAssociation.txt"
            Get-Item -Path "REGISTRY::HKEY_CLASSES_ROOT\wsffile\shell\print\command"                               >> "$Global:Destiny\$HOSTNAME\Persistence\Persistence_FileAssociation.txt"
        }

        # AppInit DLLs - https://attack.mitre.org/techniques/T1103/
        if(Test-Path "REGISTRY::HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Windows") {
            echo "Note: Look at key: AppInit_DLLs"                                                                                  >> "$Global:Destiny\$HOSTNAME\Persistence\Persistence_AppInitDLLs.txt"
            echo "More information: https://attack.mitre.org/techniques/T1103/"                                                     >> "$Global:Destiny\$HOSTNAME\Persistence\Persistence_AppInitDLLs.txt"
            echo ""                                                                                                                 >> "$Global:Destiny\$HOSTNAME\Persistence\Persistence_AppInitDLLs.txt"
            Get-Item -Path "REGISTRY::HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Windows\"                     >> "$Global:Destiny\$HOSTNAME\Persistence\Persistence_AppInitDLLs.txt"
        }
        if(Test-Path "REGISTRY::HKEY_LOCAL_MACHINE\Software\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Windows") {
            Get-Item -Path "REGISTRY::HKEY_LOCAL_MACHINE\Software\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Windows\"         >> "$Global:Destiny\$HOSTNAME\Persistence\Persistence_AppInitDLLs.txt"
        }

        # AppCert DLLs - https://attack.mitre.org/techniques/T1182/
        if(Test-Path "REGISTRY::HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager") {
            echo "Note: Look at key: AppCertDLLs. It's posible it doesn't exists "                                                  >> "$Global:Destiny\$HOSTNAME\Persistence\Persistence_AppCertDLLs.txt"
            echo "More information: https://attack.mitre.org/techniques/T1182/"                                                     >> "$Global:Destiny\$HOSTNAME\Persistence\Persistence_AppCertDLLs.txt"
            echo ""                                                                                                                 >> "$Global:Destiny\$HOSTNAME\Persistence\Persistence_AppCertDLLs.txt"
            Get-Item -Path "REGISTRY::HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager\"                         >> "$Global:Destiny\$HOSTNAME\Persistence\Persistence_AppCertDLLs.txt"
        }

        # Accessility Features - https://attack.mitre.org/techniques/T1015/
        # On-Screen Keyboard: C:\Windows\System32\osk.exe
        # Magnifier: C:\Windows\System32\Magnify.exe
        # Narrator: C:\Windows\System32\Narrator.exe
        # Display Switcher: C:\Windows\System32\DisplaySwitch.exe
        # App Switcher: C:\Windows\System32\AtBroker.exe


    } catch {
        Report-Error -evidence "Persistence"
    }
}

<########### U S B   I N F O #######################> # USB
Function Collect-USB-Info {
 
    if ( -Not ( Test-Path $Global:Destiny\$HOSTNAME\USB ) ) { New-Item -ItemType directory -Path $Global:Destiny\$HOSTNAME\USB > $null }
 
    try{
        Write-Host "[+] Collecting USB Info ..." -ForegroundColor Green
        
        if( Test-Path -Path "HKLM:\SYSTEM\CurrentControlSet\Enum\USB")
        {
            echo "RESUME: " > "$Global:Destiny\$HOSTNAME\USB\USB.txt"
            Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Enum\USB\*\*" | Select-Object FriendlyName, DeviceDesc, Mfg >> "$Global:Destiny\$HOSTNAME\USB\USB.txt" 2> $null

            echo "DETAILED: " >> "$Global:Destiny\$HOSTNAME\USB\USB.txt"
            Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Enum\USB\*\*" >> "$Global:Destiny\$HOSTNAME\USB\USB.txt" 2> $null
        }


        if( Test-Path -Path "HKLM:\SYSTEM\CurrentControlSet\Enum\USBSTOR")
        {
            echo "RESUME: " > "$Global:Destiny\$HOSTNAME\USB\USBSTOR.txt"
            Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Enum\USBSTOR\*\*" | Select-Object FriendlyName, DeviceDesc, Mfg >> "$Global:Destiny\$HOSTNAME\USB\USBSTOR.txt" 2> $null

            echo "DETAILED: " >> "$Global:Destiny\$HOSTNAME\USB\USBSTOR.txt"
            Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Enum\USBSTOR\*\*" >> "$Global:Destiny\$HOSTNAME\USB\USBSTOR.txt" 2> $null
        }

        echo "RESUME: " > "$Global:Destiny\$HOSTNAME\USB\USBControllerDevice.txt"
        Get-WmiObject Win32_USBControllerDevice | Foreach-Object { [Wmi]$_.Dependent } | Select-Object Caption, PNPClass, Present, Status >> "$Global:Destiny\$HOSTNAME\USB\USBControllerDevice.txt" 2> $null
        # Get-CimInstance
            
        echo "DETAILED: " >> "$Global:Destiny\$HOSTNAME\USB\USBControllerDevice.txt"
        Get-WmiObject Win32_USBControllerDevice | Foreach-Object { [Wmi]$_.Dependent } >> "$Global:Destiny\$HOSTNAME\USB\USBControllerDevice.txt" 2> $null
        # Get-CimInstance

        # OLD - cmd.exe /c reg export "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Enum\USBSTOR" "$Global:Destiny\$HOSTNAME\USB\USBSTOR.reg" > $null
        # OLD - cmd.exe /c reg export "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Enum\USB" "$Global:Destiny\$HOSTNAME\USB\USB.reg" > $null
        # OLD - Get-WmiObject Win32_USBControllerDevice | Foreach-Object { [Wmi]$_.Dependent } > "$Global:Destiny\$HOSTNAME\USB\USBControllerDevice.txt"
    } catch {
        Report-Error -evidence "USB info"
    }
}

<########### D E V I C E S   I N F O ###############> # DEV
Function Collect-Devices-Info {

    if ( -Not ( Test-Path $Global:Destiny\$HOSTNAME\Devices ) ) { New-Item -ItemType directory -Path $Global:Destiny\$HOSTNAME\Devices > $null }

    Write-Host "[+] Collecting Devices Info in the Registry ..." -ForegroundColor Green
    try
    {
        # OLD - cmd.exe /c reg export "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\DeviceClasses" "$Global:Destiny\$HOSTNAME\DEVICES\DeviceClasses.reg" > $null <# TODO: Review this, it seems without useful information#>
        Get-Item "REGISTRY::HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\DeviceClasses\*\*" > "$Global:Destiny\$HOSTNAME\Devices\DeviceClasses.txt" 2> $null
        # OLD - cmd.exe /c reg export "HKEY_LOCAL_MACHINE\System\MountedDevices" "$Global:Destiny\$HOSTNAME\DEVICES\MountedDevices.reg" > $null <# TODO: Review this, it seems without useful information#>
        Get-Item "REGISTRY::HKEY_LOCAL_MACHINE\System\MountedDevices\*\*" > "$Global:Destiny\$HOSTNAME\Devices\MountedDevices.txt" 2> $null
        # TODO: 
        #  Get-ItemProperty  "REGISTRY::HKEY_LOCAL_MACHINE\System\MountedDevices"
        #
        #  [System.Text.Encoding]::Default.GetString((Get-ItemProperty "HKLM:\System\MountedDevices")."\??\Volume{f688de94-3dd5-11e9-a93b-3c6aa7859fb6}")
        #  [System.Text.Encoding]::Default.GetString((Get-ItemProperty "HKLM:\System\MountedDevices")."\DosDevices\S:")

    } 
    catch 
    {
        Report-Error -evidence "Devices Info from the Registry"
    }
}

<########### S E C U R I T Y   C O N F . ###########> # SEC
Function Collect-Security-Config{

    if ( -Not ( Test-Path $Global:Destiny\$HOSTNAME\Security ) ) { New-Item -ItemType directory -Path $Global:Destiny\$HOSTNAME\Security > $null }

    try{
        Write-Host "[+] Collecting Security Configuration Info... " -ForegroundColor Green
        # cmd.exe /c reg export "HKEY_LOCAL_MACHINE\Software\Microsoft\Security Center" "$Global:Destiny\$HOSTNAME\SECURITY\HKLM_SecurityCenter.reg" > $null REMARK: I don't see useful information here.
        # OLD - cmd.exe /c reg export "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy" "$Global:Destiny\$HOSTNAME\SECURITY\HKLM_FirewallPolicy.reg" > $null 
        Get-Item "REGISTRY::HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy" > "$Global:Destiny\$HOSTNAME\Security\HKLM_FirewallPolicy.txt"

        Get-ItemProperty "HKLM:\System\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules\" > "$Global:Destiny\$HOSTNAME\Security\FW_Programs.txt"
        Get-ItemProperty "HKLM:\System\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\RestrictedServices\*\*" > "$Global:Destiny\$HOSTNAME\Security\FW_Services.txt"
        
        if($OS -eq "XP") {
            # OLD - cmd.exe /c reg export "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Action Center" "$Global:Destiny\$HOSTNAME\SECURITY\HKLM_ActionCenter.reg" > $null
            Get-ItemProperty "REGISTRY::HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Action Center" > "$Global:Destiny\$HOSTNAME\Security\HKLM_ActionCenter.txt"
        } <# TODO: Review in a XP environment #>
        
       
    } catch {
        Report-Error -evidence "Security Information"
    }
}

<########### S H E L L   F O L D E R S #############> # SFO
Function Collect-Shell-Folders {

    if ( -Not ( Test-Path $Global:Destiny\$HOSTNAME\Shell_Folders ) ) { New-Item -ItemType directory -Path $Global:Destiny\$HOSTNAME\Shell_Folders > $null }

    Write-Host "[+] Collecting Shell Folders " -ForegroundColor Green
    try
    {
        # OLD - cmd.exe /c reg export "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders" "$Global:Destiny\$HOSTNAME\Shell_Folders\HKCU_ShellFolders.reg" > $null 
        Get-Item -Path "HKCU:\software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders\" > "$Global:Destiny\$HOSTNAME\Shell_Folders\HKCU_ShellFolders.txt"
        
        # OLD - cmd.exe /c reg export "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders" "$Global:Destiny\$HOSTNAME\Shell_Folders\HKLM_ShellFolders.reg" > $null 
        Get-Item -Path "HKLM:\software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders\" > "$Global:Destiny\$HOSTNAME\Shell_Folders\HKLM_ShellFolders.txt"
        
        # OLD - cmd.exe /c reg export "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders" "$Global:Destiny\$HOSTNAME\Shell_Folders\HKCU_UserShellFolders.reg" > $null 
        Get-Item -Path "HKCU:\software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders\" > "$Global:Destiny\$HOSTNAME\Shell_Folders\HKCU_UserShellFolders.txt"

        # OLD - cmd.exe /c reg export "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders" "$Global:Destiny\$HOSTNAME\Shell_Folders\HKLM_UserShellFolders.reg" > $null 
        Get-Item -Path "HKLM:\software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders\" > "$Global:Destiny\$HOSTNAME\Shell_Folders\HKLM_UserShellFolders.txt"

    } 
    catch 
    {
        Report-Error -evidence "Shell Folders"
    }
}

<########### E N V I R O N M E N T   V A R S #######> # ENV
Function Collect-Env-Vars {
    
    if ( -Not ( Test-Path $Global:Destiny\$HOSTNAME\System_Config\ ) ) { New-Item -ItemType directory -Path $Global:Destiny\$HOSTNAME\System_Config\ > $null }

    Write-Host "[+] Collecting Environment Variables ..." -ForegroundColor Green
    try
    {
        cmd.exe /c path > "$Global:Destiny\$HOSTNAME\System_Config\9.Environment_Variables.txt"
    }
    catch
    {
        Report-Error -evidence "Environment Variables"
    }
}


<########### M R U s ###############################> # MRU
Function Collect-MRUs {

    Write-Host "[+] Collecting MRU's ..." -ForegroundColor Green

    if( -not (Test-Path "$Global:Destiny\$HOSTNAME\MRUs\") ) { New-Item -ItemType Directory -Path "$Global:Destiny\$HOSTNAME\MRUs\" > $null }

    # MUI CACHE
    Write-Host "`t[+] Collecting MUICACHE" -ForegroundColor Green

    & "$SCRIPTPATH\bin\muicacheview\MUICacheView.exe" /shtml "$Global:Destiny\$HOSTNAME\MRUs\MUICACHE.html"

    # RECENT DOCS
    Write-Host "`t[+] Collecting RECENT DOCS" -ForegroundColor Green

    & "$SCRIPTPATH\bin\recentfilesview\RecentFilesView.exe" /sort "~Modified Time" /shtml "$Global:Destiny\$HOSTNAME\MRUs\RECENTDOCS.html"

    # COMDLG32 :: OpenSavePidlMRU
    Write-Host "`t[+] Collecting OpenSavePidlMRU" -ForegroundColor Green

    & $OPEN_SAVED_FILES_VIEW /shtml "$Global:Destiny\$HOSTNAME\MRUs\OpenSavePidlMRU.html"

    # COMDLG32 :: CIDSizeMRU | COMDLG32 :: LastVisitedPidlMRU | RUN MRU
    foreach($SID in $SIDS)
    {

        if ($SID.Split("-")[7] -ne $null -and $SID.Split("-")[7] -notlike "*_Classes") # the ones that are users, removes the system, network and classes
        { 

            $N = Get-ItemPropertyValue -Path "REGISTRY::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\$SID\" -Name "ProfileImagePath"  # get's the name correspondent to the SID
            $NAME = $($N.Split("\")[2])

            if ( -Not ( Test-Path $Global:Destiny\$HOSTNAME\MRUs\$NAME ) ) { New-Item -ItemType directory -Path $Global:Destiny\$HOSTNAME\MRUs\$NAME > $null }


            # COMDLG32 :: CIDSizeMRU
            Write-Host "`t[+] CIDSizeMRU from $NAME" -ForegroundColor Green

            $cnt = Get-ItemPropertyValue "REGISTRY::HKEY_USERS\$SID\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\CIDSizeMRU\" -Name MRUListEx
            $i=0
            foreach($b in $cnt){$i++} # gets the number of entries
            $max = (($i / 4) - 1)

            for($n=0; $n -lt $max; $n++){
                        
                try 
                {
                    $temp = Get-ItemPropertyValue "REGISTRY::HKEY_USERS\$SID\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\CIDSizeMRU\" -Name $n
            
                    $read=$true
                    $i = 0
                            
                    foreach($b in $temp)
                    {
                        if($read)
                        {
                            if([int]$b -ne 0)
                            {
                                $c = [char][int]$b
                                $filename = $filename + "$c"
                            }
                            if([int]$b -eq 0) 
                            { 
                                $i = $i + 1 
                            }
                            else 
                            { 
                                $i = 0 
                            }
                            if($i -gt 1) 
                            {
                                $read = $false
                            }
                        }
                    }
                    echo "$filename" >> "$Global:Destiny\$HOSTNAME\MRUs\$NAME\CIDSizeMRU.txt"
                    $filename = ""
                } 
                catch 
                {
                        Report-Error -evidence "Collecting CIDSizeMRU"
                }
            }

            # COMDLG32 :: LastVisitedPidlMRU
            Write-Host "`t[+] LastVisitedPidlMRU from $NAME" -ForegroundColor Green

            $cnt = Get-ItemPropertyValue "REGISTRY::HKEY_USERS\$SID\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\LastVisitedPidlMRU\" -Name MRUListEx
            $i=0
            foreach($b in $cnt){$i++} # gets the number of entries
            $max = (($i / 4) - 1)

            for($n=0; $n -lt $max; $n++)
            {
                        
                try 
                {
                    $temp = Get-ItemPropertyValue "REGISTRY::HKEY_USERS\$SID\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\LastVisitedPidlMRU\" -Name $n
            
                    $read=$true
                    $i = 0
                            
                    foreach($b in $temp)
                    {
                        if($read)
                        {
                            if([int]$b -ne 0)
                            {
                                $c = [char][int]$b
                                $filename = $filename + "$c"
                            }
                            if([int]$b -eq 0) 
                            { 
                                $i = $i + 1 
                            }
                            else 
                            { 
                                $i = 0 
                            }
                            if($i -gt 1) 
                            {
                                $read = $false
                            }
                        }
                    }
                    echo "$filename" >> "$Global:Destiny\$HOSTNAME\MRUs\$NAME\LastVisitedPidlMRU.txt"
                    $filename = ""
                } 
                catch 
                {
                    Report-Error -evidence "Collecting LastVisitedPidlMRU"
                }
            }

            # RUN MRU
            Write-Host "`t[+] RunMRU from $NAME" -ForegroundColor Green
            try 
            {
                if(Test-RegistryValue -Path "REGISTRY::HKEY_USERS\$SID\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU\" -Value "MRUList")
                {
                    $cnt = Get-ItemPropertyValue "REGISTRY::HKEY_USERS\$SID\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU\" -Name MRUList
                    $temp = $cnt.ToCharArray()
                    foreach($n in $temp)
                    {
                        $temp = Get-ItemPropertyValue "REGISTRY::HKEY_USERS\$SID\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU\" -Name $n
                            
                        echo "$temp" >> "$Global:Destiny\$HOSTNAME\MRUs\$NAME\RunMRU.txt"
                    }
                }
                else
                {
                    Write-Host "`t`t[i] There is no RunMRU values in the registry for this user." -ForegroundColor Yellow
                }
            } 
            catch 
            {
                Report-Error -evidence "RunMRU"
            }
    
        }
    }
}

<########### S H I M C A C H E #####################> # SHI 
Function Collect-Shimcache {
    #  [System.Text.Encoding]::Default.GetString((Get-ItemPropertyValue "REGISTRY::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache" -Name AppCompatCache))

    Write-Host "[+] Collecting Shimcache Information ... " -ForegroundColor Green

    if( -not (Test-Path "$Global:Destiny\$HOSTNAME\MRUs\") ) { New-Item -ItemType Directory -Path "$Global:Destiny\$HOSTNAME\MRUs\" > $null }

    if($OS -eq "10") <# TESTED: Win10 #>
    {
        try
        {
            $content = Get-ItemPropertyValue "REGISTRY::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache" -Name AppCompatCache
            $index=[System.BitConverter]::ToInt32($content,0)
            $Position = 0

            echo "Position, Path, Modified" > "$Global:Destiny\$HOSTNAME\MRUs\Shimcache.csv"

            while($index -lt $content.length)
            {
           
                $Position++
                #echo "Position: $Position"
                $signature = [System.Text.Encoding]::ASCII.GetString($content,$index,4)
                $index += 4

                if($signature -notlike "10ts")
                {
                    break
                }

                $unknown = [System.Text.Encoding]::ASCII.GetString($content,$index,4)
                $index += 4
                #echo "Unknown: $unknown"

                $DataSize = [System.BitConverter]::ToUInt32($content,$index)
                $index += 4
                #echo "Data Size: $DataSize"

                $PathSize = [System.BitConverter]::ToUInt16($content,$index)
                $index += 2
                #echo "Path Size: $PathSize"

                $Path = [System.Text.Encoding]::Unicode.GetString($content, $index, $PathSize)
                if($Path -notlike "*:\*"){
                    $temp = $($Path.Split("`t")[4])
                    if($temp -eq $null){}
                    else {$Path = $temp}
                }
                $index += $PathSize
                #echo "Path: $Path"

                $DateTimeOffset = [System.DateTimeOffset]::FromFileTime([System.BitConverter]::ToInt64($content,$index))
                $LastModifiedTimeUTC = $($DateTimeOffset.UtcDateTime)
                #echo "LastModifiedTimeUTC: $LastModifiedTimeUTC"
                $index += 8
    

                $DataSize = [System.BitConverter]::ToInt32($content, $index)
                $index += 4
                #echo "Data Size: $DataSize"

                $Data = [System.Text.Encoding]::Unicode.GetString($content, $index, $DataSize)
                $index += $DataSize
                #echo "Data: $Data"

                echo "$Position, $Path, $LastModifiedTimeUTC" >> "$Global:Destiny\$HOSTNAME\MRUs\Shimcache.csv"
            }
        }
        catch
        {
            Report-Error -evidence "Shimcache Collection"
        }
        
    }

    if($OS -like "8*")
    {
        $regKey = Get-ItemProperty "REGISTRY::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache" 
        $content = $regKey.AppCompatCache
        $index=128
        $Position = 0

        echo "Position, Path, Modified" > "$Global:Destiny\$HOSTNAME\MRUs\Shimcache.csv"
        try
        {
            while($index -lt $content.length)
            {
       
                $Position++
                #echo "Position: $Position"
                $signature = [System.Text.Encoding]::ASCII.GetString($content,$index,4)
                $index += 4

                if($signature -notlike "10ts" -and $signature -notlike "00ts")
                {
                    break
                }

                $unknown = [System.Text.Encoding]::ASCII.GetString($content,$index,4)
                $index += 4
                #echo "Unknown: $unknown"

                $DataSize = [System.BitConverter]::ToUInt32($content,$index)
                $index += 4
                #echo "Data Size: $DataSize"

                $PathSize = [System.BitConverter]::ToUInt16($content,$index)
                $index += 2
                #echo "Path Size: $PathSize"

                $Path = [System.Text.Encoding]::Unicode.GetString($content, $index, $PathSize)
                if($Path -like "\??*"){
                    $temp = $Path.Replace("\??\","")
                    $Path = $temp
                }
                $index += $PathSize
                #echo "Path: $Path"

                $PackageLen = [System.BitConverter]::ToUInt16($content,$index)
                $index += 2
                #echo "Package Length: $PackageLen"

                $Package = [System.Text.Encoding]::Unicode.GetString($content, $index, $PackageLen)
                if($Package -like "*`t*"){
                    $temp = $($Package.Split("`t")[3])
                    if($temp -eq $null){}
                    else {$Package = $temp}
                }
                $index += $PackageLen
                #echo "Package: $Package"

                $Flags = [System.BitConverter]::ToInt64($content, $index)
                $index += 8
                #echo "Flags: $Flags"

                $DateTimeOffset = [System.DateTimeOffset]::FromFileTime([System.BitConverter]::ToInt64($content,$index))
                $LastModifiedTimeUTC = $($DateTimeOffset.UtcDateTime)
                #echo "LastModifiedTimeUTC: $LastModifiedTimeUTC"
                $index += 8

                $DataSize = [System.BitConverter]::ToInt32($content, $index)
                $index += 4
                #echo "Data Size: $DataSize"

                $Data = [System.Text.Encoding]::Unicode.GetString($content, $index, $DataSize)
                $index += $DataSize
                #echo "Data: $Data"

                if ($Path -eq "") { echo "$Position, Package:\$Package, $LastModifiedTimeUTC" >> "$Global:Destiny\$HOSTNAME\MRUs\Shimcache.csv" }
                else { echo "$Position, $Path, $LastModifiedTimeUTC" >> "$Global:Destiny\$HOSTNAME\MRUs\Shimcache.csv" }

            }
        }
        catch
        {
            Report-Error -evidence "Shimcache Collection"
        }
    }

    if($OS -eq "7")
    {
        $regKey = Get-ItemProperty "REGISTRY::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache" 
        $content = $regKey.AppCompatCache
        $index=128
        $Position = 0
        $limit = [System.BitConverter]::ToInt32($content, 4);
        echo "Limit: $limit"

        echo "Position, Path, Modified" > "$Global:Destiny\$HOSTNAME\MRUs\Shimcache.csv"
        try
        {
            while($index -lt $content.length)
            {

                    if($ARCH -eq "AMD64") # x64 arch
                    {
                        $Position++
                        #echo "Position: $Position"

                        $PathSize = [System.BitConverter]::ToUInt16($content,$index)
                        $index += 2
                        #echo "Path Size: $PathSize"

                        $MaxPathSize = [System.BitConverter]::ToUInt16($content,$index)
                        $index += 2
                        #echo "Max Path Size: $MaxPathSize"

                        $unknown = [System.Text.Encoding]::ASCII.GetString($content,$index,4)
                        $index += 4
                        #echo "Unknown: $unknown"

                        $PathOffset = [System.BitConverter]::ToInt64($content,$index)
                        $index += 8
                        #echo "Path Offset: $PathOffset"

                        $DateTimeOffset = [System.DateTimeOffset]::FromFileTime([System.BitConverter]::ToInt64($content,$index))
                        $LastModifiedTimeUTC = $($DateTimeOffset.UtcDateTime)
                        $index += 8
                        #echo "Last Modified Time UTC: $LastModifiedTimeUTC"
            
                        $flags = [System.Text.Encoding]::ASCII.GetString($content,$index,4)
                        $index += 4
                        #echo "flags: $flags"

                        $shimflags = [System.Text.Encoding]::ASCII.GetString($content,$index,4)
                        $index += 4
                        #echo "shim flags: $shimflags"

                        $DataSize = [System.BitConverter]::ToUInt64($content,$index)
                        $index += 8
                        #echo "Data Size: $DataSize"

                        $DataOffset = [System.BitConverter]::ToUInt64($content,$index)
                        $index += 8
                        #echo "Data Offset: $DataOffset"

                        $Path = [System.Text.Encoding]::Unicode.GetString($content, $PathOffset, $PathSize)
                        $Path = $Path.Replace("\??\","")
                        #echo "Path: $Path"


                        echo "$Position, $Path, $LastModifiedTimeUTC" >> "$Global:Destiny\$HOSTNAME\MRUs\Shimcache.csv"
            
                        if ($Position -eq $limit) { break }
                    }
                    else # x86 arch
                    {
                        $Position++
                        #echo "Position: $Position"

                        $PathSize = [System.BitConverter]::ToUInt16($content,$index)
                        $index += 2
                        #echo "Path Size: $PathSize"

                        $MaxPathSize = [System.BitConverter]::ToUInt16($content,$index)
                        $index += 2
                        #echo "Max Path Size: $MaxPathSize"

                        $PathOffset = [System.BitConverter]::ToInt32($content,$index)
                        $index += 4
                        #echo "Path Offset: $PathOffset"

                        $DateTimeOffset = [System.DateTimeOffset]::FromFileTime([System.BitConverter]::ToInt64($content,$index))
                        $LastModifiedTimeUTC = $($DateTimeOffset.UtcDateTime)
                        $index += 8
                        #echo "Last Modified Time UTC: $LastModifiedTimeUTC"
            
                        $flags = [System.BitConverter]::ToInt32($content,$index)
                        $index += 4
                        #echo "flags: $flags"

                        $shimflags = [System.BitConverter]::ToInt32($content,$index)
                        $index += 4
                        #echo "shim flags: $shimflags"

                        $DataSize = [System.BitConverter]::ToUInt64($content,$index)
                        $index += 4
                        #echo "Data Size: $DataSize"

                        $DataOffset = [System.BitConverter]::ToUInt64($content,$index)
                        $index += 4
                        #echo "Data Offset: $DataOffset"

                        $Path = [System.Text.Encoding]::Unicode.GetString($content, $PathOffset, $PathSize)
                        $Path = $Path.Replace("\??\","")
                        #echo "Path: $Path"


                        echo "$Position, $Path, $LastModifiedTimeUTC" >> "$Global:Destiny\$HOSTNAME\MRUs\Shimcache.csv"
            
                        if ($Position -eq $limit) { break }
                    }
                }
        }
        catch
        {
            Report-Error -evidence "Shimcache Collection"
        }
    }



}

<########### J U M P   L I S T S ###################> # JLI 
Function Collect-JumpLists {

    if($OS -eq "10" -or $OS -like "8" -or $OS -eq "7")
    {
        Write-Host "[+] Collecting Jump Lists ..." -ForegroundColor Green
        
        [System.Reflection.Assembly]::Load([System.IO.File]::ReadAllBytes("$SCRIPTPATH\dependencies\JumpList.dll")) > $null
        [System.Reflection.Assembly]::Load([System.IO.File]::ReadAllBytes("$SCRIPTPATH\dependencies\OleCf.dll")) > $null
        [System.Reflection.Assembly]::Load([System.IO.File]::ReadAllBytes("$SCRIPTPATH\dependencies\Lnk.dll")) > $null
        [System.Reflection.Assembly]::Load([System.IO.File]::ReadAllBytes("$SCRIPTPATH\dependencies\ExtensionBlocks.dll")) > $null
        [System.Reflection.Assembly]::Load([System.IO.File]::ReadAllBytes("$SCRIPTPATH\dependencies\GuidMapping.dll")) > $null

        foreach($u in $USERS)
        {
            # Automatic Destinations
            if( Test-Path "$Global:Source\Users\$u\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations")
            {
                # Copies Automatic Destinations
                if( -not (Test-Path "$Global:Destiny\$HOSTNAME\MRUs\JumpLists\$u\AutomaticDestinations") ) { New-Item -ItemType Directory -Path "$Global:Destiny\$HOSTNAME\MRUs\JumpLists\$u\AutomaticDestinations" > $null }    
            
                try
                {
                    cmd.exe /c copy "$Global:Source\Users\$u\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations\*.*" "$Global:Destiny\$HOSTNAME\MRUs\JumpLists\$u\AutomaticDestinations" > $null
                }
                catch
                {
                    Report-Error -evidence "Jump Lists - AutomaticDestinations from user $u"
                }

                # Treating Automatic Destinations
                if( -not (Test-Path "$Global:Destiny\$HOSTNAME\MRUs\JumpLists\$u\AutomaticDestinations") ) { New-Item -ItemType Directory -Path "$Global:Destiny\$HOSTNAME\MRUs\JumpLists\$u\AutomaticDestinations" > $null }    

                echo "File Name, Full Path, Last Modified, Creation Date, Accessed Date, Modification date, File Attributes, File Size, Entry ID, Pos. MRU, Appication ID, Application Name, Mac Address, File Extension, Computer Name, Network Share Name, Drive Type, Volume Label, Volume SN, Jump List Filename " > "$Global:Destiny\$HOSTNAME\MRUs\JumpLists\$u\AutomaticDestinations\JumplLists_Auto.csv"

                Get-ChildItem "C:\Users\$u\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations" | ForEach-Object {
    
                    try
                    {
                        $list = [JumpList.JumpList]::LoadAutoJumplist("C:\Users\$u\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations\$_")

                        $JLFilename = $($list.SourceFile)
                        $AppID = $($list.AppId.AppId)
    
                        $AppName = $($list.AppId.Description)
    
                        foreach($bla in $list.DestListEntries)
                        {
                            $EntryID = $($bla.EntryNumber)
                            $PosMRU = $($bla.MRUPosition)

                            $FullPath = $($bla.Path).Replace(","," ")
                            $FileName = $($FullPath).Split("\")[-1]
                            $Extension = $($FileName).Split(".")[-1]
                            if($Extension.length -gt 3) { $Extension = "" }
                            
                            $LastModified = $($bla.LastModified)
                            $ComputerName = $($bla.Hostname)
                            $MacAddress = $($bla.MacAddress)

                            $FileAttributes = $($bla.Lnk.Header.FileAttributes).ToString().Replace(","," ")
                            $FileSize = $($bla.Lnk.Header.FileSize)
                            $CreationDate = $($bla.Lnk.Header.TargetCreationDate)
                            $AccessedDate = $($bla.Lnk.Header.TargetLastAccessedDate)
                            $ModificationDate = $($bla.Lnk.Header.TargetModificationDate)
                            $NetworkShareName = $($bla.Lnk.NetworkShareInfo.NetworkShareName)
            
                            $DriveType = $($bla.Lnk.VolumeInfo.DriveType)
                            $VolumeLabel = $($bla.Lnk.VolumeInfo.VolumeLabel)
                            $VolumeSerialNumber = $($bla.Lnk.VolumeInfo.VolumeSerialNumber)

                            echo "$FileName, $FullPath, $LastModified, $CreationDate, $AccessedDate, $ModificationDate, $FileAttributes, $FileSize, $EntryID, $PosMRU, $AppID, $AppName, $MacAddress, $Extension, $ComputerName, $NetworkShareName, $DriveType, $VolumeLabel, $VolumeSerialNumber, $JLFilename " >> "$Global:Destiny\$HOSTNAME\MRUs\JumpLists\$u\AutomaticDestinations\JumplLists_Auto.csv"
                        }
                    }
                    catch
                    {
                        Report-Error -evidence "Jump Lists - Treating Automatic Destinations from user $u"
                    }
                }
            }

            # Custom Destinations
            if( Test-Path "$Global:Source\Users\$u\AppData\Roaming\Microsoft\Windows\Recent\CustomDestinations")
            {
                # Copies Custom Destinations
                if( -not (Test-Path "$Global:Destiny\$HOSTNAME\MRUs\JumpLists\$u\CustomDestinations") ) { New-Item -ItemType Directory -Path "$Global:Destiny\$HOSTNAME\MRUs\JumpLists\$u\CustomDestinations" > $null }    

                try
                {
                    cmd.exe /c copy "$Global:Source\Users\$u\AppData\Roaming\Microsoft\Windows\Recent\CustomDestinations\*.*" "$Global:Destiny\$HOSTNAME\MRUs\JumpLists\$u\CustomDestinations" > $null
                }
                catch
                {
                    Report-Error -evidence "Jump Lists - CustomDestinations from user $u"
                }

                # Treating Custom Destinations
                if( -not (Test-Path "$Global:Destiny\$HOSTNAME\MRUs\JumpLists\$u\CustomDestinations") ) { New-Item -ItemType Directory -Path "$Global:Destiny\$HOSTNAME\MRUs\JumpLists\$u\CustomDestinations" > $null }
                
                echo "App ID, App Name, Creation Date, Accessed Date, Modification date, File Attributes, File Size, Network Share Name, Drive Type, Volume Label, Volume SN , Jump List Filename " > "$Global:Destiny\$HOSTNAME\MRUs\JumpLists\$u\CustomDestinations\JumplLists_Custom.csv"

                Get-ChildItem "C:\Users\$u\AppData\Roaming\Microsoft\Windows\Recent\CustomDestinations" | ForEach-Object {

                    try
                    {
                        $list = [JumpList.JumpList]::LoadCustomJumplist("C:\Users\$u\AppData\Roaming\Microsoft\Windows\Recent\CustomDestinations\$_")

                        $SourceFilename = $($list)
                        $AppID = $($list.AppId.AppId)
                        $AppName = $($list.AppId.Description)

                        foreach($entry in $list.Entries)
                        {
                            foreach($bla in $entry.LnkFiles)
                            {
                                $FileAttributes = $($bla.Header.FileAttributes).ToString().Replace(","," ")
                                $FileSize = $($bla.Header.FileSize)
                                $CreationDate = $($bla.Header.TargetCreationDate)
                                $AccessedDate = $($bla.Header.TargetLastAccessedDate)
                                $ModificationDate = $($bla.Header.TargetModificationDate)
                                $NetworkShareName = $($bla.NetworkShareInfo.NetworkShareName)
                                $DriveType = $($bla.VolumeInfo.DriveType)
                                $VolumeLabel = $($bla.VolumeInfo.VolumeLabel)
                                $VolumeSerialNumber = $($bla.VolumeInfo.VolumeSerialNumber)
                            
                                echo "$AppID, $AppName, $CreationDate, $AccessedDate, $ModificationDate, $FileAttributes, $FileSize, $NetworkShareName, $DriveType, $VolumeLabel, $VolumeSerialNumber, $JLFilename " >> "$Global:Destiny\$HOSTNAME\MRUs\JumpLists\$u\CustomDestinations\JumplLists_Custom.csv"
                            }
                        }
                    }
                    catch
                    {
                        # 3 errors are always catched because of 3 Custom Destination Lists
                        # Report-Error -evidence "Jump Lists - Treating Custom Destinations from user $u - [Normal to happen]"
                    }
                }
            }
        }
    }
}

<########### B A M #################################> # BAM
Function Collect-BAM {
    
    # BAM - BACKGROUND ACTIVITY MODERATOR

    $avoidlist = "Version","SequenceNumber"

    if( Test-Path -Path "REGISTRY::HKLM\SYSTEM\CurrentControlSet\services\bam\") 
    {

        if( -not (Test-Path "$Global:Destiny\$HOSTNAME\BAM") ) { New-Item -ItemType Directory -Path "$Global:Destiny\$HOSTNAME\BAM" > $null }    
        echo "User,Application,LastExecutionDate UTC, LastExecutionDate" > "$Global:Destiny\$HOSTNAME\BAM\LastExecutionDateApps.csv"

        $SIDs = Get-Item "REGISTRY::HKLM\SYSTEM\CurrentControlSet\Services\bam\UserSettings\*"  | foreach { 
            $_.Name.split("\")[-1] 
        }

        foreach($SID in $SIDs)
        {
            $APPs = Get-Item "REGISTRY::HKLM\SYSTEM\CurrentControlSet\Services\bam\UserSettings\$SID\" | foreach{ 
                $_.Property 
            }

            foreach($APP in $APPs)
            {
                if((-not ($avoidlist -contains $APP))) # if not in the blacklist
                {
                    <# TODO: Create a function that indexes the name of the User to the SID and use for example here to print username instead of SID
                        KEY: HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\ #>
                     
                    $RawDate = Get-ItemPropertyValue "REGISTRY::HKLM\SYSTEM\CurrentControlSet\Services\bam\UserSettings\$SID\" -Name $APP
                    $DateTimeOffset = [System.DateTimeOffset]::FromFileTime([System.BitConverter]::ToInt64($RawDate,0))
                    $LastExecutedDateUTC = $($DateTimeOffset.UtcDateTime)

                    $LastExecutedDateLocal = [datetime]::FromFileTime([System.BitConverter]::ToInt64($RawDate,0))
                    
                    echo "$SID,$APP,$LastExecutedDateUTC,$LastExecutedDateLocal" >> "$Global:Destiny\$HOSTNAME\BAM\LastExecutionDateApps.csv"
                }
            }
        }
    }
    else
    {
        Write-Host "[-] No BAM registry record found in the system ..." -ForegroundColor Yellow
    }

}



<########### T I M E L I N E   H I S T O R Y #######> # TLH 
Function Collect-Timeline {

    Write-Host "[+] Collecting Timeline History ..." -ForegroundColor Green

    if($OS -eq "10")
    {
        foreach($u in $USERS)
        {
            if(Test-Path "$Global:Source\Users\$u\AppData\Local\ConnectedDevicesPlatform")
            {       
                Get-Item  "$Global:Source\Users\$u\AppData\Local\ConnectedDevicesPlatform\*" | ForEach-Object {
                 
                    if(Test-Path -Path $_.FullName -PathType Container) # if it's a folder
                    {
                        if( -not (Test-Path "$Global:Destiny\$HOSTNAME\Timeline_History\$u") ) { New-Item -ItemType Directory -Path "$Global:Destiny\$HOSTNAME\Timeline_History\$u" > $null }

                        cmd.exe /c copy "$Global:Source\Users\$u\AppData\Local\ConnectedDevicesPlatform\$($_.Name)\*.*" "$Global:Destiny\$HOSTNAME\Timeline_History\$u" > $null
                    }
                }
            }
            else
            {
                Write-Host "[-] Time Line not activated for user $u" -ForegroundColor Yellow
            }
        }
    }
}

<########### R E C E N T   A P P S #################> # RAP 
Function Collect-RecentApps {

    if($OS -eq "10")
    {
        foreach($SID in $SIDS)
        {
            if ($SID.Split("-")[7] -ne $null -and $SID.Split("-")[7] -notlike "*_Classes") # the ones that users removes the system and network and classes
            {
                $N = Get-ItemPropertyValue -Path "REGISTRY::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\$SID\" -Name "ProfileImagePath"  # get's the name correspondent to the SID
                $NAME = $($N.Split("\")[2])

                if ( -Not ( Test-Path "$Global:Destiny\$HOSTNAME\Recent_Apps\$NAME" ) ) { New-Item -ItemType directory -Path "$Global:Destiny\$HOSTNAME\Recent_Apps\$NAME" > $null }
                Write-Host "[+] Collecting Recent Apps info from $NAME" -ForegroundColor Green

                if( Test-Path "REGISTRY::HKEY_USERS\$SID\Software\Microsoft\Windows\CurrentVersion\Search\RecentApps\")
                {
                    $RA_SID = Get-ChildItem "REGISTRY::HKEY_USERS\$SID\Software\Microsoft\Windows\CurrentVersion\Search\RecentApps\" | Select-Object -ExpandProperty Name | foreach { $_.split("\")[8] }

                    foreach($R in $RA_SID)
                    {
                    echo "---------------------------------------------------" >> "$Global:Destiny\$HOSTNAME\Recent_Apps\$NAME\RecentApps.txt"
                    echo "---------------------------------------------------" >> "$Global:Destiny\$HOSTNAME\Recent_Apps\$NAME\RecentApps.txt"
                    echo "SID: $R" >> "$Global:Destiny\$HOSTNAME\Recent_Apps\$NAME\RecentApps.txt"
                    $tempAppId = Get-ItemPropertyValue "REGISTRY::HKEY_USERS\$SID\Software\Microsoft\Windows\CurrentVersion\Search\RecentApps\$R" -Name AppId
                    echo "AppID: $tempAppId"  >> "$Global:Destiny\$HOSTNAME\Recent_Apps\$NAME\RecentApps.txt"
                    $tempLaunchCount = Get-ItemPropertyValue "REGISTRY::HKEY_USERS\$SID\Software\Microsoft\Windows\CurrentVersion\Search\RecentApps\$R" -Name LaunchCount
                    echo "LaunchCount: $tempLaunchCount"  >> "$Global:Destiny\$HOSTNAME\Recent_Apps\$NAME\RecentApps.txt"
                    $tempAppPath = Get-ItemPropertyValue "REGISTRY::HKEY_USERS\$SID\Software\Microsoft\Windows\CurrentVersion\Search\RecentApps\$R" -Name AppPath
                    echo "AppPath: $tempAppPath"  >> "$Global:Destiny\$HOSTNAME\Recent_Apps\$NAME\RecentApps.txt"
                    $tempDateDec = Get-ItemPropertyValue "REGISTRY::HKEY_USERS\$SID\Software\Microsoft\Windows\CurrentVersion\Search\RecentApps\$R"-Name LastAccessedTime
                    $tempDate = [datetime]::FromFileTime($tempDateDec)
                    echo "Date: $tempDate" >> "$Global:Destiny\$HOSTNAME\Recent_Apps\$NAME\RecentApps.txt"
            
                    echo "--- Associated Files:" >> "$Global:Destiny\$HOSTNAME\Recent_Apps\$NAME\RecentApps.txt"
            
                    if(Test-Path "REGISTRY::HKEY_USERS\$SID\Software\Microsoft\Windows\CurrentVersion\Search\RecentApps\$R\RecentItems")
                    {
                        $FILE_SID = Get-ChildItem "REGISTRY::HKEY_USERS\$SID\Software\Microsoft\Windows\CurrentVersion\Search\RecentApps\$R\RecentItems\" | Select-Object -ExpandProperty Name | foreach { $_.split("\")[10] }

                        foreach($F in $FILE_SID)
                        {
                            $tempName = Get-ItemPropertyValue "REGISTRY::HKEY_USERS\$SID\Software\Microsoft\Windows\CurrentVersion\Search\RecentApps\$R\RecentItems\$F" -Name DisplayName
                            echo "`tName: $tempName"  >> "$Global:Destiny\$HOSTNAME\Recent_Apps\$NAME\RecentApps.txt"
                            $tempPath = Get-ItemPropertyValue "REGISTRY::HKEY_USERS\$SID\Software\Microsoft\Windows\CurrentVersion\Search\RecentApps\$R\RecentItems\$F" -Name Path
                            echo "`tPath: $tempPath"  >> "$Global:Destiny\$HOSTNAME\Recent_Apps\$NAME\RecentApps.txt"
                            $tempDateDec = Get-ItemPropertyValue "REGISTRY::HKEY_USERS\$SID\Software\Microsoft\Windows\CurrentVersion\Search\RecentApps\$R\RecentItems\$F" -Name LastAccessedTime
                            $tempDate = [datetime]::FromFileTime($tempDateDec)
                            echo "`tDate: $tempDate" >> "$Global:Destiny\$HOSTNAME\Recent_Apps\$NAME\RecentApps.txt"
                        }
                    }
                    else
                    {
                        echo "`tThis app doesn't have recent open files associated." >> "$Global:Destiny\$HOSTNAME\Recent_Apps\$NAME\RecentApps.txt"
                    }
                }
                }
                else
                {
                    Write-Host "`t[i] There is not RecentApps info in the registry."
                }
            }
        }
    }
}

<########### S Y S T E M   I N F O #################> # SYS
Function Collect-System-Info {    
    
    if ( -Not ( Test-Path $Global:Destiny\$HOSTNAME\System_Info\ ) ) { New-Item -ItemType directory -Path $Global:Destiny\$HOSTNAME\System_Info\ > $null }
    
    Write-Host "[+] Collecting Computer Info..." -ForegroundColor Green
    try
    {
        cmd.exe /c systeminfo > "$Global:Destiny\$HOSTNAME\System_Info\System_Info.txt"
        Get-CimInstance Win32_OperatingSystem | Select-Object * >> "$Global:Destiny\$HOSTNAME\System_Info\Operating_System_Info.txt"
        Get-CimInstance -ClassName Win32_ComputerSystem | Select-Object * >> "$Global:Destiny\$HOSTNAME\System_Info\Computer_System_Info.txt"
        Get-HotFix | Select-Object HotFixID, Description, InstalledBy, InstalledOn >> "$Global:Destiny\$HOSTNAME\System_Info\Hot_Fixes_Info.txt"
    } 
    catch 
    {
        Report-Error -evidence "Computer Info"
    }
}




<# TODO #> <########### L O C A L   S E S S I O N S #######################> # LSE 
Function Collect-Local-Sessions {
    
    if ( -Not ( Test-Path "$Global:Destiny\$HOSTNAME\System_Info" ) ) { New-Item -ItemType directory -Path "$Global:Destiny\$HOSTNAME\System_Info" > $null }

    Write-Host "[+] Collecting Local Sessions ..." -ForegroundColor Green
    Write-Host "`t[-] [DEVELOPING] ..." -ForegroundColor Yellow
    
    # query user
}

<# TODO #> <########### U S E R   A N D   P A S S W O R D   H A S H E S ###> # PWD 
Function Collect-Passwords {
    
    Write-Host "[+] Collecting Passwords" -ForegroundColor Green
    Write-Host "`t[-] [DEVELOPING] ..." -ForegroundColor Yellow

}



<##################################################################################################################################>
<############  THIRD PARTY SOFTWARE   /   LIVE SYSTEM #############################################################################>
<##################################################################################################################################>

<########### U S E R   A S S I S T ########################> # UAS
Function Collect-User-Assist {
    
    if( -not (Test-Path "$Global:Destiny\$HOSTNAME\MRUs\") ) { New-Item -ItemType Directory -Path "$Global:Destiny\$HOSTNAME\MRUs\" > $null }

    Write-Host "[+] Collecting User Assist ..." -ForegroundColor Green
    try
    {
        & "$SCRIPTPATH\bin\userassistview\UserAssistView.exe" /shtml "$Global:Destiny\$HOSTNAME\MRUs\User_Assist.html"
    }
    catch
    {
        Report-Error -evidence "User Assist"
    }
}

<########### S I G N E D   F I L E S ######################> # SFI <# TIME CONSUMING - Not by Default#>
Function Collect-Sign-Files {
    
    if( -not (Test-Path "$Global:Destiny\$HOSTNAME\Signed_Files\") ) { New-Item -ItemType Directory -Path "$Global:Destiny\$HOSTNAME\Signed_Files\" > $null }

    Write-Host "[+] Collecting Info About Signed Files " -ForegroundColor Green
    try{
        
        & $SIG_EXE /accepteula -vt -h -c -e $Global:Source\Windows\ >> "$Global:Destiny\$HOSTNAME\Signed_Files\6.SignedFiles.csv" 
        & $SIG_EXE /accepteula -vt -h -c -e $Global:Source\Windows\system32\ >> "$Global:Destiny\$HOSTNAME\Signed_Files\6.SignedFiles.csv" 
        <# & $SIG_EXE /accepteula -ct -h -vn -vt c:\Windows > "$Global:Destiny\$HOSTNAME\FILES\Signed_Windows_Files.txt" #>
        <# & $SIG_EXE /accepteula -ct -h -vn -vt c:\Windows\System32 > "$Global:Destiny\$HOSTNAME\FILES\Signed_Windows_System32_Files.txt" #>
        <# sigcheck /accepteula -s -h -e -q -c C:\ > outfilename.csv #> <# Signs all the files in the entire system - it takes a lot of time
        and if there is a onedrive installed, it will download files that are not physically in the disk#>
    } catch {
        Report-Error -evidence "Info About Signed Files"
    }
}

<########### L A S T   A C T I V I T Y ####################> # LAC
Function Collect-Last-Activity {
    
    if( -not (Test-Path "$Global:Destiny\$HOSTNAME\Last_Activity\") ) { New-Item -ItemType Directory -Path "$Global:Destiny\$HOSTNAME\Last_Activity\" > $null }

    Write-Host "[+] Collecting Last Activity ..." -ForegroundColor Green
    try
    {
        & "$SCRIPTPATH\bin\lastactivityview\LastActivityView.exe" /shtml "$Global:Destiny\$HOSTNAME\Last_Activity\Last_Ativity.html"
    }
    catch
    {
        Report-Error -evidence "Last Activity"
    }
}

<########### A L L   A U T O R U N   F I L E S ############> # AFI
Function Collect-Autorun-Files {
    
    if( -not (Test-Path "$Global:Destiny\$HOSTNAME\Autorun_Files\") ) { New-Item -ItemType Directory -Path "$Global:Destiny\$HOSTNAME\Autorun_Files\" > $null }
    
    Write-Host "[+] Collecting Autorun Files ..." -ForegroundColor Green
    try
    {
        cmd.exe /c  $SCRIPTPATH\bin\autorunsc.exe -accepteula -a * -c -h -o "$Global:Destiny\$HOSTNAME\Autorun_Files\7.AutorunFiles.csv" -s -t -u -v -vt -nobanner
    }
    catch
    {
        Report-Error -evidence "Autorun Files"
    }
}



<##################################################################################################################################>
<############  LIVE OR OFFLINE SYSTEM  /  NO VOLATILE #############################################################################>
<##################################################################################################################################>

<########### H I V E S ###########################################################> # HIV
Function Collect-Hives {

    if ( -Not ( Test-Path $Global:Destiny\$HOSTNAME\HIVES ) ) { New-Item -ItemType directory -Path $Global:Destiny\$HOSTNAME\HIVES > $null }

    try{
        Write-Host "[+] Collecting HIVES: NTUSER.DAT ..." -ForegroundColor Green
        foreach($u in $USERS){
            if($OS -eq "XP")  <# TODO: NOT SURE IF THIS WORKS, CHECK THE OS RESULT IN A XP MACHINE TO VERIFY #>
            { 
                & $RAW_EXE /FileNamePath:"$Global:Source\Documents and Settings\$u\NTUSER.dat" /OutputPath:"$Global:Destiny\$HOSTNAME\HIVES\$u" /OutputName:NTUSER.DAT > $null
            } 
            else 
            {
                if(Test-Path "$Global:Source\Users\$u\NTUSER.dat")
                {
                    if ( -Not ( Test-Path $Global:Destiny\$HOSTNAME\HIVES\$u ) ) { New-Item -ItemType directory -Path $Global:Destiny\$HOSTNAME\HIVES\$u > $null }

                    & $RAW_EXE /FileNamePath:"$Global:Source\Users\$u\NTUSER.dat" /OutputPath:"$Global:Destiny\$HOSTNAME\HIVES\$u" /OutputName:NTUSER.DAT > $null
                }
            }
        }
    }catch{
        Report-Error -evidence "HIVE NTUSER.DAT"
    }
    
    <# if(($OS -eq 10) -or ($OS -eq 8) -or ($OS -eq 7) -or ($OS -eq "VISTA") { #> 
    try{
        Write-Host "[+] Collecting HIVES: DEFAULT, SAM, SECURITY, SOFTWARE, SYSTEM ..." -ForegroundColor Green
        & $RAW_EXE /FileNamePath:"$Global:Source\Windows\System32\config\DEFAULT" /OutputPath:"$Global:Destiny\$HOSTNAME\HIVES" /OutputName:DEFAULT > $null

        & $RAW_EXE /FileNamePath:"$Global:Source\Windows\System32\config\SAM" /OutputPath:"$Global:Destiny\$HOSTNAME\HIVES" /OutputName:SAM > $null
        
        & $RAW_EXE /FileNamePath:"$Global:Source\Windows\System32\config\SECURITY" /OutputPath:"$Global:Destiny\$HOSTNAME\HIVES" /OutputName:SECURITY > $null
        
        & $RAW_EXE /FileNamePath:"$Global:Source\Windows\System32\config\SOFTWARE" /OutputPath:"$Global:Destiny\$HOSTNAME\HIVES" /OutputName:SOFTWARE > $null
        
        & $RAW_EXE /FileNamePath:"$Global:Source\Windows\System32\config\SYSTEM" /OutputPath:"$Global:Destiny\$HOSTNAME\HIVES" /OutputName:SYSTEM > $null
        
    }catch{
        Report-Error -evidence "HIVES: DEFAULT, SAM, SECURITY, SOFTWARE, SYSTEM"
    }

    try
    {
        Write-Host "[+] Collecting HIVES: COMPONENTS, UsrClass.dat ..." -ForegroundColor Green
        & $RAW_EXE /FileNamePath:"$Global:Source\Windows\System32\config\COMPONENTS" /OutputPath:"$Global:Destiny\$HOSTNAME\HIVES" /OutputName:COMPONENTS > $null
        foreach($u in $USERS)
        {
            if(Test-Path "$Global:Source\Users\$u\AppData\Local\Microsoft\Windows\UsrClass.dat")
            {
                if ( -Not ( Test-Path $Global:Destiny\$HOSTNAME\HIVES\$u ) ) { New-Item -ItemType directory -Path $Global:Destiny\$HOSTNAME\HIVES\$u > $null }

                & $RAW_EXE /FileNamePath:"$Global:Source\Users\$u\AppData\Local\Microsoft\Windows\UsrClass.dat" /OutputPath:"$Global:Destiny\$HOSTNAME\HIVES\$u" /OutputName:UsrClass.dat > $null
            }
        }
    } 
    catch 
    {
        Report-Error -evidence "HIVES: UsrClass. Maybe because of the OS."
    }
    <# if(($OS -eq 10) -or ($OS -eq 8)) { #> 

    try
    {
        Write-Host "[+] Collecting HIVES: BCD-TEMPLATE, BBI, DRIVERS, ELAM, Amcache.hve ..." -ForegroundColor Green

        & $RAW_EXE /FileNamePath:"$Global:Source\Windows\System32\config\BCD-Template" /OutputPath:"$Global:Destiny\$HOSTNAME\HIVES" /OutputName:BCD-Template > $null
        
        & $RAW_EXE /FileNamePath:"$Global:Source\Windows\System32\config\BBI" /OutputPath:"$Global:Destiny\$HOSTNAME\HIVES" /OutputName:BBI > $null
        
        & $RAW_EXE /FileNamePath:"$Global:Source\Windows\System32\config\DRIVERS" /OutputPath:"$Global:Destiny\$HOSTNAME\HIVES" /OutputName:DRIVERS > $null
        
        & $RAW_EXE /FileNamePath:"$Global:Source\Windows\System32\config\ELAM" /OutputPath:"$Global:Destiny\$HOSTNAME\HIVES" /OutputName:ELAM > $null
        
        & $RAW_EXE /FileNamePath:"$Global:Source\Windows\AppCompat\Programs\Amcache.hve" /OutputPath:"$Global:Destiny\$HOSTNAME\HIVES" /OutputName:Amcache.hve > $null
    } 
    catch 
    {
        Report-Error -evidence "HIVES: BCD-TEMPLATE, BBI, DRIVERS, ELAM, Amcache. Maybe because of the OS."
    }
}

<########### E V T X   F I L E S #################################################> # EVT
# TODO: parse "Microsoft-Windows-TaskScheduler/Operational" in search for events 106, 140, 141 - More info: https://attack.mitre.org/techniques/T1053/
Function Collect-EVTX-Files {

    if ( -Not ( Test-Path "$Global:Destiny\$HOSTNAME\EVTX" ) ) { New-Item -ItemType directory -Path "$Global:Destiny\$HOSTNAME\EVTX" > $null }

    Write-Host "[+] Collecting EVTX Files ..." -ForegroundColor Green
    Get-ChildItem "$Global:Source\Windows\System32\winevt\Logs" -Filter *.evtx | ForEach-Object {
        if($_.Length -gt 69632)
        {
            $evtx_name_ext = ($_.FullName).Split("\")[5]
            try{
                <# Write-Host "[+] ... EVTX File: $evtx_name_ext" #>
                $evtx_name = ((($_.FullName).Split("\")[5]).Split(".")[0]).Replace("%4","/")
                & cmd.exe /c wevtutil epl $evtx_name $Global:Destiny\$HOSTNAME\EVTX\$evtx_name_ext
                <# & cmd.exe /c psloglist -s $evtx_name "$Global:Destiny\$HOSTNAME\EVTX\"+(($evtx_name_ext).Split(".")[0])+".csv" #> <# Just works fot application, system and security #>
                <# & $RAW_EXE $_.FullName $Global:Destiny\$HOSTNAME\EVTX\. > $null #> <# much slower #>
            } catch {
                Report-Error -evidence "$evtx_name_ext"
            }
        }
    }

    try{
        Write-Host "[+] Parsing some EVTx files ..." -ForegroundColor Green
        & "$SCRIPTPATH\bin\psloglist.exe" -s application > "$Global:Destiny\$HOSTNAME\EVTX\Application.csv" 2> $null
        & "$SCRIPTPATH\bin\psloglist.exe" -s system > "$Global:Destiny\$HOSTNAME\EVTX\System.csv" 2> $null
        & "$SCRIPTPATH\bin\psloglist.exe" -s security > "$Global:Destiny\$HOSTNAME\EVTX\Security.csv" 2> $null
    } catch {
        Report-Error -evidence "application or system or security to csv file"
    }
}

<########### F I L E S   L I S T S ###############################################> # FIL
Function Collect-Files-Lists {

    if ( -Not ( Test-Path $Global:Destiny\$HOSTNAME\FILES ) ) { New-Item -ItemType directory -Path $Global:Destiny\$HOSTNAME\FILES > $null }

    try{
        Write-Host "[+] Collecting List of Files of the System ... " -ForegroundColor Green
        cmd.exe /c dir /t:w /a /s /o:d $Global:Source\ > "$Global:Destiny\$HOSTNAME\FILES\File_List_Sorted_Modification_Date.txt"
        cmd.exe /c dir /t:a /a /s /o:d $Global:Source\ > "$Global:Destiny\$HOSTNAME\FILES\File_List_Sorted_Last_Access.txt"
        cmd.exe /c dir /t:c /a /s /o:d $Global:Source\ > "$Global:Destiny\$HOSTNAME\FILES\File_List_Sorted_Creation_Date.txt"
    
    } catch {
        Report-Error -evidence "List of Files of the System"
    }
}

<########### P R E F E T C H #####################################################> # PRF
Function Collect-Prefetch {

    if ( -Not ( Test-Path $Global:Destiny\$HOSTNAME\Prefetch ) ) { New-Item -ItemType directory -Path $Global:Destiny\$HOSTNAME\Prefetch > $null }

    try{
        Write-Host "[+] Collecting Prefetch Files ... " -ForegroundColor Green
        copy $Global:Source\Windows\Prefetch\*.pf $Global:Destiny\$HOSTNAME\Prefetch\
        copy $Global:Source\Windows\Prefetch\*.db $Global:Destiny\$HOSTNAME\Prefetch\
    } catch {
        Report-Error -evidence "Prefetch Files"
    }
}

<########### W I N D O W S   S E A R C H #########################################> # WSE
Function Collect-Windows-Search {
    
    if( Test-Path -Path "$Global:Source\ProgramData\Microsoft\Search\Data\Applications\Windows\Windows.edb")
    {
        Write-Host "[+] Collecting Windows Search File windows.edb ... " -ForegroundColor Green
        try
        {
            if ( -Not ( Test-Path $Global:Destiny\$HOSTNAME\Windows_Search\ ) ) { New-Item -ItemType directory -Path $Global:Destiny\$HOSTNAME\Windows_Search\ > $null }

            & $RAW_EXE /FileNamePath:"$Global:Source\ProgramData\Microsoft\Search\Data\Applications\Windows\Windows.edb" /OutputPath:"$Global:Destiny\$HOSTNAME\Windows_Search" /OutputName:Windows.edb > $null
        } 
        catch 
        {
            Report-Error -evidence "Windows Search File windows.edb"
        }
    }
    else
    {
        Write-Host "[-] Windows Search File windows.edb does not exist ... " -ForegroundColor Yellow
    }
}

<########### E T W   &   E T L ###################################################> # EET
Function Collect-ETW-ETL {
    <# maybe consider the following: C:\Windows\System32\WDI #>
    try
    {
        Write-Host "[+] Collecting ETL files ..." -ForegroundColor Green

        if ( -Not ( Test-Path $Global:Destiny\$HOSTNAME\ETL\ ) ) { New-Item -ItemType directory -Path $Global:Destiny\$HOSTNAME\ETL\ > $null }
        
        & $RAW_EXE /FileNamePath:"$Global:Source\Windows\System32\WDI\LogFiles\BootCKCL.etl" /OutputPath:"$Global:Destiny\$HOSTNAME\ETL" /OutputName:BootCKCL.etl > $null

        & $RAW_EXE /FileNamePath:"$Global:Source\Windows\System32\WDI\LogFiles\ShutdownCKCL.etl" /OutputPath:"$Global:Destiny\$HOSTNAME\ETL" /OutputName:ShutdownCKCL.etl > $null
        
        & $RAW_EXE /FileNamePath:"$Global:Source\Windows\System32\LogFiles\WMI\LwtNetLog.etl" /OutputPath:"$Global:Destiny\$HOSTNAME\ETL" /OutputName:LwtNetLog.etl > $null <# TODO: Can't Copy#>

        & $RAW_EXE /FileNamePath:"$Global:Source\Windows\System32\LogFiles\WMI\Wifi.etl" /OutputPath:"$Global:Destiny\$HOSTNAME\ETL" /OutputName:Wifi.etl > $null <# TODO: Can't Copy#>
        
        & $RAW_EXE /FileNamePath:"$Global:Source\Windows\Panther\setup.etl" /OutputPath:"$Global:Destiny\$HOSTNAME\ETL" /OutputName:setup.etl > $null
        
        foreach($u in $USERS)
        {
            if(Test-Path "$Global:Source\Users\$u\AppData\Local\Microsoft\Windows\Explorer\ExplorerStartupLog.etl")
            {
                if ( -Not ( Test-Path $Global:Destiny\$HOSTNAME\ETL\$u\ ) ) { New-Item -ItemType directory -Path $Global:Destiny\$HOSTNAME\ETL\$u\ > $null }
                & $RAW_EXE /FileNamePath:"$Global:Source\Users\$u\AppData\Local\Microsoft\Windows\Explorer\ExplorerStartupLog.etl" /OutputPath:"$Global:Destiny\$HOSTNAME\ETL\$u" /OutputName:ExplorerStartupLog.etl > $null
            }
            
            if(Test-Path "$Global:Source\Users\$u\AppData\Local\Microsoft\Windows\Explorer\ExplorerStartupLog_RunOnce.etl")
            {
                if ( -Not ( Test-Path $Global:Destiny\$HOSTNAME\ETL\$u\ ) ) { New-Item -ItemType directory -Path $Global:Destiny\$HOSTNAME\ETL\$u\ > $null }
                & $RAW_EXE /FileNamePath:"$Global:Source\Users\$u\AppData\Local\Microsoft\Windows\Explorer\ExplorerStartupLog_RunOnce.etl" /OutputPath:"$Global:Destiny\$HOSTNAME\ETL\$u" /OutputName:ExplorerStartupLog_RunOnce.etl > $null
            }
        }
    } 
    catch 
    {
        Report-Error -evidence "ETL files"
    }
}

<########### T H U M C A C H E ###################################################> # THC
Function Collect-Thumcache {
    
    Write-Host "[+] Collecting THUMCACHE files. Check log file for more info." -ForegroundColor Green
    foreach($u in $USERS)
    {
        try
        {
            New-Item -ItemType directory -Path $Global:Destiny\$HOSTNAME\THUMCACHE\$u\ > $null
            cmd.exe /c copy "$Global:Source\Users\$u\AppData\Local\Microsoft\Windows\Explorer\thumbcache*.db" "$Global:Destiny\$HOSTNAME\THUMCACHE\$u\." > $null
        } 
        catch 
        {
            Report-Error -evidence "THUMCACHE files"
        }
    }
}

<########### I C O N C A C H E ###################################################> # ICO
Function Collect-Iconcache {
    
    Write-Host "[+] Collecting ICONCACHE files. Check log file for more info." -ForegroundColor Green
    
    foreach($u in $USERS)
    {
        if(Test-Path "$Global:Source\Users\$u\AppData\Local\IconCache.db")
        {
            try
            {
                if ( -Not ( Test-Path $Global:Destiny\$HOSTNAME\ICONCACHE\$u\ ) ) { New-Item -ItemType directory -Path $Global:Destiny\$HOSTNAME\ICONCACHE\$u\ > $null }
            
                & $RAW_EXE /FileNamePath:"$Global:Source\Users\$u\AppData\Local\IconCache.db" /OutputPath:"$Global:Destiny\$HOSTNAME\ICONCACHE\$u" /OutputName:IconCache.db > $null
                cmd.exe /c copy "$Global:Source\Users\$u\AppData\Local\Microsoft\Windows\Explorer\iconcache*.db" "$Global:Destiny\$HOSTNAME\ICONCACHE\$u\." > $null
            } 
            catch 
            {
                Report-Error -evidence "ICONCACHE files"
            }
        }
    }
}

<########### M F T   A N D   U S R J R N L #######################################> # MUL
Function Collect-MFT-UsnJrnl-LogFile {
    
    if ( -Not ( Test-Path "$Global:Destiny\$HOSTNAME\ROOT_FILES\" ) ) { New-Item -ItemType directory -Path "$Global:Destiny\$HOSTNAME\ROOT_FILES\" > $null }

    # $MFT
    Write-Host "[+] Collecting `$MFT file. Check log file for more info." -ForegroundColor Green

    try
    {
        & $RAW_EXE /FileNamePath:$Global:Source\`$MFT /OutputPath:$Global:Destiny\$HOSTNAME\ROOT_FILES /OutputName:`$MFT > $null
    }
    catch
    {
        Report-Error -evidence "`$MFT file"
    }

    # $UsnJrnl
    Write-Host "[+] Collecting `$UsnJrnl file. Check log file for more info." -ForegroundColor Green

    try
    {
        & $RAW_EXE /FileNamePath:$Global:Source\`$Extend\`$UsnJrnl /OutputPath:$Global:Destiny\$HOSTNAME\ROOT_FILES /OutputName:`$UsnJrnl > $null
    }
    catch
    {
        Report-Error -evidence "`$UsnJrnl file"
    }

    # $LogFile
    Write-Host "[+] Collecting `$LogFile file. Check log file for more info." -ForegroundColor Green

    try
    {
        & $RAW_EXE /FileNamePath:"$Global:Source\`$LogFile" /OutputPath:"$Global:Destiny\$HOSTNAME\ROOT_FILES" /OutputName:"`$LogFile" > $null
    }
    catch
    {
        Report-Error -evidence "`$LogFile file"
    }

}

<########### H I B E R F I L   P A G E F I L E   S W A P F I L E #################> # HPS
Function Collect-Hiberfil-Pagefile-Swapfile {

    if ( -Not ( Test-Path "$Global:Destiny\$HOSTNAME\ROOT_FILES\" ) ) { New-Item -ItemType directory -Path "$Global:Destiny\$HOSTNAME\ROOT_FILES\" > $null }

    # hiberfil.sys
    Write-Host "[+] Collecting hiberfil.sys file. Check log file for more info." -ForegroundColor Green

    try
    {
        & $RAW_EXE /FileNamePath:$Global:Source\hiberfil.sys /OutputPath:$Global:Destiny\$HOSTNAME\ROOT_FILES /OutputName:hiberfil.sys > $null
    }
    catch
    {
        Report-Error -evidence "hiberfil.sys file"
    }

    # pagefile.sys
    Write-Host "[+] Collecting pagefile.sys file. Check log file for more info." -ForegroundColor Green

    try
    {
        & $RAW_EXE /FileNamePath:$Global:Source\pagefile.sys /OutputPath:$Global:Destiny\$HOSTNAME\ROOT_FILES /OutputName:pagefile.sys > $null
    }
    catch
    {
        Report-Error -evidence "pagefile.sys file"
    }

    # swapfile.sys
    Write-Host "[+] Collecting swapfile.sys file. Check log file for more info." -ForegroundColor Green

    try
    {
        & $RAW_EXE /FileNamePath:"$Global:Source\swapfile.sys" /OutputPath:"$Global:Destiny\$HOSTNAME\ROOT_FILES" /OutputName:"swapfile.sys" > $null
    }
    catch
    {
        Report-Error -evidence "swapfile.sys file"
    }
}

<########### D A N G E R O U S   E X T E N S I O N S #############################> # DEX <# TODO: Change letter C:\ for variable so it also works with offline file system. #>
Function Collect-Dangerous-Extensions {
    
    $extensions = "VB","VBS","PIF","BAT","CMD","JS","JSE","WS","WSF","WSC","WSH","PS1","PS1XML","PS2","PS2XML","PSC1","PSC2","MSH","MSH1","MSH2","MSHXML","MSH1XML","MSH2XML","SCF","LNK","INF","APPLICATION","GADGET","SCR","HTA","CPL", "MSI", "COM", "EXE"

    Write-Host "[+] Collecting List of files with Dangerous extensions..." -ForegroundColor Green

    foreach ($extension in $extensions)
    {
        try
        {
            if ( -Not ( Test-Path $Global:Destiny\$HOSTNAME\Extensions ) ) { New-Item -ItemType directory -Path $Global:Destiny\$HOSTNAME\Extensions > $null }
            
            Get-ChildItem "C:\" -File -Recurse "*.$extension" | ForEach-Object {        # +- 14 mins
                $_.FullName >> "$Global:Destiny\$HOSTNAME\Extensions\$extension.txt"
            }
            if($extension -like "VB") {Write-Host -n "`t└>$extension" -ForegroundColor Green }
            if($extension -notlike "VB" -or $extension -notlike "EXE") {Write-Host -n ", $extension" -ForegroundColor Green }
            if($extension -like "EXE") {Write-Host ", $extension" -ForegroundColor Green }

            # cmd.exe /c dir /T:C /S c:\*.$extension >> "$Global:Destiny\$HOSTNAME\Extensions\dir_$extension.txtdir" # - Alternative  +- 3mins
        } 
        catch 
        {
            Report-Error -evidence "List of Extension $extension"
        }
    }

}

<########### T E X T   H A R V E S T E R #########################################> # THA
Function Collect-TextHarvester { <# TODO: Have to activate this option in a OS an try it. #>

    Write-Host "[+] Collecting Text Harvester ..." -ForegroundColor Green

    if( ($OS -like "8") -or ($OS -eq "10") ) 
    {
        foreach($u in $USERS)
        {
            if( Test-Path -Path "$Global:Source\Users\$u\AppData\Local\Microsoft\InputPersonalization\TextHarvester\WaitList.dat") 
            {
                try 
                {
                    Write-Host "[+] Collecting TextHarvester for user $u..." -ForegroundColor DarkGreen
                
                    if ( -Not ( Test-Path "$Global:Destiny\$HOSTNAME\TextHarvester\$u" ) ) { New-Item -ItemType directory -Path "$Global:Destiny\$HOSTNAME\TextHarvester\$u" > $null }
                    
                    # OLD & $RAW_EXE "$Global:Source\Users\$u\AppData\Local\Microsoft\InputPersonalization\TextHarvester\WaitList.dat" "$Global:Destiny\$HOSTNAME\TextHarvester\$u\." > $null
                    & $RAW_EXE /FileNamePath:"$Global:Source\Users\$u\AppData\Local\Microsoft\InputPersonalization\TextHarvester\WaitList.dat" /OutputPath:"$Global:Destiny\$HOSTNAME\TextHarvester\$u" /OutputName:WaitList.dat > $null
                } 
                catch 
                {
                    Report-Error -evidence "TextHarvester"
                }
            }
        }
    }
} 

<########### S R U M #############################################################> # SRU
Function Collect-SRUM {

    # SRUM - SYSTEM RESOURCE USAGE MONITOR 

    if( Test-Path -Path "$Global:Source\Windows\System32\sru\SRUDB.dat") 
    {
        # COLLECT THE RAW INFORMATION/EVIDENCE
        try 
        {
            Write-Host "[+] Collecting - System Resource Usage Monitor (SRUM) ..." -ForegroundColor Green
                
            if ( -Not ( Test-Path -Path "$Global:Destiny\$HOSTNAME\SRUM\" ) ) { New-Item -ItemType directory -Path "$Global:Destiny\$HOSTNAME\SRUM" > $null }

            cmd.exe /c copy "$Global:Source\Windows\System32\sru\SRUDB.dat" "$Global:Destiny\$HOSTNAME\SRUM" > $null
        } 
        catch 
        {
            Report-Error -evidence "Collecting - System Resource Usage Monitor (SRUM)"
        }

        # TREAT THE INFORMATION/EVIDENCE
        try
        {
            Write-Host "[+] Treating - System Resource Usage Monitor (SRUM) ..." -ForegroundColor Green
                
            if( -Not (Test-Path -Path "$Global:Destiny\$HOSTNAME\HIVES\SOFTWARE") ) # Collect HIVE SOFTWARE in case it was not collected yet
            {
                Write-Host "`t[*] Collecting HIVE SOFTWARE ..." -ForegroundColor Yellow
                
                if ( -Not ( Test-Path $Global:Destiny\$HOSTNAME\HIVES ) ) { New-Item -ItemType directory -Path $Global:Destiny\$HOSTNAME\HIVES > $null }

                & $RAW_EXE /FileNamePath:"$Global:Source\Windows\System32\config\SOFTWARE" /OutputPath:"$Global:Destiny\$HOSTNAME\HIVES" /OutputName:SOFTWARE > $null
            }
            
            if ( -Not ( Test-Path -Path "$Global:Destiny\$HOSTNAME\SRUM\" ) ) { New-Item -ItemType directory -Path "$Global:Destiny\$HOSTNAME\SRUM" > $null }

            cmd.exe /c $SCRIPTPATH\bin\srum-dump\srum_dump.exe --SRUM_INFILE "$Global:Destiny\$HOSTNAME\SRUM\srudb.dat" --XLSX_OUTFILE "$Global:Destiny\$HOSTNAME\SRUM\SRUM.xlsx" --XLSX_TEMPLATE $SCRIPTPATH\bin\srum-dump\SRUM_TEMPLATE.xlsx --REG_HIVE "$Global:Destiny\$HOSTNAME\HIVES\SOFTWARE" > $null
            cmd.exe /c $SCRIPTPATH\bin\srum-dump\srum_dump_csv.exe --SRUM_INFILE "$Global:Destiny\$HOSTNAME\SRUM\srudb.dat" --OUT_PATH "$Global:Destiny\$HOSTNAME\SRUM" --XLSX_TEMPLATE $SCRIPTPATH\bin\srum-dump\SRUM_TEMPLATE.xlsx --REG_HIVE "$Global:Destiny\$HOSTNAME\HIVES\SOFTWARE"  > $null
        }
        catch
        {
            Report-Error -evidence "Treating - System Resource Usage Monitor (SRUM)"
        }

    }
    else
    {
        Write-Host "[-] No System Resource Usage Monitor (SRUM) found in the system ..." -ForegroundColor Yellow
    }

}

<########### C R E D E N T I A L S ###############################################> # CRE
Function Collect-Credentials {

    # Credentials

    foreach($u in $USERS)
    {
        # COLLECT THE RAW INFORMATION/EVIDENCE
        try 
        {
            Write-Host "[+] Collecting - Credentials Stored in File System ..." -ForegroundColor Green


            # "C:\Users\<user>\AppData\Roaming\Microsoft\Credentials"
            if("$Global:Source\Users\$u\AppData\Roaming\Microsoft\Credentials")
            {
                if ( -Not ( Test-Path -Path "$Global:Destiny\$HOSTNAME\Credentials\$u\Roaming" ) ) { New-Item -ItemType directory -Path "$Global:Destiny\$HOSTNAME\Credentials\$u\Roaming" > $null }

                $tempFileList1 = Get-ChildItem -Force "$Global:Source\Users\$u\AppData\Roaming\Microsoft\Credentials" | ForEach-Object { $_.Name }
                
                foreach($file in $tempFileList1)
                {
                    & $RAW_EXE /FileNamePath:"$Global:Source\Users\$u\AppData\Roaming\Microsoft\Credentials\$file" /OutputPath:"$Global:Destiny\$HOSTNAME\Credentials\$u\Roaming" /OutputName:$file > $null
                }
            }

            # "C:\Users\<user>\AppData\Local\Microsoft\Credentials"
            if("$Global:Source\Users\$u\AppData\Local\Microsoft\Credentials")
            {
                if ( -Not ( Test-Path -Path "$Global:Destiny\$HOSTNAME\Credentials\$u\Local" ) ) { New-Item -ItemType directory -Path "$Global:Destiny\$HOSTNAME\Credentials\$u\Local" > $null }

                $tempFileList2 = Get-ChildItem -Force "$Global:Source\Users\$u\AppData\Local\Microsoft\Credentials" | ForEach-Object { $_.Name }
                
                foreach($file in $tempFileList2)
                {
                    & $RAW_EXE /FileNamePath:"$Global:Source\Users\$u\AppData\Local\Microsoft\Credentials\$file" /OutputPath:"$Global:Destiny\$HOSTNAME\Credentials\$u\Local" /OutputName:$file  > $null
                }
            }

        } 
        catch 
        {
            Report-Error -evidence "Collecting - Credentials Stored in File System"
        }

        # TREAT THE INFORMATION/EVIDENCE
        try
        {
            Write-Host "[+] Treating - Credentials Stored in File System  ..." -ForegroundColor Green
            Write-Host "`t[-] [DEVELOPING] ..." -ForegroundColor Yellow

        }
        catch
        {
            Report-Error -evidence "Treating - Credentials Stored in File System"
        }

    }

}


<########### S K Y P E ###########################################################> #SKY 
Function Collect-Skype-History {

    $blacklist = "Content","DataRv","logs","RootTools"

    Write-Host "[+] Trying to collect Skype Information ... " -ForegroundColor Green

    if($OS -eq "XP")
    {
        foreach($u in $USERS)
        {
            Write-Host "`t[+] User $u ... " -ForegroundColor Green
            
            if(Test-Path "$Global:Source\Documents and Settings\$u\Application\Skype\")
            {       
                Get-Item  "$Global:Source\Documents and Settings\$u\Application\Skype\*" | ForEach-Object {
                 
                    if(Test-Path -Path $_.FullName -PathType Container) # if it's a folder
                    {
                        if((-not ($blacklist -contains $_.Name ))   ) # if not in the blacklist
                        {
                            if($_.Name -like "My Skype Received Files" )
                            {
                                if( -not (Test-Path "$Global:Destiny\$HOSTNAME\SKYPE\$u\ReceivedFiles") ) { New-Item -ItemType Directory -Path "$Global:Destiny\$HOSTNAME\SKYPE\$u\ReceivedFiles" > $null }

                                cmd.exe /c copy "$Global:Source\Documents and Settings\$u\Application\Skype\My Skype Received Files\*.*" "$Global:Destiny\$HOSTNAME\SKYPE\$u\ReceivedFiles\" > $null
                            }
                            else
                            {
                                if( -not (Test-Path "$Global:Destiny\$HOSTNAME\SKYPE\$u\$($_.Name)") ) { New-Item -ItemType Directory -Path "$Global:Destiny\$HOSTNAME\SKYPE\$u\$($_.Name)" > $null }

                                cmd.exe /c copy "$Global:Source\Documents and Settings\$u\Application\Skype\$($_.Name)\*.*" "$Global:Destiny\$HOSTNAME\SKYPE\$u\$($_.Name)\" > $null
                                $bla = $_.Name
                            }
                        }
                    }
                }
                & "$SCRIPTPATH\bin\skypelogview\SkypeLogView.exe" /logsfolder "$Global:Destiny\$HOSTNAME\SKYPE\$u\$bla\" /shtml "$Global:Destiny\$HOSTNAME\SKYPE\$u\Skype_Conversations.html"
            }
            else
            {
                Write-Host "`t[-] Skype is not installed for user $u" -ForegroundColor Yellow
            }
        }
    }
    else
    {
        foreach($u in $USERS)
        {
            Write-Host "`t[+] User $u ... " -ForegroundColor Green
            
            if(Test-Path "$Global:Source\Users\$u\AppData\Roaming\Skype\")
            {       
                Get-Item  "$Global:Source\Users\$u\AppData\Roaming\Skype\*" | ForEach-Object {
                 
                    if(Test-Path -Path $_.FullName -PathType Container) # if it's a folder
                    {
                        if((-not ($blacklist -contains $_.Name ))   ) # if not in the blacklist
                        {
                            if($_.Name -like "My Skype Received Files" )
                            {
                                if( -not (Test-Path "$Global:Destiny\$HOSTNAME\SKYPE\$u\ReceivedFiles") ) { New-Item -ItemType Directory -Path "$Global:Destiny\$HOSTNAME\SKYPE\$u\ReceivedFiles" > $null }

                                cmd.exe /c copy "$Global:Source\Users\$u\AppData\Roaming\Skype\My Skype Received Files\*.*" "$Global:Destiny\$HOSTNAME\SKYPE\$u\ReceivedFiles\" > $null
                            }
                            else
                            {
                                if( -not (Test-Path "$Global:Destiny\$HOSTNAME\SKYPE\$u\$($_.Name)") ) { New-Item -ItemType Directory -Path "$Global:Destiny\$HOSTNAME\SKYPE\$u\$($_.Name)" > $null }

                                cmd.exe /c copy "$Global:Source\Users\$u\AppData\Roaming\Skype\$($_.Name)\*.*" "$Global:Destiny\$HOSTNAME\SKYPE\$u\$($_.Name)\" > $null
                                $bla = $_.Name
                            }
                        }
                    }
                }
                & "$SCRIPTPATH\bin\skypelogview\SkypeLogView.exe" /logsfolder "$Global:Destiny\$HOSTNAME\SKYPE\$u\$bla\" /shtml "$Global:Destiny\$HOSTNAME\SKYPE\$u\Skype_Conversations.html"
            }
            else
            {
                Write-Host "`t[-] Skype is not installed for user $u" -ForegroundColor Yellow
            }
        }
    }
}

<########### B R O W S E R S #####################################################>

<########### C H R O M E   W E B   B R O W S E R #############> # CHR
Function Collect-Chrome-Data {
    foreach($u in $USERS){
    
        if($OS -eq "XP")
        {
            if(Test-Path "C:\Documents and Settings\$u\Local Settings\Application Data\Google\Chrome\")
            {
                try{
                    Write-Host "[+] Collecting Chrome files (from Windows $OS system)..." -ForegroundColor Green
                    New-Item -ItemType directory -Path $Global:Destiny\$HOSTNAME\WEB_BROWSERS\CHROME\$u > $null
                    cmd.exe /c copy "$Global:Source\Documents and Settings\$u\Local Settings\Application Data\Google\Chrome\User Data\Default\Preferences" "$Global:Destiny\$HOSTNAME\WEB_BROWSERS\CHROME\$u\."> $null
                    cmd.exe /c copy "$Global:Source\Documents and Settings\$u\Local Settings\Application Data\Google\Chrome\User Data\Cache\*.*" "$Global:Destiny\$HOSTNAME\WEB_BROWSERS\CHROME\$u\."> $null
                } catch {
                    Report-Error -evidence "Chrome files"
                }
            }  
        }

        if( ($OS -eq "7") -or ($OS -eq "Vista") -or ($OS -eq "8") -or ($OS -eq "10") )
        {
            if(Test-Path "C:\Users\$u\AppData\Local\Google\Chrome\User data")
            {
                try{
                    Write-Host "[+] Collecting Chrome files (from Windows $OS system)..." -ForegroundColor Green
                    New-Item -ItemType directory -Path $Global:Destiny\$HOSTNAME\WEB_BROWSERS\CHROME\$u > $null
                    cmd.exe /c copy "$Global:Source\Users\$u\AppData\Local\Google\Chrome\User Data\Default\Preferences" "$Global:Destiny\$HOSTNAME\WEB_BROWSERS\CHROME\$u\."> $null
                    cmd.exe /c copy "$Global:Source\Users\$u\AppData\Local\Google\Chrome\User Data\Default\Cache\*.*" "$Global:Destiny\$HOSTNAME\WEB_BROWSERS\CHROME\$u\."> $null
                    cmd.exe /c copy "$Global:Source\Users\$u\AppData\Local\Google\Chrome\User Data\Default\Application Cache\Cache\*.*" "$Global:Destiny\$HOSTNAME\WEB_BROWSERS\CHROME\$u\."> $null
                    cmd.exe /c copy "$Global:Source\Users\$u\AppData\Local\Google\Chrome\User Data\Default\Media Cache\*.*" "$Global:Destiny\$HOSTNAME\WEB_BROWSERS\CHROME\$u\."> $null
                    cmd.exe /c copy "$Global:Source\Users\$u\AppData\Local\Google\Chrome\User Data\Default\GPUCache\*.*" "$Global:Destiny\$HOSTNAME\WEB_BROWSERS\CHROME\$u\."> $null
                } catch {
                    Report-Error -evidence "Chrome files"
                }
            }
        }

        if( -not (Test-Path "$Global:Destiny\$HOSTNAME\WEB_BROWSERS\CHROME\")){
            Write-Host "`t[i] There is no Chrome Browser in the System ..." -ForegroundColor Yellow
        }
    }
}

<########### F I R E F O X   W E B   B R O W S E R ###########> # MFI
Function Collect-Firefox-Data {
    foreach($u in $USERS){
    
        if($OS -eq "XP")
        {
            if(Test-Path "$Global:Source\Documents and Settings\$u\Application Data\Mozilla\Firefox\Profiles\")
            {
                $FF_PROFS = Get-ChildItem "$Global:Source\Documents and Settings\$u\Application Data\Mozilla\Firefox\Profiles\" | Select-Object -ExpandProperty Name
                foreach($PROF in $FF_PROFS){
                    try{
                        Write-Host "[+] Collecting Firefox files ..." -ForegroundColor Green
                        New-Item -ItemType directory -Path $Global:Destiny\$HOSTNAME\WEB_BROWSERS\FIREFOX\$u > $null
                        cmd.exe /c copy "$Global:Source\Documents and Settings\$u\Application Data\Mozilla\Firefox\Profiles\$PROF\places.sqlite" "$Global:Destiny\$HOSTNAME\WEB_BROWSERS\FIREFOX\$u\$PROF\."> $null
                    
                    } catch {
                        Report-Error -evidence "Firefox files"
                    }
                }
            }  
        }

        if( ($OS -eq "7") -or ($OS -eq "Vista") -or ($OS -eq "8") -or ($OS -eq "10") )
        {
            if(Test-Path "$Global:Source\Users\$u\AppData\Roaming\Mozilla\Firefox\Profiles\")
            {
                $FF_PROFS = Get-ChildItem "$Global:Source\Users\$u\AppData\Roaming\Mozilla\Firefox\Profiles\" | Select-Object -ExpandProperty Name
                foreach($PROF in $FF_PROFS){
                    try{ 
                        Write-Host "[+] Collecting Firefox files ..." -ForegroundColor Green
                        New-Item -ItemType directory -Path $Global:Destiny\$HOSTNAME\WEB_BROWSERS\FIREFOX\$u\$PROF > $null
                        cmd.exe /c copy "$Global:Source\Users\$u\AppData\Roaming\Mozilla\Firefox\Profiles\$PROF\places.sqlite" "$Global:Destiny\$HOSTNAME\WEB_BROWSERS\FIREFOX\$u\$PROF\."> $null
                        <# cmd.exe /c copy "C:\Users\$u\AppData\Local\Mozilla\Firefox\Profiles\$PROF\Cache\*.*" "$Global:Destiny\$HOSTNAME\WEB_BROWSERS\FIREFOX\$u\$PROF\." #>
                    } catch {
                        Report-Error -evidence "Firefox files"
                    }
                }
            }
        }

        if( -not (Test-Path "$Global:Destiny\$HOSTNAME\WEB_BROWSERS\FIREFOX\")){
            Write-Host "`t[i] There is no Firefox Browser installed for user $u ..." -ForegroundColor Yellow
        }
    }
}

<########### I E   W E B   B R O W S E R #####################> # IEX
Function Collect-IE-Data {
    # TODO: see if it adds something new -> Extracts cache inf0rmation from IE - http://www.nirsoft.net/utils/ie_cache_viewer.html 
    foreach($u in $USERS)
    {
        if($OS -eq "XP")
        {
            if(Test-Path -Path "$Global:Source\Documents and Settings\$u\Local Settings\Temporary Internet Files\")
            {
                try
                {
                    Write-Host "[+] Collecting IE files ..." -ForegroundColor Green
                    
                    New-Item -ItemType directory -Path $Global:Destiny\$HOSTNAME\WEB_BROWSERS\IE\$u > $null
                    
                    cmd.exe /c copy "$Global:Source\Documents and Settings\$u\Local Settings\Temporary Internet Files\" "$Global:Destiny\$HOSTNAME\WEB_BROWSERS\IE\$u\."> $null
                } 
                catch 
                {
                    Report-Error -evidence "IE files"
                }
            }  
        }

        if( ($OS -eq "7") -or ($OS -eq "Vista") -or ($OS -like "8") -or ($OS -eq "10") )
        {
            if(Test-Path -Path "$Global:Source\Users\$u\AppData\Local\Microsoft\Windows\WebCache\")
            {
                try
                {
                    Write-Host "[+] Collecting IE files, user: $u ... " -ForegroundColor Green

                    New-Item -ItemType directory -Path $Global:Destiny\$HOSTNAME\WEB_BROWSERS\IE\$u > $null
                    
                    & $RAW_EXE /FileNamePath:"$Global:Source\Users\$u\AppData\Local\Microsoft\Windows\WebCache\WebCacheV01.dat" /OutputPath:"$Global:Destiny\$HOSTNAME\WEB_BROWSERS\IE\$u" /OutputName:WebCacheV01.dat > $null

                    # Coockies folder: C:\Users\f4d0\AppData\Roaming\Microsoft\Windows\Cookies\low
                    # History Folder: C:\Users\f4d0\AppData\Local\Microsoft\Windows\History
                } 
                catch 
                {
                    Report-Error -evidence "IE files, user: $u"
                }
            }
        }

        if( -not (Test-Path "$Global:Destiny\$HOSTNAME\WEB_BROWSERS\IE\"))
        {
            Write-Host "`t[i] There is no IE Browser in the System ..." -ForegroundColor Yellow
        }
    }
}

<########### E D G E   W E B   B R O W S E R #################> # EDG
Function Collect-EDGE-Data {
    <#
    https://www.dataforensics.org/microsoft-edge-browser-forensics/

    Cache: \users\user_name\AppData\Local\Packages\Microsoft.MicrosoftEdge_xxxx\AC\#!001\MicrosoftEdge\Cache
    Bookmark: %LocalAppData%\packages\microsoft.windows.spartan_{PackageID}\AC\Spartan\User\Default\Favorites
    Last Browse Session: \User\user_name\AppData\Local\Packages\Microsoft.MicrosoftEdge_xxxx\AC\MicrosoftEdge\User\Default\Recovery\Active\
    History: \Users\user_name\AppData\Local\Microsoft\Windows\WebCache\WebCacheV01.dat
    Web Note: %LocalAppData%\packages\microsoft.windows.spartan_{PackageID}\AC\Spartan\User\Default\favorites
    InPrivateBrowsing: \users\user_name\AppData\Local\Packages\Microsoft.MicrosoftEdge_xxxxx\AC\MicrosoftEdge\User\Default\Recovery\Active\{browsing-session-ID}.dat
    #>
    Write-Host "[+] Collecting EDGE files (from Windows $OS system)..." -ForegroundColor Green
    
    if( ($OS -eq "7") -or ($OS -eq "Vista") -or ($OS -eq "8") -or ($OS -eq "10") )
    {
        foreach($u in $USERS)
        {
            if( Test-Path -Path "$Global:Source\users\$u\AppData\Local\Packages\")
            {
                Write-Host "`t[+] User: $u ..." -ForegroundColor Green

                New-Item -ItemType directory -Path $Global:Destiny\$HOSTNAME\WEB_BROWSERS\EDGE\$u\ > $null

                Get-ChildItem "$Global:Source\users\$u\AppData\Local\Packages\" | ForEach-Object {
                    
                    if($_.FullName -like "*Microsoft.MicrosoftEdge_*") 
                    {
                        $dir=$_.FullName
                        # get SPARTAN.edb file
                        Get-ChildItem "$dir\AC\MicrosoftEdge\User\Default\DataStore\Data\nouser1\" | ForEach-Object {
                            
                            $dirDB=$_.FullName

                            & $RAW_EXE /FileNamePath:"$dirDB\DBStore\spartan.edb" /OutputPath:"$Global:Destiny\$HOSTNAME\WEB_BROWSERS\EDGE\$u" /OutputName:spartan.edb > $null
                        }
                    } 
                }
                # get cache files
                & $RAW_EXE /FileNamePath:"$Global:Source\Users\$u\AppData\Local\Microsoft\Windows\WebCache\WebCacheV01.dat" /OutputPath:"$Global:Destiny\$HOSTNAME\WEB_BROWSERS\EDGE\$u" /OutputName:WebCacheV01.dat > $null
            }
        }
        
        if( -not (Test-Path "$Global:Destiny\$HOSTNAME\WEB_BROWSERS\EDGE\"))
        {
            Write-Host "`t[i] There is no IE Browser in the System ..." -ForegroundColor Yellow
        }
    }
}

<########### S A F A R I #####################################> # SAF <# TODO #>  
Function Collect-Safari-Data {
    Write-Host "[+] Collecting SAFARI files (from Windows $OS system)..." -ForegroundColor Green
    Write-Host "`t[-] [DEVELOPING] ..." -ForegroundColor Yellow
}

<########### O P E R A #######################################> # OPE <# TODO #> 
Function Collect-Opera-Data {
    Write-Host "[+] Collecting OPERA files (from Windows $OS system)..." -ForegroundColor Green
    Write-Host "`t[-] [DEVELOPING] ..." -ForegroundColor Yellow
}

<########### T O R ###########################################> # TOR <# TODO #> 
<#: I think it is similar to Mozilla #> 
Function Collect-Tor-Data {
    Write-Host "[+] Collecting TOR files (from Windows $OS system)..." -ForegroundColor Green
    Write-Host "`t[-] [DEVELOPING] ..." -ForegroundColor Yellow
}


<########### O U T L O O K #####################################################>

<########### O U T L O O K ###################################> # OUT
Function Collect-Outlook-Files {

    # TODO: Check if it's reliable instead to search for the entire disk for OST and PST files, get their path and copy them
    #  Get-ChildItem C: -Recurse *.pst
    
    Write-Host "[+] Collecting OUTLOOK files. Check log file for more info." -ForegroundColor Green

    foreach($u in $USERS)
    {
        if( Test-Path -Path "$Global:Source\Users\$u\AppData\Local\Microsoft\Outlook\")
        {
            if ( -Not ( Test-Path $Global:Destiny\$HOSTNAME\OUTLOOK\$u ) ) { New-Item -ItemType directory -Path $Global:Destiny\$HOSTNAME\OUTLOOK\$u > $null }
        
            <# OST Files #>
            Get-ChildItem "$Global:Source\Users\$u\AppData\Local\Microsoft\Outlook\" -Filter *.ost | ForEach-Object {
                try
                {
                    $email_file = ($_.FullName).Split("\")[7]
                    
                    Write-Host "`t[+] Collecting `"$email_file`" from user $u." -ForegroundColor Green
                    
                    & $RAW_EXE /FileNamePath:"$Global:Source\Users\$u\AppData\Local\Microsoft\Outlook\$email_file" /OutputPath:"$Global:Destiny\$HOSTNAME\OUTLOOK\$u" /OutputName:$email_file > $null
                } 
                catch 
                {
                    Report-Error -evidence "OUTLOOK OST File from $u"
                }
        
            }

            <# PST Files #>
            Get-ChildItem "$Global:Source\Users\$u\AppData\Local\Microsoft\Outlook" -Filter *.pst | ForEach-Object {
                try
                {
                    $email_file = ($_.FullName).Split("\")[7]
                    
                    Write-Host "`t[+] Collecting `"$email_file`" from user $u." -ForegroundColor Green
                    
                    & $RAW_EXE /FileNamePath:"$Global:Source\Users\$u\AppData\Local\Microsoft\Outlook\$email_file" /OutputPath:"$Global:Destiny\$HOSTNAME\OUTLOOK\$u" /OutputName:$email_file > $null
                } 
                catch 
                {
                    Report-Error -evidence "OUTLOOK PST File from $u"
                }
            }
        }
    }
}


<########### C L O U D #####################################################>

<########### CLOUD - ONEDRIVE ##############################> # COD
# It collects the logs, but I don't know how to TREAT the information
Function Collect-Cloud-OneDrive-Logs {
    
    Write-Host "[+] Collecting OneDrive Logs ..." -ForegroundColor Green

    foreach($u in $USERS)
    {
        if( Test-Path "$Global:Source\Users\$u\AppData\Local\Microsoft\OneDrive\logs" )
        {
            Write-Host "`t○ From user: $u" -ForegroundColor Green

            # BUSINESS1 logs
            try 
            {
                if ( -Not ( Test-Path "$Global:Destiny\$HOSTNAME\CLOUD\ONEDRIVE\$u\Business1" ) ) { New-Item -ItemType directory -Path "$Global:Destiny\$HOSTNAME\CLOUD\ONEDRIVE\$u\Business1" > $null }
                
                & cmd.exe /c copy "$Global:Source\Users\$u\AppData\Local\Microsoft\OneDrive\logs\Business1\*.*" "$Global:Destiny\$HOSTNAME\CLOUD\ONEDRIVE\$u\Business1" > $null
            } 
            catch 
            {
                Report-Error -evidence "OneDrive Business1 Logs"
            }

            # COMMON logs
            try 
            {
                if ( -Not ( Test-Path "$Global:Destiny\$HOSTNAME\CLOUD\ONEDRIVE\$u\Common" ) ) { New-Item -ItemType directory -Path "$Global:Destiny\$HOSTNAME\CLOUD\ONEDRIVE\$u\Common" > $null }
                
                & cmd.exe /c copy "$Global:Source\Users\$u\AppData\Local\Microsoft\OneDrive\logs\Common\*.*" "$Global:Destiny\$HOSTNAME\CLOUD\ONEDRIVE\$u\Common" > $null
            } 
            catch 
            {
                Report-Error -evidence "OneDrive Common Logs"
            }

            # Personal logs
            try 
            {
                if ( -Not ( Test-Path "$Global:Destiny\$HOSTNAME\CLOUD\ONEDRIVE\$u\Personal" ) ) { New-Item -ItemType directory -Path "$Global:Destiny\$HOSTNAME\CLOUD\ONEDRIVE\$u\Personal" > $null }
                
                & cmd.exe /c copy "$Global:Source\Users\$u\AppData\Local\Microsoft\OneDrive\logs\Personal\*.*" "$Global:Destiny\$HOSTNAME\CLOUD\ONEDRIVE\$u\Personal" > $null
            } 
            catch 
            {
                Report-Error -evidence "OneDrive Personal Logs"
            }
        }
    }
}

<########### CLOUD - GOOGLE DRIVE ##########################> # CGD
Function Collect-Cloud-GoogleDrive-Logs {
    
    Write-Host "[+] Collecting GoogleDrive Logs ..." -ForegroundColor Green

    foreach($u in $USERS)
    {
        if( Test-Path "$Global:Source\Users\$u\AppData\Local\Google\Drive\user_default" )
        {
            Write-Host "`t○ From user: $u" -ForegroundColor Green
            
            # DB google drive files
            try 
            {
                if ( -Not ( Test-Path "$Global:Destiny\$HOSTNAME\CLOUD\GOOGLEDRIVE\$u" ) ) { New-Item -ItemType directory -Path "$Global:Destiny\$HOSTNAME\CLOUD\GOOGLEDRIVE\$u" > $null }
                cmd.exe /c copy "$Global:Source\Users\$u\AppData\Local\Google\Drive\user_default\*.db" "$Global:Destiny\$HOSTNAME\CLOUD\GOOGLEDRIVE\$u" > $null
            } 
            catch 
            {
                Report-Error -evidence "Google Drive DB files"
            }

            # LOG google drive file
            try 
            {
                if ( -Not ( Test-Path "$Global:Destiny\$HOSTNAME\CLOUD\GOOGLEDRIVE\$u" ) ) { New-Item -ItemType directory -Path "$Global:Destiny\$HOSTNAME\CLOUD\GOOGLEDRIVE\$u" > $null }
                cmd.exe /c copy "$Global:Source\Users\$u\AppData\Local\Google\Drive\user_default\*.log" "$Global:Destiny\$HOSTNAME\CLOUD\GOOGLEDRIVE\$u\." > $null
            } 
            catch 
            {
                Report-Error -evidence "Google Drive LOG file"
            }
        }
    }
}

<########### CLOUD - DROPBOX ##############################>  # CDB
Function Collect-Cloud-Dropbox-Logs {
    
    Write-Host "[+] Collecting Dropbox Logs ..." -ForegroundColor Green

    foreach($u in $USERS)
    {
        if( Test-Path "$Global:Source\Users\$u\AppData\Local\Dropbox" )
        {
            Write-Host "`t○ From user: $u" -ForegroundColor Green        
            
            # INSTANCE1
            if ( -Not ( Test-Path "$Global:Destiny\$HOSTNAME\CLOUD\DROPBOX\$u\instance1" ) ) { New-Item -ItemType directory -Path "$Global:Destiny\$HOSTNAME\CLOUD\DROPBOX\$u\instance1" > $null }
            
            try
            {
                cmd.exe /c copy "$Global:Source\Users\$u\AppData\Local\Dropbox\instance1\*.dbx" "$Global:Destiny\$HOSTNAME\CLOUD\DROPBOX\$u\instance1\." > $null
            } 
            catch 
            {
                Report-Error -evidence "DropBox DBX Files from INSTANCE1"
            }
            
            # INSTANCE_DB
            if ( -Not ( Test-Path "$Global:Destiny\$HOSTNAME\CLOUD\DROPBOX\$u\instance_db" ) ) { New-Item -ItemType directory -Path "$Global:Destiny\$HOSTNAME\CLOUD\DROPBOX\$u\instance_db" > $null }

            try
            {
                cmd.exe /c copy "$Global:Source\Users\$u\AppData\Local\Dropbox\instance_db\*.dbx" "$Global:Destiny\$HOSTNAME\CLOUD\DROPBOX\$u\instance_db\." > $null
            } 
            catch 
            {
                Report-Error -evidence "DropBox DBX Files from INSTANCE_DB"
            }
        }
    }

    # GETTING KEYS TO DECRYPT DROPBOX FILES
    Write-Host "`t[+] Getting Keys to Decrypt Dropbox DBX files ..." -ForegroundColor Green

    if ( -Not ( Test-Path "$Global:Destiny\$HOSTNAME\z_temp" ) ) { New-Item -ItemType directory -Path "$Global:Destiny\$HOSTNAME\z_temp" > $null }

    cmd.exe /c powershell.exe $SCRIPTPATH\bin\dbx-key-win-live.ps1 > "$Global:Destiny\$HOSTNAME\z_temp\keys.txt"

    Select-String -Path "$Global:Destiny\$HOSTNAME\z_temp\keys.txt" -Pattern DBX | ForEach-Object { 
                
        if( ($_.Line.Split(":")[0]).Contains("ks1") ) 
        {
            $ks1_key=($_.Line.Split(":")[1]).Trim()
            #Write-Host "`tks1_key: $ks1_key" -ForegroundColor Cyan
        } 
        else 
        {
            $ks_key=($_.Line.Split(":")[1]).Trim()
            #Write-Host "`tks_key: $ks_key" -ForegroundColor Cyan
        }
    }

    # DECRYPTING FILES WITH THE KEYS FROM ABOVE
    foreach($u in $USERS)
    {
        Write-Host "`t[+] Decrypting Dropbox DBX files ..." -ForegroundColor Green

        Write-Host "`t`t○ From user: $u" -ForegroundColor Green

        # & $SQL_DBX_EXE -key $ks1_key "$Global:Destiny\$HOSTNAME\CLOUD\DROPBOX\$u\instance1\filecache.dbx" ".backup $Global:Destiny\\$HOSTNAME\\CLOUD\\DROPBOX\\$u\\instance1\\filecache.db" 
        $rootTemp = $Global:Destiny -replace "\\","\\"

        Get-ChildItem "$Global:Destiny\$HOSTNAME\CLOUD\DROPBOX\$u\instance1" -Filter *.dbx | ForEach-Object {
            try
            {
                if($_.Extension -ne ".dbx-wal" -and $_.Extension -ne ".dbx-shm" -and $_.BaseName -ne "aggregation")
                {
                    $bn=$_.BaseName
                    & $SQL_DBX_EXE -key $ks1_key $_.FullName ".backup $rootTemp\\$HOSTNAME\\\CLOUD\\DROPBOX\\$u\\instance1\\$bn.db" 
                }
            } 
            catch 
            {
                Report-Error -evidence "DropBox File: $_.FullName"
            }
        }

        Get-ChildItem "$Global:Destiny\$HOSTNAME\CLOUD\DROPBOX\$u\instance_db" -Filter *.dbx | ForEach-Object {
            try
            {
                $bn=$_.BaseName
                & $SQL_DBX_EXE -key $ks_key $_.FullName ".backup $rootTemp\\$HOSTNAME\\\CLOUD\\DROPBOX\\$u\\instance_db\\$bn.db" 
            } 
            catch 
            {
                Report-Error -evidence "DropBox File: $_.FullName"
            }
        }
    }

    Remove-Item -Recurse -Path "$Global:Destiny\$HOSTNAME\z_temp"
}
    


<##################################################################################################################################>
<############  MANAGE GRAPHIC AND NON GRAPHIC EXECUTION  #############################>
<##################################################################################################################################>



<# MANAGE NO GUI EXECUTION #>
Function Control-NOGUI{

    # LIVE                                                                                                                                                                                                                 # mm:ss

    if ($true         ) {$ScriptTime = [Diagnostics.Stopwatch]::StartNew(); Collect-Time ; $ScriptTime.Stop(); Write-Host "`t└>Execution time: $($ScriptTime.Elapsed)" -ForegroundColor Gray }                             # 00:00
    
    if (         $RAM ) {$ScriptTime = [Diagnostics.Stopwatch]::StartNew(); Collect-Memory-Dump ; $ScriptTime.Stop(); Write-Host "`t└>Execution time: $($ScriptTime.Elapsed)" -ForegroundColor Gray }                      # ??:??
    if ($All -or $NET ) {$ScriptTime = [Diagnostics.Stopwatch]::StartNew(); Collect-Network-Information ; $ScriptTime.Stop(); Write-Host "`t└>Execution time: $($ScriptTime.Elapsed)" -ForegroundColor Gray }              # 00:20
    if ($All -or $SAP ) {$ScriptTime = [Diagnostics.Stopwatch]::StartNew(); Collect-Services-and-Processes ; $ScriptTime.Stop(); Write-Host "`t└>Execution time: $($ScriptTime.Elapsed)" -ForegroundColor Gray }           # 00:??
    if ($All -or $STJ ) {$ScriptTime = [Diagnostics.Stopwatch]::StartNew(); Collect-Scheduled-Tasks-Jobs ; $ScriptTime.Stop(); Write-Host "`t└>Execution time: $($ScriptTime.Elapsed)" -ForegroundColor Gray }             # ??:??
    if ($All -or $CPH ) {$ScriptTime = [Diagnostics.Stopwatch]::StartNew(); Collect-Command-History ; $ScriptTime.Stop(); Write-Host "`t└>Execution time: $($ScriptTime.Elapsed)" -ForegroundColor Gray }                  # ??:??
    if ($All -or $INS ) {$ScriptTime = [Diagnostics.Stopwatch]::StartNew(); Collect-Installed-Software ; $ScriptTime.Stop(); Write-Host "`t└>Execution time: $($ScriptTime.Elapsed)" -ForegroundColor Gray }               # ??:??
    if ($All -or $UGR ) {$ScriptTime = [Diagnostics.Stopwatch]::StartNew(); Collect-Users-Groups ; $ScriptTime.Stop(); Write-Host "`t└>Execution time: $($ScriptTime.Elapsed)" -ForegroundColor Gray }                     # ??:??
    if ($All -or $PER ) {$ScriptTime = [Diagnostics.Stopwatch]::StartNew(); Collect-Persistence ; $ScriptTime.Stop(); Write-Host "`t└>Execution time: $($ScriptTime.Elapsed)" -ForegroundColor Gray }                      # ??:??
    if ($All -or $USB ) {$ScriptTime = [Diagnostics.Stopwatch]::StartNew(); Collect-USB-Info ; $ScriptTime.Stop(); Write-Host "`t└>Execution time: $($ScriptTime.Elapsed)" -ForegroundColor Gray }                         # ??:??
    if ($All -or $DEV ) {$ScriptTime = [Diagnostics.Stopwatch]::StartNew(); Collect-Devices-Info ; $ScriptTime.Stop(); Write-Host "`t└>Execution time: $($ScriptTime.Elapsed)" -ForegroundColor Gray }                     # ??:??
    if ($All -or $SEC ) {$ScriptTime = [Diagnostics.Stopwatch]::StartNew(); Collect-Security-Config ; $ScriptTime.Stop(); Write-Host "`t└>Execution time: $($ScriptTime.Elapsed)" -ForegroundColor Gray }                  # ??:??
    if ($All -or $SFO ) {$ScriptTime = [Diagnostics.Stopwatch]::StartNew(); Collect-Shell-Folders ; $ScriptTime.Stop(); Write-Host "`t└>Execution time: $($ScriptTime.Elapsed)" -ForegroundColor Gray }                    # ??:??
    if ($All -or $ENV ) {$ScriptTime = [Diagnostics.Stopwatch]::StartNew(); Collect-Env-Vars ; $ScriptTime.Stop(); Write-Host "`t└>Execution time: $($ScriptTime.Elapsed)" -ForegroundColor Gray }                         # ??:??

    if ($All -or $MRU ) {$ScriptTime = [Diagnostics.Stopwatch]::StartNew(); Collect-MRUs ; $ScriptTime.Stop(); Write-Host "`t└>Execution time: $($ScriptTime.Elapsed)" -ForegroundColor Gray }                             # ??:??
    if ($All -or $SHI ) {$ScriptTime = [Diagnostics.Stopwatch]::StartNew(); Collect-Shimcache ; $ScriptTime.Stop(); Write-Host "`t└>Execution time: $($ScriptTime.Elapsed)" -ForegroundColor Gray }                        # ??:??
    if ($All -or $JLI ) {$ScriptTime = [Diagnostics.Stopwatch]::StartNew(); Collect-JumpLists ; $ScriptTime.Stop(); Write-Host "`t└>Execution time: $($ScriptTime.Elapsed)" -ForegroundColor Gray }                        # ??:??
    if ($All -or $BAM ) {$ScriptTime = [Diagnostics.Stopwatch]::StartNew(); Collect-BAM ; $ScriptTime.Stop(); Write-Host "`t└>Execution time: $($ScriptTime.Elapsed)" -ForegroundColor Gray }                              # ??:??
    
    if ($All -or $TLH ) {$ScriptTime = [Diagnostics.Stopwatch]::StartNew(); Collect-Timeline ; $ScriptTime.Stop(); Write-Host "`t└>Execution time: $($ScriptTime.Elapsed)" -ForegroundColor Gray }                         # ??:??
    if ($All -or $RAP ) {$ScriptTime = [Diagnostics.Stopwatch]::StartNew(); Collect-RecentApps ; $ScriptTime.Stop(); Write-Host "`t└>Execution time: $($ScriptTime.Elapsed)" -ForegroundColor Gray }                       # ??:??
    if ($All -or $SYS ) {$ScriptTime = [Diagnostics.Stopwatch]::StartNew(); Collect-System-Info ; $ScriptTime.Stop(); Write-Host "`t└>Execution time: $($ScriptTime.Elapsed)" -ForegroundColor Gray }                      # ??:??

    if ($All -or $UAS ) {$ScriptTime = [Diagnostics.Stopwatch]::StartNew(); Collect-User-Assist ; $ScriptTime.Stop(); Write-Host "`t└>Execution time: $($ScriptTime.Elapsed)" -ForegroundColor Gray }                      # ??:??
    if (         $SFI ) {$ScriptTime = [Diagnostics.Stopwatch]::StartNew(); Collect-Sign-Files ; $ScriptTime.Stop(); Write-Host "`t└>Execution time: $($ScriptTime.Elapsed)" -ForegroundColor Gray }                       # ??:??
    if ($All -or $LAC ) {$ScriptTime = [Diagnostics.Stopwatch]::StartNew(); Collect-Last-Activity ; $ScriptTime.Stop(); Write-Host "`t└>Execution time: $($ScriptTime.Elapsed)" -ForegroundColor Gray }                    # ??:??
    if (         $AFI ) {$ScriptTime = [Diagnostics.Stopwatch]::StartNew(); Collect-Autorun-Files ; $ScriptTime.Stop(); Write-Host "`t└>Execution time: $($ScriptTime.Elapsed)" -ForegroundColor Gray }                    # 05:40

    if ($All -or $LSE ) {$ScriptTime = [Diagnostics.Stopwatch]::StartNew(); Collect-Local-Sessions ; $ScriptTime.Stop(); Write-Host "`t└>Execution time: $($ScriptTime.Elapsed)" -ForegroundColor Gray }                   # ??:??
    if ($All -or $PWD ) {$ScriptTime = [Diagnostics.Stopwatch]::StartNew(); Collect-Passwords ; $ScriptTime.Stop(); Write-Host "`t└>Execution time: $($ScriptTime.Elapsed)" -ForegroundColor Gray }                        # ??:??


    # OFFLINE
    if ($All -or $HIV ) {$ScriptTime = [Diagnostics.Stopwatch]::StartNew(); Collect-Hives ; $ScriptTime.Stop(); Write-Host "`t└>Execution time: $($ScriptTime.Elapsed)" -ForegroundColor Gray }                            # ??:??
    if ($All -or $EVT ) {$ScriptTime = [Diagnostics.Stopwatch]::StartNew(); Collect-EVTX-Files ; $ScriptTime.Stop(); Write-Host "`t└>Execution time: $($ScriptTime.Elapsed)" -ForegroundColor Gray }                       # ??:??
    if ($All -or $FIL ) {$ScriptTime = [Diagnostics.Stopwatch]::StartNew(); Collect-Files-Lists ; $ScriptTime.Stop(); Write-Host "`t└>Execution time: $($ScriptTime.Elapsed)" -ForegroundColor Gray }                      # ??:??
    if ($All -or $PRF ) {$ScriptTime = [Diagnostics.Stopwatch]::StartNew(); Collect-Prefetch ; $ScriptTime.Stop(); Write-Host "`t└>Execution time: $($ScriptTime.Elapsed)" -ForegroundColor Gray }                         # ??:??
    if ($All -or $WSE ) {$ScriptTime = [Diagnostics.Stopwatch]::StartNew(); Collect-Windows-Search ; $ScriptTime.Stop(); Write-Host "`t└>Execution time: $($ScriptTime.Elapsed)" -ForegroundColor Gray }                   # ??:??
    if ($All -or $EET ) {$ScriptTime = [Diagnostics.Stopwatch]::StartNew(); Collect-ETW-ETL ; $ScriptTime.Stop(); Write-Host "`t└>Execution time: $($ScriptTime.Elapsed)" -ForegroundColor Gray }                          # ??:??
    if ($All -or $THC ) {$ScriptTime = [Diagnostics.Stopwatch]::StartNew(); Collect-Thumcache ; $ScriptTime.Stop(); Write-Host "`t└>Execution time: $($ScriptTime.Elapsed)" -ForegroundColor Gray }                        # ??:??
    if ($All -or $ICO ) {$ScriptTime = [Diagnostics.Stopwatch]::StartNew(); Collect-Iconcache ; $ScriptTime.Stop(); Write-Host "`t└>Execution time: $($ScriptTime.Elapsed)" -ForegroundColor Gray }                        # ??:??
    if ($All -or $MUL ) {$ScriptTime = [Diagnostics.Stopwatch]::StartNew(); Collect-MFT-UsnJrnl-LogFile ; $ScriptTime.Stop(); Write-Host "`t└>Execution time: $($ScriptTime.Elapsed)" -ForegroundColor Gray }              # ??:??
    if ($All -or $HPS ) {$ScriptTime = [Diagnostics.Stopwatch]::StartNew(); Collect-Hiberfil-Pagefile-Swapfile ; $ScriptTime.Stop(); Write-Host "`t└>Execution time: $($ScriptTime.Elapsed)" -ForegroundColor Gray }       # ??:??
    if (         $DEX ) {$ScriptTime = [Diagnostics.Stopwatch]::StartNew(); Collect-Dangerous-Extensions ; $ScriptTime.Stop(); Write-Host "`t└>Execution time: $($ScriptTime.Elapsed)" -ForegroundColor Gray }             # 07:05
    if ($All -or $THA ) {$ScriptTime = [Diagnostics.Stopwatch]::StartNew(); Collect-TextHarvester ; $ScriptTime.Stop(); Write-Host "`t└>Execution time: $($ScriptTime.Elapsed)" -ForegroundColor Gray }                    # ??:??
    if ($All -or $SRU ) {$ScriptTime = [Diagnostics.Stopwatch]::StartNew(); Collect-SRUM ; $ScriptTime.Stop(); Write-Host "`t└>Execution time: $($ScriptTime.Elapsed)" -ForegroundColor Gray }                             # ??:??
    if ($All -or $CRE ) {$ScriptTime = [Diagnostics.Stopwatch]::StartNew(); Collect-Credentials ; $ScriptTime.Stop(); Write-Host "`t└>Execution time: $($ScriptTime.Elapsed)" -ForegroundColor Gray }                      # ??:??
    
    if ($All -or $SKY ) {$ScriptTime = [Diagnostics.Stopwatch]::StartNew(); Collect-Skype-History ; $ScriptTime.Stop(); Write-Host "`t└>Execution time: $($ScriptTime.Elapsed)" -ForegroundColor Gray }                    # ??:??

    if ($All -or $CHR ) {$ScriptTime = [Diagnostics.Stopwatch]::StartNew(); Collect-Chrome-Data ; $ScriptTime.Stop(); Write-Host "`t└>Execution time: $($ScriptTime.Elapsed)" -ForegroundColor Gray }                      # ??:??
    if ($All -or $MFI ) {$ScriptTime = [Diagnostics.Stopwatch]::StartNew(); Collect-Firefox-Data ; $ScriptTime.Stop(); Write-Host "`t└>Execution time: $($ScriptTime.Elapsed)" -ForegroundColor Gray }                     # ??:??
    if ($All -or $IEX ) {$ScriptTime = [Diagnostics.Stopwatch]::StartNew(); Collect-IE-Data ; $ScriptTime.Stop(); Write-Host "`t└>Execution time: $($ScriptTime.Elapsed)" -ForegroundColor Gray }                          # ??:??
    if ($All -or $EDG ) {$ScriptTime = [Diagnostics.Stopwatch]::StartNew(); Collect-EDGE-Data ; $ScriptTime.Stop(); Write-Host "`t└>Execution time: $($ScriptTime.Elapsed)" -ForegroundColor Gray }                        # ??:??
    if ($All -or $SAF ) {$ScriptTime = [Diagnostics.Stopwatch]::StartNew(); Collect-Safari-Data ; $ScriptTime.Stop(); Write-Host "`t└>Execution time: $($ScriptTime.Elapsed)" -ForegroundColor Gray }                      # ??:??
    if ($All -or $OPE ) {$ScriptTime = [Diagnostics.Stopwatch]::StartNew(); Collect-Opera-Data ; $ScriptTime.Stop(); Write-Host "`t└>Execution time: $($ScriptTime.Elapsed)" -ForegroundColor Gray }                       # ??:??
    if ($All -or $TOR ) {$ScriptTime = [Diagnostics.Stopwatch]::StartNew(); Collect-Tor-Data ; $ScriptTime.Stop(); Write-Host "`t└>Execution time: $($ScriptTime.Elapsed)" -ForegroundColor Gray }                         # ??:??

    if ($All -or $OUT ) {$ScriptTime = [Diagnostics.Stopwatch]::StartNew(); Collect-Outlook-Files ; $ScriptTime.Stop(); Write-Host "`t└>Execution time: $($ScriptTime.Elapsed)" -ForegroundColor Gray }                    # ??:??

    if ($All -or $COD ) {$ScriptTime = [Diagnostics.Stopwatch]::StartNew(); Collect-Cloud-OneDrive-Logs ; $ScriptTime.Stop(); Write-Host "`t└>Execution time: $($ScriptTime.Elapsed)" -ForegroundColor Gray }              # ??:??
    if ($All -or $CGD ) {$ScriptTime = [Diagnostics.Stopwatch]::StartNew(); Collect-Cloud-GoogleDrive-Logs ; $ScriptTime.Stop(); Write-Host "`t└>Execution time: $($ScriptTime.Elapsed)" -ForegroundColor Gray }           # ??:??
    if ($All -or $CDB ) {$ScriptTime = [Diagnostics.Stopwatch]::StartNew(); Collect-Cloud-Dropbox-Logs ; $ScriptTime.Stop(); Write-Host "`t└>Execution time: $($ScriptTime.Elapsed)" -ForegroundColor Gray }               # ??:??
     


}

<# MANAGE GUI EXECTION #> 
Function Control-GUI {

    <#TODO: separate the creation of the interface with the execution control #>
    
    param(
        [string]$testtt="bla"
    )

    Add-Type -AssemblyName System.Windows.Forms
    Add-Type -AssemblyName System.Drawing

    $form = New-Object System.Windows.Forms.Form
    $form.Text = 'Data Entry Form'
    $form.Size = New-Object System.Drawing.Size(300,200)
    $form.StartPosition = 'CenterScreen'

    $OKButton = New-Object System.Windows.Forms.Button
    $OKButton.Location = New-Object System.Drawing.Point(75,120)
    $OKButton.Size = New-Object System.Drawing.Size(75,23)
    $OKButton.Text = 'OK'
    $OKButton.DialogResult = [System.Windows.Forms.DialogResult]::OK
    $form.AcceptButton = $OKButton
    $form.Controls.Add($OKButton)

    $CancelButton = New-Object System.Windows.Forms.Button
    $CancelButton.Location = New-Object System.Drawing.Point(150,120)
    $CancelButton.Size = New-Object System.Drawing.Size(75,23)
    $CancelButton.Text = 'Cancel'
    $CancelButton.DialogResult = [System.Windows.Forms.DialogResult]::Cancel
    $form.CancelButton = $CancelButton
    $form.Controls.Add($CancelButton)

    $label = New-Object System.Windows.Forms.Label
    $label.Location = New-Object System.Drawing.Point(10,20)
    $label.Size = New-Object System.Drawing.Size(280,20)
    $label.Text = 'Please enter the information in the space below:'
    $form.Controls.Add($label)

    $textBox = New-Object System.Windows.Forms.TextBox
    $textBox.Location = New-Object System.Drawing.Point(10,40)
    $textBox.Size = New-Object System.Drawing.Size(260,20)
    $form.Controls.Add($textBox)

    $form.Topmost = $true

    $form.Add_Shown({$textBox.Select()})
    $result = $form.ShowDialog()

    if ($result -eq [System.Windows.Forms.DialogResult]::OK)
    {
        $x = $textBox.Text
        $x
    }
    

}


<##################################################################################################################################>
<############  SEVERAL OTHER FUNCTIONS  ##############################################>
<##################################################################################################################################>

<# HANDLES THE ERRORS REPORT AND OUTPUT #>
Function Report-Error {

    param(
        [string]$evidence        
    )

    Write-Host "`t[-] Error Collecting $evidence . Check log file for more info."  -ForegroundColor Red
    echo "`t[-] Error Collecting $evidence :" >> $Global:Destiny\$HOSTNAME\errors.log
    $_.Exception.GetType().FullName >> $Global:Destiny\$HOSTNAME\errors.log
    $_.Exception.Message >> $Global:Destiny\$HOSTNAME\errors.log
}

<# Show Banner #>
Function Show-Banner {

    cls
    Write-Host '▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▒'
    Write-Host '▓                                                                                              ▒'
    Write-Host '▓    ######\                               ##\           ##\   ##\                             ▒'
    Write-Host '▓    \_##  _|                              \__|          \__|  ## |                            ▒'
    Write-Host '▓      ## |  #######\   ######\  ##\   ##\ ##\  #######\ ##\ ######\    ######\   ######\      ▒'
    Write-Host '▓      ## |  ##  __##\ ##  __##\ ## |  ## |## |##  _____|## |\_##  _|  ##  __##\ ##  __##\     ▒'
    Write-Host '▓      ## |  ## |  ## |## /  ## |## |  ## |## |\######\  ## |  ## |    ## /  ## |## |  \__|    ▒'
    Write-Host '▓      ## |  ## |  ## |## |  ## |## |  ## |## | \____##\ ## |  ## |##\ ## |  ## |## |          ▒'
    Write-Host '▓    ######\ ## |  ## |\####### |\######  |## |#######  |## |  \####  |\######  |## |          ▒'
    Write-Host '▓    \______|\__|  \__| \____## | \______/ \__|\_______/ \__|   \____/  \______/ \__|          ▒'
    Write-Host '▓                            ## |                                                              ▒'
    Write-Host '▓                            ## |                                                              ▒'
    Write-Host '▓                            \__|                           By:      f4d0                      ▒'
    Write-Host '▓                                                           Version: 0.7                       ▒'
    Write-Host '▓                                                                                              ▒'
    Write-Host '▓▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒'

}

<# Show Simple Options Resume #>
Function Show-Simple-Options-Resume {

    Write-Host ""
    Write-Host "╔═══════════════════════════════════════════"
    Write-Host "║                                           "
    Write-Host "║ Input information:                        "
    Write-Host "║                                           "
    Write-Host "║     GUI:         $GUI                     "
    Write-Host "║     Source:      $Global:Source                  "
    Write-Host "║     Destiny:     $Global:Destiny                 "
    Write-Host "║     Memory Dump: $RAM                     "
    Write-Host "║     Format:      $Global:FormatType              "
    Write-Host "║     Dev. Mode:   $DevMode                 "  
    Write-Host "║                                           "
    Write-Host "║                                           "
    Write-Host "╚═══════════════════════════════════════════"
    Write-Host ""
    $result = Read-Host "Please click <ENTER> to continue."

}

<# Execute FORMAT #>
Function Execute-Format {

    <# If format is defined, execute the format #>
    if($Global:FormatType -ne "No" -and $Global:FormatType -ne ""){

        if($Global:Destiny -eq "C:") {
            Write-Host "[-]This Script prohibits the format of unit C" -ForegroundColor Red
        }

        if($Global:FormatType -eq "Zero"){
            Write-Host "[+]Executing ZEROS Format of drive $Global:Destiny, please wait... " -ForegroundColor Green
            cmd.exe /c format $Global:Destiny /FS:NTFS /V:INQUISITOR /p:0
        }
        if($Global:FormatType -eq "Quick"){
            Write-Host "[+]Executing QUICK Format of drive $Global:Destiny, please wait... " -ForegroundColor Green
            cmd.exe /c format $Global:Destiny /FS:NTFS /V:INQUISITOR /Q
        }
    }
}

<# Test if specific value exists in the registry #>
Function Test-RegistryValue {
    param (
        [parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]$Path,
        [parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]$Value
    )

    $regvalue = Get-ItemProperty $Path $Value -ErrorAction SilentlyContinue

    return ($? -and ($regvalue -ne $null))
}

<##################################################################################################################################>
<#########################  START CONTROL  ###########################################>
<##################################################################################################################################>

Function Check-Variables {
    
    <# Check DEVELOPER MODE and apply configurations if true #>    
    if($DevMode -eq $true){
        $Global:Source="C:"         
        $Global:Destiny="D:\TFM\Inquisitor"
        $Global:FormatType="No"
        $Global:RAM=$false
        $All=$false
    }

    <# Check SOURCE #>
    if($Global:Source -eq ""){ <# In case it is empy which means the user did not define the unit #>
        cls
        Show-Banner
        Write-Host ""
        Write-Host "No SOURCE drive defined!! The following below are available:" -ForegroundColor Yellow
        gdr -PSProvider "FileSystem"  
        Write-Host ""
        $Global:Source = Read-Host 'Please select a destiny drive(e.g. C: )'
    }
        
    if($Global:Source -ne "C:"){   <# In case it is not C: and it's not empty, Let's check if the unit is MOUNTED #>
            cls
            Show-Banner
            Write-Host ""
            Write-Host "The SOURCE drive is not C:" -ForegroundColor Yellow
            $Answer = Read-Host 'Is this a mounted DRIVE? (Yes or No): '
            if($Answer -eq "Yes"){ $Global:Mounted=$True }                           <#TODO: This variable will stop the execution of some parts of the script in case the drive is mounted. #>
    }


    <# Check DESTINY #>
    if($Global:Destiny -eq ""){
        cls
        Show-Banner
        Write-Host ""
        Write-Host "No DESTINY drive defined!! The following below are available:"  -ForegroundColor Yellow
        gdr -PSProvider "FileSystem"
        Write-Host ""
        $Global:Destiny = Read-Host 'Please select a destiny drive(e.g. D: ) '
    }

    <# Check FORMAT #>
    if($FormatType -ne "No"){
        if( ($DevMode -eq $false) -and (($Global:FormatType -eq "Quick" ) -or ($Global:FormatType -eq "Zeros" ))){
            cls
            Show-Banner
            Write-Host ""
            Write-Host "You have selected to format the DESTINY drive!"  -ForegroundColor Yellow
            Write-Host "Are you sure you wish to format the destiny driver?"  -ForegroundColor DarkYellow
            do{
                $Global:FormatType = Read-Host  'Which type of formating? "Zeros" or "Quick"? ("No" to give up format.)'
                if( ($Global:FormatType -ne "No") -and ($Global:FormatType -ne "Quick") -and ($Global:FormatType -ne "Zeros") ) {
                    Write-Host "Wrong option!"  -ForegroundColor Red
                } else {
                    break
                }
            } while(1)
        }
        if( ($DevMode -eq $false) -and ($Global:FormatType -eq "" ) ){
            cls
            Show-Banner
            Write-Host ""
            Write-Host "You have not defined the format parameter for the DESTINY drive!" -ForegroundColor Yellow
            Write-Host "Do you wish to format the DESTINY driver?"  -ForegroundColor Yellow
            do{
                $Global:FormatType = Read-Host  'Which type of formating? "Zeros" or "Quick"? ("No" to give up format.)'
                if( ($Global:FormatType -ne "No") -and ($Global:FormatType -ne "Quick") -and ($Global:FormatType -ne "Zeros") ) {
                    Write-Host "Wrong option!"  -ForegroundColor Red
                } else {
                    break
                }
            } while(1)
        }
    }
    
    <# Check RAM #>
    if ( ($DevMode -eq $false) -and ($RAM -eq "$false") ){
        $Answer = Read-Host 'Do you wish to collect a Memory Dump? (YES or NO): '
        if ($Answer -eq "YES") { 
            $RAM=$true 
            }
    }

}


Function Start-Execution {

    Show-Banner

    if($GUI)
    {
        Control-GUI
        exit
    }

    if( -not $GUI)
    {
        Check-Variables
        Show-Simple-Options-Resume
        Execute-Format
                
        <# Creates base folder to the collect data. The folder name is the name of the computer where the data is being collected #>
        if ( -Not ( Test-Path $Global:Destiny\$HOSTNAME ) ) { New-Item -ItemType directory -Path $Global:Destiny\$HOSTNAME > $null }

        Write-Host "[+] Start to Collect computer info data."  -ForegroundColor Magenta
        $TotalScriptTime = [Diagnostics.Stopwatch]::StartNew()
                
        Control-NOGUI
    
        $TotalScriptTime.Stop()
        Write-Host "[*] TOTAL Script Execution time: $($TotalScriptTime.Elapsed)"  -ForegroundColor Magenta
        Write-Host "[*] Finished to collect all the Evidence!"   -ForegroundColor Magenta
    
        exit
    }
}

Start-Execution # STARTS THE EXECUTION OF THE PROGRAM

<##################################################################################################################################>
<#########################  FUTURE DEVELOPMENTS  ###########################################>
<##################################################################################################################################>

<########### S Y S T E M   P O L I C I E S #######################################> # SPO <# TODO #>
Function Collect-System-Policies {

    Write-Host "[+] Collecting System Policies ..." -ForegroundColor Green
    Write-Host "`t[-] [DEVELOPING] ..." -ForegroundColor Yellow

    # https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-gpsb/12867da0-2e4e-4a4f-9dc4-84a7f354c8d9
    # Computer\HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System


}

<########### BROWSERS PASSWORD RECOVER ###########################################> # BPR <# TODO #>
Function Collect-Browsers-Passwords {
    
    Write-Host "[+] Collecting IE Passwords ..." -ForegroundColor Green

    if( -not (Test-Path "$Global:Destiny\$HOSTNAME\PASSWORDS\") ) { New-Item -ItemType Directory -Path "$Global:Destiny\$HOSTNAME\PASSWORDS\" > $null }

    Write-Host "`t[-] [DEVELOPING] ..." -ForegroundColor Yellow


}

<# TODO: Adjust info collection to the below map
    Windows Versions MAP:
    VERSION                        CORE
    Windows 1.0                    1.04
    Windows 2.0                    2.11
    Windows 3.0                    3
    Windows NT 3.1                 3.10.528
    Windows for Workgroups 3.11    3.11
    Windows NT Workstation 3.5     3.5.807
    Windows NT Workstation 3.51    3.51.1057
    Windows 95                     4.0.950
    Windows NT Workstation 4.0     4.0.1381
    Windows 98                     4.1.1998
    Windows 98 Second Edition      4.1.2222
    Windows Me                     4.90.3000
    Windows 2000 Professional      5.0.2195
    Windows 2000 Server            5.0
    Windows XP                     5.1.2600
    Windows Server 2003            5.2
    Windows Vista                  6.0.6000
    Windows Server 2008            6.0
    Windows 7                      6.1.7600
    Windows Server 2008 R2         6.1
    Windows Server 2012            6.2
    Windows 8.1                    6.3.9600
    Windows 10                     10.0.10240
    Windows Server 2016            10.0
    Windows Server 2019            10.0
#>


<##################################################################################################################################>
<##################################################################################################################################>
<############################# G A R B A G E ###############################################>
<##################################################################################################################################>
<##################################################################################################################################>



# Others - SYSTEM INFO
# Get-ComputerInfo >> "$Global:Destiny\$HOSTNAME\1.ComputerInfo.txt"



Function Code-Snippets {


    <# TEST PATH AND CREATE DIR #>
    if ( -Not ( Test-Path $Global:Destiny\$HOSTNAME\SHELLFOLDERS ) ) { New-Item -ItemType directory -Path $Global:Destiny\$HOSTNAME\SHELLFOLDERS > $null }


    <# ITERATE USERS #>
    foreach($u in $USERS){
        New-Item -ItemType directory -Path $Global:Destiny\$HOSTNAME\HIVES\$u > $null
    }


    <# ITERATE FOLDER #>
    Get-ChildItem "C:\Windows\System32\winevt\Logs" -Filter *.evtx | ForEach-Object {
        if($_.Length -gt 69632) {
            <# DO SOMETHING #>
        }
    }

    <# USER INPUT #>
    $Answer = Read-Host 'Do you want o use GUI? ("Yes" or "No")'

    <# Copy with RawCopy #>
    & $RAW_EXE  "$Global:Source\Users\$u\NTUSER.dat" "$Global:Destiny\$HOSTNAME\HIVES\$u\." > $null

    <# Script Path #>
    Write-Host $PSScriptRoot  <#Powershell 3+#>

    $scriptPath = split-path -parent $MyInvocation.MyCommand.Definition   <# Powershell 2- #>
    Write-Host $scriptPath

    <# Version de Powershell #>
    $PSVersionTable
    $PSVersionTable.PSVersion
    $PSVersionTable.PSVersion.Major
    
    if($PSVersionTable.PSVersion.Major -ge 5)
    { "do something" }
    else
    { "don't do something" }

    <# Get Magic number of file #>
    '{0:x2}' -f (Get-Content .\inquisitor_v0.5.ps1 -Encoding Byte -ReadCount 4)


    <# String Manpulation in Dropox #>

    <# Iterate folder with specific extension file #>
    Get-ChildItem "$Global:Source\Users\$u\AppData\Local\Google\Drive\user_default" -Filter *.db | ForEach-Object {
    if ( -Not ( Test-Path "$Global:Destiny\$HOSTNAME\CLOUD\GOOGLEDRIVE\$u" ) ) { New-Item -ItemType directory -Path "$Global:Destiny\$HOSTNAME\CLOUD\GOOGLEDRIVE\$u" > $null }
        & $RAW_EXE $_.FullName "$Global:Destiny\$HOSTNAME\CLOUD\GOOGLEDRIVE\$u\." > $null
    }

}

<# Displays an alternive HELP #>
[switch]$Help=$false        

<# OLD Help. Dificult to mantain.
Better to use "PS C:\> Get-Help Inquisitor.ps1" #>
Function Show-Help {
    
    Write-Host '▓                                                                                                                                  ▒'
    Write-Host '▓    INFO: Inquisitor is a tool to collect evidences from a windows system. It works in all types of windows.                      ▒'
    Write-Host '▓                                                                                                                                  ▒'
    Write-Host '▓    Syntax:                                                                                                                       ▒'
    Write-Host '▓       .\inquisitor.ps1 -SOURCE <drive> -DESTINY <drive> <parameters>                                                             ▒' 
    Write-Host '▓                                                                                                                                  ▒'
    Write-Host '▓    Examples:                                                                                                                     ▒'
    Write-Host '▓       1) .\inquisitor.ps1 -SOURCE c: DESTINY d: -ALL -RAM -SF -FORMAT Zeros                                                      ▒'
    Write-Host '▓       2) .\inquisitor.ps1 -SOURCE c: DESTINY d: -HI -EVT                                                                         ▒'
    Write-Host '▓       3) .\inquisitor.ps1 -GUI                                                                                                   ▒'
    Write-Host '▓                                                                                                                                  ▒'
    Write-Host '▓    Controlling parameters:                                                                                                       ▒'
    Write-Host '▓                                                                                                                                  ▒'
    Write-Host '▓    -HELP    -> Show this Menu              -SOURCE  -> Source Drive               -FORMAT -> Format DESTINY drive                ▒'
    Write-Host '▓    -GUI     -> Use of GUI                  -DESTINY -> Destiny Drive                                                             ▒'
    Write-Host '▓                                                                                                                                  ▒'
    Write-Host '▓    Collection parameters:                                                                                                        ▒'
    Write-Host '▓                                                                                                                                  ▒'
    Write-Host '▓    -ALL -> Collect Everything (except "Sign Files" and "RAM")                                                                    ▒'
    Write-Host '▓                                                                                                                                  ▒'
    Write-Host '▓    -RAM -> Memory Dump                    -NC  -> Network Configuration                                                          ▒'
    Write-Host '▓                                           -TC  -> TCP Connections                                                                ▒'
    Write-Host '▓    -SI  -> System Info                    -NEC -> Netbios Connections                                                            ▒'
    Write-Host '▓    -DT  -> Date and Timezone              -RES -> Remote Established Sessions                                                    ▒'
    Write-Host '▓    -SRS -> Services Running and Stopped   -CFN -> Copied Files Through Netbios                                                   ▒'
    Write-Host '▓    -P   -> Processes                      -OP  -> Open Ports                                                                     ▒'
    Write-Host '▓    -IS  -> Installed Software             -AOP -> Applications with Open Ports                                                   ▒'
    Write-Host '▓    -SF  -> Sign Files                     -DNS -> DNS Cache                                                                      ▒'
    Write-Host '▓    -AAF -> All Autorun Files              -ARP -> ARP Cache                                                                      ▒'
    Write-Host '▓                                           -HI  -> Hives                                                                          ▒'
    Write-Host '▓    -WCE -> Chrome Web Browser             -REG -> Registry                                                                       ▒'
    Write-Host '▓    -WCU -> Chromium Web Browser           -RUI -> Registry USB Info                                                              ▒'
    Write-Host '▓    -WFI -> Firefox Web Browser            -RDI -> Registry Devices Info                                                          ▒'
    Write-Host '▓    -WIE -> IE Web Browser                 -WI  -> Wireless Info                                                                  ▒'
    Write-Host '▓    -WED -> EDGE Web Browser               -EVT -> EVTX Files                                                                     ▒'
    Write-Host '▓    -WSA -> SAFARI                         -SC  -> Security Configuration                                                         ▒'
    Write-Host '▓    -WOP -> Opera                          -FL  -> Files Lists                                                                    ▒'
    Write-Host '▓                                           -PRF -> Prefetch                                                                       ▒'
    Write-Host '▓    -OUT -> Outlook                        -WS  -> Windows Search                                                                 ▒'
    Write-Host '▓                                           -EE  -> ETW & ETL                                                                      ▒'
    Write-Host '▓    -COD -> Cloud - OneDrive               -THC -> Thumbcache                                                                     ▒'
    Write-Host '▓    -CGD -> Cloud - Google Drive           -ICO -> Iconcache                                                                      ▒'
    Write-Host '▓    -CDB -> Cloud - Dropbox                -CPH -> CL & PS Command History                                                        ▒'
    Write-Host '▓                                           -SFO -> Shell Folders                                                                  ▒'
    Write-Host '▓                                           -PER -> Persistence                                                                    ▒'
    Write-Host '▓                                           -FEX -> File Extensions                                                                ▒'
    Write-Host '▓                                                                                                                                  ▒' 
    Write-Host '▓                                                                                                                                  ▒'
    Write-Host '▓▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒'
}

<#
do{
    if($GUI -eq $True)
    {
        Create-GUI
        exit
    }
    if($GUI -eq $False)
    {
        Control-NOGUI
        exit
    }

    
    $Answer = Read-Host 'Do you want o use GUI? ("Yes" or "No")'
    if($Answer -eq "Yes") { $GUI=$True  }
    if($Answer -eq "No" ) { $GUI=$False }
    

}While(($Graphic -ne $True) -or ($Graphic -ne $False))
#>

# NetWork Configuration Removed Commands
# Substitute the below with: Get-CimInstance Win32_NetworkAdapterConfiguration
# Get-WmiObject Win32_NetworkAdapterConfiguration | Select-Object * | Export-Csv "$Global:Destiny\$HOSTNAME\Network\Network_Adapters_Configuration_Complete.csv"
# Get-CimInstance Win32_NetworkAdapterConfiguration | Select-Object * | Export-Csv "$Global:Destiny\$HOSTNAME\Network\Network_Adapters_Configuration_Complete.csv"


<#
TEMP LIST OF DONE LIST:

VERSION 0.7
    - BAM - BACKGROUND ACTIVITY MODERATOR

#>

<# OLD CODE #>
<########### R E G I S T R Y #####################################################> # REG
Function Collect-Registry {
    <# TODO: investigate what is the advantage in having this if we already have the HIVES #>
    if ( -Not ( Test-Path $Global:Destiny\$HOSTNAME\REG_FILES ) ) { New-Item -ItemType directory -Path $Global:Destiny\$HOSTNAME\REG_FILES > $null }

    try{
        Write-Host "[+] Extracting Registry: Key Classes Root ..." -ForegroundColor Green
        reg export HKEY_CLASSES_ROOT $Global:Destiny\$HOSTNAME\REG_FILES\"HKCR.reg" > $null
        Write-Host "[+] Extracting Registry: Key Current User ..." -ForegroundColor Green
        reg export HKEY_CURRENT_USER $Global:Destiny\$HOSTNAME\REG_FILES\"HKCU.reg" > $null
        Write-Host "[+] Extracting Registry: Key Local Machine ..." -ForegroundColor Green
        reg export HKEY_LOCAL_MACHINE $Global:Destiny\$HOSTNAME\REG_FILES\"HKLM.reg" > $null
        Write-Host "[+] Extracting Registry: Key Users ..." -ForegroundColor Green
        reg export HKEY_USERS $Global:Destiny\$HOSTNAME\REG_FILES\"HKU.reg" > $null
        Write-Host "[+] Extracting Registry: Key Current Config ..." -ForegroundColor Green
        reg export HKEY_CURRENT_CONFIG $Global:Destiny\$HOSTNAME\REG_FILES\"HKCC.reg" > $null
    } catch {
        Report-Error -evidence "main REG files."
    }
}


<########### C H R O M I U M   W E B   B R O W S E R #########> # WCU
Function Collect-Chromium-Data {
    foreach($u in $USERS){
    
        if($OS -eq "XP")
        {
            if(Test-Path "C:\Documents and Settings\$u\Local Settings\Application Data\Google\Chrome\")
            {
                try{
                    Write-Host "[+] Collecting Chromium files (from Windows $OS system)..." -ForegroundColor Green
                    New-Item -ItemType directory -Path $Global:Destiny\$HOSTNAME\WEB_BROWSERS\CHROMIUM\$u > $null
                    cmd.exe /c copy "$Global:Source\Documents and Settings\$u\Local Settings\Application Data\Chromium\User Data\Default\Preferences" "$Global:Destiny\$HOSTNAME\WEB_BROWSERS\CHROMIUM\$u\."> $null
                    cmd.exe /c copy "$Global:Source\Documents and Settings\$u\Local Settings\Application Data\Chromium\User Data\Cache\*.*" "$Global:Destiny\$HOSTNAME\WEB_BROWSERS\CHROMIUM\$u\."> $null
                } catch {
                    Report-Error -evidence "Chromium files"
                }
            }  
        }

        if( ($OS -eq "7") -or ($OS -eq "Vista") -or ($OS -eq "8") -or ($OS -eq "10") )
        {
            if(Test-Path "$Global:Source\Users\$u\AppData\Local\Google\Chrome\User data")
            {
                try{
                    Write-Host "[+] Collecting Chromium files (from Windows $OS system)..." -ForegroundColor Green
                    New-Item -ItemType directory -Path $Global:Destiny\$HOSTNAME\WEB_BROWSERS\CHROMIUM\$u > $null
                    cmd.exe /c copy "$Global:Source\Users\$u\AppData\Local\Google\Chromium\Default\Preferences" "$Global:Destiny\$HOSTNAME\WEB_BROWSERS\CHROMIUM\$u\."> $null
                    cmd.exe /c copy "$Global:Source\Users\$u\AppData\Local\Google\Chromium\Default\Cache\*.*" "$Global:Destiny\$HOSTNAME\WEB_BROWSERS\CHROMIUM\$u\."> $null
                    cmd.exe /c copy "$Global:Source\Users\$u\AppData\Local\Google\Chromium\Default\Application Cache\Cache\*.*" "$Global:Destiny\$HOSTNAME\WEB_BROWSERS\CHROMIUM\$u\."> $null
                    cmd.exe /c copy "$Global:Source\Users\$u\AppData\Local\Google\Chromium\Default\Media Cache\*.*" "$Global:Destiny\$HOSTNAME\WEB_BROWSERS\CHROMIUM\$u\."> $null
                    cmd.exe /c copy "$Global:Source\Users\$u\AppData\Local\Google\Chromium\Default\GPUCache\*.*" "$Global:Destiny\$HOSTNAME\WEB_BROWSERS\CHROMIUM\$u\."> $null
                } catch {
                    Report-Error -evidence "Chromium files"
                }
            }
        }

        if( -not (Test-Path "$Global:Destiny\$HOSTNAME\WEB_BROWSERS\CHROMIUM\")){
            Write-Host "[i] There is no Chromium Browser in the System ..." -ForegroundColor Yellow
        }
    }
}



<########### A P P L I C A T I O N S   W I T H   O P E N   P O R T S   ###########> # AOP # REMOVED: Because we already have this information in the network connections with the xorresponding executing software and path
Function Collect-Application-With-Open-Ports {

    if ( -Not ( Test-Path $Global:Destiny\$HOSTNAME\NETWORK ) ) { New-Item -ItemType directory -Path $Global:Destiny\$HOSTNAME\NETWORK > $null }

    try{
        Write-Host "[+] Collecting Applications with Open Ports ..." -ForegroundColor Green
        cmd.exe /c netstat -anob > "$Global:Destiny\$HOSTNAME\NETWORK\ApplicationsWithOpenPorts.txt"
    }catch{
        Report-Error -evidence "Applications with Open Ports"
    }
}

<########### O P E N   P O R T S  ################################################> # OP #REMOVED: Because this information already exists in Get-NetTCPConnection
Function Collect-Open-Ports {

    if ( -Not ( Test-Path $Global:Destiny\$HOSTNAME\NETWORK ) ) { New-Item -ItemType directory -Path $Global:Destiny\$HOSTNAME\NETWORK > $null }

    try{
        Write-Host "[+] Collecting Open Ports ..." -ForegroundColor Green
        cmd.exe /c netstat -an |findstr /i "state listening established" > "$Global:Destiny\$HOSTNAME\NETWORK\OpenPorts.txt"
    }catch{
        Report-Error -evidence "Open Ports"
    }
}

<########### A C T I V E   D I R E C T O R Y   I N F O ###############> <# NEW #> # AD # Removed because the cmdlets for the AD do not come by default, and also, AD info is not so important for local computer forensics.
Function Collect-AD-Info {
    try{
        Write-Host "[+] Collecting Users and Groups from the Active Directory" -ForegroundColor Green
        Get-ADUser -Filter 'Name -Like "*"' | where Enabled -eq $True > "$Global:Destiny\$HOSTNAME\11.Users_And_Groups_AD.txt"
        Get-ADGroupMember Administrators | where objectClass -eq 'user' >> "$Global:Destiny\$HOSTNAME\11.Users_And_Groups_AD.txt"
        Get-ADComputer -Filter "Name -Like '0'" -Properties * | where Enabled -eq $True | Select-Object Name, OperatingSystem, Enabled >> "$Global:Destiny\$HOSTNAME\10.Users_And_Groups_AD.txt"
    }catch{
        Report-Error -evidence "Users and Groups from the Active Director"
    }
    
    try{
        Write-Host "[+] Collecting Active Directory Group Policy" -ForegroundColor Green
        Get-ADDefaultDomainPasswordPolicy -Current LoggedOnUser > "$Global:Destiny\$HOSTNAME\11.AD_GPO.txt"
        Get-ADDefaultDomainPasswordPolicy -Current LocalComputer >> "$Global:Destiny\$HOSTNAME\11.AD_GPO.txt"
        Get-GPO -all >> "$Global:Destiny\$HOSTNAME\11.AD_GPO.txt"        
        Get-GPOReport -Name "*" - ReportType Html >> "$Global:Destiny\$HOSTNAME\11.AD_GPO.html"
        <#
        IF I CAN ITERATE BY USERS AND COMPUTERS OVER THE AD NETWORK, I CAN USE THE FOLLOWING:

        Get-GPResultantSetOfPolicy –user <user> -computer <computer> -ReportType Html -Path ".\user-computer-RSoP.html"

        #>
    }catch{
        Report-Error -evidence "Active Directory Group Policy"
    }
}

<########### M O U N T E D   P O I N T S #########################################> # MNT <# TODO #> # Removed because there is one command above that gets this information. This might be useful if in the future I want to work only with registry files.
Function Collect-Mounted-Points {

    Write-Host "[+] Collecting Mounted Points ..." -ForegroundColor Green
    Write-Host "`t[-] [DEVELOPING] ..." -ForegroundColor Yellow

    # Computer\HKEY_USERS\S-1-5-21-1177053623-3576167574-2408905411-1001\Software\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2
    # Computer\HKEY_USERS\S-1-5-21-1177053623-3576167574-2408905411-1027\Software\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2\{5c00978b-7362-11e7-b923-d0577bd77e67}
    
    # Computer\HKEY_LOCAL_MACHINE\SYSTEM\MountedDevices
}

Function Collect-Wireless-Info {

        <# TODO: Review in respective OS #>       
        if ($OS -eq "XP") 
        {
            #OLD - cmd.exe /c reg export "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\WZCSVC\Parameters\Interfaces" "$Global:Destiny\$HOSTNAME\WIFI\WifiNetworkList.reg" > $null
            Get-Item "REGISTRY::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\WZCSVC\Parameters\Interfaces" "$Global:Destiny\$HOSTNAME\WIFI\WifiNetworkList.txt"
        } 
        <# TODO: Check the equivalent to the above for windows vista,7,8,10 #>
        # OLD - cmd.exe /c reg export "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\TCPIP\Parameters\Interfaces" "$Global:Destiny\$HOSTNAME\WIFI\WifiNetworkCfg.reg" > $null
        Get-Item "REGISTRY::HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\TCPIP\Parameters\Interfaces\*" > "$Global:Destiny\$HOSTNAME\WIFI\WifiNetworkCfg.reg" <# TODO: Is this really WIFI #>

}

<########### Pieces of lost code #########################################>
Function Old-Code{


    $SIDs = Get-ChildItem "REGISTRY::HKEY_USERS" | ForEach-Object { ($_.Name).Split("\")[1] } # list of user SIDs

    foreach($SID in $SIDS){

        if ($SID.Split("-")[7] -ne $null -and $SID.Split("-")[7] -notlike "*_Classes") # the ones that users removes the system and network and classes
        { 

            $N = Get-ItemPropertyValue -Path "REGISTRY::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\$SID\" -Name "ProfileImagePath"  # get's the name correspondent to the SID
            $NAME = $($N.Split("\")[2])

            if ( -Not ( Test-Path $Global:Destiny\$HOSTNAME\MRUs\$NAME ) ) { New-Item -ItemType directory -Path $Global:Destiny\$HOSTNAME\MRUs\$NAME > $null }

            # MUI CACHE
            try{           
                Get-ItemProperty "REGISTRY::HKEY_USERS\$SID\Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\MuiCache" | Out-File "$Global:Destiny\$HOSTNAME\MRUs\$NAME\MUICache.txt" -Width 200
            } catch {
                Report-Error -evidence "Collecting MUI CACHE"
            }

            
            # RECENT DOCS
            Write-Host "`t[+] RecentDOCS from $NAME" -ForegroundColor Green

            for($n=0; $n -le 149; $n++)
            {
                try 
                {
                    $temp = Get-ItemPropertyValue "REGISTRY::HKEY_USERS\$SID\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs" -Name $n
            
                    $read=$true
                    $i = 0
                            
                    foreach($b in $temp)
                    {
                        if($read)
                        {
                            if([int]$b -ne 0)
                            {
                                $c = [char][int]$b
                                $filename = $filename + "$c"
                            }
                            if([int]$b -eq 0) 
                            { 
                                $i = $i + 1 
                            }
                            else 
                            { 
                                $i = 0 
                            }
                            if($i -gt 1) 
                            {
                                $read = $false
                            }
                        }
                    }
                    echo "$filename" >> "$Global:Destiny\$HOSTNAME\MRUs\$NAME\RecentDocs.txt"
                    $filename = ""
                } 
                catch 
                {
                        Report-Error -evidence "Collecting RecentDOCS"
                }
            }


            # COMDLG32 :: CIDSizeMRU
            Write-Host "`t[+] CIDSizeMRU from $NAME" -ForegroundColor Green

            $cnt = Get-ItemPropertyValue "REGISTRY::HKEY_USERS\$SID\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\CIDSizeMRU\" -Name MRUListEx
            $i=0
            foreach($b in $cnt){$i++} # gets the number of entries
            $max = (($i / 4) - 1)

            for($n=0; $n -lt $max; $n++){
                        
                try 
                {
                    $temp = Get-ItemPropertyValue "REGISTRY::HKEY_USERS\$SID\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\CIDSizeMRU\" -Name $n
            
                    $read=$true
                    $i = 0
                            
                    foreach($b in $temp)
                    {
                        if($read)
                        {
                            if([int]$b -ne 0)
                            {
                                $c = [char][int]$b
                                $filename = $filename + "$c"
                            }
                            if([int]$b -eq 0) 
                            { 
                                $i = $i + 1 
                            }
                            else 
                            { 
                                $i = 0 
                            }
                            if($i -gt 1) 
                            {
                                $read = $false
                            }
                        }
                    }
                    echo "$filename" >> "$Global:Destiny\$HOSTNAME\MRUs\$NAME\CIDSizeMRU.txt"
                    $filename = ""
                } 
                catch 
                {
                        Report-Error -evidence "Collecting CIDSizeMRU"
                }
            }


            # COMDLG32 :: LastVisitedPidlMRU
            Write-Host "`t[+] LastVisitedPidlMRU from $NAME" -ForegroundColor Green

            $cnt = Get-ItemPropertyValue "REGISTRY::HKEY_USERS\$SID\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\LastVisitedPidlMRU\" -Name MRUListEx
            $i=0
            foreach($b in $cnt){$i++} # gets the number of entries
            $max = (($i / 4) - 1)

            for($n=0; $n -lt $max; $n++)
            {
                        
                try 
                {
                    $temp = Get-ItemPropertyValue "REGISTRY::HKEY_USERS\$SID\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\LastVisitedPidlMRU\" -Name $n
            
                    $read=$true
                    $i = 0
                            
                    foreach($b in $temp)
                    {
                        if($read)
                        {
                            if([int]$b -ne 0)
                            {
                                $c = [char][int]$b
                                $filename = $filename + "$c"
                            }
                            if([int]$b -eq 0) 
                            { 
                                $i = $i + 1 
                            }
                            else 
                            { 
                                $i = 0 
                            }
                            if($i -gt 1) 
                            {
                                $read = $false
                            }
                        }
                    }
                    echo "$filename" >> "$Global:Destiny\$HOSTNAME\MRUs\$NAME\LastVisitedPidlMRU.txt"
                    $filename = ""
                } 
                catch 
                {
                    Report-Error -evidence "Collecting LastVisitedPidlMRU"
                }
            }


            # RUN MRU
            Write-Host "`t[+] RunMRU from $NAME" -ForegroundColor Green

            try 
            {
                if(Get-ItemPropertyValue "REGISTRY::HKEY_USERS\$SID\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU\" -Name MRUList -ErrorAction Ignore)
                {

                    $cnt = Get-ItemPropertyValue "REGISTRY::HKEY_USERS\$SID\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU\" -Name MRUList
                    $temp = $cnt.ToCharArray()
                    foreach($n in $temp)
                    {
                        $temp = Get-ItemPropertyValue "REGISTRY::HKEY_USERS\$SID\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU\" -Name $n
                            
                        echo "$temp" >> "$Global:Destiny\$HOSTNAME\MRUs\$NAME\RunMRU.txt"
                    }
                }
            } 
            catch 
            {
                Report-Error -evidence "Collecting RunMRU"
            }

            
            # COMDLG32 :: OpenSavePidlMRU <# TODO: Substitute the SID static number in the function by variable #>
            <# TODO: Translation of the ecnripted code into readable code #>
            #  [System.Text.Encoding]::Default.GetString((Get-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\OpenSavePidlMRU\docx")."9")
            
            Write-Host "`t[+] OpenSavePidlMRU from $NAME" -ForegroundColor Green

            $cnt = Get-ItemPropertyValue -LiteralPath "REGISTRY::HKEY_USERS\S-1-5-21-1177053623-3576167574-2408905411-1001\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\OpenSavePidlMRU\*" -Name MRUListEx
            $i=0
            foreach($b in $cnt){$i++} # gets the number of entries
            $max = (($i / 4) - 1)

            for($n=0; $n -lt $max; $n++)
            {
                try 
                {
                    # Get-ItemPropertyValue -LiteralPath "REGISTRY::HKEY_USERS\S-1-5-21-1177053623-3576167574-2408905411-1001\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\OpenSavePidlMRU\*" -Name 3 | Format-Hex -Encoding UTF32
                    $temp = Get-ItemPropertyValue -LiteralPath "REGISTRY::HKEY_USERS\S-1-5-21-1177053623-3576167574-2408905411-1001\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\OpenSavePidlMRU\*" -Name $n
            
                    $read=$true
                    $i = 0
                            
                    foreach($b in $temp)
                    {
                        if($read)
                        {
                            if([int]$b -ne 0 -and [int]$b -ge 33 -and [int]$b -le 126)
                            {
                                $c = [char][int]$b
                                $filename = $filename + "$c"
                            }
                            <#
                            if([int]$b -eq 0) 
                            { 
                                $i = $i + 1 
                            }
                            else 
                            { 
                                $i = 0 
                            }
                            if($i -gt 1) 
                            {
                                $read = $false
                            }
                            #>
                        }
                    }
                    echo "$filename" >> "$Global:Destiny\$HOSTNAME\MRUs\$NAME\OpenSavePidlMRU.txt"
                    $filename = ""
                } 
                catch 
                {
                    Report-Error -evidence "Collecting LastVisitedPidlMRU"
                }
                
            }
        }
    }


}

# Queries for TCP connection, puts in a variable, than iterates through all of them and adds information about the the process name and process command line
<#
        $TCPConns = Get-NetTCPConnection | Select-Object CreationTime, LocalAddress, LocalPort, RemoteAddress, RemotePort, OwningProcess, State

        for($i=0;$i -le $TCPConns.count;$i++)
        {
            $TCPConns[$i]

            Write-Host("Process:")`            (Get-CimInstance -ClassName Win32_Process | where ProcessID -eq $TCPConns[$i].OwningProcess).ProcessName
            Write-Host("CmdLine:")`            (Get-CimInstance -ClassName Win32_Process | where ProcessID -eq $TCPConns[$i].OwningProcess).CommandLine
            Write-Host("----------------------------------------")
        }


        $UDPConns = Get-NetUDPEndpoint | Select-Object CreationTime, LocalAddress, LocalPort, RemoteAddress , RemotePort, OwningProcess, State

        for($i=0;$i -le $UDPConns.count;$i++)
        {
            $UDPConns[$i]

            Write-Host("Process:")`            (Get-CimInstance -ClassName Win32_Process | where ProcessID -eq $UDPConns[$i].OwningProcess).ProcessName
            Write-Host("CmdLine:")`            (Get-CimInstance -ClassName Win32_Process | where ProcessID -eq $UDPConns[$i].OwningProcess).CommandLine
            Write-Host("----------------------------------------")
        }

#>