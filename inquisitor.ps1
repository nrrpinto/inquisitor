#Requires -RunAsAdministrator
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
    ▓                            ## |                           Forensic artifacts collector       ▒
    ▓                            \__|                           By:      f4d0                      ▒
    ▓                                                           Version: 0.7                       ▒ 
    ▓                                                                                              ▒
    ▓▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒



.DESCRIPTION
    Script in powershell to collect forensic artifacts from windows machines.

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
    .\inquisitor.ps1 -PER -Source c: -Destiny e: -FormatType No

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

    References:
        - CIR_CODE\obtain_evidences.ps1 de Jaime Ferrer 
        - https://es.wikipedia.org/wiki/Windows_Server
        - https://www.fwhibbit.es/windows-registry-prepare-the-coffeemaker
        - https://docs.microsoft.com/en-us/windows/desktop/SysInfo/about-the-registry
        - https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/wevtutil
        - https://www.sans.org/cyber-security-summit/archives/file/summit-archive-1544032916.pdf

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
    
    <# Defines if the triage is over a Live system #>
    [switch]$Live=$null,
    
    <# Defines if the triage is over an Offline system #>
    [switch]$Offline=$null,

    
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
    [switch]$STA=$false, 
    
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
    
    <# Collects Information about PnP Devices from the OS. #>
    [switch]$PNP=$false, 
    
    <# Collects Information about Security configuration of the system. #>
    [switch]$SEC=$false, 
         

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

    <# Developing. #>
    [switch]$LSE=$false, 
    
    <# Developing. #>
    [switch]$PWD=$false, 

##### Third Party Tools  
    
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
    
    <# Collects ETW and ETL Files #>
    [switch]$EET=$false, 
    
    <# Collects Information about all the files in the system orderer by different dates. #>
    [switch]$FIL=$false,         
    
    <# Collects Prefectch Files #>
    [switch]$PRF=$false,         
    
    <# Collects Windows Search database file. #>
    [switch]$WSE=$false,          
    
    <# Collects Thumcache and Thumbicons files from the system. #>
    [switch]$TIC=$false,          
    
    <# Collects File System files: $MFT, $UsnJrnl and $LogFile #>
    [switch]$FSF=$false,         
    
    <# Collects Memory Support files: Hiberfil.sys, Pagefile.sys and Swapfile.sys #>
    [switch]$MSF=$false,   

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

    
    <# Collects emails storage file from OUTLOOK. #>
    [switch]$EMA=$false,

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




    <# Collects logs from OneDrive cloud app. #>
    [switch]$COD=$false,

    <# Collects logs from Google Drive cloud app. #>
    [switch]$CGD=$false,
    
    <# Collects logs from DropBox cloud app. #>
    [switch]$CDB=$false
)



<# The Global variables that are almost a mirror of the inut parameters, but they are needed to change then at runtime in case necessary. #>
$Global:Source=$Source
$Global:Destiny=$Destiny
$Global:FormatType=$FormatType
$Global:Live=$Live
$Global:Offline=$Offline
$Global:All=$All

##### LIVE
   
$Global:RAM=$RAM

$Global:NET=$NET 
$Global:SAP=$SAP 
$Global:STA=$STA 
$Global:CPH=$CPH 
$Global:INS=$INS 
$Global:UGR=$UGR 
$global:PER=$PER 
$Global:USB=$USB 
$Global:PNP=$PNP 
$Global:SEC=$SEC 
 
$Global:MRU=$MRU 
$Global:SHI=$SHI 
$Global:JLI=$JLI      
$Global:BAM=$BAM

$Global:TLH=$TLH 
$Global:RAP=$RAP      
$Global:SYS=$SYS

$Global:LSE=$LSE
$Global:PWD=$PWD  

##### THIRD PARTY TOOLS    
      
$Global:LAC=$LAC         
$Global:AFI=$AFI       
        
##### OFFLINE  

$Global:HIV=$HIV          
$Global:EVT=$EVT         
$Global:EET=$EET
$Global:FIL=$FIL         
$Global:PRF=$PRF         
$Global:WSE=$WSE          
$Global:TIC=$TIC          

$Global:FSF=$FSF         
$Global:MSF=$MSF
        
$Global:THA=$THA
$Global:SRU=$SRU
$Global:CRE=$CRE

$Global:SKY=$SKY
$Global:EMA=$EMA

$Global:CHR=$CHR
$Global:MFI=$MFI
$Global:IEX=$IEX
$Global:EDG=$EDG
$Global:SAF=$SAF
$Global:OPE=$OPE
$Global:TOR=$TOR

$Global:COD=$COD
$Global:CGD=$CGD
$Global:CDB=$CDB


$Global:SFI=$SFI    
$Global:DEX=$DEX

<##################################################################################################################################>
<############  GENERAL CONFIGURATIONS AND SETUPS  ####################################>
<##################################################################################################################################>

$APPName = "Inquisitor"
$APPVersion = "v1.0"

<# GLOBAL VARIABLES #>
$HOSTNAME = hostname
$OS = ((Get-CimInstance win32_operatingsystem).name).split(" ")[2] <# Intead of collecting the windows version: XP, Vista, 7, 10, ... should be according to the core #>
$USERS = Get-LocalUser | ? { $_.Enabled } | Select-Object -ExpandProperty Name # TODO: Get the users from Users folder and not from PowerShell command, it will not work correctly for offline collection like it is at the moment
$SIDS = Get-ChildItem "REGISTRY::HKEY_USERS" | ForEach-Object { ($_.Name).Split("\")[1] } # list of user SIDs
$ARCH = $env:PROCESSOR_ARCHITECTURE
$SCRIPTPATH = split-path -parent $MyInvocation.MyCommand.Definition
$DRIVES = $(Get-PSDrive -PSProvider FileSystem).Root

<# defines according to architecture which version of Rawcpoy and SigCheck to use #>
if($ARCH -eq "AMD64") 
{
    $RAW_EXE = "$SCRIPTPATH\bin\RawCopy64.exe"
    $SIG_EXE = "$SCRIPTPATH\bin\sigcheck64.exe"
    $SQL_DBX_EXE = "$SCRIPTPATH\bin\sqlite-dbx-win64.exe"
    $OPEN_SAVED_FILES_VIEW = "$SCRIPTPATH\bin\opensavefilesview-x64\OpenSaveFilesView.exe" # not used
    $THUMB_CACHE_VIEWER = "$SCRIPTPATH\bin\thumbcache_viewer_64\thumbcache_viewer.exe"
    $AUTORUNS = "$SCRIPTPATH\bin\autorunsc64.exe"
    
} 
else 
{
    $RAW_EXE = "$SCRIPTPATH\bin\RawCopy.exe"
    $SIG_EXE = "$SCRIPTPATH\bin\sigcheck.exe"
    $SQL_DBX_EXE = "$SCRIPTPATH\bin\sqlite-dbx-win32.exe"
    $OPEN_SAVED_FILES_VIEW = "$SCRIPTPATH\bin\opensavefilesview\OpenSaveFilesView.exe"
    $THUMB_CACHE_VIEWER = "$SCRIPTPATH\bin\thumbcache_viewer_32\thumbcache_viewer.exe"
    $AUTORUNS = "$SCRIPTPATH\bin\autorunsc.exe"
}

$UsedParameters = $PSBoundParameters.Keys <# TODO: Will use this variable to check which parameters were inserted in the command line and therefore don't need confirmation #>


<##################################################################################################################################>
<############ E V I D E N C E   C O L L E C T I O N ###############################################################################>
<##################################################################################################################################>

<##################################################################################################################################>
<############  LIVE SYSTEM  /  VOLATILE ###########################################################################################>
<##################################################################################################################################>

<########### S Y S T E M   T I M E #################> # TIM*
Function Collect-Time {
    
    param(
        [ValidateSet("Start","Finish")][string]$Status=""
    )

    if ( -Not ( Test-Path $Global:Destiny\$HOSTNAME\System_Info\ ) ) { New-Item -ItemType directory -Path $Global:Destiny\$HOSTNAME\System_Info\ > $null }

    Write-Host "[+] Collecting $Status Date and Timezone ..." -ForegroundColor Green
    try
    {
        Get-Date > "$Global:Destiny\$HOSTNAME\System_Info\Date_Time_TimeZone_$Status.txt"  # Other options: cmd.exe /c Write-Host %DATE% %TIME% OR  cmd.exe /c "date /t & time /t"
        Get-TimeZone >> "$Global:Destiny\$HOSTNAME\System_Info\Date_Time_TimeZone_$Status.txt"
    }
    catch
    {
        Report-Error -evidence "Date or Timezone"
    }
}

<########### M E M O R Y   D U M P #################> # RAM*
Function Collect-Memory-Dump {

    Write-Host "[+] Collecting Memory Dump ..." -ForegroundColor Green

    if ( -Not ( Test-Path "$Global:Destiny\$HOSTNAME\MEMORY_DUMP" ) ) { New-Item -ItemType directory -Path "$Global:Destiny\$HOSTNAME\MEMORY_DUMP" > $null }
    
    try 
    {
        cmd.exe /c $SCRIPTPATH\bin\winpmem_1.6.2.exe $Global:Destiny\$HOSTNAME\MEMORY_DUMP\"$HOSTNAME".raw > $null
        Write-Host "`t└>Successfully collected" -ForegroundColor DarkGreen
    } 
    catch 
    {
        Report-Error -evidence "Memory Dump"
    }
} 


<########### N E T W O R K #########################> # NET*
Function Collect-Network-Information {
    
    if ( -Not ( Test-Path "$Global:Destiny\$HOSTNAME\Network" ) ) { New-Item -ItemType directory -Path "$Global:Destiny\$HOSTNAME\Network" > $null }
    
    Write-Host "[+] Collecting TCP Connections ..." -ForegroundColor Green
    try
    {
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
        cmd.exe /c netsh wlan show all > "$Global:Destiny\$HOSTNAME\Network\WIFI_All_Configuration.txt"
        cmd.exe /c netsh wlan export profile folder=$Global:Destiny\$HOSTNAME\Network\ > $null

        cmd.exe /c netsh wlan show profiles | Select-String "All User Profile" | ForEach {
             $bla = netsh wlan show profiles name=$(($_ -split ":")[1].Trim()) key="clear"
             $SSID = ((($bla | Select-String "SSID Name") -split ":")[1].Trim())
             $KEY = ((($bla | Select-string "Key Content") -split ":")[1].Trim())
             echo "SSID: $SSID | Key: $KEY" >> "$Global:Destiny\$HOSTNAME\Network\WIFI_Credentials.txt"
        }  2>$null
        
    } 
    catch 
    {
        Report-Error -evidence "WIFI Info"
    }



}

<########### S E R V I C E S   P R O C E S S E S ###> # SAP*
Function Collect-Services-and-Processes {
    
    if ( -Not ( Test-Path $Global:Destiny\$HOSTNAME\Services_Processes\ ) ) { New-Item -ItemType directory -Path $Global:Destiny\$HOSTNAME\Services_Processes\ > $null }


    Write-Host "[+] Collecting Services ..." -ForegroundColor Green
    try # Dependency of PowerShell 3.1 because or the Export-Csv
    {
        Get-CimInstance -ClassName Win32_Service | Select-Object Name, DisplayName, StartMode, State, PathName, StartName, ServiceType | Export-Csv "$Global:Destiny\$HOSTNAME\Services_Processes\Services_simplified.csv"
        Get-CimInstance -ClassName Win32_Service | Select-Object * | Export-Csv "$Global:Destiny\$HOSTNAME\Services_Processes\Services_detailed.csv"
        # Get-CimInstance -Query "SELECT * from Win32_Service"
        # Get-Service  (Powershell 3.1)
    }
    catch
    {
        Report-Error -evidence "Services in CSV format"
    }
    # Duplicated because it has less Dependency: PowerShell 1.0 - This is in case the powershell in the machine is lower
    try
    {
        Get-CimInstance -ClassName Win32_Service | Select-Object Name, DisplayName, StartMode, State, PathName, StartName, ServiceType > "$Global:Destiny\$HOSTNAME\Services_Processes\Services_simplified.txt" # Duplicated but with 
        Get-CimInstance -ClassName Win32_Service | Select-Object * > "$Global:Destiny\$HOSTNAME\Services_Processes\Services_detailed.txt"
    }
    catch
    {
        Report-Error -evidence "Services in TXT format"
    }
    
    Write-Host "[+] Collecting Processes ..." -ForegroundColor Green
    try # Dependency of PowerShell 3.1 because or the Export-Csv
    {
        Get-CimInstance -ClassName Win32_Process | Select-Object ProcessId,ProcessName,Path, CreationDate | Sort-Object ProcessId | Export-Csv $Global:Destiny\$HOSTNAME\Services_Processes\"Processes_Simplified.txt"
        Get-CimInstance -ClassName Win32_Process | Select-Object * | Sort-Object ProcessId | Export-Csv $Global:Destiny\$HOSTNAME\Services_Processes\"Processes_All.txt"

    }
    catch
    {
        Report-Error -evidence "Processes in CSV format"
    }
    # Duplicated because it has less Dependency: PowerShell 1.0 - This is in case the powershell in the machine is lower
    try
    {
        Get-CimInstance -ClassName Win32_Process | Select-Object ProcessId,ProcessName,Path, CreationDate | Sort-Object ProcessId >> $Global:Destiny\$HOSTNAME\Services_Processes\"Processes_Simplified.txt"
        Get-CimInstance -ClassName Win32_Process | Select-Object * | Sort-Object ProcessId >> $Global:Destiny\$HOSTNAME\Services_Processes\"Processes_All.txt"

    }
    catch
    {
        Report-Error -evidence "Processes in TXT format"
    }

    # For each existing Process shows information about parent process
    try
    {
       $runningProcesses = Get-CimInstance -ClassName Win32_Process | Select-Object ProcessId, ProcessName, CreationDate, CommandLine, ParentProcessId

       for($i=0; $i -le $runningProcesses.count; $i++)
       {
            $runningProcesses[$i] >> $Global:Destiny\$HOSTNAME\Services_Processes\"Processes_Child_Parent.txt"

            "Parent ProcessId:  " + (Get-CimInstance -ClassName Win32_Process | where ProcessId -eq $runningProcesses[$i].ParentProcessId).ProcessId >> $Global:Destiny\$HOSTNAME\Services_Processes\"Processes_Child_Parent.txt"
            "Parent ProcessName:  " + (Get-CimInstance -ClassName Win32_Process | where ProcessId -eq $runningProcesses[$i].ParentProcessId).ProcessName >> $Global:Destiny\$HOSTNAME\Services_Processes\"Processes_Child_Parent.txt"
            "Parent CreationDate:  " + (Get-CimInstance -ClassName Win32_Process | where ProcessId -eq $runningProcesses[$i].ParentProcessId).CreationDate >> $Global:Destiny\$HOSTNAME\Services_Processes\"Processes_Child_Parent.txt"
            "Parent CmdLine:  " + (Get-CimInstance -ClassName Win32_Process | where ProcessId -eq $runningProcesses[$i].ParentProcessId).CommandLine >> $Global:Destiny\$HOSTNAME\Services_Processes\"Processes_Child_Parent.txt"
            "Parent ParentProcessId:  " + (Get-CimInstance -ClassName Win32_Process | where ProcessId -eq $runningProcesses[$i].ParentProcessId).ParentProcessId >> $Global:Destiny\$HOSTNAME\Services_Processes\"Processes_Child_Parent.txt"
            (" ") >> $Global:Destiny\$HOSTNAME\Services_Processes\"Processes_Child_Parent.txt"
            ("--------------------") >> $Global:Destiny\$HOSTNAME\Services_Processes\"Processes_Child_Parent.txt"
            (" ") >> $Global:Destiny\$HOSTNAME\Services_Processes\"Processes_Child_Parent.txt"
       }
    }
    catch
    {
        Report-Error -evidence "Processes - Parente Child"
    }


}

<########### S C H E D U L E D   T A S K S #########> # STA*
Function Collect-Scheduled-Tasks {

    if ( -Not ( Test-Path $Global:Destiny\$HOSTNAME\Scheduled_Tasks\Tasks_Xml ) ) { New-Item -ItemType directory -Path $Global:Destiny\$HOSTNAME\Scheduled_Tasks\Tasks_Xml > $null }
    
    Write-Host "[+] Collecting Scheduled Tasks ..." -ForegroundColor Green    
    try
    {
        cmd.exe /c schtasks > "$Global:Destiny\$HOSTNAME\Scheduled_Tasks\Scheduled_Tasks.txt"
    }
    catch
    {
        Report-Error -evidence "Scheduled Tasks"
    }
    
    try 
    {
        Get-ScheduledTask | where Author -NotLike "Microsoft*" | where Author -NotLike "*SystemRoot*" | where Author -ne $null |  foreach {
             Export-ScheduledTask -TaskName $_.TaskName -TaskPath $_.TaskPath |
             Out-File (Join-Path "$Global:Destiny\$HOSTNAME\Scheduled_Tasks\Tasks_Xml" "$($_.TaskName).xml")
        }  
    } 
    catch 
    {
        Report-Error -evidence "Scheduled Tasks"
    }
}

<########### PS C O M M A N D   H I S T O R Y ######> # CPH*
Function Collect-PSCommand-History {
    
    Write-Host "[+] Collecting PowerShell CMD history for each user ... " -ForegroundColor Green
    # For each user reads the Console History from Powershell
    foreach($u in $USERS)
    {
        Write-Host "`t`tUser: $u " -ForegroundColor Green
        if ( -Not ( Test-Path $Global:Destiny\$HOSTNAME\PSCMD_HISTORY\$u ) ) { New-Item -ItemType directory -Path $Global:Destiny\$HOSTNAME\PSCMD_HISTORY\$u > $null }
    
        if(Test-Path -Path "$Global:Source\Users\$u\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt")
        {
            try
            {
                cmd.exe /c type "$Global:Source\Users\$u\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt" > "$Global:Destiny\$HOSTNAME\PSCMD_HISTORY\$u\ConsoleHost_history.txt"
            }
            catch
            {
                Report-Error -evidence "PS Command History"    
            }
        }
    }
}

<########### I N S T A L L E D   S O F T W A R E ###> # INS*
Function Collect-Installed-Software {

    if ( -Not ( Test-Path $Global:Destiny\$HOSTNAME\Software ) ) { New-Item -ItemType directory -Path $Global:Destiny\$HOSTNAME\Software > $null }

    Write-Host "[+] Collecting List of Installed Software ..." -ForegroundColor Green
    try
    {
        Get-ChildItem -Force -Directory "$Global:Source\Program Files"                                   >> "$Global:Destiny\$HOSTNAME\Software\InstalledSoftware_ProgramsFolder_x64.txt"
        Get-ChildItem -Force -Directory "$Global:Source\Program Files (x86)"                             >> "$Global:Destiny\$HOSTNAME\Software\InstalledSoftware_ProgramsFolder_x86.txt"
        

        Get-ItemProperty "HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*"           >> "$Global:Destiny\$HOSTNAME\Software\InstalledSoftware_RegUninstall_x64.txt"
        Get-ItemProperty "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*"                       >> "$Global:Destiny\$HOSTNAME\Software\InstalledSoftware_RegUninstall_x86.txt"
        
        Get-CimInstance -ClassName Win32_Product | Select-Object Name, Version, Vendor, InstallDate, InstallSource, PackageName, LocalPackage >> "$Global:Destiny\$HOSTNAME\Software\InstalledSoftware_CimInstance.txt"
    } 
    catch 
    {
        Report-Error -evidence "List of Installed Software"
    }
}

<########### U S E R S   A N D   G R O U P S #######> # UGR*
Function Collect-Users-Groups {
    
    if ( -Not ( Test-Path $Global:Destiny\$HOSTNAME\Users_Groups ) ) { New-Item -ItemType directory -Path $Global:Destiny\$HOSTNAME\Users_Groups > $null }
    
    Write-Host "[+] Collecting Users and Groups" -ForegroundColor Green
    try
    {
        Get-LocalUser | Select-Object *                            > "$Global:Destiny\$HOSTNAME\Users_Groups\Users_Local.txt"
        Get-LocalGroup | Select-Object *                           > "$Global:Destiny\$HOSTNAME\Users_Groups\Groups_Local.txt"
        Get-LocalGroupMember Administrators | Select-Object *      > "$Global:Destiny\$HOSTNAME\Users_Groups\Administrator_LocalMembers.txt"  #TODO: There might be a problem with the word Administrators in systems that use other languages.
    }
    catch
    {
        Report-Error -evidence "Users and Groups"
    }
}

<########### P E R S I S T E N C E #################> # PER*
Function Collect-Persistence { 
    
    if ( -Not ( Test-Path $Global:Destiny\$HOSTNAME\Persistence ) ) { New-Item -ItemType directory -Path $Global:Destiny\$HOSTNAME\Persistence > $null }
    
    try{
        Write-Host "[+] Collecting Persistence " -ForegroundColor Green
        
        echo "Notes: Look for Strange Executables"                                                                              >> "$Global:Destiny\$HOSTNAME\Persistence\Persistence_RegistryRunKeys.txt"
        echo "More information: https://attack.mitre.org/techniques/T1060/"                                                     >> "$Global:Destiny\$HOSTNAME\Persistence\Persistence_RegistryRunKeys.txt"
        echo ""                                                                                                                 >> "$Global:Destiny\$HOSTNAME\Persistence\Persistence_RegistryRunKeys.txt" 
        
        Get-Item -Path "REGISTRY::HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run"                              >> "$Global:Destiny\$HOSTNAME\Persistence\Persistence_RegistryRunKeys.txt" 2> $null
        Get-Item -Path "REGISTRY::HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\RunOnce"                          >> "$Global:Destiny\$HOSTNAME\Persistence\Persistence_RegistryRunKeys.txt" 2> $null
        
        if(Test-Path "REGISTRY::HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\RunOnceEx") {
            Get-Item -Path "REGISTRY::HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\RunOnceEx"                    >> "$Global:Destiny\$HOSTNAME\Persistence\Persistence_RegistryRunKeys.txt" 
        }

        Get-Item -Path "REGISTRY::HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run"                             >> "$Global:Destiny\$HOSTNAME\Persistence\Persistence_RegistryRunKeys.txt" 2> $null
        Get-Item -Path "REGISTRY::HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunOnce"                         >> "$Global:Destiny\$HOSTNAME\Persistence\Persistence_RegistryRunKeys.txt" 2> $null
        
        Get-Item -Path "REGISTRY::HKEY_LOCAL_MACHINE\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run"                 >> "$Global:Destiny\$HOSTNAME\Persistence\Persistence_RegistryRunKeys.txt" 2> $null
        Get-Item -Path "REGISTRY::HKEY_LOCAL_MACHINE\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce"             >> "$Global:Destiny\$HOSTNAME\Persistence\Persistence_RegistryRunKeys.txt" 2> $null

        Get-Item -Path "REGISTRY::HKEY_USERS\.DEFAULT\Software\Microsoft\Windows\CurrentVersion\Run"                            >> "$Global:Destiny\$HOSTNAME\Persistence\Persistence_RegistryRunKeys.txt" 2> $null

        if(Test-Path "REGISTRY::HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunServices") {
            Get-Item -Path "REGISTRY::HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunServices"                 >> "$Global:Destiny\$HOSTNAME\Persistence\Persistence_RegistryRunKeys.txt"
        }

        if(Test-Path "REGISTRY::HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce") {
            Get-Item -Path "REGISTRY::HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce"             >> "$Global:Destiny\$HOSTNAME\Persistence\Persistence_RegistryRunKeys.txt"
        }

        if(Test-Path "REGISTRY::HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\Userinit") {
            Get-Item -Path "REGISTRY::HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\Userinit"        >> "$Global:Destiny\$HOSTNAME\Persistence\Persistence_RegistryRunKeys.txt"
        }

        if(Test-Path "REGISTRY::HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\RunServices") {
            Get-Item -Path "REGISTRY::HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\RunServices"                  >> "$Global:Destiny\$HOSTNAME\Persistence\Persistence_RegistryRunKeys.txt"
        }

        if(Test-Path "REGISTRY::HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce") {
            Get-Item -Path "REGISTRY::HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce"              >> "$Global:Destiny\$HOSTNAME\Persistence\Persistence_RegistryRunKeys.txt"
        }

        if(Test-Path "REGISTRY::HKEY_CURRENT_USER\Software\Microsoft\Windows NT\CurrentVersion\Windows") {
            Get-Item -Path "REGISTRY::HKEY_CURRENT_USER\Software\Microsoft\Windows NT\CurrentVersion\Windows"                   >> "$Global:Destiny\$HOSTNAME\Persistence\Persistence_RegistryRunKeys.txt"
        }

        # Shell Folders - https://attack.mitre.org/techniques/T1060/
        echo "Notes: Look for Strange Paths"                                                                      > "$Global:Destiny\$HOSTNAME\Persistence\Persistence_ShellFolders.txt"
        echo "More information: https://attack.mitre.org/techniques/T1060/"                                      >> "$Global:Destiny\$HOSTNAME\Persistence\Persistence_ShellFolders.txt"
        echo ""                                                                                                  >> "$Global:Destiny\$HOSTNAME\Persistence\Persistence_ShellFolders.txt"
        Get-Item -Path "HKCU:\software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders\"                 >> "$Global:Destiny\$HOSTNAME\Persistence\Persistence_ShellFolders.txt"
        Get-Item -Path "HKLM:\software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders\"                 >> "$Global:Destiny\$HOSTNAME\Persistence\Persistence_ShellFolders.txt"
        Get-Item -Path "HKCU:\software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders\"            >> "$Global:Destiny\$HOSTNAME\Persistence\Persistence_ShellFolders.txt"
        Get-Item -Path "HKLM:\software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders\"            >> "$Global:Destiny\$HOSTNAME\Persistence\Persistence_ShellFolders.txt"


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
        if(Test-Path "REGISTRY::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon") {
            Get-Item -Path "REGISTRY::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"                 >> "$Global:Destiny\$HOSTNAME\Persistence\Persistence_WinlogonHalperDLL.txt"
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
        # TOD: Hash the DLL's and send them to virustotal and receive the results
        if(Test-Path "REGISTRY::HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Microsoft\Cryptography\OID\EncodingType 0\CryptSIPDllVerifyIndirectData") {
            echo "Notes: Look for Strange DLLs"                                                                                                          >> "$Global:Destiny\$HOSTNAME\Persistence\Persistence_SIP&TrustProviderHijacking.txt"
            echo "More information: https://attack.mitre.org/techniques/T1198/"                                                                          >> "$Global:Destiny\$HOSTNAME\Persistence\Persistence_SIP&TrustProviderHijacking.txt"
            echo ""                                                                                                                                      >> "$Global:Destiny\$HOSTNAME\Persistence\Persistence_SIP&TrustProviderHijacking.txt"   
            Get-Item -Path "REGISTRY::HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Microsoft\Cryptography\OID\EncodingType 0\CryptSIPDllVerifyIndirectData\*" >> "$Global:Destiny\$HOSTNAME\Persistence\Persistence_SIP&TrustProviderHijacking.txt"
        }
        if(Test-Path "REGISTRY::HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Microsoft\Cryptography\OID\EncodingType 0\CryptSIPDllGetSignedDataMsg") {
            Get-Item -Path "REGISTRY::HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Microsoft\Cryptography\OID\EncodingType 0\CryptSIPDllGetSignedDataMsg\*"   >> "$Global:Destiny\$HOSTNAME\Persistence\Persistence_SIP&TrustProviderHijacking.txt"
        }
        if(Test-Path "REGISTRY::HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Microsoft\Cryptography\Providers\Trust\FinalPolicy") {
            Get-Item -Path "REGISTRY::HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Microsoft\Cryptography\Providers\Trust\FinalPolicy\*"                      >> "$Global:Destiny\$HOSTNAME\Persistence\Persistence_SIP&TrustProviderHijacking.txt"
        }
        if(Test-Path "REGISTRY::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Cryptography\OID\EncodingType 0\CryptSIPDllVerifyIndirectData") {
            Get-Item -Path "REGISTRY::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Cryptography\OID\EncodingType 0\CryptSIPDllVerifyIndirectData\*"             >> "$Global:Destiny\$HOSTNAME\Persistence\Persistence_SIP&TrustProviderHijacking.txt"
        }
        if(Test-Path "REGISTRY::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Cryptography\OID\EncodingType 0\CryptSIPDllGetSignedDataMsg") {
            Get-Item -Path "REGISTRY::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Cryptography\OID\EncodingType 0\CryptSIPDllGetSignedDataMsg\*"               >> "$Global:Destiny\$HOSTNAME\Persistence\Persistence_SIP&TrustProviderHijacking.txt"
        }
        if(Test-Path "REGISTRY::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Cryptography\Providers\Trust\FinalPolicy") {
            Get-Item -Path "REGISTRY::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Cryptography\Providers\Trust\FinalPolicy\*"                                  >> "$Global:Destiny\$HOSTNAME\Persistence\Persistence_SIP&TrustProviderHijacking.txt"
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

        foreach($u in $USERS)
        {
            if( Test-Path "$Global:Source\Users\$u\AppData\Roaming\Microsoft\Templates\Normal.dotm")
            {
                if( -not (Test-Path "$Global:Destiny\$HOSTNAME\Persistence\$u") ) { New-Item -ItemType Directory -Path "$Global:Destiny\$HOSTNAME\Persistence\$u" > $null }    

                try
                {
                    cmd.exe /c copy "$Global:Source\Users\$u\AppData\Roaming\Microsoft\Templates\Normal.dotm" "$Global:Destiny\$HOSTNAME\Persistence\$u" > $null
                }
                catch
                {
                    Report-Error -evidence "Persistence - Word template from user $u"
                }
            }

            if( Test-Path "$Global:Source\Users\$u\AppData\Roaming\Microsoft\Excel\XLSTART\PERSONAL.XLSB")
            {
                if( -not (Test-Path "$Global:Destiny\$HOSTNAME\Persistence\$u") ) { New-Item -ItemType Directory -Path "$Global:Destiny\$HOSTNAME\Persistence\$u" > $null }    

                try
                {
                    cmd.exe /c copy "$Global:Source\Users\$u\AppData\Roaming\Microsoft\Excel\XLSTART\PERSONAL.XLSB" "$Global:Destiny\$HOSTNAME\Persistence\$u" > $null
                }
                catch
                {
                    Report-Error -evidence "Persistence - Excel template from user $u"
                }
            }
        }


        # Change Default File Association - https://attack.mitre.org/techniques/T1042/
        # https://fileinfo.com/extension/bat
        if(Test-Path "REGISTRY::HKEY_CLASSES_ROOT\batfile\shell\open\command") {
            echo "BAT files:"                                                                                      > "$Global:Destiny\$HOSTNAME\Persistence\Persistence_FileAssociation.txt"
            Get-Item -Path "REGISTRY::HKEY_CLASSES_ROOT\batfile\shell\edit\command"                                >> "$Global:Destiny\$HOSTNAME\Persistence\Persistence_FileAssociation.txt"
            Get-Item -Path "REGISTRY::HKEY_CLASSES_ROOT\batfile\shell\open\command"                                >> "$Global:Destiny\$HOSTNAME\Persistence\Persistence_FileAssociation.txt"
            Get-Item -Path "REGISTRY::HKEY_CLASSES_ROOT\batfile\shell\print\command"                               >> "$Global:Destiny\$HOSTNAME\Persistence\Persistence_FileAssociation.txt"
            Get-Item -Path "REGISTRY::HKEY_CLASSES_ROOT\batfile\shell\runas\command"                               >> "$Global:Destiny\$HOSTNAME\Persistence\Persistence_FileAssociation.txt"
        }
        if(Test-Path "REGISTRY::HKEY_LOCAL_MACHINE\software\Classes\batfile\shell\open\command") {
            Get-Item -Path "REGISTRY::HKEY_LOCAL_MACHINE\software\Classes\batfile\shell\edit\command"              >> "$Global:Destiny\$HOSTNAME\Persistence\Persistence_FileAssociation.txt"
            Get-Item -Path "REGISTRY::HKEY_LOCAL_MACHINE\software\Classes\batfile\shell\open\command"              >> "$Global:Destiny\$HOSTNAME\Persistence\Persistence_FileAssociation.txt"
            Get-Item -Path "REGISTRY::HKEY_LOCAL_MACHINE\software\Classes\batfile\shell\print\command"             >> "$Global:Destiny\$HOSTNAME\Persistence\Persistence_FileAssociation.txt"
            Get-Item -Path "REGISTRY::HKEY_LOCAL_MACHINE\software\Classes\batfile\shell\runas\command"             >> "$Global:Destiny\$HOSTNAME\Persistence\Persistence_FileAssociation.txt"
        }
        
        # https://fileinfo.com/extension/cmd
        if(Test-Path "REGISTRY::HKEY_CLASSES_ROOT\cmdfile\shell\open\command") {
            echo "CMD files:"                                                                                      >> "$Global:Destiny\$HOSTNAME\Persistence\Persistence_FileAssociation.txt"
            Get-Item -Path "REGISTRY::HKEY_CLASSES_ROOT\cmdfile\shell\edit\command"                                >> "$Global:Destiny\$HOSTNAME\Persistence\Persistence_FileAssociation.txt"
            Get-Item -Path "REGISTRY::HKEY_CLASSES_ROOT\cmdfile\shell\open\command"                                >> "$Global:Destiny\$HOSTNAME\Persistence\Persistence_FileAssociation.txt"
            Get-Item -Path "REGISTRY::HKEY_CLASSES_ROOT\cmdfile\shell\print\command"                               >> "$Global:Destiny\$HOSTNAME\Persistence\Persistence_FileAssociation.txt"
            Get-Item -Path "REGISTRY::HKEY_CLASSES_ROOT\cmdfile\shell\runas\command"                               >> "$Global:Destiny\$HOSTNAME\Persistence\Persistence_FileAssociation.txt"
        }
        if(Test-Path "REGISTRY::HKEY_LOCAL_MACHINE\software\Classes\cmdfile\shell\open\command") {
            Get-Item -Path "REGISTRY::HKEY_LOCAL_MACHINE\software\Classes\cmdfile\shell\edit\command"              >> "$Global:Destiny\$HOSTNAME\Persistence\Persistence_FileAssociation.txt"
            Get-Item -Path "REGISTRY::HKEY_LOCAL_MACHINE\software\Classes\cmdfile\shell\open\command"              >> "$Global:Destiny\$HOSTNAME\Persistence\Persistence_FileAssociation.txt"
            Get-Item -Path "REGISTRY::HKEY_LOCAL_MACHINE\software\Classes\cmdfile\shell\print\command"             >> "$Global:Destiny\$HOSTNAME\Persistence\Persistence_FileAssociation.txt"
            Get-Item -Path "REGISTRY::HKEY_LOCAL_MACHINE\software\Classes\cmdfile\shell\runas\command"             >> "$Global:Destiny\$HOSTNAME\Persistence\Persistence_FileAssociation.txt"
        }
        
        # https://fileinfo.com/extension/com
        if(Test-Path "REGISTRY::HKEY_CLASSES_ROOT\comfile\shell\open\command") {
            echo "COM files:"                                                                                      >> "$Global:Destiny\$HOSTNAME\Persistence\Persistence_FileAssociation.txt"
            Get-Item -Path "REGISTRY::HKEY_CLASSES_ROOT\comfile\shell\open\command"                                >> "$Global:Destiny\$HOSTNAME\Persistence\Persistence_FileAssociation.txt"
        }
        if(Test-Path "REGISTRY::HKEY_LOCAL_MACHINE\software\Classes\comfile\shell\open\command") {
            Get-Item -Path "REGISTRY::HKEY_LOCAL_MACHINE\software\Classes\comfile\shell\open\command"              >> "$Global:Destiny\$HOSTNAME\Persistence\Persistence_FileAssociation.txt"
        }
        
        # https://fileinfo.com/extension/exe
        if(Test-Path "REGISTRY::HKEY_CLASSES_ROOT\exefile\shell\open\command") {
            echo "EXE files:"                                                                                      >> "$Global:Destiny\$HOSTNAME\Persistence\Persistence_FileAssociation.txt"
            Get-Item -Path "REGISTRY::HKEY_CLASSES_ROOT\exefile\shell\open\command"                                >> "$Global:Destiny\$HOSTNAME\Persistence\Persistence_FileAssociation.txt"
            Get-Item -Path "REGISTRY::HKEY_CLASSES_ROOT\exefile\shell\runas\command"                               >> "$Global:Destiny\$HOSTNAME\Persistence\Persistence_FileAssociation.txt"
        }
        if(Test-Path "REGISTRY::HKEY_LOCAL_MACHINE\software\Classes\exefile\shell\open\command") {
            Get-Item -Path "REGISTRY::HKEY_LOCAL_MACHINE\software\Classes\exefile\shell\open\command"              >> "$Global:Destiny\$HOSTNAME\Persistence\Persistence_FileAssociation.txt"
            Get-Item -Path "REGISTRY::HKEY_LOCAL_MACHINE\software\Classes\exefile\shell\runas\command"             >> "$Global:Destiny\$HOSTNAME\Persistence\Persistence_FileAssociation.txt"
        }
        
        # https://fileinfo.com/extension/hta
        if(Test-Path "REGISTRY::HKEY_CLASSES_ROOT\htafile\shell\open\command") {
            echo "HTA files:"                                                                                      >> "$Global:Destiny\$HOSTNAME\Persistence\Persistence_FileAssociation.txt"
            Get-Item -Path "REGISTRY::HKEY_CLASSES_ROOT\htafile\shell\open\command"                                >> "$Global:Destiny\$HOSTNAME\Persistence\Persistence_FileAssociation.txt"
        }
        if(Test-Path "REGISTRY::HKEY_LOCAL_MACHINE\SOFTWARE\Classes\htafile\Shell\Open\Command") {
            Get-Item -Path "REGISTRY::HKEY_LOCAL_MACHINE\SOFTWARE\Classes\htafile\Shell\Open\Command"              >> "$Global:Destiny\$HOSTNAME\Persistence\Persistence_FileAssociation.txt"
        }
        
        if(Test-Path "REGISTRY::HKEY_CLASSES_ROOT\https\shell\open\command") {
            echo "HTTPS:"                                                                                          >> "$Global:Destiny\$HOSTNAME\Persistence\Persistence_FileAssociation.txt"
            Get-Item -Path "REGISTRY::HKEY_CLASSES_ROOT\https\shell\open\command"                                  >> "$Global:Destiny\$HOSTNAME\Persistence\Persistence_FileAssociation.txt"
        }
        if(Test-Path "REGISTRY::HKEY_LOCAL_MACHINE\SOFTWARE\Classes\https\Shell\Open\Command") {
            Get-Item -Path "REGISTRY::HKEY_LOCAL_MACHINE\SOFTWARE\Classes\https\Shell\Open\Command"                >> "$Global:Destiny\$HOSTNAME\Persistence\Persistence_FileAssociation.txt"
        }

        if(Test-Path "REGISTRY::HKEY_CLASSES_ROOT\http\shell\open\command") {
            echo "HTTP:"                                                                                           >> "$Global:Destiny\$HOSTNAME\Persistence\Persistence_FileAssociation.txt"
            Get-Item -Path "REGISTRY::HKEY_CLASSES_ROOT\http\shell\open\command"                                   >> "$Global:Destiny\$HOSTNAME\Persistence\Persistence_FileAssociation.txt"
        }
        if(Test-Path "REGISTRY::HKEY_LOCAL_MACHINE\SOFTWARE\Classes\http\Shell\Open\Command") {
            Get-Item -Path "REGISTRY::HKEY_LOCAL_MACHINE\SOFTWARE\Classes\http\Shell\Open\Command"                 >> "$Global:Destiny\$HOSTNAME\Persistence\Persistence_FileAssociation.txt"
        }
        
        # https://fileinfo.com/extension/jse
        if(Test-Path "REGISTRY::HKEY_CLASSES_ROOT\JSEfile\shell\open\command") {
            echo "JSE file:"                                                                                       >> "$Global:Destiny\$HOSTNAME\Persistence\Persistence_FileAssociation.txt"
            Get-Item -Path "REGISTRY::HKEY_CLASSES_ROOT\JSEfile\shell\edit\command"                                >> "$Global:Destiny\$HOSTNAME\Persistence\Persistence_FileAssociation.txt"
            Get-Item -Path "REGISTRY::HKEY_CLASSES_ROOT\JSEfile\shell\open\command"                                >> "$Global:Destiny\$HOSTNAME\Persistence\Persistence_FileAssociation.txt"
            Get-Item -Path "REGISTRY::HKEY_CLASSES_ROOT\JSEfile\shell\open2\command"                               >> "$Global:Destiny\$HOSTNAME\Persistence\Persistence_FileAssociation.txt"
            Get-Item -Path "REGISTRY::HKEY_CLASSES_ROOT\JSEfile\shell\print\command"                               >> "$Global:Destiny\$HOSTNAME\Persistence\Persistence_FileAssociation.txt"
        }
        if(Test-Path "REGISTRY::HKEY_LOCAL_MACHINE\SOFTWARE\Classes\JSEfile\Shell\open\Command") {
            Get-Item -Path "REGISTRY::HKEY_LOCAL_MACHINE\SOFTWARE\Classes\JSEfile\Shell\edit\Command"              >> "$Global:Destiny\$HOSTNAME\Persistence\Persistence_FileAssociation.txt"
            Get-Item -Path "REGISTRY::HKEY_LOCAL_MACHINE\SOFTWARE\Classes\JSEfile\Shell\open\Command"              >> "$Global:Destiny\$HOSTNAME\Persistence\Persistence_FileAssociation.txt"
            Get-Item -Path "REGISTRY::HKEY_LOCAL_MACHINE\SOFTWARE\Classes\JSEfile\Shell\open2\Command"             >> "$Global:Destiny\$HOSTNAME\Persistence\Persistence_FileAssociation.txt"
            Get-Item -Path "REGISTRY::HKEY_LOCAL_MACHINE\SOFTWARE\Classes\JSEfile\Shell\print\Command"             >> "$Global:Destiny\$HOSTNAME\Persistence\Persistence_FileAssociation.txt"
        }
        
        # https://fileinfo.com/extension/pif
        if(Test-Path "REGISTRY::HKEY_CLASSES_ROOT\piffile\shell\open\command") {
            echo "PIF file:"                                                                                       >> "$Global:Destiny\$HOSTNAME\Persistence\Persistence_FileAssociation.txt"
            Get-Item -Path "REGISTRY::HKEY_CLASSES_ROOT\piffile\shell\open\command"                                >> "$Global:Destiny\$HOSTNAME\Persistence\Persistence_FileAssociation.txt"
        }
        if(Test-Path "REGISTRY::HKEY_LOCAL_MACHINE\software\Classes\piffile\shell\open\command") {
            Get-Item -Path "REGISTRY::HKEY_LOCAL_MACHINE\software\Classes\piffile\shell\open\command"              >> "$Global:Destiny\$HOSTNAME\Persistence\Persistence_FileAssociation.txt"
        }
        
        # https://fileinfo.com/extension/reg
        if(Test-Path "REGISTRY::HKEY_CLASSES_ROOT\regfile\shell\open\command") {
            echo "REG file:"                                                                                       >> "$Global:Destiny\$HOSTNAME\Persistence\Persistence_FileAssociation.txt"
            Get-Item -Path "REGISTRY::HKEY_CLASSES_ROOT\regfile\shell\edit\command"                                >> "$Global:Destiny\$HOSTNAME\Persistence\Persistence_FileAssociation.txt"
            Get-Item -Path "REGISTRY::HKEY_CLASSES_ROOT\regfile\shell\open\command"                                >> "$Global:Destiny\$HOSTNAME\Persistence\Persistence_FileAssociation.txt"
            Get-Item -Path "REGISTRY::HKEY_CLASSES_ROOT\regfile\shell\print\command"                               >> "$Global:Destiny\$HOSTNAME\Persistence\Persistence_FileAssociation.txt"
        }
        if(Test-Path "REGISTRY::HKEY_LOCAL_MACHINE\software\Classes\regfile\shell\open\command") {
            Get-Item -Path "REGISTRY::HKEY_LOCAL_MACHINE\software\Classes\regfile\shell\edit\command"              >> "$Global:Destiny\$HOSTNAME\Persistence\Persistence_FileAssociation.txt"
            Get-Item -Path "REGISTRY::HKEY_LOCAL_MACHINE\software\Classes\regfile\shell\open\command"              >> "$Global:Destiny\$HOSTNAME\Persistence\Persistence_FileAssociation.txt"
            Get-Item -Path "REGISTRY::HKEY_LOCAL_MACHINE\software\Classes\regfile\shell\print\command"             >> "$Global:Destiny\$HOSTNAME\Persistence\Persistence_FileAssociation.txt"
        }
        
        # https://fileinfo.com/extension/scr
        if(Test-Path "REGISTRY::HKEY_CLASSES_ROOT\scrfile\shell\open\command") {
            echo "SCR file:"                                                                                       >> "$Global:Destiny\$HOSTNAME\Persistence\Persistence_FileAssociation.txt"
            Get-Item -Path "REGISTRY::HKEY_CLASSES_ROOT\scrfile\shell\config\command"                              >> "$Global:Destiny\$HOSTNAME\Persistence\Persistence_FileAssociation.txt"
            Get-Item -Path "REGISTRY::HKEY_CLASSES_ROOT\scrfile\shell\install\command"                             >> "$Global:Destiny\$HOSTNAME\Persistence\Persistence_FileAssociation.txt"
            Get-Item -Path "REGISTRY::HKEY_CLASSES_ROOT\scrfile\shell\open\command"                                >> "$Global:Destiny\$HOSTNAME\Persistence\Persistence_FileAssociation.txt"
        }
        if(Test-Path "REGISTRY::HKEY_LOCAL_MACHINE\software\Classes\scrfile\shell\open\command") {
            Get-Item -Path "REGISTRY::HKEY_LOCAL_MACHINE\software\Classes\scrfile\shell\config\command"            >> "$Global:Destiny\$HOSTNAME\Persistence\Persistence_FileAssociation.txt"
            Get-Item -Path "REGISTRY::HKEY_LOCAL_MACHINE\software\Classes\scrfile\shell\install\command"           >> "$Global:Destiny\$HOSTNAME\Persistence\Persistence_FileAssociation.txt"
            Get-Item -Path "REGISTRY::HKEY_LOCAL_MACHINE\software\Classes\scrfile\shell\open\command"              >> "$Global:Destiny\$HOSTNAME\Persistence\Persistence_FileAssociation.txt"
        }
        
        # https://fileinfo.com/extension/txt
        if(Test-Path "REGISTRY::HKEY_CLASSES_ROOT\txtfile\shell\open\command") {
            echo "TXT file:"                                                                                       >> "$Global:Destiny\$HOSTNAME\Persistence\Persistence_FileAssociation.txt"
            Get-Item -Path "REGISTRY::HKEY_CLASSES_ROOT\txtfile\shell\open\command"                                >> "$Global:Destiny\$HOSTNAME\Persistence\Persistence_FileAssociation.txt"
            Get-Item -Path "REGISTRY::HKEY_CLASSES_ROOT\txtfile\shell\print\command"                               >> "$Global:Destiny\$HOSTNAME\Persistence\Persistence_FileAssociation.txt"
            Get-Item -Path "REGISTRY::HKEY_CLASSES_ROOT\txtfile\shell\printto\command"                             >> "$Global:Destiny\$HOSTNAME\Persistence\Persistence_FileAssociation.txt"
        }
        if(Test-Path "REGISTRY::HKEY_LOCAL_MACHINE\software\Classes\txtfile\shell\open\command") {
            Get-Item -Path "REGISTRY::HKEY_LOCAL_MACHINE\software\Classes\txtfile\shell\open\command"              >> "$Global:Destiny\$HOSTNAME\Persistence\Persistence_FileAssociation.txt"
            Get-Item -Path "REGISTRY::HKEY_LOCAL_MACHINE\software\Classes\txtfile\shell\print\command"             >> "$Global:Destiny\$HOSTNAME\Persistence\Persistence_FileAssociation.txt"
            Get-Item -Path "REGISTRY::HKEY_LOCAL_MACHINE\software\Classes\txtfile\shell\printto\command"           >> "$Global:Destiny\$HOSTNAME\Persistence\Persistence_FileAssociation.txt"
        }
        
        # https://fileinfo.com/extension/vbs
        if(Test-Path "REGISTRY::HKEY_CLASSES_ROOT\VBSfile\shell\open\command") {
            echo "VBS file:"                                                                                       >> "$Global:Destiny\$HOSTNAME\Persistence\Persistence_FileAssociation.txt"
            Get-Item -Path "REGISTRY::HKEY_CLASSES_ROOT\vbsfile\shell\edit\command"                                >> "$Global:Destiny\$HOSTNAME\Persistence\Persistence_FileAssociation.txt"
            Get-Item -Path "REGISTRY::HKEY_CLASSES_ROOT\vbsfile\shell\open\command"                                >> "$Global:Destiny\$HOSTNAME\Persistence\Persistence_FileAssociation.txt"
            Get-Item -Path "REGISTRY::HKEY_CLASSES_ROOT\vbsfile\shell\open2\command"                               >> "$Global:Destiny\$HOSTNAME\Persistence\Persistence_FileAssociation.txt"
            Get-Item -Path "REGISTRY::HKEY_CLASSES_ROOT\vbsfile\shell\print\command"                               >> "$Global:Destiny\$HOSTNAME\Persistence\Persistence_FileAssociation.txt"
        }
        if(Test-Path "REGISTRY::HKEY_LOCAL_MACHINE\software\Classes\vbsfile\shell\open\command") {
            Get-Item -Path "REGISTRY::HKEY_LOCAL_MACHINE\software\Classes\vbsfile\shell\edit\command"              >> "$Global:Destiny\$HOSTNAME\Persistence\Persistence_FileAssociation.txt"
            Get-Item -Path "REGISTRY::HKEY_LOCAL_MACHINE\software\Classes\vbsfile\shell\open\command"              >> "$Global:Destiny\$HOSTNAME\Persistence\Persistence_FileAssociation.txt"
            Get-Item -Path "REGISTRY::HKEY_LOCAL_MACHINE\software\Classes\vbsfile\shell\open2\command"             >> "$Global:Destiny\$HOSTNAME\Persistence\Persistence_FileAssociation.txt"
            Get-Item -Path "REGISTRY::HKEY_LOCAL_MACHINE\software\Classes\vbsfile\shell\print\command"             >> "$Global:Destiny\$HOSTNAME\Persistence\Persistence_FileAssociation.txt"
        }

        # https://fileinfo.com/extension/vbe
        if(Test-Path "REGISTRY::HKEY_CLASSES_ROOT\VBEfile\shell\open\command") {
            echo "VBE file:"                                                                                       >> "$Global:Destiny\$HOSTNAME\Persistence\Persistence_FileAssociation.txt"
            Get-Item -Path "REGISTRY::HKEY_CLASSES_ROOT\vbefile\shell\edit\command"                                >> "$Global:Destiny\$HOSTNAME\Persistence\Persistence_FileAssociation.txt"
            Get-Item -Path "REGISTRY::HKEY_CLASSES_ROOT\vbefile\shell\open\command"                                >> "$Global:Destiny\$HOSTNAME\Persistence\Persistence_FileAssociation.txt"
            Get-Item -Path "REGISTRY::HKEY_CLASSES_ROOT\vbefile\shell\open2\command"                               >> "$Global:Destiny\$HOSTNAME\Persistence\Persistence_FileAssociation.txt"
            Get-Item -Path "REGISTRY::HKEY_CLASSES_ROOT\vbefile\shell\print\command"                               >> "$Global:Destiny\$HOSTNAME\Persistence\Persistence_FileAssociation.txt"
        }
        if(Test-Path "REGISTRY::HKEY_LOCAL_MACHINE\software\Classes\vbefile\shell\open\command") {
            Get-Item -Path "REGISTRY::HKEY_LOCAL_MACHINE\software\Classes\vbefile\shell\edit\command"              >> "$Global:Destiny\$HOSTNAME\Persistence\Persistence_FileAssociation.txt"
            Get-Item -Path "REGISTRY::HKEY_LOCAL_MACHINE\software\Classes\vbefile\shell\open\command"              >> "$Global:Destiny\$HOSTNAME\Persistence\Persistence_FileAssociation.txt"
            Get-Item -Path "REGISTRY::HKEY_LOCAL_MACHINE\software\Classes\vbefile\shell\open2\command"             >> "$Global:Destiny\$HOSTNAME\Persistence\Persistence_FileAssociation.txt"
            Get-Item -Path "REGISTRY::HKEY_LOCAL_MACHINE\software\Classes\vbefile\shell\print\command"             >> "$Global:Destiny\$HOSTNAME\Persistence\Persistence_FileAssociation.txt"
        }
        
        # https://fileinfo.com/extension/wsf
        if(Test-Path "REGISTRY::HKEY_CLASSES_ROOT\WSFfile\shell\open\command") {
            echo "WSF file:"                                                                                       >> "$Global:Destiny\$HOSTNAME\Persistence\Persistence_FileAssociation.txt"
            Get-Item -Path "REGISTRY::HKEY_CLASSES_ROOT\wsffile\shell\edit\command"                                >> "$Global:Destiny\$HOSTNAME\Persistence\Persistence_FileAssociation.txt"
            Get-Item -Path "REGISTRY::HKEY_CLASSES_ROOT\wsffile\shell\open\command"                                >> "$Global:Destiny\$HOSTNAME\Persistence\Persistence_FileAssociation.txt"
            Get-Item -Path "REGISTRY::HKEY_CLASSES_ROOT\wsffile\shell\open2\command"                               >> "$Global:Destiny\$HOSTNAME\Persistence\Persistence_FileAssociation.txt"
            Get-Item -Path "REGISTRY::HKEY_CLASSES_ROOT\wsffile\shell\print\command"                               >> "$Global:Destiny\$HOSTNAME\Persistence\Persistence_FileAssociation.txt"
        }
        if(Test-Path "REGISTRY::HKEY_LOCAL_MACHINE\software\Classes\WSFfile\shell\open\command") {
            Get-Item -Path "REGISTRY::HKEY_LOCAL_MACHINE\software\Classes\wsffile\shell\edit\command"              >> "$Global:Destiny\$HOSTNAME\Persistence\Persistence_FileAssociation.txt"
            Get-Item -Path "REGISTRY::HKEY_LOCAL_MACHINE\software\Classes\wsffile\shell\open\command"              >> "$Global:Destiny\$HOSTNAME\Persistence\Persistence_FileAssociation.txt"
            Get-Item -Path "REGISTRY::HKEY_LOCAL_MACHINE\software\Classes\wsffile\shell\open2\command"             >> "$Global:Destiny\$HOSTNAME\Persistence\Persistence_FileAssociation.txt"
            Get-Item -Path "REGISTRY::HKEY_LOCAL_MACHINE\software\Classes\wsffile\shell\print\command"             >> "$Global:Destiny\$HOSTNAME\Persistence\Persistence_FileAssociation.txt"
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

        # TODO:
            # Accessility Features - https://attack.mitre.org/techniques/T1015/
            # On-Screen Keyboard: C:\Windows\System32\osk.exe
            # Magnifier: C:\Windows\System32\Magnify.exe
            # Narrator: C:\Windows\System32\Narrator.exe
            # Display Switcher: C:\Windows\System32\DisplaySwitch.exe
            # App Switcher: C:\Windows\System32\AtBroker.exe
            # utilman.exe

            # others - https://threatvector.cylance.com/en_us/home/windows-registry-persistence-part-2-the-run-keys-and-search-order.html
            # HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\BootExecute 
            # HKLM\System\CurrentControlSet\Services TODO: Implement a list that shows all drivers that start before Kernel initialization that have value 0, maybe hash files and send them to VT
            # HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\ShellServiceObjectDelayLoad
            # HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run
            # HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run
            # HKCU\Software\Microsoft\Windows NT\CurrentVersion\Windows\load
            # HKLM\Software\Microsoft\Windows NT\CurrentVersion\Windows
            # HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\SharedTaskScheduler

    } catch {
        Report-Error -evidence "Persistence"
    }
}

<########### U S B   I N F O #######################> # USB*
Function Collect-USB-Info {
 
    # TODO: https://blogs.sans.org/computer-forensics/files/2009/09/USBKEY-Guide.pdf (page 3 win7) 
    # TODO: Cross with this: HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows Portable Devices\Devices

    if ( -Not ( Test-Path $Global:Destiny\$HOSTNAME\USB_PnPDevices ) ) { New-Item -ItemType directory -Path $Global:Destiny\$HOSTNAME\USB_PnPDevices > $null }
 
    try{
        Write-Host "[+] Collecting USB Info ..." -ForegroundColor Green
        
        if( Test-Path -Path "HKLM:\SYSTEM\CurrentControlSet\Enum\USB")
        {
            echo "RESUME: "                                                                                                       > "$Global:Destiny\$HOSTNAME\USB_PnPDevices\USB.txt"
            Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Enum\USB\*\*" | Select-Object FriendlyName, DeviceDesc, Mfg    >> "$Global:Destiny\$HOSTNAME\USB_PnPDevices\USB.txt" 2> $null

            echo "DETAILED: "                                                                                                     >> "$Global:Destiny\$HOSTNAME\USB_PnPDevices\USB.txt"
            Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Enum\USB\*\*"                                                  >> "$Global:Destiny\$HOSTNAME\USB_PnPDevices\USB.txt" 2> $null
        }


        if( Test-Path -Path "HKLM:\SYSTEM\CurrentControlSet\Enum\USBSTOR")
        {
            echo "RESUME: "                                                                                                            > "$Global:Destiny\$HOSTNAME\USB_PnPDevices\USBSTOR.txt"
            Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Enum\USBSTOR\*\*" | Select-Object FriendlyName, DeviceDesc, Mfg     >> "$Global:Destiny\$HOSTNAME\USB_PnPDevices\USBSTOR.txt" 2> $null

            echo "DETAILED: "                                                                                                          >> "$Global:Destiny\$HOSTNAME\USB_PnPDevices\USBSTOR.txt"
            Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Enum\USBSTOR\*\*"                                                   >> "$Global:Destiny\$HOSTNAME\USB_PnPDevices\USBSTOR.txt" 2> $null
        }

        echo "RESUME: "                                                                                                                      > "$Global:Destiny\$HOSTNAME\USB_PnPDevices\USBControllerDevice.txt"
        Get-WmiObject Win32_USBControllerDevice | Foreach-Object { [Wmi]$_.Dependent } | Select-Object Caption, PNPClass, Present, Status    >> "$Global:Destiny\$HOSTNAME\USB_PnPDevices\USBControllerDevice.txt" 2> $null
            
        echo "DETAILED: "                                                                                                                    >> "$Global:Destiny\$HOSTNAME\USB_PnPDevices\USBControllerDevice.txt"
        Get-WmiObject Win32_USBControllerDevice | Foreach-Object { [Wmi]$_.Dependent }                                                       >> "$Global:Destiny\$HOSTNAME\USB_PnPDevices\USBControllerDevice.txt" 2> $null

    } catch {
        Report-Error -evidence "USB info"
    }
}

<########### D E V I C E S   I N F O ###############> # PNP*
Function Collect-PnPDevices-Info {

    if ( -Not ( Test-Path "$Global:Destiny\$HOSTNAME\USB_PnPDevices" ) ) { New-Item -ItemType directory -Path "$Global:Destiny\$HOSTNAME\USB_PnPDevices" > $null }

    Write-Host "[+] Collecting Plug and Play Devices Info ..." -ForegroundColor Green
    try
    {
        echo "Devices Resume: "                                                                     > "$Global:Destiny\$HOSTNAME\USB_PnPDevices\PnP_Devices.txt"
        Get-PnpDevice | Select-Object Class, FriendlyName, InstanceID | Sort-Object Class          >> "$Global:Destiny\$HOSTNAME\USB_PnPDevices\PnP_Devices.txt"
        echo "Devices Details: "                                                                   >> "$Global:Destiny\$HOSTNAME\USB_PnPDevices\PnP_Devices.txt"
        Get-PnpDevice | Select-Object * | Sort-Object Class                                        >> "$Global:Destiny\$HOSTNAME\USB_PnPDevices\PnP_Devices.txt"
        echo "Devices Deep Details: "                                                              >> "$Global:Destiny\$HOSTNAME\USB_PnPDevices\PnP_Devices.txt" 
        Get-PnpDevice | Select-Object InstanceId | ForEach-Object {
            echo $_.Name                                                                           >> "$Global:Destiny\$HOSTNAME\USB_PnPDevices\PnP_Devices.txt"
            Get-PnpDeviceProperty -InstanceId $_.instanceID | Sort-Object type                     >> "$Global:Destiny\$HOSTNAME\USB_PnPDevices\PnP_Devices.txt"
        }
    } 
    catch 
    {
        Report-Error -evidence "Devices Info"
    }
}

<########### F I R E W A L L   C O N F . ###########> # SEC*
Function Collect-Firewall-Config{

    if ( -Not ( Test-Path $Global:Destiny\$HOSTNAME\Firewall ) ) { New-Item -ItemType directory -Path $Global:Destiny\$HOSTNAME\Firewall > $null }

    try{
        Write-Host "[+] Collecting Firewall Configuration Info... " -ForegroundColor Green
        Get-NetFirewallProfile | Select-Object *           >> "$Global:Destiny\$HOSTNAME\Firewall\FW_Profiles.txt"
        Get-NetFirewallSetting | Select-Object *           >> "$Global:Destiny\$HOSTNAME\Firewall\FW_Settings.txt"
        Get-NetFirewallRule                                | Export-Csv "$Global:Destiny\$HOSTNAME\Firewall\FW_Rules.csv"
        
        if($OS -eq "XP") {
            Get-ItemProperty "REGISTRY::HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Action Center" > "$Global:Destiny\$HOSTNAME\Firewall\HKLM_ActionCenter.txt"
        } <# TODO: Review in a XP environment #>
        
       
    } catch {
        Report-Error -evidence "Firewall Information"
    }
}

##########################################################################################################

<########### M R U s ###############################> # MRU*
Function Collect-MRUs {

    Write-Host "[+] Collecting MRU's ..." -ForegroundColor Green

    if( -not (Test-Path "$Global:Destiny\$HOSTNAME\MRUs\") ) { New-Item -ItemType Directory -Path "$Global:Destiny\$HOSTNAME\MRUs\" > $null }

    # MUI CACHE - HKEY_CURRENT_USER\Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\MuiCache | TODO: Collect without external tool
    Collect-MUICache
        
    # RECENT DOCS -  C:\Documents and Settings\[Profile]\Recent - C:\Users\[Profile]\Recent - HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\OpenSaveMRU | TODO: Collect without external tool
    Collect-RecentDocs1

    # RECENT DOCS -  NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs | TODO: Read subkeys that store info by extension
    # Same info as in C:\Users\[PROFILE]\Recent or C:\Users\[PROFILE]\AppData\Roaming\Microsoft\Windows\Recent
    Collect-RecentDocs2

    # COMDLG32 :: OpenSavePidlMRU - HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\OpenSaveMRU - HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\OpenSavePidlMRU | TODO: Collect without external tool
    Collect-OpenSavePidlMRU

    # Userassist - HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist
    Collect-UserAssist

    # ShellBags - HKEY_CURRENT_USER\Software\Microsoft\Windows\ShellNoRoam - HKEY_CURRENT_USER\Software\Microsoft\Windows\Shell - HKEY_CURRENT_USER\Software\Classes\Local Settings\Software\Microsoft\Windows\Shell 
    Collect-ShellBags

    # COMDLG32 :: CIDSizeMRU - NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\CIDSizeMRU
    Collect-CIDSizeMRU

    # COMDLG32 :: LastVisitedPidlMRU - NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\LastVisitedPidlMRU
    Collect-COMDLG32-LastVisitedPidlMRU

    # RUN DialogBox MRU
    Collect-RunDialogBoxMRU

    # SHIMCACHE
    Collect-Shimcache

    # RECENT APPS
    Collect-RecentApps
}


<########### MUI CACHE #############################> # N/A - Used with MRUs*
Function Collect-MUICache {
    
    Write-Host "`t○ Collecting MUICACHE" -ForegroundColor Green
    try
    {
        & "$SCRIPTPATH\bin\muicacheview\MUICacheView.exe" /shtml "$Global:Destiny\$HOSTNAME\MRUs\MuiCache.html"
    }
    catch
    {
        Report-Error -evidence "MUI CACHE"
    }
}

<########### RECENT DOCS - Third Party #############> # N/A - Used with MRUs*
Function Collect-RecentDocs1 {
    
    Write-Host "`t○ Collecting RECENT DOCS - Third Party Tool" -ForegroundColor Green
    try
    {
        & "$SCRIPTPATH\bin\recentfilesview\RecentFilesView.exe" /sort "~Modified Time" /shtml "$Global:Destiny\$HOSTNAME\MRUs\RecentDocs.html"
    }
    catch
    {
        Report-Error -evidence "RECENT DOCS"
    }
}

<########### RECENT DOCS ###########################> # N/A - Used with MRUs*
Function Collect-RecentDocs2 {
    
    foreach($SID in $SIDS)
    {

        if ($SID.Split("-")[7] -ne $null -and $SID.Split("-")[7] -notlike "*_Classes") # the ones that users removes the system and network and classes
        { 

            $N = Get-ItemPropertyValue -Path "REGISTRY::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\$SID\" -Name "ProfileImagePath"  # get's the name correspondent to the SID
            $NAME = $($N.Split("\")[2])

            if ( -Not ( Test-Path $Global:Destiny\$HOSTNAME\MRUs\$NAME ) ) { New-Item -ItemType directory -Path $Global:Destiny\$HOSTNAME\MRUs\$NAME > $null }
            
            Write-Host "`t○ Collecting RECENT DOCS from $NAME - From Registry" -ForegroundColor Green

            echo " " >> "$Global:Destiny\$HOSTNAME\MRUs\$NAME\RecentDocs.txt"
            echo "KEY: NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs" >> "$Global:Destiny\$HOSTNAME\MRUs\$NAME\RecentDocs.txt"
            echo "INFO: Identifies recently accessed documents by extension subkeys. Values in the main RecentDocs subkey lists the last 150 objects opened in order." >> "$Global:Destiny\$HOSTNAME\MRUs\$NAME\RecentDocs.txt"
            echo "INFO: Same info as in C:\Users\[PROFILE]\Recent or C:\Users\[PROFILE]\AppData\Roaming\Microsoft\Windows\Recent " >> "$Global:Destiny\$HOSTNAME\MRUs\$NAME\RecentDocs.txt"
            echo "INFO: This function overcomes a failure in Microsoft Explorer: the obove folders don't show any record after a deleted entry, this list does show" >> "$Global:Destiny\$HOSTNAME\MRUs\$NAME\RecentDocs.txt"
            echo " " >> "$Global:Destiny\$HOSTNAME\MRUs\$NAME\RecentDocs.txt"
            echo "More Info(page.20): https://www.syntricate.com/files/Registry%20Reference%20Guide%20AD%20100116.pdf" >> "$Global:Destiny\$HOSTNAME\MRUs\$NAME\RecentDocs.txt"
            echo " " >> "$Global:Destiny\$HOSTNAME\MRUs\$NAME\RecentDocs.txt"

            $list = Get-ItemPropertyValue "REGISTRY::HKEY_USERS\$SID\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs" -Name MRUListEx 2> $null # gets the list that has the order of las open

            $count = 0
            $n = 0
            foreach($pos in $list)
            {
                if( (($count % 4) -eq 0) -and (-not ($pos -eq 255)) )
                {
                
                    try
                    {
                        $entry = Get-ItemPropertyValue "REGISTRY::HKEY_USERS\$SID\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs" -Name $pos 2>$null
                    }
                    catch
                    {
                        $entry = "29A"
                    }

                    if($entry -like "29A") 
                    { 
                        $count++
                        continue 
                    }
            
                    $read=$true
                    $i = 0
                            
                    foreach($b in $entry)
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
                    echo "$n : $filename" >> "$Global:Destiny\$HOSTNAME\MRUs\$NAME\RecentDocs.txt"
                
                    $n++    
                
                }
                $filename = ""
                $entry = ""
                $count++
            }
        }
    }
}

<########### OpenSavePidlMRU #######################> # N/A - Used with MRUs*
Function Collect-OpenSavePidlMRU {
    
    Write-Host "`t○ Collecting OpenSavePidlMRU" -ForegroundColor Green
    try
    {
        & $OPEN_SAVED_FILES_VIEW /shtml "$Global:Destiny\$HOSTNAME\MRUs\OpenSavePidlMRU.html"
    }
    catch
    {
        Report-Error -evidence "COMDLG32 :: OpenSavePidlMRU"
    }
}

<########### USER ASSIST ###########################> # N/A - Used with MRUs*
Function Collect-UserAssist {
    
    Write-Host "`t○ Collecting User Assist ..." -ForegroundColor Green
    try
    {
        & "$SCRIPTPATH\bin\userassistview\UserAssistView.exe" /sort "~Modified Time" /shtml "$Global:Destiny\$HOSTNAME\MRUs\User_Assist.html"
    }
    catch
    {
        Report-Error -evidence "User Assist"
    }
}

<########### SHELLBAGS #############################> # N/A - Used with MRUs*
Function Collect-ShellBags {
    
    Write-Host "`t○ Collecting ShellBags ..." -ForegroundColor Green
    try
    {
        & "$SCRIPTPATH\bin\shellbagsview\ShellBagsView.exe" /sort "~Modified Time" /shtml "$Global:Destiny\$HOSTNAME\MRUs\ShellBags.html"
    }
    catch
    {
        Report-Error -evidence "ShellBags"
    }
}

<########### CID Size MRU ##########################> # N/A - Used with MRUs*
Function Collect-CIDSizeMRU {
 
    foreach($SID in $SIDS) # Instead of using current user, it iterates through the connected users to the system.
    {
        if(Test-Path -Path "REGISTRY::HKEY_USERS\$SID\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\CIDSizeMRU\")
        {
            if ($SID.Split("-")[7] -ne $null -and $SID.Split("-")[7] -notlike "*_Classes") # the ones that are users, removes the system, network and classes
            { 
                $N = Get-ItemPropertyValue -Path "REGISTRY::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\$SID\" -Name "ProfileImagePath"  # get's the name correspondent to the SID
                $NAME = $($N.Split("\")[2])

                if ( -Not ( Test-Path $Global:Destiny\$HOSTNAME\MRUs\$NAME ) ) { New-Item -ItemType directory -Path $Global:Destiny\$HOSTNAME\MRUs\$NAME > $null }
            
                Write-Host "`t○ CIDSizeMRU from $NAME" -ForegroundColor Green

                echo " " >> "$Global:Destiny\$HOSTNAME\MRUs\$NAME\RecentUsedApps_CIDSizeMRU.txt"
                echo "KEY: NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\CIDSizeMRU" >> "$Global:Destiny\$HOSTNAME\MRUs\$NAME\RecentUsedApps_CIDSizeMRU.txt"
                echo "INFO: Tracks applications used to access documents using Dialog Box because this record is reponsible for the size of the Dialog Box." >> "$Global:Destiny\$HOSTNAME\MRUs\$NAME\RecentUsedApps_CIDSizeMRU.txt"
                echo " " >> "$Global:Destiny\$HOSTNAME\MRUs\$NAME\RecentUsedApps_CIDSizeMRU.txt"
                echo "More Info(page.10): https://www.syntricate.com/files/Registry%20Reference%20Guide%20AD%20100116.pdf" >> "$Global:Destiny\$HOSTNAME\MRUs\$NAME\RecentUsedApps_CIDSizeMRU.txt"
                echo "More Info: http://windowsir.blogspot.com/2013/07/howto-determine-program-execution.html" >> "$Global:Destiny\$HOSTNAME\MRUs\$NAME\RecentUsedApps_CIDSizeMRU.txt"
                echo " " >> "$Global:Destiny\$HOSTNAME\MRUs\$NAME\RecentUsedApps_CIDSizeMRU.txt"

                # TODO: Order the extraction of the data using the MRUListEx like it's implemented in "Collect-RecentDocs2"
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
                        echo "$filename" >> "$Global:Destiny\$HOSTNAME\MRUs\$NAME\RecentUsedApps_CIDSizeMRU.txt"
                        $filename = ""
                    } 
                    catch 
                    {
                            Report-Error -evidence "Collecting CIDSizeMRU"
                    }
                }
            }
        }
    }

}

<########### Last Visited Pidl MRU #################> # N/A - Used with MRUs*
Function Collect-COMDLG32-LastVisitedPidlMRU {
    
    foreach($SID in $SIDS) # Instead of using current user, it iterates through the connected users to the system.
    {
        if(Test-Path -Path "REGISTRY::HKEY_USERS\$SID\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\LastVisitedPidlMRU\")
        {   
            if ($SID.Split("-")[7] -ne $null -and $SID.Split("-")[7] -notlike "*_Classes") # the ones that are users, removes the system, network and classes
            { 
            $N = Get-ItemPropertyValue -Path "REGISTRY::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\$SID\" -Name "ProfileImagePath"  # get's the name correspondent to the SID
            $NAME = $($N.Split("\")[2])

            if ( -Not ( Test-Path $Global:Destiny\$HOSTNAME\MRUs\$NAME ) ) { New-Item -ItemType directory -Path $Global:Destiny\$HOSTNAME\MRUs\$NAME > $null }

            Write-Host "`t○ LastVisitedPidlMRU from $NAME" -ForegroundColor Green

            echo " "                                                                                                                 >> "$Global:Destiny\$HOSTNAME\MRUs\$NAME\RecentUsedApps_LastVisitedPidMRU.txt"
            echo "KEY: NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\LastVisitedPidlMRU"                    >> "$Global:Destiny\$HOSTNAME\MRUs\$NAME\RecentUsedApps_LastVisitedPidMRU.txt"
            echo "INFO: Tracks applications used to access documents. This is that have opened the Commom Dialog Box of windows."    >> "$Global:Destiny\$HOSTNAME\MRUs\$NAME\RecentUsedApps_LastVisitedPidMRU.txt"
            echo " "                                                                                                                 >> "$Global:Destiny\$HOSTNAME\MRUs\$NAME\RecentUsedApps_LastVisitedPidMRU.txt"
            echo "More Info(page.10): https://www.syntricate.com/files/Registry%20Reference%20Guide%20AD%20100116.pdf"               >> "$Global:Destiny\$HOSTNAME\MRUs\$NAME\RecentUsedApps_LastVisitedPidMRU.txt"
            echo "http://windowsir.blogspot.com/2013/07/howto-determine-user-access-to-files.html"                                   >> "$Global:Destiny\$HOSTNAME\MRUs\$NAME\RecentUsedApps_LastVisitedPidMRU.txt"
            echo " "                                                                                                                 >> "$Global:Destiny\$HOSTNAME\MRUs\$NAME\RecentUsedApps_LastVisitedPidMRU.txt"

            # TODO: Order the extraction of the data using the MRUListEx like it's implemented in "Collect-RecentDocs2"
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
                    echo "$filename" >> "$Global:Destiny\$HOSTNAME\MRUs\$NAME\RecentUsedApps_LastVisitedPidMRU.txt"
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

}

<########### RUN DialogBOX MRU #####################> # N/A - Used with MRUs*
Function Collect-RunDialogBoxMRU {
    foreach($SID in $SIDS) # Instead of using current user, it iterates through the connected users to the system.
    {

        if ($SID.Split("-")[7] -ne $null -and $SID.Split("-")[7] -notlike "*_Classes") # the ones that are users, removes the system, network and classes
        { 

            $N = Get-ItemPropertyValue -Path "REGISTRY::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\$SID\" -Name "ProfileImagePath"  # get's the name correspondent to the SID
            $NAME = $($N.Split("\")[2])

            if ( -Not ( Test-Path $Global:Destiny\$HOSTNAME\MRUs\$NAME ) ) { New-Item -ItemType directory -Path $Global:Destiny\$HOSTNAME\MRUs\$NAME > $null }

            # RUN MRU
            Write-Host "`t○ RunMRU from $NAME" -ForegroundColor Green

            echo " "                                                                                                    > "$Global:Destiny\$HOSTNAME\MRUs\$NAME\RunMRU.txt"
            echo "KEY: NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU"                           >> "$Global:Destiny\$HOSTNAME\MRUs\$NAME\RunMRU.txt"
            echo "INFO: Lists the most recent commands entered in the Windows Run Dialog Box."                         >> "$Global:Destiny\$HOSTNAME\MRUs\$NAME\RunMRU.txt"
            echo " "                                                                                                   >> "$Global:Destiny\$HOSTNAME\MRUs\$NAME\RunMRU.txt"
            echo "More Info(page.20): https://www.syntricate.com/files/Registry%20Reference%20Guide%20AD%20100116.pdf" >> "$Global:Destiny\$HOSTNAME\MRUs\$NAME\RunMRU.txt"
            echo " "                                                                                                   >> "$Global:Destiny\$HOSTNAME\MRUs\$NAME\RunMRU.txt"

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

<########### S H I M C A C H E #####################> # SHI - Used with MRUs*
Function Collect-Shimcache {
    #  [System.Text.Encoding]::Default.GetString((Get-ItemPropertyValue "REGISTRY::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache" -Name AppCompatCache))

    Write-Host "`t○ Collecting Shimcache Information ... " -ForegroundColor Green

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

<########### R E C E N T   A P P S #################> # RAP - Used with MRUs*
Function Collect-RecentApps {

    if($OS -eq "10")
    {
        foreach($SID in $SIDS)
        {
            if ($SID.Split("-")[7] -ne $null -and $SID.Split("-")[7] -notlike "*_Classes") # the ones that users removes the system and network and classes
            {
                $N = Get-ItemPropertyValue -Path "REGISTRY::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\$SID\" -Name "ProfileImagePath"  # get's the name correspondent to the SID
                $NAME = $($N.Split("\")[2])

                if ( -Not ( Test-Path "$Global:Destiny\$HOSTNAME\MRUs\$NAME" ) ) { New-Item -ItemType directory -Path "$Global:Destiny\$HOSTNAME\MRUs\$NAME" > $null }
                Write-Host "`t○ Collecting Recent Apps info from $NAME" -ForegroundColor Green

                if( Test-Path "REGISTRY::HKEY_USERS\$SID\Software\Microsoft\Windows\CurrentVersion\Search\RecentApps\")
                {
                    $RA_SID = Get-ChildItem "REGISTRY::HKEY_USERS\$SID\Software\Microsoft\Windows\CurrentVersion\Search\RecentApps\" | Select-Object -ExpandProperty Name | foreach { $_.split("\")[8] }

                    foreach($R in $RA_SID)
                    {
                        echo "---------------------------------------------------" >> "$Global:Destiny\$HOSTNAME\MRUs\$NAME\RecentApps.txt"
                        echo "---------------------------------------------------" >> "$Global:Destiny\$HOSTNAME\MRUs\$NAME\RecentApps.txt"
                        echo "SID: $R" >> "$Global:Destiny\$HOSTNAME\MRUs\$NAME\RecentApps.txt"
                        $tempAppId = Get-ItemPropertyValue "REGISTRY::HKEY_USERS\$SID\Software\Microsoft\Windows\CurrentVersion\Search\RecentApps\$R" -Name AppId
                        echo "AppID: $tempAppId"  >> "$Global:Destiny\$HOSTNAME\MRUs\$NAME\RecentApps.txt"
                        $tempLaunchCount = Get-ItemPropertyValue "REGISTRY::HKEY_USERS\$SID\Software\Microsoft\Windows\CurrentVersion\Search\RecentApps\$R" -Name LaunchCount
                        echo "LaunchCount: $tempLaunchCount"  >> "$Global:Destiny\$HOSTNAME\MRUs\$NAME\RecentApps.txt"
                        $tempAppPath = Get-ItemPropertyValue "REGISTRY::HKEY_USERS\$SID\Software\Microsoft\Windows\CurrentVersion\Search\RecentApps\$R" -Name AppPath
                        echo "AppPath: $tempAppPath"  >> "$Global:Destiny\$HOSTNAME\MRUs\$NAME\RecentApps.txt"
                        $tempDateDec = Get-ItemPropertyValue "REGISTRY::HKEY_USERS\$SID\Software\Microsoft\Windows\CurrentVersion\Search\RecentApps\$R"-Name LastAccessedTime
                        $tempDate = [datetime]::FromFileTime($tempDateDec)
                        echo "Date: $tempDate" >> "$Global:Destiny\$HOSTNAME\MRUs\$NAME\RecentApps.txt"
            
                        echo "--- Associated Files:" >> "$Global:Destiny\$HOSTNAME\MRUs\$NAME\RecentApps.txt"
            
                        if(Test-Path "REGISTRY::HKEY_USERS\$SID\Software\Microsoft\Windows\CurrentVersion\Search\RecentApps\$R\RecentItems")
                        {
                            $FILE_SID = Get-ChildItem "REGISTRY::HKEY_USERS\$SID\Software\Microsoft\Windows\CurrentVersion\Search\RecentApps\$R\RecentItems\" | Select-Object -ExpandProperty Name | foreach { $_.split("\")[10] }

                            foreach($F in $FILE_SID)
                            {
                                $tempName = Get-ItemPropertyValue "REGISTRY::HKEY_USERS\$SID\Software\Microsoft\Windows\CurrentVersion\Search\RecentApps\$R\RecentItems\$F" -Name DisplayName
                                echo "`tName: $tempName"  >> "$Global:Destiny\$HOSTNAME\MRUs\$NAME\RecentApps.txt"
                                $tempPath = Get-ItemPropertyValue "REGISTRY::HKEY_USERS\$SID\Software\Microsoft\Windows\CurrentVersion\Search\RecentApps\$R\RecentItems\$F" -Name Path
                                echo "`tPath: $tempPath"  >> "$Global:Destiny\$HOSTNAME\MRUs\$NAME\RecentApps.txt"
                                $tempDateDec = Get-ItemPropertyValue "REGISTRY::HKEY_USERS\$SID\Software\Microsoft\Windows\CurrentVersion\Search\RecentApps\$R\RecentItems\$F" -Name LastAccessedTime
                                $tempDate = [datetime]::FromFileTime($tempDateDec)
                                echo "`tDate: $tempDate" >> "$Global:Destiny\$HOSTNAME\MRUs\$NAME\RecentApps.txt"
                            }
                        }
                        else
                        {
                            echo "`tThis app doesn't have recent open files associated." >> "$Global:Destiny\$HOSTNAME\MRUs\$NAME\RecentApps.txt"
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

##########################################################################################################

<########### B A M #################################> # BAM*
Function Collect-BAM {
    
    # BAM - BACKGROUND ACTIVITY MODERATOR

    $avoidlist = "Version","SequenceNumber"

    if( Test-Path -Path "REGISTRY::HKLM\SYSTEM\CurrentControlSet\services\bam\") 
    {
        Write-Host "[+] Collecting BAM (Background Activiy Moderator) ..." -ForegroundColor Green

        if( -not (Test-Path "$Global:Destiny\$HOSTNAME\Execution") ) { New-Item -ItemType Directory -Path "$Global:Destiny\$HOSTNAME\Execution" > $null }    
        echo "UserSID,Username,Application,LastExecutionDate UTC, LastExecutionDate" > "$Global:Destiny\$HOSTNAME\Execution\BAM_LastExecutionDateApps.csv"

        $SIDs = Get-Item "REGISTRY::HKLM\SYSTEM\CurrentControlSet\Services\bam\UserSettings\*"  | foreach { 
            $_.Name.split("\")[-1] 
        }

        foreach($SID in $SIDs)
        {
            $USERNAME = Get-SIDUsername -sid $SID

            Write-Host "`t○ for user $USERNAME ..." -ForegroundColor Green
            
            $APPs = Get-Item "REGISTRY::HKLM\SYSTEM\CurrentControlSet\Services\bam\UserSettings\$SID\" | foreach{ 
                $_.Property 
            }
            
            foreach($APP in $APPs)
            {
                if((-not ($avoidlist -contains $APP))) # if not in the blacklist
                {
                    $RawDate = Get-ItemPropertyValue "REGISTRY::HKLM\SYSTEM\CurrentControlSet\Services\bam\UserSettings\$SID\" -Name $APP
                    $DateTimeOffset = [System.DateTimeOffset]::FromFileTime([System.BitConverter]::ToInt64($RawDate,0))
                    $LastExecutedDateUTC = $($DateTimeOffset.UtcDateTime)

                    $LastExecutedDateLocal = [datetime]::FromFileTime([System.BitConverter]::ToInt64($RawDate,0))

                    echo "$SID,$USERNAME,$APP,$LastExecutedDateUTC,$LastExecutedDateLocal" >> "$Global:Destiny\$HOSTNAME\Execution\BAM_LastExecutionDateApps.csv"
                }
            }
        }
    }
    else
    {
        Write-Host "[-] No BAM registry record found in the system ..." -ForegroundColor Yellow
    }

}

<########### S Y S T E M   I N F O #################> # SYS*
Function Collect-System-Info {    
    
    if ( -Not ( Test-Path $Global:Destiny\$HOSTNAME\System_Info\ ) ) { New-Item -ItemType directory -Path $Global:Destiny\$HOSTNAME\System_Info\ > $null }
    
    Write-Host "[+] Collecting Computer Info..." -ForegroundColor Green
    try
    {
        cmd.exe /c systeminfo                                                          > "$Global:Destiny\$HOSTNAME\System_Info\System_Info.txt"
        Get-CimInstance Win32_OperatingSystem | Select-Object *                        > "$Global:Destiny\$HOSTNAME\System_Info\Operating_System_Info.txt"
        Get-CimInstance -ClassName Win32_ComputerSystem | Select-Object *              > "$Global:Destiny\$HOSTNAME\System_Info\Computer_System_Info.txt"
        Get-HotFix | Select-Object HotFixID, Description, InstalledBy, InstalledOn     > "$Global:Destiny\$HOSTNAME\System_Info\Hot_Fixes_Info.txt"
    } 
    catch 
    {
        Report-Error -evidence "Computer Info"
    }

    # https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_environment_variables?view=powershell-6
    Write-Host "`t○ Environment Variables ..." -ForegroundColor Green
    try
    {
        echo ""                                    > "$Global:Destiny\$HOSTNAME\System_Info\Environment_Variables.txt"
        echo "Environment Valiables: "            >> "$Global:Destiny\$HOSTNAME\System_Info\Environment_Variables.txt"
        Get-ChildItem Env:                        >> "$Global:Destiny\$HOSTNAME\System_Info\Environment_Variables.txt"
        echo ""                                   >> "$Global:Destiny\$HOSTNAME\System_Info\Environment_Variables.txt"
        echo "Path: "                             >> "$Global:Destiny\$HOSTNAME\System_Info\Environment_Variables.txt"
        (Get-Item Env:\Path).Value                >> "$Global:Destiny\$HOSTNAME\System_Info\Environment_Variables.txt"
        echo ""                                   >> "$Global:Destiny\$HOSTNAME\System_Info\Environment_Variables.txt"
        echo "PowerShell Module Path: "           >> "$Global:Destiny\$HOSTNAME\System_Info\Environment_Variables.txt"
        (Get-Item Env:\PSModulePath).Value        >> "$Global:Destiny\$HOSTNAME\System_Info\Environment_Variables.txt"
    }
    catch
    {
        Report-Error -evidence "Environment Variables"
    }
}

<########### L A S T   A C T I V I T Y #############> # LAC*
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

<########### A L L   A U T O R U N   F I L E S #####> # AFI*
Function Collect-Autorun-Files {
    
    if( -not (Test-Path "$Global:Destiny\$HOSTNAME\Persistence\") ) { New-Item -ItemType Directory -Path "$Global:Destiny\$HOSTNAME\Persistence\" > $null }
    
    Write-Host "[+] Collecting Autorun Files ..." -ForegroundColor Green
    try
    {
        & cmd.exe /c $AUTORUNS -accepteula -a * -c -h -o "$Global:Destiny\$HOSTNAME\Persistence\Persistence_AutorunFiles.csv" -s -t -u -v -vt -nobanner
    }
    catch
    {
        Report-Error -evidence "Autorun Files"
    }
}


<##################################################################################################################################>
<############  LIVE OR OFFLINE SYSTEM  /  NO VOLATILE #############################################################################>
<##################################################################################################################################>


<########### H I V E S ###########################################################> # HIV*
Function Collect-Hives {

    if ( -Not ( Test-Path $Global:Destiny\$HOSTNAME\HIVES ) ) { New-Item -ItemType directory -Path $Global:Destiny\$HOSTNAME\HIVES > $null }

    try{
        Write-Host "[+] Collecting HIVES: NTUSER.DAT ..." -ForegroundColor Green
        foreach($u in $USERS)
        {
            if($OS -eq "XP")  <# TODO: NOT SURE IF THIS WORKS, CHECK THE OS RESULT IN A XP MACHINE TO VERIFY #>
            { 
                & $RAW_EXE /FileNamePath:$Global:Source\Documents and Settings\$u\NTUSER.dat /OutputPath:$Global:Destiny\$HOSTNAME\HIVES\$u /OutputName:NTUSER.DAT > $null
            } 
            else 
            {
                if(Test-Path "$Global:Source\Users\$u\NTUSER.dat")
                {
                    if ( -Not ( Test-Path $Global:Destiny\$HOSTNAME\HIVES\$u ) ) { New-Item -ItemType directory -Path $Global:Destiny\$HOSTNAME\HIVES\$u > $null }

                    

                    & $RAW_EXE /FileNamePath:$Global:Source\Users\$u\NTUSER.dat /OutputPath:$Global:Destiny\$HOSTNAME\HIVES\$u /OutputName:NTUSER.DAT > $null
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

<########### E V T X   F I L E S #################################################> # EVT*
Function Collect-EVTX-Files {
# TODO: parse important suspicious event numbers
# TODO: parse "Microsoft-Windows-TaskScheduler/Operational" in search for events 106, 140, 141 - More info: https://attack.mitre.org/techniques/T1053/
    if ( -Not ( Test-Path "$Global:Destiny\$HOSTNAME\EVTX" ) ) { New-Item -ItemType directory -Path "$Global:Destiny\$HOSTNAME\EVTX" > $null }

    Write-Host "[+] Collecting EVTX Files ..." -ForegroundColor Green
    Get-ChildItem "$Global:Source\Windows\System32\winevt\Logs" -Filter *.evtx | ForEach-Object {
        if($_.Length -gt 69632)
        {
            $evtx_name_ext = ($_.FullName).Split("\")[5]
            try{
                # Write-Host "[+] ... EVTX File: $evtx_name_ext"
                $evtx_name = ((($_.FullName).Split("\")[5]).Split(".")[0]).Replace("%4","/")
                & cmd.exe /c wevtutil epl $evtx_name $Global:Destiny\$HOSTNAME\EVTX\$evtx_name_ext
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

<########### E T W   &   E T L ###################################################> # EET*
Function Collect-ETW-ETL {
    <# TODO: maybe consider the following: C:\Windows\System32\WDI #>
    try
    {
        Write-Host "[+] Collecting ETL files ..." -ForegroundColor Green

        if ( -Not ( Test-Path $Global:Destiny\$HOSTNAME\ETL\ ) ) { New-Item -ItemType directory -Path $Global:Destiny\$HOSTNAME\ETL\ > $null }
        
        & $RAW_EXE /FileNamePath:"$Global:Source\Windows\System32\WDI\LogFiles\BootCKCL.etl" /OutputPath:"$Global:Destiny\$HOSTNAME\ETL" /OutputName:BootCKCL.etl > $null
        
        & copy "$Global:Source\Windows\System32\WDI\LogFiles\WdiContextLog.*" "$Global:Destiny\$HOSTNAME\ETL"

        & $RAW_EXE /FileNamePath:"$Global:Source\Windows\System32\WDI\LogFiles\ShutdownCKCL.etl" /OutputPath:"$Global:Destiny\$HOSTNAME\ETL" /OutputName:ShutdownCKCL.etl > $null
        
        & copy "$Global:Source\Windows\System32\LogFiles\WMI\LwtNetLog.etl" "$Global:Destiny\$HOSTNAME\ETL"

        & copy "$Global:Source\Windows\System32\LogFiles\WMI\Wifi.etl" "$Global:Destiny\$HOSTNAME\ETL"
        
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

<########### F I L E S   L I S T S ###############################################> # FIL*   04:23
Function Collect-Files-Lists {

    if ( -Not ( Test-Path $Global:Destiny\$HOSTNAME\FilesLists ) ) { New-Item -ItemType directory -Path $Global:Destiny\$HOSTNAME\FilesLists > $null }

    try{
        Write-Host "[+] Collecting List of Files of the System ... " -ForegroundColor Green
        Write-Host "`t○ List of Files sorted by Modification Date ... " -ForegroundColor Green
        cmd.exe /c dir /t:w /a /s /o:d $Global:Source\ > "$Global:Destiny\$HOSTNAME\FilesLists\FileList_Sorted_Modification_Date.txt"
        Write-Host "`t○ List of Files sorted by Last Access Date ... " -ForegroundColor Green
        cmd.exe /c dir /t:a /a /s /o:d $Global:Source\ > "$Global:Destiny\$HOSTNAME\FilesLists\FileList_Sorted_Last_Access.txt"
        Write-Host "`t○ List of Files sorted by Creation Date ... " -ForegroundColor Green
        cmd.exe /c dir /t:c /a /s /o:d $Global:Source\ > "$Global:Destiny\$HOSTNAME\FilesLists\FileList_Sorted_Creation_Date.txt"
    
    } catch {
        Report-Error -evidence "List of Files of the System"
    }
}

<########### D A N G E R O U S   E X T E N S I O N S #############################> # DEX*   04:16
Function Collect-Dangerous-Extensions {
    
    # 34 extensions
    if ( -Not ( Test-Path $Global:Destiny\$HOSTNAME\FilesLists ) ) { New-Item -ItemType directory -Path $Global:Destiny\$HOSTNAME\FilesLists > $null }

    Write-Host "[+] Collecting List of files with dangerous extensions..." -ForegroundColor Green
    
    try
    {
        Get-ChildItem "$Global:Source`\" -Include *.VB, *.VBS, *.PIF, *.BAT, *.CMD, *.JS, *.JSE, *.WS, *.WSF, *.WSC, *.WSH, *.PS1, *.PS1XML, *.PS2, *.PS2XML, *.PSC1, *.PSC2, *.MSH, *.MSH1, *.MSH2, *.MSHXML, *.MSH1XML, *.MSH2XML, *.SCF, *.LNK, *.INF, *.APPLICATION, *.GADGET, *.SCR, *.HTA, *.CPL, *.MSI, *.COM, *.EXE  -Recurse 2> $null | ForEach-Object {
            $_.FullName >> "$Global:Destiny\$HOSTNAME\FilesLists\Possible_Dangerrous_Extension.txt"
        }
    } 
    catch 
    {
        Report-Error -evidence "List of Extension $extension"
    }
}

<########### P R E F E T C H #####################################################> # PRF*
Function Collect-Prefetch {
    # TODO: Use Nirsoft tool to parse the information

    if ( -Not ( Test-Path $Global:Destiny\$HOSTNAME\Prefetch ) ) { New-Item -ItemType directory -Path $Global:Destiny\$HOSTNAME\Prefetch > $null }

    try{
        Write-Host "[+] Collecting Prefetch Files ... " -ForegroundColor Green
        copy $Global:Source\Windows\Prefetch\*.pf $Global:Destiny\$HOSTNAME\Prefetch\
        copy $Global:Source\Windows\Prefetch\*.db $Global:Destiny\$HOSTNAME\Prefetch\
    } catch {
        Report-Error -evidence "Prefetch Files"
    }
}

<########### W I N D O W S   S E A R C H #########################################> # WSE*
Function Collect-Windows-Search {
    # TODO: User ESEDatabaseView to export content to a CSV file for better analysis

    if( Test-Path -Path "$Global:Source\ProgramData\Microsoft\Search\Data\Applications\Windows\Windows.edb") # TODO: if it does not find the file search in the registry for posible change: \HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows Search\Databases
    {
        Write-Host "[+] Collecting Windows Search File windows.edb ... " -ForegroundColor Green
        try
        {
            if ( -Not ( Test-Path $Global:Destiny\$HOSTNAME\Windows_Search\ ) ) { New-Item -ItemType directory -Path $Global:Destiny\$HOSTNAME\Windows_Search\ > $null }

            & $RAW_EXE /FileNamePath:"$Global:Source\ProgramData\Microsoft\Search\Data\Applications\Windows\Windows.edb" /OutputPath:"$Global:Destiny\$HOSTNAME\Windows_Search" /OutputName:Windows.edb > $null
        } 
        catch 
        {
            Report-Error -evidence "Collecting Windows Search File windows.edb"
        }
        
        Write-Host "`t○ Converting Windows Search File windows.edb to CSV file ... " -ForegroundColor Green
        try
        {
            if ( -Not ( Test-Path $Global:Destiny\$HOSTNAME\Windows_Search\ ) ) { New-Item -ItemType directory -Path $Global:Destiny\$HOSTNAME\Windows_Search\ > $null }

            & "$SCRIPTPATH\bin\esedatabaseview\ESEDatabaseView.exe" /table "$Global:Destiny\$HOSTNAME\Windows_Search\Windows.edb" * /scomma "$Global:Destiny\$HOSTNAME\Windows_Search\WindowsSearchDatabase_*.csv"
        } 
        catch 
        {
            Report-Error -evidence "Converting Windows Search File windows.edb"
        }
    }
    else
    {
        Write-Host "[-] Windows Search File windows.edb does not exist ... " -ForegroundColor Yellow
    }
}

<########### J U M P   L I S T S #################################################> # JLI*
Function Collect-JumpLists {

    if($OS -eq "10" -or $OS -like "8" -or $OS -eq "7")
    {
        Write-Host "[+] Collecting Jump Lists ..." -ForegroundColor Green
        
        [System.Reflection.Assembly]::Load([System.IO.File]::ReadAllBytes("$SCRIPTPATH\dependencies\JumpList.dll")) > $null
        [System.Reflection.Assembly]::Load([System.IO.File]::ReadAllBytes("$SCRIPTPATH\dependencies\OleCf.dll")) > $null
        [System.Reflection.Assembly]::Load([System.IO.File]::ReadAllBytes("$SCRIPTPATH\dependencies\Lnk.dll")) > $null
        [System.Reflection.Assembly]::Load([System.IO.File]::ReadAllBytes("$SCRIPTPATH\dependencies\ExtensionBlocks.dll")) > $null
        [System.Reflection.Assembly]::Load([System.IO.File]::ReadAllBytes("$SCRIPTPATH\dependencies\GuidMapping.dll")) > $null

        foreach($u in $USERS) # TODO: Sometimes the user might have something more in the name in \Users\[user] - adjust it so it identifies the name part of the folder and not as the obsolute name of the folder.
        {
            # Automatic Destinations
            if( Test-Path "$Global:Source\Users\$u\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations")
            {
                Write-Host "`t○ Collecting Automatic Jump Lists for user $u ..." -ForegroundColor Green

                # Copies Automatic Destinations
                if( -not (Test-Path "$Global:Destiny\$HOSTNAME\MRUs\$u\JumpLists_AutomaticDestinations") ) { New-Item -ItemType Directory -Path "$Global:Destiny\$HOSTNAME\MRUs\$u\JumpLists_AutomaticDestinations" > $null }    
            
                try
                {
                    cmd.exe /c copy "$Global:Source\Users\$u\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations\*.*" "$Global:Destiny\$HOSTNAME\MRUs\$u\JumpLists_AutomaticDestinations" > $null
                }
                catch
                {
                    Report-Error -evidence "Jump Lists - AutomaticDestinations from user $u"
                }

                # Treating Automatic Destinations
                if( -not (Test-Path "$Global:Destiny\$HOSTNAME\MRUs\$u") ) { New-Item -ItemType Directory -Path "$Global:Destiny\$HOSTNAME\MRUs\$u" > $null }    

                Write-Host "`t○ Parsing Automatic Jump Lists for user $u ..." -ForegroundColor Green
                
                echo "File Name, Full Path, Last Modified, Creation Date, Accessed Date, Modification date, File Attributes, File Size, Entry ID, Pos. MRU, Appication ID, Application Name, Mac Address, File Extension, Computer Name, Network Share Name, Drive Type, Volume Label, Volume SN, Jump List Filename " > "$Global:Destiny\$HOSTNAME\MRUs\$u\JumplLists_Auto.csv"

                Get-ChildItem "$Global:Source\Users\$u\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations" | ForEach-Object {
    
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

                            echo "$FileName, $FullPath, $LastModified, $CreationDate, $AccessedDate, $ModificationDate, $FileAttributes, $FileSize, $EntryID, $PosMRU, $AppID, $AppName, $MacAddress, $Extension, $ComputerName, $NetworkShareName, $DriveType, $VolumeLabel, $VolumeSerialNumber, $JLFilename " >> "$Global:Destiny\$HOSTNAME\MRUs\$u\JumplLists_Auto.csv"
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
                Write-Host "`t○ Collecting Custom Jump Lists for user $u ..." -ForegroundColor Green

                # Copies Custom Destinations
                if( -not (Test-Path "$Global:Destiny\$HOSTNAME\MRUs\$u\JumpLists_CustomDestinations") ) { New-Item -ItemType Directory -Path "$Global:Destiny\$HOSTNAME\MRUs\$u\JumpLists_CustomDestinations" > $null }    

                try
                {
                    cmd.exe /c copy "$Global:Source\Users\$u\AppData\Roaming\Microsoft\Windows\Recent\CustomDestinations\*.*" "$Global:Destiny\$HOSTNAME\MRUs\$u\JumpLists_CustomDestinations" > $null
                }
                catch
                {
                    Report-Error -evidence "Jump Lists - CustomDestinations from user $u"
                }

                # Treating Custom Destinations
                if( -not (Test-Path "$Global:Destiny\$HOSTNAME\MRUs\$u") ) { New-Item -ItemType Directory -Path "$Global:Destiny\$HOSTNAME\MRUs\$u" > $null }
                
                Write-Host "`t○ Parsing Custom Jump Lists for user $u ..." -ForegroundColor Green
                
                echo "App ID, App Name, Creation Date, Accessed Date, Modification date, File Attributes, File Size, Network Share Name, Drive Type, Volume Label, Volume SN , Jump List Filename " > "$Global:Destiny\$HOSTNAME\MRUs\$u\JumplLists_Custom.csv"

                Get-ChildItem "$Global:Source\Users\$u\AppData\Roaming\Microsoft\Windows\Recent\CustomDestinations" | ForEach-Object {

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
                            
                                echo "$AppID, $AppName, $CreationDate, $AccessedDate, $ModificationDate, $FileAttributes, $FileSize, $NetworkShareName, $DriveType, $VolumeLabel, $VolumeSerialNumber, $JLFilename " >> "$Global:Destiny\$HOSTNAME\MRUs\$u\JumplLists_Custom.csv"
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

<########### T H U M C A C H E   &   I C O N C A C H E ###########################> # TIC*
Function Collect-Thumcache-Iconcache {
    
    Write-Host "[+] Collecting Thumbcache and Iconcache files..." -ForegroundColor Green
    foreach($u in $USERS)
    {
        # THUMBCACHE
        Write-Host "`t○ Thumbcache files from user $u." -ForegroundColor Green
        New-Item -ItemType directory -Path "$Global:Destiny\$HOSTNAME\Thumbcache_Iconcache\$u\DB_Thumbcache" > $null
        
        try
        {
            cmd.exe /c copy "$Global:Source\Users\$u\AppData\Local\Microsoft\Windows\Explorer\thumbcache*.db" "$Global:Destiny\$HOSTNAME\Thumbcache_Iconcache\$u\DB_Thumbcache\." > $null
        } 
        catch 
        {
            Report-Error -evidence "Thumbcache and Iconcache files"
        }

        Write-Host "`t○ Extracting images from Thumbcache files from user $u." -ForegroundColor Green
        
        New-Item -ItemType directory -Path "$Global:Destiny\$HOSTNAME\Thumbcache_Iconcache\$u\Images_Thumbcache" > $null
        
        try
        {
            Get-ChildItem "$Global:Destiny\$HOSTNAME\Thumbcache_Iconcache\$u\DB_Thumbcache" | ForEach-Object {
                & $THUMB_CACHE_VIEWER "$Global:Destiny\$HOSTNAME\Thumbcache_Iconcache\$u\DB_Thumbcache\$_" -O "$Global:Destiny\$HOSTNAME\Thumbcache_Iconcache\$u\Images_Thumbcache"
            }
        }
        catch
        {
            Report-Error -evidence "Extracting Thumbcache image files."
        }

        # ICONCACHE
        Write-Host "`t○ Iconcache files from user $u." -ForegroundColor Green
        New-Item -ItemType directory -Path "$Global:Destiny\$HOSTNAME\Thumbcache_Iconcache\$u\DB_Iconcache" > $null

        try
        {
            cmd.exe /c copy "$Global:Source\Users\$u\AppData\Local\Microsoft\Windows\Explorer\iconcache*.db" "$Global:Destiny\$HOSTNAME\Thumbcache_Iconcache\$u\DB_Iconcache\." > $null
        } 
        catch 
        {
            Report-Error -evidence "Thumbcache and Iconcache files"
        }
        
        Write-Host "`t○ Extracting icons from Iconcache files from user $u." -ForegroundColor Green
        New-Item -ItemType directory -Path "$Global:Destiny\$HOSTNAME\Thumbcache_Iconcache\$u\Images_Iconcache" > $null

        try
        {
            Get-ChildItem "$Global:Destiny\$HOSTNAME\Thumbcache_Iconcache\$u\DB_Iconcache" | ForEach-Object {
                & $THUMB_CACHE_VIEWER "$Global:Destiny\$HOSTNAME\Thumbcache_Iconcache\$u\DB_Iconcache\$_" -O "$Global:Destiny\$HOSTNAME\Thumbcache_Iconcache\$u\Images_Iconcache"
            }
        }
        catch
        {
            Report-Error -evidence "Iconcache icons."
        }
    }
}

##########################################################################################################

<########### F I L E   S Y S T E M   F I L E S ###################################> # FSF*
Function Collect-FileSystemFiles {
    
    # TODO: Use tools like MFT2csv, Usn2csv and LogParser to automate the extraction of this content. Very easy to do, the problem is the time. Must create variable for the investigator choose if want just collect or collect and parsing.

    Write-Host "[+] Collecting File System Files..." -ForegroundColor Green
    
    Collect-MFT
    Collect-UsnJrnl
    Collect-LogFile
}

<########### M F T   F I L E #######################> # MFT- - Used in File System Files*
Function Collect-MFT {
    
    if ( -Not ( Test-Path "$Global:Destiny\$HOSTNAME\FileSystemFiles\" ) ) { New-Item -ItemType directory -Path "$Global:Destiny\$HOSTNAME\FileSystemFiles\" > $null }

    Write-Host "`t○ Collecting `$MFT file. " -ForegroundColor Green

    try
    {
        & $RAW_EXE /FileNamePath:$Global:Source\`$MFT /OutputPath:$Global:Destiny\$HOSTNAME\FileSystemFiles /OutputName:`$MFT > $null
    }
    catch
    {
        Report-Error -evidence "`$MFT file"
    }
}

<########### U S N J R N L   F I L E ###############> # USN- - Used in File System Files*
Function Collect-UsnJrnl {

    if ( -Not ( Test-Path "$Global:Destiny\$HOSTNAME\FileSystemFiles\" ) ) { New-Item -ItemType directory -Path "$Global:Destiny\$HOSTNAME\FileSystemFiles\" > $null }

    Write-Host "`t○ Collecting `$UsnJrnl file." -ForegroundColor Green

    try
    {
        & $RAW_EXE /FileNamePath:$Global:Source\`$Extend\`$UsnJrnl /OutputPath:$Global:Destiny\$HOSTNAME\FileSystemFiles /OutputName:`$UsnJrnl > $null
    }
    catch
    {
        Report-Error -evidence "`$UsnJrnl file"
    }

}

<########### L O G F I L E   F I L E ###############> # LOG- - Used in File System Files*
Function Collect-LogFile {

    if ( -Not ( Test-Path "$Global:Destiny\$HOSTNAME\FileSystemFiles\" ) ) { New-Item -ItemType directory -Path "$Global:Destiny\$HOSTNAME\FileSystemFiles\" > $null }

    Write-Host "`t○ Collecting `$LogFile file." -ForegroundColor Green

    try
    {
        & $RAW_EXE /FileNamePath:"$Global:Source\`$LogFile" /OutputPath:"$Global:Destiny\$HOSTNAME\FileSystemFiles" /OutputName:"`$LogFile" > $null
    }
    catch
    {
        Report-Error -evidence "`$LogFile file"
    }
}

##########################################################################################################

<########### M E M O R Y   S U P P O R T   F I L E S ###############################> # MSF*
Function Collect-MemorySupportFiles {
    
    # TODO: Use Yara rules ober this files.
    
    Write-Host "[+] Collecting Memory Support Files." -ForegroundColor Green

    Collect-Hiberfil           # hiberfil.sys
    Collect-Pagefile           # pagefile.sys
    Collect-Swapfile           # swapfile.sys
}

<########### H I B E R F I L   F I L E ###############> # HIB- - Used in Memory Support Files*
Function Collect-Hiberfil {
    
    if ( -Not ( Test-Path "$Global:Destiny\$HOSTNAME\MemorySupportFiles\" ) ) { New-Item -ItemType directory -Path "$Global:Destiny\$HOSTNAME\MemorySupportFiles\" > $null }

    # hiberfil.sys
    Write-Host "`t○ Collecting hiberfil.sys file." -ForegroundColor Green

    try
    {
        & $RAW_EXE /FileNamePath:$Global:Source\hiberfil.sys /OutputPath:$Global:Destiny\$HOSTNAME\MemorySupportFiles /OutputName:hiberfil.sys > $null
    }
    catch
    {
        Report-Error -evidence "hiberfil.sys file"
    }
}

<########### P A G E F I L E   F I L E ###############> # PGF- - Used in Memory Support Files*
Function Collect-Pagefile {

    if ( -Not ( Test-Path "$Global:Destiny\$HOSTNAME\MemorySupportFiles\" ) ) { New-Item -ItemType directory -Path "$Global:Destiny\$HOSTNAME\MemorySupportFiles\" > $null }

    # pagefile.sys
    Write-Host "`t○ Collecting pagefile.sys file." -ForegroundColor Green

    try
    {
        & $RAW_EXE /FileNamePath:$Global:Source\pagefile.sys /OutputPath:$Global:Destiny\$HOSTNAME\MemorySupportFiles /OutputName:pagefile.sys > $null
    }
    catch
    {
        Report-Error -evidence "pagefile.sys file"
    }

}

<########### S W A P F I L E   F I L E ###############> # SWA- - Used in Memory Support Files*
Function Collect-Swapfile {

    if ( -Not ( Test-Path "$Global:Destiny\$HOSTNAME\MemorySupportFiles\" ) ) { New-Item -ItemType directory -Path "$Global:Destiny\$HOSTNAME\MemorySupportFiles\" > $null }

    # swapfile.sys
    Write-Host "`t○ Collecting swapfile.sys file." -ForegroundColor Green

    try
    {
        & $RAW_EXE /FileNamePath:"$Global:Source\swapfile.sys" /OutputPath:"$Global:Destiny\$HOSTNAME\MemorySupportFiles" /OutputName:"swapfile.sys" > $null
    }
    catch
    {
        Report-Error -evidence "swapfile.sys file"
    }
}

##########################################################################################################

<########### T I M E L I N E   H I S T O R Y #####################################> # TLH*
Function Collect-Timeline {

    if($OS -eq "10")
    {
        Write-Host "[+] Collecting Timeline History ..." -ForegroundColor Green
        
        foreach($u in $USERS)
        {
            if(Test-Path "$Global:Source\Users\$u\AppData\Local\ConnectedDevicesPlatform")
            {       
                Get-Item  "$Global:Source\Users\$u\AppData\Local\ConnectedDevicesPlatform\*" | ForEach-Object {
                 
                    if(Test-Path -Path $_.FullName -PathType Container) # if it's a folder
                    {
                        if( -not (Test-Path "$Global:Destiny\$HOSTNAME\Timeline_History\$u") ) { New-Item -ItemType Directory -Path "$Global:Destiny\$HOSTNAME\Timeline_History\$u" > $null }
                        
                        try
                        {
                            Write-Host "`t○ Timeline History from user $u..." -ForegroundColor Green
                            & cmd.exe /c copy "$Global:Source\Users\$u\AppData\Local\ConnectedDevicesPlatform\$($_.Name)\*.*" "$Global:Destiny\$HOSTNAME\Timeline_History\$u" > $null
                        }
                        catch
                        {
                            Report-Error -evidence "Timeline History - copying files"
                        }

                        try
                        {
                            Write-Host "`t○ Parsing Timeline History from user $u..." -ForegroundColor Green
                            & cmd.exe /c "$SCRIPTPATH\bin\WxTCmd\WxTCmd.exe" -f "$Global:Destiny\$HOSTNAME\Timeline_History\$u\ActivitiesCache.db" --csv "$Global:Destiny\$HOSTNAME\Timeline_History\$u\Timeline_Parsed" > $null
                        }
                        catch
                        {
                            Report-Error -evidence "Timeline History - parsing files"
                        }
                    }
                }
            }
            else
            {
                Write-Host "`t[-] Timeline not activated for user $u" -ForegroundColor Yellow
            }
        }
    }
}

<########### T E X T   H A R V E S T E R #########################################> # THA*
Function Collect-TextHarvester { <# TODO: Have to activate this option in a OS an try it. #>

    Write-Host "[+] Collecting Text Harvester ..." -ForegroundColor Green

    if( ($OS -like "8*") -or ($OS -eq "10") ) 
    {
        foreach($u in $USERS)
        {
            if( Test-Path -Path "$Global:Source\Users\$u\AppData\Local\Microsoft\InputPersonalization\TextHarvester\WaitList.dat") 
            {
                # Collect File
                try 
                {
                    Write-Host "`t○ Collect for user $u..." -ForegroundColor DarkGreen
                
                    if ( -Not ( Test-Path "$Global:Destiny\$HOSTNAME\TextHarvester\$u" ) ) { New-Item -ItemType directory -Path "$Global:Destiny\$HOSTNAME\TextHarvester\$u" > $null }
                    
                    & $RAW_EXE /FileNamePath:"$Global:Source\Users\$u\AppData\Local\Microsoft\InputPersonalization\TextHarvester\WaitList.dat" /OutputPath:"$Global:Destiny\$HOSTNAME\TextHarvester\$u" /OutputName:WaitList.dat > $null
                } 
                catch 
                {
                    Report-Error -evidence "TextHarvester collection user $u"
                }

                # Parse file
                try
                {
                    Write-Host "`t○ Parse user $u..." -ForegroundColor DarkGreen

                    if ( -Not ( Test-Path "$Global:Destiny\$HOSTNAME\TextHarvester\$u\ParsedData" ) ) { New-Item -ItemType directory -Path "$Global:Destiny\$HOSTNAME\TextHarvester\$u\ParsedData" > $null }

                    & cmd.exe /c "$SCRIPTPATH\bin\wlripEXE-master\wlrip.exe" -c -x -f "$Global:Destiny\$HOSTNAME\TextHarvester\$u\WaitList.dat" -o "$Global:Destiny\$HOSTNAME\TextHarvester\$u\ParsedData.csv" > $null
                }
                catch
                {
                    Report-Error -evidence "TextHarvester parsing user $u"
                }
            }
            else
            {
                Write-Host "`t[-] Not activated for user $u" -ForegroundColor Yellow
            }
        }
    }
} 

<########### S R U M #############################################################> # SRU*
Function Collect-SRUM {

    # SRUM - SYSTEM RESOURCE USAGE MONITOR 
    Write-Host "[+] SRUM - System Resource Usage Monitor ..." -ForegroundColor Green

    if( Test-Path -Path "$Global:Source\Windows\System32\sru\SRUDB.dat") 
    {
        # COLLECT THE RAW INFORMATION/EVIDENCE/ARTIFACT
        try 
        {
            Write-Host "`t○ Collecting Data ..." -ForegroundColor Green
                
            if ( -Not ( Test-Path -Path "$Global:Destiny\$HOSTNAME\SRUM\" ) ) { New-Item -ItemType directory -Path "$Global:Destiny\$HOSTNAME\SRUM" > $null }

            cmd.exe /c copy "$Global:Source\Windows\System32\sru\SRUDB.dat" "$Global:Destiny\$HOSTNAME\SRUM" > $null
        } 
        catch 
        {
            Report-Error -evidence "Collecting Data - System Resource Usage Monitor (SRUM)"
        }

        # PARSE THE INFORMATION/EVIDENCE/ARTIFACT
        try
        {
            if( -Not (Test-Path -Path "$Global:Destiny\$HOSTNAME\HIVES\SOFTWARE") ) # Collect HIVE SOFTWARE in case it was not collected yet
            {
                Write-Host "`t[*] Collecting HIVE SOFTWARE file ..." -ForegroundColor Yellow
                
                if ( -Not ( Test-Path $Global:Destiny\$HOSTNAME\HIVES ) ) { New-Item -ItemType directory -Path $Global:Destiny\$HOSTNAME\HIVES > $null }

                & $RAW_EXE /FileNamePath:"$Global:Source\Windows\System32\config\SOFTWARE" /OutputPath:"$Global:Destiny\$HOSTNAME\HIVES" /OutputName:SOFTWARE > $null
            }
            
            if ( -Not ( Test-Path -Path "$Global:Destiny\$HOSTNAME\SRUM\ParsedData" ) ) { New-Item -ItemType directory -Path "$Global:Destiny\$HOSTNAME\SRUM\ParsedData" > $null }

            Write-Host "`t○ Parsing Data ..." -ForegroundColor Green

            cmd.exe /c $SCRIPTPATH\bin\srum-dump\srum_dump.exe --SRUM_INFILE "$Global:Destiny\$HOSTNAME\SRUM\srudb.dat" --XLSX_OUTFILE "$Global:Destiny\$HOSTNAME\SRUM\ParsedData\SRUM.xlsx" --XLSX_TEMPLATE $SCRIPTPATH\bin\srum-dump\SRUM_TEMPLATE.xlsx --REG_HIVE "$Global:Destiny\$HOSTNAME\HIVES\SOFTWARE" > $null
            cmd.exe /c $SCRIPTPATH\bin\srum-dump\srum_dump_csv.exe --SRUM_INFILE "$Global:Destiny\$HOSTNAME\SRUM\srudb.dat" --OUT_PATH "$Global:Destiny\$HOSTNAME\SRUM\ParsedData" --XLSX_TEMPLATE $SCRIPTPATH\bin\srum-dump\SRUM_TEMPLATE.xlsx --REG_HIVE "$Global:Destiny\$HOSTNAME\HIVES\SOFTWARE"  > $null
            
            echo "" > $null
        }
        catch
        {
            Report-Error -evidence "Parsing Data - System Resource Usage Monitor (SRUM)"
        }
    }
    else
    {
        Write-Host "[-] No System Resource Usage Monitor (SRUM) found in the system ..." -ForegroundColor Yellow
    }
}

<########### C R E D E N T I A L S ###############################################> # CRE*
Function Collect-Credentials {

    Write-Host "[+] Credentials Stored in File System ..." -ForegroundColor Green

    foreach($u in $USERS)
    {
        Write-Host "`t○ User $u ..." -ForegroundColor Green
        
        # COLLECT THE RAW INFORMATION/EVIDENCE
        try 
        {
            Write-Host "`t`t○ Collecting ..." -ForegroundColor Green

            # "C:\Users\<user>\AppData\Roaming\Microsoft\Credentials"
            if(Test-Path -Path "$Global:Source\Users\$u\AppData\Roaming\Microsoft\Credentials")
            {
                if ( -Not ( Test-Path -Path "$Global:Destiny\$HOSTNAME\Credentials\$u\Roaming" ) ) { New-Item -ItemType directory -Path "$Global:Destiny\$HOSTNAME\Credentials\$u\Roaming" > $null }

                $tempFileList1 = Get-ChildItem -Force "$Global:Source\Users\$u\AppData\Roaming\Microsoft\Credentials" 2> $null | ForEach-Object { $_.Name }
                
                foreach($file in $tempFileList1)
                {
                    & $RAW_EXE /FileNamePath:"$Global:Source\Users\$u\AppData\Roaming\Microsoft\Credentials\$file" /OutputPath:"$Global:Destiny\$HOSTNAME\Credentials\$u\Roaming" /OutputName:$file > $null
                }
            }
            else
            {
                Write-Host "`t`t`t[-] This user does not have Roaming Credentials ..." -ForegroundColor Yellow
            }

            # "C:\Users\<user>\AppData\Local\Microsoft\Credentials"
            if(Test-Path -Path "$Global:Source\Users\$u\AppData\Local\Microsoft\Credentials")
            {
                if ( -Not ( Test-Path -Path "$Global:Destiny\$HOSTNAME\Credentials\$u\Local" ) ) { New-Item -ItemType directory -Path "$Global:Destiny\$HOSTNAME\Credentials\$u\Local" > $null }

                $tempFileList2 = Get-ChildItem -Force "$Global:Source\Users\$u\AppData\Local\Microsoft\Credentials" 2> $null | ForEach-Object { $_.Name }
                
                foreach($file in $tempFileList2)
                {
                    & $RAW_EXE /FileNamePath:"$Global:Source\Users\$u\AppData\Local\Microsoft\Credentials\$file" /OutputPath:"$Global:Destiny\$HOSTNAME\Credentials\$u\Local" /OutputName:$file  > $null
                }
            }
            else
            {
                Write-Host "`t`t`t[-] This user does not have Local Credentials ..." -ForegroundColor Yellow
            }
        } 
        catch 
        {
            Report-Error -evidence "Collecting - Credentials Stored in File System"
        }

        if(Test-Path -Path "$Global:Destiny\$HOSTNAME\Credentials\$u\")
        {
            # PARSE THE INFORMATION/EVIDENCE
            try
            {
                if ( -Not ( Test-Path -Path "$Global:Destiny\$HOSTNAME\Credentials\$u\Parsed" ) ) { New-Item -ItemType directory -Path "$Global:Destiny\$HOSTNAME\Credentials\$u\Parsed" > $null }
            
                Write-Host "`t`t○ Parsing ..." -ForegroundColor Green
                Invoke-WCMDump | Out-File -FilePath "$Global:Destiny\$HOSTNAME\Credentials\$u\Parsed\Credentials.txt" 2> $null #TODO: if(LIVE)
                # Write-Host " [DEVELOPING] ..." -ForegroundColor Yellow
            }
            catch
            {
                Report-Error -evidence "Treating - Credentials Stored in File System"
            }
        }
    }
}

<########### S K Y P E ###########################################################> # SKY*
Function Collect-Skype-History {

    $blacklist = "Content","DataRv","logs","RootTools"

    Write-Host "[+] Trying to collect Skype Information ... " -ForegroundColor Green

    if($OS -eq "XP")
    {
        foreach($u in $USERS)
        {
            Write-Host "`t○ User $u ... " -ForegroundColor Green
            
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
            Write-Host "`t○ User $u ... " -ForegroundColor Green
            
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

<########### E M A I L   F I L E S ###############################################> # EMA*
Function Collect-Email-Files {

    Write-Host "[+] Collecting Email files." -ForegroundColor Green

    $existingEmails = ""

    Write-Host "`t○ OUTLOOK folders." -ForegroundColor Green

    foreach($u in $USERS)
    {
        if( Test-Path -Path "$Global:Source\Users\$u\AppData\Local\Microsoft\Outlook\")
        {
            if ( -Not ( Test-Path $Global:Destiny\$HOSTNAME\EmailFiles\$u ) ) { New-Item -ItemType directory -Path $Global:Destiny\$HOSTNAME\EmailFiles\$u > $null }
        
            <# OST Files #>
            Get-ChildItem "$Global:Source\Users\$u\AppData\Local\Microsoft\Outlook\" -Filter *.ost | ForEach-Object {
                try
                {
                    $email_file = ($_.FullName).Split("\")[7]
                    $existingEmails += $email_file

                    Write-Host "`t`t○ Collecting `"$email_file`" from user $u." -ForegroundColor Green
                    
                    & $RAW_EXE /FileNamePath:"$Global:Source\Users\$u\AppData\Local\Microsoft\Outlook\$email_file" /OutputPath:"$Global:Destiny\$HOSTNAME\EmailFiles\$u" /OutputName:$email_file > $null
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
                    $existingEmails += $email_file

                    Write-Host "`t`t○ Collecting `"$email_file`" from user $u." -ForegroundColor Green
                    
                    & $RAW_EXE /FileNamePath:"$Global:Source\Users\$u\AppData\Local\Microsoft\Outlook\$email_file" /OutputPath:"$Global:Destiny\$HOSTNAME\EmailFiles\$u" /OutputName:$email_file > $null
                } 
                catch 
                {
                    Report-Error -evidence "OUTLOOK PST File from $u"
                }
            }
        }
    }

    # Find PST files in other locations
    try
    {
        Write-Host "`t○ Searching other PST files ..." -ForegroundColor Green

        Get-ChildItem "$Global:Source`\" -Recurse *.pst 2> $null | ForEach-Object {
            if (-not ($_.Name -in $existingEmails))
            {
                Write-Host "`t`t○ Found one $($_.FullName) ..." -ForegroundColor Green

                if ( -Not ( Test-Path $Global:Destiny\$HOSTNAME\EmailFiles\LostEmailFiles ) ) { New-Item -ItemType directory -Path $Global:Destiny\$HOSTNAME\EmailFiles\LostEmailFiles > $null }
                
                & $RAW_EXE /FileNamePath:"$($_.FullName)" /OutputPath:"$Global:Destiny\$HOSTNAME\EmailFiles\LostEmailFiles" /OutputName:"$($_.Name)" > $null
            }
        }
        
    }
    catch
    {
        Report-Error -evidence "Lost PST email file."
    }

    # Find OST files in other locations
    try
    {
        Write-Host "`t○ Searching other OST files ..." -ForegroundColor Green

        Get-ChildItem "$Global:Source`\" -Recurse *.ost 2> $null | ForEach-Object {
            if (-not ($_.Name -in $existingEmails))
            {
                Write-Host "`t`t○ Found one $_.FullName ..." -ForegroundColor Green

                if ( -Not ( Test-Path $Global:Destiny\$HOSTNAME\EmailFiles\LostEmailFiles ) ) { New-Item -ItemType directory -Path $Global:Destiny\$HOSTNAME\EmailFiles\LostEmailFiles > $null }
                
                & $RAW_EXE /FileNamePath:"$($_.FullName)" /OutputPath:"$Global:Destiny\$HOSTNAME\EmailFiles\LostEmailFiles" /OutputName:"$($_.Name)" > $null
            }
        }
    }
    catch
    {
        Report-Error -evidence "Lost OST email file."
    }
}

############ B R O W S E R S #############################################################################

<########### C H R O M E   W E B   B R O W S E R #################################> # CHR*
Function Collect-Chrome-Data {
    
    # TODO: parse SQLite tables to CSV files

    Write-Host "[+] Collecting Chrome files ..." -ForegroundColor Green

    $filesToDownload = "Cookies","Favicons","History","Login Data","Network Action Predictor","QuotaManager","Shortcuts","Top sites","Web Data"

    foreach($u in $USERS){
    
        Write-Host "`t○ for user $u ..." -ForegroundColor Green

        if($OS -eq "XP")
        {
            if(Test-Path "$Global:Source\Documents and Settings\$u\Local Settings\ApplicationData\Google\Chrome\User Data")
            {
                try
                {
                    # In case Default profile exists
                    if(Test-Path "$Global:Source\Documents and Settings\$u\Local Settings\ApplicationData\Google\Chrome\User Data\Default")
                    {
                        if ( -Not ( Test-Path "$Global:Destiny\$HOSTNAME\WebBrowsers\Chrome\$u\Default" ) ) { New-Item -ItemType directory -Path "$Global:Destiny\$HOSTNAME\WebBrowsers\Chrome\$u\Default" > $null }

                        Write-Host "`t`t○ `"Default profile`" found ..." -ForegroundColor Green

                        foreach($file in $filesToDownload)
                        {
                            if (Test-Path "$Global:Source\Documents and Settings\$u\Local Settings\ApplicationData\Google\Chrome\User Data\Default\$file")
                            {
                                copy "$Global:Source\Documents and Settings\$u\Local Settings\ApplicationData\Google\Chrome\User Data\Default\$file" "$Global:Destiny\$HOSTNAME\WebBrowsers\Chrome\$u\Default"
                            }
                        }
                    }

                    # Other Profiles that should have the word profile in it                    
                    Get-ChildItem "$Global:Source\Documents and Settings\$u\Local Settings\ApplicationData\Google\Chrome\User Data" | ForEach-Object {
                        
                        if($_.Name -match "Profile")
                        {
                            if(Test-Path "$Global:Source\Documents and Settings\$u\Local Settings\ApplicationData\Google\Chrome\User Data\$($_.Name)")
                            {
                                if ( -Not ( Test-Path "$Global:Destiny\$HOSTNAME\WebBrowsers\Chrome\$u\$($_.Name)" ) ) { New-Item -ItemType directory -Path "$Global:Destiny\$HOSTNAME\WebBrowsers\Chrome\$u\$($_.Name)" > $null }

                                Write-Host "`t`t○ `"$($_.Name)`" found ..." -ForegroundColor Green

                                foreach($file in $filesToDownload)
                                {
                                    if (Test-Path "$Global:Source\Documents and Settings\$u\Local Settings\ApplicationData\Google\Chrome\User Data\$($_.Name)\$file")
                                    {
                                        copy "$Global:Source\Documents and Settings\$u\Local Settings\ApplicationData\Google\Chrome\User Data\$($_.Name)\$file" "$Global:Destiny\$HOSTNAME\WebBrowsers\Chrome\$u\$($_.Name)"
                                    }
                                }
                            }
                        }
                    }
                } 
                catch 
                {
                    Report-Error -evidence "Chrome files"
                }
            }
        }
        else # all other windows versions after VISTA
        {
            if(Test-Path "$Global:Source\Users\$u\AppData\Local\Google\Chrome\User data")
            {
                try
                {
                    # In case Default profile exists
                    if(Test-Path "$Global:Source\Users\$u\AppData\Local\Google\Chrome\User Data\Default")
                    {
                        if ( -Not ( Test-Path "$Global:Destiny\$HOSTNAME\WebBrowsers\Chrome\$u\Default" ) ) { New-Item -ItemType directory -Path "$Global:Destiny\$HOSTNAME\WebBrowsers\Chrome\$u\Default" > $null }

                        Write-Host "`t`t○ `"Default profile`" found ..." -ForegroundColor Green

                        foreach($file in $filesToDownload)
                        {
                            if (Test-Path "$Global:Source\Users\$u\AppData\Local\Google\Chrome\User Data\Default\$file")
                            {
                                copy "$Global:Source\Users\$u\AppData\Local\Google\Chrome\User Data\Default\$file" "$Global:Destiny\$HOSTNAME\WebBrowsers\Chrome\$u\Default"
                            }
                        }
                    }

                    # Other Profiles that should have the word profile in it                    
                    Get-ChildItem "$Global:Source\Users\$u\AppData\Local\Google\Chrome\User Data" | ForEach-Object {
                        
                        if($_.Name -match "Profile")
                        {
                            if(Test-Path "$Global:Source\Users\$u\AppData\Local\Google\Chrome\User Data\$($_.Name)")
                            {
                                if ( -Not ( Test-Path "$Global:Destiny\$HOSTNAME\WebBrowsers\Chrome\$u\$($_.Name)" ) ) { New-Item -ItemType directory -Path "$Global:Destiny\$HOSTNAME\WebBrowsers\Chrome\$u\$($_.Name)" > $null }

                                Write-Host "`t`t○ `"$($_.Name)`" found ..." -ForegroundColor Green

                                foreach($file in $filesToDownload)
                                {
                                    if (Test-Path "$Global:Source\Users\$u\AppData\Local\Google\Chrome\User Data\$($_.Name)\$file")
                                    {
                                        copy "$Global:Source\Users\$u\AppData\Local\Google\Chrome\User Data\$($_.Name)\$file" "$Global:Destiny\$HOSTNAME\WebBrowsers\Chrome\$u\$($_.Name)"
                                    }
                                }
                            }
                        }
                    }
                } 
                catch 
                {
                    Report-Error -evidence "Chrome files"
                }
            }
        }

        if( -not (Test-Path "$Global:Destiny\$HOSTNAME\WebBrowsers\Chrome\")){
            Write-Host "`t[i] There is no Chrome Browser in the System for user $u ..." -ForegroundColor Yellow
        }
    }
}

<########### F I R E F O X   W E B   B R O W S E R ###############################> # MFI*
Function Collect-Firefox-Data {
    
    # TODO: parse SQLite tables to CSV files

    Write-Host "[+] Collecting Firefox files ..." -ForegroundColor Green

    $filesToDownload = "content-prefs.sqlite","cookies.sqlite","favicons.sqlite","formhistory.sqlite","permissions.sqlite","places.sqlite","storage.sqlite","storage-sync.sqlite","webappsstore.sqlite"

    foreach($u in $USERS){

        Write-Host "`t○ for user $u ..." -ForegroundColor Green

        if($OS -eq "XP")
        {
            if(Test-Path "$Global:Source\Documents and Settings\$u\Application Data\Mozilla\Firefox\Profiles")
            {
                try
                {
                    # Search for profiles                
                    Get-ChildItem "$Global:Source\Documents and Settings\$u\Application Data\Mozilla\Firefox\Profiles" | ForEach-Object {
                        
                        if(Test-Path "$Global:Source\Documents and Settings\$u\Application Data\Mozilla\Firefox\Profiles\$($_.Name)")
                        {
                            if ( -Not ( Test-Path "$Global:Destiny\$HOSTNAME\WebBrowsers\Firefox\$u\$($_.Name)" ) ) { New-Item -ItemType directory -Path "$Global:Destiny\$HOSTNAME\WebBrowsers\Firefox\$u\$($_.Name)" > $null }

                            Write-Host "`t`t○ `"$($_.Name)`" found ..." -ForegroundColor Green

                            foreach($file in $filesToDownload)
                            {
                                if (Test-Path "$Global:Source\Documents and Settings\$u\Application Data\Mozilla\Firefox\Profiles\$($_.Name)\$file")
                                {
                                    copy "$Global:Source\Documents and Settings\$u\Application Data\Mozilla\Firefox\Profiles\$($_.Name)\$file" "$Global:Destiny\$HOSTNAME\WebBrowsers\Firefox\$u\$($_.Name)"
                                }
                            }
                        }
                        
                    }
                } 
                catch 
                {
                    Report-Error -evidence "Firefox files"
                }
            }
        }
        else # all other windows versions after VISTA
        {
            if(Test-Path "$Global:Source\Users\$u\AppData\Roaming\Mozilla\Firefox\Profiles")
            {
                try
                {
                    # Search for profiles                
                    Get-ChildItem "$Global:Source\Users\$u\AppData\Roaming\Mozilla\Firefox\Profiles" | ForEach-Object {
                        
                        if(Test-Path "$Global:Source\Users\$u\AppData\Roaming\Mozilla\Firefox\Profiles\$($_.Name)")
                        {
                            if ( -Not ( Test-Path "$Global:Destiny\$HOSTNAME\WebBrowsers\Firefox\$u\$($_.Name)" ) ) { New-Item -ItemType directory -Path "$Global:Destiny\$HOSTNAME\WebBrowsers\Firefox\$u\$($_.Name)" > $null }

                            Write-Host "`t`t○ `"$($_.Name)`" found ..." -ForegroundColor Green

                            foreach($file in $filesToDownload)
                            {
                                if (Test-Path "$Global:Source\Users\$u\AppData\Roaming\Mozilla\Firefox\Profiles\$($_.Name)\$file")
                                {
                                    copy "$Global:Source\Users\$u\AppData\Roaming\Mozilla\Firefox\Profiles\$($_.Name)\$file" "$Global:Destiny\$HOSTNAME\WebBrowsers\Firefox\$u\$($_.Name)"
                                }
                            }
                        }
                        
                    }
                } 
                catch 
                {
                    Report-Error -evidence "Firefox files"
                }
            }
        }

        if( -not (Test-Path "$Global:Destiny\$HOSTNAME\WebBrowsers\Firefox\")){
            Write-Host "`t[i] There is no Firefox Browser in the System for user $u ..." -ForegroundColor Yellow
        }
    }
}

<########### I E   W E B   B R O W S E R #########################################> # IEX*
Function Collect-IE-Data {
    # TODO: see if it adds something new -> Extracts cache inf0rmation from IE - http://www.nirsoft.net/utils/ie_cache_viewer.html
    
    Write-Host "[+] Collecting IE Artifacts ..." -ForegroundColor Green
    
    if(-not (Test-Path "$Global:Destiny\$HOSTNAME\WebBrowsers\IE")) { New-Item -ItemType directory -Path "$Global:Destiny\$HOSTNAME\WebBrowsers\IE" > $null }

    # TODO: Cross with the time:. HKEY_CURRENT_USER\Software\Microsoft\Internet Explorer\TypedURLsTime
    echo ""                                                                                          > "$Global:Destiny\$HOSTNAME\WebBrowsers\IE\Registry_TypedURLs.txt" 2> $null
    echo "Registry Key: Computer\HKEY_CURRENT_USER\Software\Microsoft\Internet Explorer\TypedURLs"  >> "$Global:Destiny\$HOSTNAME\WebBrowsers\IE\Registry_TypedURLs.txt" 2> $null
    echo "Info: Date - HKEY_CURRENT_USER\Software\Microsoft\Internet Explorer\TypedURLsTime"        >> "$Global:Destiny\$HOSTNAME\WebBrowsers\IE\Registry_TypedURLs.txt" 2> $null
    echo ""                                                                                         >> "$Global:Destiny\$HOSTNAME\WebBrowsers\IE\Registry_TypedURLs.txt" 2> $null
    Get-ItemProperty "REGISTRY::HKEY_CURRENT_USER\Software\Microsoft\Internet Explorer\TypedURLs"   >> "$Global:Destiny\$HOSTNAME\WebBrowsers\IE\Registry_TypedURLs.txt" 2> $null

    foreach($u in $USERS)
    {
        Write-Host "`t○ for user: $u ... " -ForegroundColor Green

        if($OS -eq "XP")
        {
            if(Test-Path -Path "$Global:Source\Documents and Settings\$u\Local Settings\Temporary Internet Files\")
            {
                try
                {
                    if(-not (Test-Path "$Global:Destiny\$HOSTNAME\WebBrowsers\IE\$u")) { New-Item -ItemType directory -Path "$Global:Destiny\$HOSTNAME\WebBrowsers\IE\$u" > $null }
                    
                    cmd.exe /c copy "$Global:Source\Documents and Settings\$u\Local Settings\Temporary Internet Files\" "$Global:Destiny\$HOSTNAME\WebBrowsers\IE\$u\."> $null
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
                    if(-not (Test-Path "$Global:Destiny\$HOSTNAME\WebBrowsers\IE\$u")) { New-Item -ItemType directory -Path "$Global:Destiny\$HOSTNAME\WebBrowsers\IE\$u" > $null }
                    
                    & $RAW_EXE /FileNamePath:"$Global:Source\Users\$u\AppData\Local\Microsoft\Windows\WebCache\WebCacheV01.dat" /OutputPath:"$Global:Destiny\$HOSTNAME\WebBrowsers\IE\$u" /OutputName:WebCacheV01.dat > $null

                    # Coockies folder: C:\Users\f4d0\AppData\Roaming\Microsoft\Windows\Cookies\low
                    # History Folder: C:\Users\f4d0\AppData\Local\Microsoft\Windows\History
                } 
                catch 
                {
                    Report-Error -evidence "IE files, user: $u"
                }
            }
        }

        if( -not (Test-Path "$Global:Destiny\$HOSTNAME\WebBrowsers\IE\"))
        {
            Write-Host "`t[i] There is no IE Browser in the System for user $u ..." -ForegroundColor Yellow
        }
    }
}

<########### E D G E   W E B   B R O W S E R #####################################> # EDG*
Function Collect-EDGE-Data {
    
    # TODO: REVIEW THE BELOW PATHS
    # https://www.dataforensics.org/microsoft-edge-browser-forensics/
    # Cache: \users\user_name\AppData\Local\Packages\Microsoft.MicrosoftEdge_xxxx\AC\#!001\MicrosoftEdge\Cache
    # Last Browse Session: \User\user_name\AppData\Local\Packages\Microsoft.MicrosoftEdge_xxxx\AC\MicrosoftEdge\User\Default\Recovery\Active\
    # History: \Users\user_name\AppData\Local\Microsoft\Windows\WebCache\WebCacheV01.dat
    # Web Note: %LocalAppData%\packages\microsoft.windows.spartan_{PackageID}\AC\Spartan\User\Default\favorites
    # InPrivateBrowsing: \users\user_name\AppData\Local\Packages\Microsoft.MicrosoftEdge_xxxxx\AC\MicrosoftEdge\User\Default\Recovery\Active\{browsing-session-ID}.dat
    
    Write-Host "[+] Collecting EDGE files ..." -ForegroundColor Green
    
    if( ($OS -eq "7") -or ($OS -eq "Vista") -or ($OS -eq "8") -or ($OS -eq "10") )
    {
        foreach($u in $USERS)
        {
            if( Test-Path -Path "$Global:Source\users\$u\AppData\Local\Packages\")
            {
                Write-Host "`t○ user: $u ..." -ForegroundColor Green

                if(-not (Test-Path "$Global:Destiny\$HOSTNAME\WebBrowsers\EDGE\$u")) { New-Item -ItemType directory -Path "$Global:Destiny\$HOSTNAME\WebBrowsers\EDGE\$u" > $null }

                Get-ChildItem "$Global:Source\users\$u\AppData\Local\Packages\" | ForEach-Object {
                    
                    if($_.FullName -like "*Microsoft.MicrosoftEdge_*") 
                    {
                        $dir=$_.FullName
                        # get SPARTAN.edb file
                        Get-ChildItem "$dir\AC\MicrosoftEdge\User\Default\DataStore\Data\nouser1\" | ForEach-Object {
                            
                            $dirDB=$_.FullName

                            & $RAW_EXE /FileNamePath:"$dirDB\DBStore\spartan.edb" /OutputPath:"$Global:Destiny\$HOSTNAME\WebBrowsers\EDGE\$u" /OutputName:spartan.edb > $null
                        }
                    } 
                }
                # get cache files
                & $RAW_EXE /FileNamePath:"$Global:Source\Users\$u\AppData\Local\Microsoft\Windows\WebCache\WebCacheV01.dat" /OutputPath:"$Global:Destiny\$HOSTNAME\WebBrowsers\EDGE\$u" /OutputName:WebCacheV01.dat > $null
            }
        }
        
        if( -not (Test-Path "$Global:Destiny\$HOSTNAME\WebBrowsers\EDGE\"))
        {
            Write-Host "`t[i] There is no IE Browser in the System for user $u ..." -ForegroundColor Yellow
        }
    }
}

<########### S A F A R I #########################################################> # SAF*
Function Collect-Safari-Data {
    
    Write-Host "[+] Collecting SAFARI Artifacts ..." -ForegroundColor Green
    
    foreach($u in $USERS){

        Write-Host "`t○ for user $u ..." -ForegroundColor Green

        if($OS -eq "XP")
        {
            # CACHE ARTIFACTS
            if(Test-Path "$Global:Source\Documents and Settings\$u\Local Settings\Application Data\Apple Computer\Safari")
            {
                try
                {
                    Write-Host "`t`t○ Cache Artifacts ..." -ForegroundColor Green
                    
                    if ( -Not ( Test-Path "$Global:Destiny\$HOSTNAME\WebBrowsers\Safari\$u\CahceFiles" ) ) { New-Item -ItemType directory -Path "$Global:Destiny\$HOSTNAME\WebBrowsers\Safari\$u\CahceFiles" > $null }

                    copy "$Global:Source\Documents and Settings\$u\Local Settings\Application Data\Apple Computer\Safari\*" "$Global:Destiny\$HOSTNAME\WebBrowsers\Safari\$u\CahceFiles" 2> $null
                } 
                catch 
                {
                    Report-Error -evidence "Safari Cache artifacts"
                }
            }

            # USER DATA ARTIFACTS
            if(Test-Path "$Global:Source\Documents and Settings\$u\Application Data\Apple Computer\Safari")
            {
                try
                {
                    Write-Host "`t`t○ User data Artifacts ..." -ForegroundColor Green
                    
                    if ( -Not ( Test-Path "$Global:Destiny\$HOSTNAME\WebBrowsers\Safari\$u\UserData" ) ) { New-Item -ItemType directory -Path "$Global:Destiny\$HOSTNAME\WebBrowsers\Safari\$u\UserData" > $null }

                    copy "$Global:Source\Documents and Settings\$u\Application Data\Apple Computer\Safari\*" "$Global:Destiny\$HOSTNAME\WebBrowsers\Safari\$u\UserData"  2> $null
                } 
                catch 
                {
                    Report-Error -evidence "Safari User data artifacts"
                }
            }
        }
        else # all other windows versions after VISTA
        {
            # CACHE ARTIFACTS
            if(Test-Path "$Global:Source\Users\$u\AppData\Local\Apple Computer\Safari")
            {
                try
                {
                    Write-Host "`t`t○ Cache Artifacts ..." -ForegroundColor Green
                    
                    if ( -Not ( Test-Path "$Global:Destiny\$HOSTNAME\WebBrowsers\Safari\$u\CahceFiles" ) ) { New-Item -ItemType directory -Path "$Global:Destiny\$HOSTNAME\WebBrowsers\Safari\$u\CahceFiles" > $null }

                    copy "$Global:Source\Users\$u\AppData\Local\Apple Computer\Safari\*" "$Global:Destiny\$HOSTNAME\WebBrowsers\Safari\$u\CahceFiles"  2> $null
                } 
                catch 
                {
                    Report-Error -evidence "Safari Cache artifacts"
                }
            }

            # USER DATA ARTIFACTS
            if(Test-Path "$Global:Source\Users\$u\AppData\Roaming\Apple Computer\Safari")
            {
                try
                {
                    Write-Host "`t`t○ User data Artifacts ..." -ForegroundColor Green
                    
                    if ( -Not ( Test-Path "$Global:Destiny\$HOSTNAME\WebBrowsers\Safari\$u\UserData" ) ) { New-Item -ItemType directory -Path "$Global:Destiny\$HOSTNAME\WebBrowsers\Safari\$u\UserData" > $null }

                    copy "$Global:Source\Users\$u\AppData\Roaming\Apple Computer\Safari\*" "$Global:Destiny\$HOSTNAME\WebBrowsers\Safari\$u\UserData"  2> $null
                } 
                catch 
                {
                    Report-Error -evidence "Safari User data artifacts"
                }
            }
        }

        if( -not (Test-Path "$Global:Destiny\$HOSTNAME\WebBrowsers\Safari\")){
            Write-Host "`t[i] There is no Opera Browser in the System for user $u ..." -ForegroundColor Yellow
        }
    }
}

<########### O P E R A ###########################################################> # OPE*
Function Collect-Opera-Data {

    Write-Host "[+] Collecting Opera Artifacts ..." -ForegroundColor Green

    $filesToDownload = "Cookies","Favicons","History","Login Data","Network Action Predictor","QuotaManager","Shortcuts","Top sites","Web Data"

    foreach($u in $USERS){
    
        Write-Host "`t○ for user $u ..." -ForegroundColor Green

        if($OS -eq "XP")
        {
            # C:\Documents and Settings\%USERNAME%\Application Data\Opera Software\Opera Stable
            if(Test-Path "$Global:Source\Documents and Settings\$u\Application Data\Opera Software")
            {
                try
                {
                    # Other Profiles that should have the word profile in it                    
                    Get-ChildItem "$Global:Source\Documents and Settings\$u\Application Data\Opera Software" -Directory | ForEach-Object {
                        
                        if(Test-Path "$Global:Source\Documents and Settings\$u\Application Data\Opera Software\$($_.Name)")
                        {
                            if ( -Not ( Test-Path "$Global:Destiny\$HOSTNAME\WebBrowsers\Opera\$u\$($_.Name)" ) ) { New-Item -ItemType directory -Path "$Global:Destiny\$HOSTNAME\WebBrowsers\Opera\$u\$($_.Name)" > $null }

                            Write-Host "`t`t○ `"$($_.Name)`" found ..." -ForegroundColor Green

                            foreach($file in $filesToDownload)
                            {
                                if (Test-Path "$Global:Source\Documents and Settings\$u\Application Data\Opera Software\$($_.Name)\$file")
                                {
                                    copy "$Global:Source\Documents and Settings\$u\Application Data\Opera Software\$($_.Name)\$file" "$Global:Destiny\$HOSTNAME\WebBrowsers\Opera\$u\$($_.Name)"
                                }
                            }
                        }
                    }
                } 
                catch 
                {
                    Report-Error -evidence "Opera files"
                }
            }
        }
        else # all other windows versions after VISTA
        {
            #C:\Users\IMFReversing\AppData\Roaming\Opera Software\Opera Stable
            if(Test-Path "$Global:Source\Users\$u\AppData\Roaming\Opera Software")
            {
                try
                {
                    # Other Profiles that should have the word profile in it                    
                    Get-ChildItem "$Global:Source\Users\$u\AppData\Roaming\Opera Software" -Directory | ForEach-Object {
                        
                        if(Test-Path "$Global:Source\Users\$u\AppData\Roaming\Opera Software\$($_.Name)")
                        {
                            if ( -Not ( Test-Path "$Global:Destiny\$HOSTNAME\WebBrowsers\Opera\$u\$($_.Name)" ) ) { New-Item -ItemType directory -Path "$Global:Destiny\$HOSTNAME\WebBrowsers\Opera\$u\$($_.Name)" > $null }

                            Write-Host "`t`t○ `"$($_.Name)`" found ..." -ForegroundColor Green

                            foreach($file in $filesToDownload)
                            {
                                if (Test-Path "$Global:Source\Users\$u\AppData\Roaming\Opera Software\$($_.Name)\$file")
                                {
                                    copy "$Global:Source\Users\$u\AppData\Roaming\Opera Software\$($_.Name)\$file" "$Global:Destiny\$HOSTNAME\WebBrowsers\Opera\$u\$($_.Name)"
                                }
                            }
                        }
                    }
                } 
                catch 
                {
                    Report-Error -evidence "Chrome files"
                }
            }
        }

        if( -not (Test-Path "$Global:Destiny\$HOSTNAME\WebBrowsers\Opera\")){
            Write-Host "`t[i] There is no Opera Browser in the System for user $u ..." -ForegroundColor Yellow
        }
    }
}

<########### T O R ###############################################################> # TOR*
Function Collect-Tor-Data {
    
    $filesToDownload = "content-prefs.sqlite","cookies.sqlite","favicons.sqlite","formhistory.sqlite","permissions.sqlite","places.sqlite","storage.sqlite","storage-sync.sqlite","webappsstore.sqlite"

    Write-Host "[+] Searching for Tor in the System ..." -ForegroundColor Green

    # Search for the TOR Browser un the Source unit
    Get-ChildItem -Directory -Recurse "$Global:Source`\" 2> $null | foreach{
        if($_.Name -match "Tor Browser") 
        {
            $pathTOR = $_.FullName

            Write-Host "`t○ Tor Browser found in the System on folder $pathTOR..." -ForegroundColor Green

            try
            {
                Write-Host "`t○ Collecting TOR Artifacts ..." -ForegroundColor Green

                # Search for profiles                
                Get-ChildItem "$pathTOR\Browser\TorBrowser\Data\Browser" -Directory 2> $null | ForEach-Object {
                        
                    if($_.Name -match "Profile" -and $_.Name -notmatch "meek-http-helper" -and $_.Name -notmatch "moat-http-helper" )
                    {
                        if(Test-Path "$pathTOR\Browser\TorBrowser\Data\Browser\$($_.Name)")
                        {
                            if ( -Not ( Test-Path "$Global:Destiny\$HOSTNAME\WebBrowsers\TOR\$($_.Name)" ) ) { New-Item -ItemType directory -Path "$Global:Destiny\$HOSTNAME\WebBrowsers\TOR\$($_.Name)" > $null }

                            Write-Host "`t`t○ `"$($_.Name)`" found ..." -ForegroundColor Green

                            foreach($file in $filesToDownload)
                            {
                                if (Test-Path "$pathTOR\Browser\TorBrowser\Data\Browser\$($_.Name)\$file")
                                {
                                    copy "$pathTOR\Browser\TorBrowser\Data\Browser\$($_.Name)\$file" "$Global:Destiny\$HOSTNAME\WebBrowsers\TOR\$($_.Name)"
                                }
                            }
                        }
                    }
                }
            } 
            catch 
            {
                Report-Error -evidence "TOR Artifacts"
            }
            
            #break #continue #return #continue # After found finish searching # TODO: Whether Continue whether Break it breaks the code execution of the script
        }
    }

    # The Below only if Break, continue or return work in finishing this foreach
    # Write-Host "`t○ Tor NOT found in the System ..." -ForegroundColor Yellow 
}


<########### C L O U D #####################################################>

<########### CLOUD - ONEDRIVE ##############################> # COD*
Function Collect-Cloud-OneDrive-Logs {
# It collects the logs, but I don't know how to Parse the information   
    Write-Host "[+] Collecting OneDrive Logs ..." -ForegroundColor Green

    foreach($u in $USERS)
    {
        if( Test-Path "$Global:Source\Users\$u\AppData\Local\Microsoft\OneDrive\logs" )
        {
            Write-Host "`t○ from user: $u" -ForegroundColor Green

            # BUSINESS1 logs
            try 
            {
                Write-Host "`t`t○ Business1 folder" -ForegroundColor Green
                if ( -Not ( Test-Path "$Global:Destiny\$HOSTNAME\Cloud\ONEDRIVE\$u\Business1" ) ) { New-Item -ItemType directory -Path "$Global:Destiny\$HOSTNAME\Cloud\ONEDRIVE\$u\Business1" > $null }
                Copy-Item "$Global:Source\Users\$u\AppData\Local\Microsoft\OneDrive\logs\Business1\*.*" "$Global:Destiny\$HOSTNAME\Cloud\ONEDRIVE\$u\Business1" > $null
            } 
            catch 
            {
                Report-Error -evidence "OneDrive Business1 Logs"
            }

            # COMMON logs
            try 
            {
                Write-Host "`t`t○ Common folder" -ForegroundColor Green
                if ( -Not ( Test-Path "$Global:Destiny\$HOSTNAME\Cloud\ONEDRIVE\$u\Common" ) ) { New-Item -ItemType directory -Path "$Global:Destiny\$HOSTNAME\Cloud\ONEDRIVE\$u\Common" > $null }
                Copy-Item "$Global:Source\Users\$u\AppData\Local\Microsoft\OneDrive\logs\Common\*.*" "$Global:Destiny\$HOSTNAME\Cloud\ONEDRIVE\$u\Common" > $null
            } 
            catch 
            {
                Report-Error -evidence "OneDrive Common Logs"
            }

            # Personal logs
            try 
            {
                Write-Host "`t`t○ Personal folder" -ForegroundColor Green
                if ( -Not ( Test-Path "$Global:Destiny\$HOSTNAME\Cloud\ONEDRIVE\$u\Personal" ) ) { New-Item -ItemType directory -Path "$Global:Destiny\$HOSTNAME\Cloud\ONEDRIVE\$u\Personal" > $null }
                Copy-Item "$Global:Source\Users\$u\AppData\Local\Microsoft\OneDrive\logs\Personal\*.*" "$Global:Destiny\$HOSTNAME\Cloud\ONEDRIVE\$u\Personal" > $null
            } 
            catch 
            {
                Report-Error -evidence "OneDrive Personal Logs"
            }
        }
    }
}

<########### CLOUD - GOOGLE DRIVE ##########################> # CGD*
Function Collect-Cloud-GoogleDrive-Logs {
    
    Write-Host "[+] Collecting GoogleDrive Logs ..." -ForegroundColor Green

    foreach($u in $USERS)
    {
        if( Test-Path "$Global:Source\Users\$u\AppData\Local\Google\Drive\user_default" )
        {
            Write-Host "`t○ from user: $u" -ForegroundColor Green
            
            # DB google drive files
            try 
            {
                Write-Host "`t`t○ DB files" -ForegroundColor Green
                if ( -Not ( Test-Path "$Global:Destiny\$HOSTNAME\Cloud\GOOGLEDRIVE\$u" ) ) { New-Item -ItemType directory -Path "$Global:Destiny\$HOSTNAME\Cloud\GOOGLEDRIVE\$u" > $null }
                Copy-Item "$Global:Source\Users\$u\AppData\Local\Google\Drive\user_default\*.db" "$Global:Destiny\$HOSTNAME\Cloud\GOOGLEDRIVE\$u" > $null
            } 
            catch 
            {
                Report-Error -evidence "Google Drive DB files"
            }

            # LOG google drive file
            try 
            {
                Write-Host "`t`t○ LOG files" -ForegroundColor Green
                if ( -Not ( Test-Path "$Global:Destiny\$HOSTNAME\Cloud\GOOGLEDRIVE\$u" ) ) { New-Item -ItemType directory -Path "$Global:Destiny\$HOSTNAME\Cloud\GOOGLEDRIVE\$u" > $null }
                Copy-Item "$Global:Source\Users\$u\AppData\Local\Google\Drive\user_default\*.log" "$Global:Destiny\$HOSTNAME\Cloud\GOOGLEDRIVE\$u\." > $null
            } 
            catch 
            {
                Report-Error -evidence "Google Drive LOG file"
            }
        }
    }
}

<########### CLOUD - DROPBOX ##############################>  # CDB*
Function Collect-Cloud-Dropbox-Logs {
    
    Write-Host "[+] Collecting Dropbox Logs ..." -ForegroundColor Green

    foreach($u in $USERS)
    {
        if( Test-Path "$Global:Source\Users\$u\AppData\Local\Dropbox" )
        {
            Write-Host "`t○ From user: $u" -ForegroundColor Green        
            
            # INSTANCE1
            if ( -Not ( Test-Path "$Global:Destiny\$HOSTNAME\Cloud\DROPBOX\$u\instance1" ) ) { New-Item -ItemType directory -Path "$Global:Destiny\$HOSTNAME\Cloud\DROPBOX\$u\instance1" > $null }
            
            try
            {
                Copy-Item "$Global:Source\Users\$u\AppData\Local\Dropbox\instance1\*.dbx" "$Global:Destiny\$HOSTNAME\Cloud\DROPBOX\$u\instance1\." > $null
            } 
            catch 
            {
                Report-Error -evidence "DropBox DBX Files from INSTANCE1"
            }
            
            # INSTANCE_DB
            if ( -Not ( Test-Path "$Global:Destiny\$HOSTNAME\Cloud\DROPBOX\$u\instance_db" ) ) { New-Item -ItemType directory -Path "$Global:Destiny\$HOSTNAME\Cloud\DROPBOX\$u\instance_db" > $null }

            try
            {
                Copy-Item "$Global:Source\Users\$u\AppData\Local\Dropbox\instance_db\*.dbx" "$Global:Destiny\$HOSTNAME\Cloud\DROPBOX\$u\instance_db\." > $null
            } 
            catch 
            {
                Report-Error -evidence "DropBox DBX Files from INSTANCE_DB"
            }
        }
    }

    # GETTING KEYS TO DECRYPT DROPBOX FILES
    Write-Host "`t○ Getting Keys to Decrypt Dropbox DBX files ..." -ForegroundColor Green

    if ( -Not ( Test-Path "$Global:Destiny\$HOSTNAME\z_temp" ) ) { New-Item -ItemType directory -Path "$Global:Destiny\$HOSTNAME\z_temp" > $null }

    & $SCRIPTPATH\bin\dbx-key-win-live.ps1 > "$Global:Destiny\$HOSTNAME\z_temp\keys.txt"

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
        Write-Host "`t○ Decrypting Dropbox DBX files ..." -ForegroundColor Green

        Write-Host "`t`t○ From user: $u" -ForegroundColor Green

        $rootTemp = $Global:Destiny -replace "\\","\\"

        Get-ChildItem "$Global:Destiny\$HOSTNAME\Cloud\DROPBOX\$u\instance1" -Filter *.dbx | ForEach-Object {
            try
            {
                if($_.Extension -ne ".dbx-wal" -and $_.Extension -ne ".dbx-shm" -and $_.BaseName -ne "aggregation")
                {
                    $bn=$_.BaseName
                    & $SQL_DBX_EXE -key $ks1_key $_.FullName ".backup $rootTemp\\$HOSTNAME\\\Cloud\\DROPBOX\\$u\\instance1\\$bn.db" 
                }
            } 
            catch 
            {
                Report-Error -evidence "DropBox File: $_.FullName"
            }
        }

        Get-ChildItem "$Global:Destiny\$HOSTNAME\Cloud\DROPBOX\$u\instance_db" -Filter *.dbx | ForEach-Object {
            try
            {
                $bn=$_.BaseName
                & $SQL_DBX_EXE -key $ks_key $_.FullName ".backup $rootTemp\\$HOSTNAME\\\Cloud\\DROPBOX\\$u\\instance_db\\$bn.db" 
            } 
            catch 
            {
                Report-Error -evidence "DropBox File: $_.FullName"
            }
        }
    }

    Remove-Item -Recurse -Path "$Global:Destiny\$HOSTNAME\z_temp"
}


<########### S I G N E D   F I L E S ######################> # SFI <# TIME CONSUMING - Not by Default#>
Function Collect-Sign-Files {
    
    if( -not (Test-Path "$Global:Destiny\$HOSTNAME\Signed_Files\") ) { New-Item -ItemType Directory -Path "$Global:Destiny\$HOSTNAME\Signed_Files\" > $null }

    Write-Host "[+] Collecting Info About Signed Files " -ForegroundColor Green
    try
    {
        & $SIG_EXE /accepteula -vt -h -c -e -q -v $Global:Source\Windows\ >> "$Global:Destiny\$HOSTNAME\Signed_Files\SignedFiles_Windows.csv" 
        & $SIG_EXE /accepteula -vt -h -c -e -q -v $Global:Source\Windows\system32\ >> "$Global:Destiny\$HOSTNAME\Signed_Files\SignedFiles_WindowsSystem32.csv" 
    } 
    catch 
    {
        Report-Error -evidence "Info About Signed Files"
    }
}


<##################################################################################################################################>
<############  MANAGE GRAPHIC AND NON GRAPHIC EXECUTION  #############################>
<##################################################################################################################################>

<# MANAGE NO GUI EXECUTION #>
Function Control-NOGUI{

    Write-Host "[+] Starting the collection of $HOSTNAME computer artifacts..."  -ForegroundColor Magenta
    $TotalScriptTime = [Diagnostics.Stopwatch]::StartNew()
    Collect-Time -Status Start
    
    if($GUI -eq $false) {$Global:Destiny = "$Global:Destiny\"}

    # LIVE
    
    if ($All -or $Global:RAM ) {$ScriptTime = [Diagnostics.Stopwatch]::StartNew(); Collect-Memory-Dump ; $ScriptTime.Stop(); Write-Host "`t└>Execution time: $($ScriptTime.Elapsed)" -ForegroundColor Gray }                      # 00:22 4GB

    if ($All -or $Global:NET ) {$ScriptTime = [Diagnostics.Stopwatch]::StartNew(); Collect-Network-Information ; $ScriptTime.Stop(); Write-Host "`t└>Execution time: $($ScriptTime.Elapsed)" -ForegroundColor Gray }              # 00:23
    if ($All -or $Global:SAP ) {$ScriptTime = [Diagnostics.Stopwatch]::StartNew(); Collect-Services-and-Processes ; $ScriptTime.Stop(); Write-Host "`t└>Execution time: $($ScriptTime.Elapsed)" -ForegroundColor Gray }           # 01:03
    if ($All -or $Global:STA ) {$ScriptTime = [Diagnostics.Stopwatch]::StartNew(); Collect-Scheduled-Tasks ; $ScriptTime.Stop(); Write-Host "`t└>Execution time: $($ScriptTime.Elapsed)" -ForegroundColor Gray }                  # 00:02
    if ($All -or $Global:CPH ) {$ScriptTime = [Diagnostics.Stopwatch]::StartNew(); Collect-PSCommand-History ; $ScriptTime.Stop(); Write-Host "`t└>Execution time: $($ScriptTime.Elapsed)" -ForegroundColor Gray }                # 00:00
    if ($All -or $Global:INS ) {$ScriptTime = [Diagnostics.Stopwatch]::StartNew(); Collect-Installed-Software ; $ScriptTime.Stop(); Write-Host "`t└>Execution time: $($ScriptTime.Elapsed)" -ForegroundColor Gray }               # 00:11
    if ($All -or $Global:UGR ) {$ScriptTime = [Diagnostics.Stopwatch]::StartNew(); Collect-Users-Groups ; $ScriptTime.Stop(); Write-Host "`t└>Execution time: $($ScriptTime.Elapsed)" -ForegroundColor Gray }                     # 00:00
    if ($All -or $Global:PER ) {$ScriptTime = [Diagnostics.Stopwatch]::StartNew(); Collect-Persistence ; $ScriptTime.Stop(); Write-Host "`t└>Execution time: $($ScriptTime.Elapsed)" -ForegroundColor Gray }                      # 00:03
    if ($All -or $Global:USB ) {$ScriptTime = [Diagnostics.Stopwatch]::StartNew(); Collect-USB-Info ; $ScriptTime.Stop(); Write-Host "`t└>Execution time: $($ScriptTime.Elapsed)" -ForegroundColor Gray }                         # 00:00
    if ($All -or $Global:PNP ) {$ScriptTime = [Diagnostics.Stopwatch]::StartNew(); Collect-PnPDevices-Info ; $ScriptTime.Stop(); Write-Host "`t└>Execution time: $($ScriptTime.Elapsed)" -ForegroundColor Gray }                     # 00:40
    if ($All -or $Global:SEC ) {$ScriptTime = [Diagnostics.Stopwatch]::StartNew(); Collect-Firewall-Config ; $ScriptTime.Stop(); Write-Host "`t└>Execution time: $($ScriptTime.Elapsed)" -ForegroundColor Gray }                  # 00:03

    if ($All -or $Global:MRU ) {$ScriptTime = [Diagnostics.Stopwatch]::StartNew(); Collect-MRUs ; $ScriptTime.Stop(); Write-Host "`t└>Execution time: $($ScriptTime.Elapsed)" -ForegroundColor Gray }                             # 00:25
    if (         $Global:SHI ) {$ScriptTime = [Diagnostics.Stopwatch]::StartNew(); Collect-Shimcache ; $ScriptTime.Stop(); Write-Host "`t└>Execution time: $($ScriptTime.Elapsed)" -ForegroundColor Gray }                        # ??:??
    if (         $Global:RAP ) {$ScriptTime = [Diagnostics.Stopwatch]::StartNew(); Collect-RecentApps ; $ScriptTime.Stop(); Write-Host "`t└>Execution time: $($ScriptTime.Elapsed)" -ForegroundColor Gray }                       # ??:??

    if ($All -or $Global:BAM ) {$ScriptTime = [Diagnostics.Stopwatch]::StartNew(); Collect-BAM ; $ScriptTime.Stop(); Write-Host "`t└>Execution time: $($ScriptTime.Elapsed)" -ForegroundColor Gray }                              # ??:??
    if ($All -or $Global:SYS ) {$ScriptTime = [Diagnostics.Stopwatch]::StartNew(); Collect-System-Info ; $ScriptTime.Stop(); Write-Host "`t└>Execution time: $($ScriptTime.Elapsed)" -ForegroundColor Gray }                      # ??:??
    if ($All -or $Global:LAC ) {$ScriptTime = [Diagnostics.Stopwatch]::StartNew(); Collect-Last-Activity ; $ScriptTime.Stop(); Write-Host "`t└>Execution time: $($ScriptTime.Elapsed)" -ForegroundColor Gray }                    # ??:??
    if (         $Global:AFI ) {$ScriptTime = [Diagnostics.Stopwatch]::StartNew(); Collect-Autorun-Files ; $ScriptTime.Stop(); Write-Host "`t└>Execution time: $($ScriptTime.Elapsed)" -ForegroundColor Gray }                    # 05:40

    # OFFLINE
    if ($All -or $Global:HIV ) {$ScriptTime = [Diagnostics.Stopwatch]::StartNew(); Collect-Hives ; $ScriptTime.Stop(); Write-Host "`t└>Execution time: $($ScriptTime.Elapsed)" -ForegroundColor Gray }                            # ??:??
    if ($All -or $Global:EVT ) {$ScriptTime = [Diagnostics.Stopwatch]::StartNew(); Collect-EVTX-Files ; $ScriptTime.Stop(); Write-Host "`t└>Execution time: $($ScriptTime.Elapsed)" -ForegroundColor Gray }                       # ??:??
    if ($All -or $Global:EET ) {$ScriptTime = [Diagnostics.Stopwatch]::StartNew(); Collect-ETW-ETL ; $ScriptTime.Stop(); Write-Host "`t└>Execution time: $($ScriptTime.Elapsed)" -ForegroundColor Gray }                          # ??:??
    if ($All -or $Global:FIL ) {$ScriptTime = [Diagnostics.Stopwatch]::StartNew(); Collect-Files-Lists ; $ScriptTime.Stop(); Write-Host "`t└>Execution time: $($ScriptTime.Elapsed)" -ForegroundColor Gray }                      # ??:??
    if (         $Global:DEX ) {$ScriptTime = [Diagnostics.Stopwatch]::StartNew(); Collect-Dangerous-Extensions ; $ScriptTime.Stop(); Write-Host "`t└>Execution time: $($ScriptTime.Elapsed)" -ForegroundColor Gray }             # 07:05
    if ($All -or $Global:PRF ) {$ScriptTime = [Diagnostics.Stopwatch]::StartNew(); Collect-Prefetch ; $ScriptTime.Stop(); Write-Host "`t└>Execution time: $($ScriptTime.Elapsed)" -ForegroundColor Gray }                         # ??:??
    if ($All -or $Global:WSE ) {$ScriptTime = [Diagnostics.Stopwatch]::StartNew(); Collect-Windows-Search ; $ScriptTime.Stop(); Write-Host "`t└>Execution time: $($ScriptTime.Elapsed)" -ForegroundColor Gray }                   # ??:??
    if ($All -or $Global:JLI ) {$ScriptTime = [Diagnostics.Stopwatch]::StartNew(); Collect-JumpLists ; $ScriptTime.Stop(); Write-Host "`t└>Execution time: $($ScriptTime.Elapsed)" -ForegroundColor Gray }                        # ??:??
    if ($All -or $Global:TIC ) {$ScriptTime = [Diagnostics.Stopwatch]::StartNew(); Collect-Thumcache-Iconcache ; $ScriptTime.Stop(); Write-Host "`t└>Execution time: $($ScriptTime.Elapsed)" -ForegroundColor Gray }              # ??:??
    
    if ($All -or $Global:FSF ) {$ScriptTime = [Diagnostics.Stopwatch]::StartNew(); Collect-FileSystemFiles ; $ScriptTime.Stop(); Write-Host "`t└>Execution time: $($ScriptTime.Elapsed)" -ForegroundColor Gray }                  # ??:??
    if ($All -or $Global:MSF ) {$ScriptTime = [Diagnostics.Stopwatch]::StartNew(); Collect-MemorySupportFiles ; $ScriptTime.Stop(); Write-Host "`t└>Execution time: $($ScriptTime.Elapsed)" -ForegroundColor Gray }               # ??:??

    if ($All -or $Global:TLH ) {$ScriptTime = [Diagnostics.Stopwatch]::StartNew(); Collect-Timeline ; $ScriptTime.Stop(); Write-Host "`t└>Execution time: $($ScriptTime.Elapsed)" -ForegroundColor Gray }                         # ??:??

    if ($All -or $Global:THA ) {$ScriptTime = [Diagnostics.Stopwatch]::StartNew(); Collect-TextHarvester ; $ScriptTime.Stop(); Write-Host "`t└>Execution time: $($ScriptTime.Elapsed)" -ForegroundColor Gray }                    # ??:??
    if ($All -or $Global:SRU ) {$ScriptTime = [Diagnostics.Stopwatch]::StartNew(); Collect-SRUM ; $ScriptTime.Stop(); Write-Host "`t└>Execution time: $($ScriptTime.Elapsed)" -ForegroundColor Gray }                             # ??:??
    if ($All -or $Global:CRE ) {$ScriptTime = [Diagnostics.Stopwatch]::StartNew(); Collect-Credentials ; $ScriptTime.Stop(); Write-Host "`t└>Execution time: $($ScriptTime.Elapsed)" -ForegroundColor Gray }                      # ??:??
    
    if ($All -or $Global:SKY ) {$ScriptTime = [Diagnostics.Stopwatch]::StartNew(); Collect-Skype-History ; $ScriptTime.Stop(); Write-Host "`t└>Execution time: $($ScriptTime.Elapsed)" -ForegroundColor Gray }                    # ??:??
    if ($All -or $Global:EMA ) {$ScriptTime = [Diagnostics.Stopwatch]::StartNew(); Collect-Email-Files ; $ScriptTime.Stop(); Write-Host "`t└>Execution time: $($ScriptTime.Elapsed)" -ForegroundColor Gray }                      # 04:00

    if ($All -or $Global:CHR ) {$ScriptTime = [Diagnostics.Stopwatch]::StartNew(); Collect-Chrome-Data ; $ScriptTime.Stop(); Write-Host "`t└>Execution time: $($ScriptTime.Elapsed)" -ForegroundColor Gray }                      # ??:??
    if ($All -or $Global:MFI ) {$ScriptTime = [Diagnostics.Stopwatch]::StartNew(); Collect-Firefox-Data ; $ScriptTime.Stop(); Write-Host "`t└>Execution time: $($ScriptTime.Elapsed)" -ForegroundColor Gray }                     # ??:??
    if ($All -or $Global:IEX ) {$ScriptTime = [Diagnostics.Stopwatch]::StartNew(); Collect-IE-Data ; $ScriptTime.Stop(); Write-Host "`t└>Execution time: $($ScriptTime.Elapsed)" -ForegroundColor Gray }                          # ??:??
    if ($All -or $Global:EDG ) {$ScriptTime = [Diagnostics.Stopwatch]::StartNew(); Collect-EDGE-Data ; $ScriptTime.Stop(); Write-Host "`t└>Execution time: $($ScriptTime.Elapsed)" -ForegroundColor Gray }                        # ??:??
    if ($All -or $Global:SAF ) {$ScriptTime = [Diagnostics.Stopwatch]::StartNew(); Collect-Safari-Data ; $ScriptTime.Stop(); Write-Host "`t└>Execution time: $($ScriptTime.Elapsed)" -ForegroundColor Gray }                      # ??:??
    if ($All -or $Global:OPE ) {$ScriptTime = [Diagnostics.Stopwatch]::StartNew(); Collect-Opera-Data ; $ScriptTime.Stop(); Write-Host "`t└>Execution time: $($ScriptTime.Elapsed)" -ForegroundColor Gray }                       # ??:??
    if ($All -or $Global:TOR ) {$ScriptTime = [Diagnostics.Stopwatch]::StartNew(); Collect-Tor-Data ; $ScriptTime.Stop(); Write-Host "`t└>Execution time: $($ScriptTime.Elapsed)" -ForegroundColor Gray }                         # ??:??

    if ($All -or $Global:COD ) {$ScriptTime = [Diagnostics.Stopwatch]::StartNew(); Collect-Cloud-OneDrive-Logs ; $ScriptTime.Stop(); Write-Host "`t└>Execution time: $($ScriptTime.Elapsed)" -ForegroundColor Gray }              # ??:??
    if ($All -or $Global:CGD ) {$ScriptTime = [Diagnostics.Stopwatch]::StartNew(); Collect-Cloud-GoogleDrive-Logs ; $ScriptTime.Stop(); Write-Host "`t└>Execution time: $($ScriptTime.Elapsed)" -ForegroundColor Gray }           # ??:??
    if ($All -or $Global:CDB ) {$ScriptTime = [Diagnostics.Stopwatch]::StartNew(); Collect-Cloud-Dropbox-Logs ; $ScriptTime.Stop(); Write-Host "`t└>Execution time: $($ScriptTime.Elapsed)" -ForegroundColor Gray }               # ??:??
    
    if (         $Global:SFI ) {$ScriptTime = [Diagnostics.Stopwatch]::StartNew(); Collect-Sign-Files ; $ScriptTime.Stop(); Write-Host "`t└>Execution time: $($ScriptTime.Elapsed)" -ForegroundColor Gray }                       # ??:??

    Collect-Time -Status Finish

    $TotalScriptTime.Stop()
    Write-Host "[*] TOTAL Script Execution time: $($TotalScriptTime.Elapsed)"  -ForegroundColor Magenta
    Write-Host "[*] Finished to collect all the Evidence!"   -ForegroundColor Magenta
}

<# MANAGE GUI EXECTION #> 
Function Control-GUI {

    <#TODO: separate the creation of the interface with the execution control #>
    
    param(
        [string]$testtt="bla"
    )
    ############################################ Import Assemblies ################################################################
    Add-Type -AssemblyName System.Windows.Forms
    Add-Type -AssemblyName System.Drawing

    ############################################ B A N N E R ######################################################################

    $Banner = New-Object System.Windows.Forms.RichTextBox
    $Banner.location = New-Object System.Drawing.Point(50, 30)
    $Banner.Size = New-Object System.Drawing.Size(710, 225)
    $Banner.Name = "Banner"
    $Banner.Font = New-Object System.Drawing.Font("Lucida Console", "9")
    $Banner.Multiline = $True
    $Banner.ReadOnly = $True
    $Banner.TabStop = $False
    $Banner.ForeColor = [System.Drawing.Color]::GhostWhite        #AntiqueWhite, FloralWhite
    $Banner.BackColor = [System.Drawing.Color]::Black
    $Banner.Text += "`n"
    $Banner.Text += "  ▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▒`n"
    $Banner.Text += "  ▓                                                                                              ▒`n"
    $Banner.Text += "  ▓    ######\                               ##\           ##\   ##\                             ▒`n"
    $Banner.Text += "  ▓    \_##  _|                              \__|          \__|  ## |                            ▒`n"
    $Banner.Text += "  ▓      ## |  #######\   ######\  ##\   ##\ ##\  #######\ ##\ ######\    ######\   ######\      ▒`n"
    $Banner.Text += "  ▓      ## |  ##  __##\ ##  __##\ ## |  ## |## |##  _____|## |\_##  _|  ##  __##\ ##  __##\     ▒`n"
    $Banner.Text += "  ▓      ## |  ## |  ## |## /  ## |## |  ## |## |\######\  ## |  ## |    ## /  ## |## |  \__|    ▒`n"
    $Banner.Text += "  ▓      ## |  ## |  ## |## |  ## |## |  ## |## | \____##\ ## |  ## |##\ ## |  ## |## |          ▒`n"
    $Banner.Text += "  ▓    ######\ ## |  ## |\####### |\######  |## |#######  |## |  \####  |\######  |## |          ▒`n"
    $Banner.Text += "  ▓    \______|\__|  \__| \____## | \______/ \__|\_______/ \__|   \____/  \______/ \__|          ▒`n"
    $Banner.Text += "  ▓                            ## |                                                              ▒`n"
    $Banner.Text += "  ▓                            ## |                              Forensic artifacts collector    ▒`n"
    $Banner.Text += "  ▓                            \__|                              By:      f4d0                   ▒`n"
    $Banner.Text += "  ▓                                                              Version: 0.7                    ▒`n"
    $Banner.Text += "  ▓                                                                                              ▒`n"
    $Banner.Text += "  ▓▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒`n"
    
    ############################################ Pop Up Help Definition ################################################################

    #define a tooltip object
    $tooltipOptions = New-Object System.Windows.Forms.ToolTip
 
    <#
    define a scriptblock to display the tooltip
    add a _MouseHover event to display the corresponding tool tip
     e.g. $txtPath.add_MouseHover($ShowHelp)
     #>
    $ShowHelp={
     #display popup help
        #each value is the name of a control on the form.
        echo $this.name
        Switch ($this.name) {
            
            "labelSource" {$tip = "Please select the source to collect artifacts from"}
            "labelDestiny" {$tip = "Please select the destiny to collect artifacts to"}
            "buttonDestiny" {$tip = "Click to select the destiny."}
            "checkBoxFormat" {$tip = "To format the destiny unit."}
            "checkBoxFormatQuick" {$tip = "Quick format the destiny unit."}
            "checkBoxFormatZero" {$tip = "Format the destiny unit setting all the bits to Zero."}
            "checkBoxHash" {$tip = "Hash all the collected files."}
            "checkBoxHashMD5" {$tip = "Use MD5 hashing algorithm."}
            "checkBoxHashSHA256" {$tip = "Use SHA256 hashing algorithm."}
            "buttonExecute" {$tip = "Execute the collection and parsing of the selected options."}
            "labelColType" {$tip = "Please select a collection type to quick select the desirable options."}
            "radioButtonAll" {$tip = "Select all the options."}
            "radioButtonLive" {$tip = "Only live acquisition options."}
            "radioButtonLiveOpt" {$tip = "Live acquisition options optimized to take the less time."}
            "radioButtonOffline" {$tip = "Only offline acquisition options."}
            "radioButtonOfflineOpt" {$tip = "Offline acquisition options optimized to take the less time."}
            "checkBoxRAM" {$tip = "Collection of: `n- Random Access Memory (RAM)"}
            "checkBoxNET" {$tip = "Collection of: `n- TCP and UDP connections `n- Netbios sessions `n- Net session and Net file `n- Network configuration `n- DNS and ARP cache `n- WiFi network"}
            "checkBoxSAP" {$tip = "Collection of: `n- Running services `n- Running processes `n- Processes and their process parents"}
            "checkBoxSTA" {$tip = "Collection of: `n- Scheduled tasks"}
            "checkBoxCPH" {$tip = "Collection of: `n- Powershell command line history"}
            "checkBoxINS" {$tip = "Collection of: `n- List of Installed software"}
            "checkBoxUGR" {$tip = "Collection of: `n- Users `n- Groups `n- Administrator users"}
            "checkBoxPER" {$tip = "Collection of: `n- Persistence : Registry run keys `n- Persistence : Shell Folders `n- Persistence : Winlogon helper dll `n- Persistence : Time providers `n- Persistence : SIP and trust provider hijacking `n- Persistence : Security Support Provider `n- Persistence : Port monitors `n- Persistence : Office application startup `n- Persistence : Change default file association `n- Persistence : AppInit DLLs `n- Persistence : AppCert DLLs"}
            "checkBoxUSB" {$tip = "Collection of: `n- USB devices information"}
            "checkBoxPNP" {$tip = "Collection of: `n- Plug and Play (PnP) devices information"}
            "checkBoxSEC" {$tip = "Collection of: `n- Firewall configuration and rules"}
            "checkBoxMRU" {$tip = "Collection and Parsing of: `n- MRUs : MUICache `n- MRUs : Recent docs `n- MRUs : Open/Saved files MRU `n- MRUs : User Assist `n- MRUs : ShellBags `n- MRUs : CIDSizeMRU `n- MRUs : Last Visited MRU `n- MRUs : RUN DialogBox MRU `n- MRUs : AppCompatCache (Shimcache) `n- MRUs : Recent Applications"}
            "checkBoxSHI" {$tip = "Collection and Parsing of: `n- AppCompatCache (Shimcache)"}
            "checkBoxRAP" {$tip = "Collection and Parsing of: `n- Recent applications"}
            "checkBoxBAM" {$tip = "Collection and Parsing of: `n- Background Activity Moderator (BAM)"}
            "checkBoxSYS" {$tip = "Collection of: `n- System Information `n- Hotfixes `n- Environment variables"}
            "checkBoxLAC" {$tip = "Collection of: `n- Running executables `n- Opening open/save dialog-box `n- Opening file/folder from Explorer or other software `n- software installation `n- system shutdown/start `n- application or system crash `n- network connection/disconnection `n- more..."}
            "checkBoxAFI" {$tip = "Collection of: `n- Running programs configured to run during the bootup or login"}
            "checkBoxHIV" {$tip = "Collection of: `n- HIVE : NTUDER.dat `n- DEFAULT `n- SAM `n- SECURITY `n- SOFTWARE `n- SYSTEM `n- COMPONENTS `n- UsrClass.dat `n- BCD-Template `n- BBI `n- DRIVERS `n- ELAM `n- Amcache.hve"}
            "checkBoxEVT" {$tip = "Collection of: `n- All EVTX files that are not empty"}
            "checkBoxEET" {$tip = "Collection of: `n- BootCKCL.etl `n- ShutdownCKCL.etl `n- WdiContextLog.etl.### `n- LwtNetLog.etl `n- Wifi.etl `n- setup.etl `n- ExplorerStartupLog.etl `n- ExplorerStartupLog_RunOnce.etl"}
            "checkBoxFIL" {$tip = "Collection of: `n- File system directory tree"}
            "checkBoxDEX" {$tip = "Collection of: `n- List of all the files in the system with the following extensions: `n- *.VB, `n- *.VBS, `n- *.PIF, `n- *.BAT, `n- *.CMD, `n- *.JS, `n- *.JSE, `n- *.WS, `n- *.WSF, `n- *.WSC, `n- *.WSH, `n- *.PS1, `n- *.PS1XML, `n- *.PS2, `n- *.PS2XML, `n- *.PSC1, `n- *.PSC2, `n- *.MSH, `n- *.MSH1, `n- *.MSH2, `n- *.MSHXML, `n- *.MSH1XML, `n- *.MSH2XML, `n- *.SCF, `n- *.LNK, `n- *.INF, `n- *.APPLICATION, `n- *.GADGET, `n- *.SCR, `n-*.HTA, `n- *.CPL, `n- *.MSI, `n- *.COM, `n- *.EXE"}
            "checkBoxPRF" {$tip = "Collection of: `n- All files with extension *.pf and *.db from prefetch directory"}
            "checkBoxWSE" {$tip = "Collection and Parsing of: `n- Windows Search Database (windows.edb)"}
            "checkBoxJLI" {$tip = "Collection and Parsing of: `n- AutomaticDestinations `n- CustomDestinations”}
            "checkBoxTIC" {$tip = "Collection and Parsing of: `n- ThumbCache files `n- IconCache files"}
            "checkBoxFSF" {$tip = "Collection of: `n- `$MFT `n- `$UsnJrnl `n- `$Logfile "}
            "checkBoxMSF" {$tip = "Collection of: `n- hiberfil.sys `n- pagefile.sys `n- swapfile.sys"}
            "checkBoxTLH" {$tip = "Collection and Parsing of: `n- Timeline History (ActivitiesCache.db)"}
            "checkBoxTHA" {$tip = "Collection and Parsing of: `n- Text Harverter (WaitList.dat)"}
            "checkBoxSRU" {$tip = "Collection and Parsing of: `n- System Resource Usage Monitor (SRUM) (SRUDB.dat)"}
            "checkBoxCRE" {$tip = "Collection and Parsing of: `n- Credentials Manager"}
            "checkBoxSKY" {$tip = "Collection and Parsing of: `n- Skype logs and conversations"}
            "checkBoxEMA" {$tip = "Collection of: `n- All OST files in the system `n- All PST files in the system"}
            "checkBoxCHR" {$tip = "Collection of: `n- Cookies `n- Favicons `n- History `n- Login Data `n- Network Action Predictor `n- QuotaManager `n- Shortcuts `n- Top sites `n- Web Data"}
            "checkBoxMFI" {$tip = "Collection of: `n- content-prefs.sqlite `n- cookies.sqlite `n- favicons.sqlite `n- formhistory.sqlite `n- permissions.sqlite `n- places.sqlite `n- storage.sqlite `n- storage-sync.sqlite `n- webappsstore.sqlite"}
            "checkBoxIEX" {$tip = "Collection of: `n- Registry Typed URLs `n- History (WebCacheV01.dat)"}
            "checkBoxEDG" {$tip = "Collection of: `n- Registry Typed URLs `n- History (WebCacheV01.dat)"}
            "checkBoxSAF" {$tip = "Collection of: `n- User Data logs `n- Cache logs"}
            "checkBoxOPE" {$tip = "Collection of: `n- Cookies `n- Favicons `n- History `n- Login Data `n- Network Action Predictor `n- QuotaManager `n- Shortcuts `n- Top sites `n- Web Data"}
            "checkBoxTOR" {$tip = "Collection of: `n- content-prefs.sqlite `n- cookies.sqlite `n- favicons.sqlite `n- formhistory.sqlite `n- permissions.sqlite `n- places.sqlite `n- storage.sqlite `n- storage-sync.sqlite `n- webappsstore.sqlite"}
            "checkBoxCOD" {$tip = "Collection of: `n- Business1 folder content `n- Common folder content `n- Personal folder content"}
            "checkBoxCGD" {$tip = "Collection of: `n- All *.log files from profile folder `n- All *.db files from profile folder"}
            "checkBoxCDB" {$tip = "Collection and Parsing of: `n- *.dbx files from the profile folder"}
            "checkBoxSFI" {$tip = "Collection of: `n- File signature from all files in %SystemDrive%\Windows\ `n- %SystemDrive%\Windows\System32"}
        }
    $tooltipOptions.SetToolTip($this,$tip)
    } #end ShowHelp
    
    ############################################ Controls Creation ################################################################

    # GENERAL PANEL
    $groupBoxGeneral = New-Object System.Windows.Forms.GroupBox
    $labelSource = New-Object System.Windows.Forms.Label
    $comboBoxSource = New-Object System.Windows.Forms.ComboBox
    $labelDestiny = New-Object System.Windows.Forms.Label
    $textBoxDestiny = New-Object System.Windows.Forms.TextBox
    $buttonDestiny = New-Object System.Windows.Forms.Button
    $checkBoxFormat = New-Object System.Windows.Forms.CheckBox
    $checkBoxFormatQuick = New-Object System.Windows.Forms.CheckBox
    $checkBoxFormatZero = New-Object System.Windows.Forms.CheckBox
    $checkBoxHash = New-Object System.Windows.Forms.CheckBox
    $checkBoxHashMD5 = New-Object System.Windows.Forms.CheckBox
    $checkBoxHashSHA256 = New-Object System.Windows.Forms.CheckBox
    $buttonExecute = New-Object System.Windows.Forms.Button
    $labelColType = New-Object System.Windows.Forms.Label
    $radioButtonAll = New-Object System.Windows.Forms.RadioButton
    $radioButtonLive = New-Object System.Windows.Forms.RadioButton
    $radioButtonLiveOpt = New-Object System.Windows.Forms.RadioButton
    $radioButtonOffline = New-Object System.Windows.Forms.RadioButton
    $radioButtonOfflineOpt = New-Object System.Windows.Forms.RadioButton

    # LIVE PANEL
    $groupBoxOnline = New-Object System.Windows.Forms.GroupBox
    $checkBoxRAM = New-Object System.Windows.Forms.CheckBox
    $checkBoxNET = New-Object System.Windows.Forms.CheckBox
    $checkBoxSAP = New-Object System.Windows.Forms.CheckBox
    $checkBoxSTA = New-Object System.Windows.Forms.CheckBox
    $checkBoxCPH = New-Object System.Windows.Forms.CheckBox
    $checkBoxINS = New-Object System.Windows.Forms.CheckBox
    $checkBoxUGR = New-Object System.Windows.Forms.CheckBox
    $checkBoxPER = New-Object System.Windows.Forms.CheckBox
    $checkBoxUSB = New-Object System.Windows.Forms.CheckBox
    $checkBoxPNP = New-Object System.Windows.Forms.CheckBox
    $checkBoxSEC = New-Object System.Windows.Forms.CheckBox
    $checkBoxMRU = New-Object System.Windows.Forms.CheckBox
    $checkBoxSHI = New-Object System.Windows.Forms.CheckBox
    $checkBoxRAP = New-Object System.Windows.Forms.CheckBox
    $checkBoxBAM = New-Object System.Windows.Forms.CheckBox
    $checkBoxSYS = New-Object System.Windows.Forms.CheckBox
    $checkBoxLAC = New-Object System.Windows.Forms.CheckBox
    $checkBoxAFI = New-Object System.Windows.Forms.CheckBox    
    
    # OFFLINE PANEL
    $groupBoxOffline = New-Object System.Windows.Forms.GroupBox
    $checkBoxHIV = New-Object System.Windows.Forms.CheckBox
    $checkBoxEVT = New-Object System.Windows.Forms.CheckBox
    $checkBoxFIL = New-Object System.Windows.Forms.CheckBox
    $checkBoxDEX = New-Object System.Windows.Forms.CheckBox
    $checkBoxPRF = New-Object System.Windows.Forms.CheckBox
    $checkBoxWSE = New-Object System.Windows.Forms.CheckBox
    $checkBoxEET = New-Object System.Windows.Forms.CheckBox
    $checkBoxJLI = New-Object System.Windows.Forms.CheckBox
    $checkBoxTIC = New-Object System.Windows.Forms.CheckBox
    $checkBoxFSF = New-Object System.Windows.Forms.CheckBox
    $checkBoxMSF = New-Object System.Windows.Forms.CheckBox
    $checkBoxTLH = New-Object System.Windows.Forms.CheckBox
    $checkBoxTHA = New-Object System.Windows.Forms.CheckBox
    $checkBoxSRU = New-Object System.Windows.Forms.CheckBox
    $checkBoxCRE = New-Object System.Windows.Forms.CheckBox
    $checkBoxSFI = New-Object System.Windows.Forms.CheckBox
    $checkBoxSKY = New-Object System.Windows.Forms.CheckBox
    $checkBoxEMA = New-Object System.Windows.Forms.CheckBox
    $checkBoxCHR = New-Object System.Windows.Forms.CheckBox
    $checkBoxMFI = New-Object System.Windows.Forms.CheckBox
    $checkBoxIEX = New-Object System.Windows.Forms.CheckBox
    $checkBoxEDG = New-Object System.Windows.Forms.CheckBox
    $checkBoxSAF = New-Object System.Windows.Forms.CheckBox
    $checkBoxOPE = New-Object System.Windows.Forms.CheckBox
    $checkBoxTOR = New-Object System.Windows.Forms.CheckBox
    $checkBoxCOD = New-Object System.Windows.Forms.CheckBox
    $checkBoxCGD = New-Object System.Windows.Forms.CheckBox
    $checkBoxCDB = New-Object System.Windows.Forms.CheckBox

    ############################################ General groupBox ################################################################

    
    # Label Source
    $labelSource.Location = New-Object System.Drawing.Point(55, 280)
    $labelSource.Size = New-Object System.Drawing.Size(50, 13)
    $labelSource.AutoSize = $True
    $labelSource.Name = "labelSource"
    $labelSource.TabIndex = 0 
    $labelSource.TabStop = $False
    $labelSource.Text = "Source: "
    $labelSource.add_MouseHover($ShowHelp)
    
    # Combobox Source
    $comboBoxSource.Location = New-Object System.Drawing.Point(105, 277)
    $comboBoxSource.Size = New-Object System.Drawing.Size(60, 20)
    $comboBoxSource.FormattingEnabled = $True
    $comboBoxSource.Name = "comboBoxSource"
    $comboBoxSource.TabIndex = 1
    $comboBoxSource.Items.AddRange($DRIVES)

    # Label Destiny
    $labelDestiny.Location = New-Object System.Drawing.Point(180, 280)
    $labelDestiny.Size = New-Object System.Drawing.Size(50, 13)
    $labelDestiny.AutoSize = $True
    $labelDestiny.Name = "labelDestiny"
    $labelDestiny.TabIndex = 0
    $labelDestiny.TabStop = $False
    $labelDestiny.Text = "Destiny: "
    $labelDestiny.add_MouseHover($ShowHelp)

    # Textbox Destiny
    $textBoxDestiny.Location = New-Object System.Drawing.Point(230, 277)
    $textBoxDestiny.Size = New-Object System.Drawing.Size(262, 20)
    $textBoxDestiny.Name = "textBox1"
    $textBoxDestiny.TabIndex = 2

    # Button Select Destiny
    $buttonDestiny.Location = New-Object System.Drawing.Point(500, 275)
    $buttonDestiny.Size = New-Object System.Drawing.Size(75, 23)
    $buttonDestiny.Name = "buttonDestiny"
    $buttonDestiny.TabIndex = 3
    $buttonDestiny.Text = "Select ..."
    $buttonDestiny.UseVisualStyleBackColor = $True
    $buttonDestiny.add_MouseHover($ShowHelp)
    $buttonDestiny.Add_Click(
        {
        $dialogDestiny = New-Object System.Windows.Forms.FolderBrowserDialog
        $dialogDestiny.ShowDialog()
        $textBoxDestiny.Text = $dialogDestiny.SelectedPath
        $dialogDestiny.Dispose()
        }
    )
    

    # Format Checkbox
    $checkBoxFormat.Location = New-Object System.Drawing.Point(600, 280)
    $checkBoxFormat.Size = New-Object System.Drawing.Size(60, 17)
    $checkBoxFormat.AutoSize = $True
    $checkBoxFormat.Name = "checkBoxFormat"
    $checkBoxFormat.TabIndex = 4
    $checkBoxFormat.Text = "Format"
    $checkBoxFormat.UseVisualStyleBackColor = $True
    $checkBoxFormat.add_MouseHover($ShowHelp)
    $checkBoxFormat.Add_Click(
        {
            if($checkBoxFormat.Checked -eq $True)
            {
                $checkBoxFormatQuick.Enabled = $True
                $checkBoxFormatZero.Enabled = $True
            }
            else
            {
                $checkBoxFormatQuick.Enabled = $False
                $checkBoxFormatZero.Enabled = $False
                $checkBoxFormatQuick.Checked = $False
                $checkBoxFormatZero.Checked = $False
            }
        }
    )
    

    # Quick Format Checkbox
    $checkBoxFormatQuick.Location = New-Object System.Drawing.Point(610, 300)
    $checkBoxFormatQuick.Size = New-Object System.Drawing.Size(60, 17)
    $checkBoxFormatQuick.AutoSize = $True
    $checkBoxFormatQuick.Name = "checkBoxFormatQuick"
    $checkBoxFormatQuick.TabIndex = 4
    $checkBoxFormatQuick.Text = "Quick"
    $checkBoxFormatQuick.UseVisualStyleBackColor = $True
    $checkBoxFormatQuick.Enabled = $False
    $checkBoxFormatQuick.add_MouseHover($ShowHelp)
    $checkBoxFormatQuick.Add_Click(
        {
            if($checkBoxFormatQuick.Checked -eq $True)
            {
                $checkBoxFormatZero.Checked = $False
            }
            else
            {
                $checkBoxFormatZero.Checked = $True
            }
        }
    )
    

    # Zeros Format Checkbox
    $checkBoxFormatZero.Location = New-Object System.Drawing.Point(610, 320)
    $checkBoxFormatZero.Size = New-Object System.Drawing.Size(50, 17)
    $checkBoxFormatZero.AutoSize = $True
    $checkBoxFormatZero.Name = "checkBoxFormatZero"
    $checkBoxFormatZero.TabIndex = 4
    $checkBoxFormatZero.Text = "Zero"
    $checkBoxFormatZero.UseVisualStyleBackColor = $True
    $checkBoxFormatZero.Enabled = $False
    $checkBoxFormatZero.add_MouseHover($ShowHelp)
    $checkBoxFormatZero.Add_Click(
        {
            if($checkBoxFormatZero.Checked -eq $True)
            {
                $checkBoxFormatQuick.Checked = $False
            }
            else
            {
                $checkBoxFormatQuick.Checked = $True
            }            
        }
    )
    

    # Hash Checkbox
    $checkBoxHash.Location = New-Object System.Drawing.Point(670, 280)
    $checkBoxHash.Size = New-Object System.Drawing.Size(60, 17)
    $checkBoxHash.AutoSize = $True
    $checkBoxHash.Name = "checkBoxHash"
    $checkBoxHash.TabIndex = 4
    $checkBoxHash.Text = "Hash"
    $checkBoxHash.UseVisualStyleBackColor = $True
    $checkBoxHash.add_MouseHover($ShowHelp)
    $checkBoxHash.Add_Click(
        {
            if($checkBoxHash.Checked -eq $True)
            {
                $checkBoxHashMD5.Enabled = $True
                $checkBoxHashSHA256.Enabled = $True
            }
            else
            {
                $checkBoxHashMD5.Enabled = $False
                $checkBoxHashSHA256.Enabled = $False
                $checkBoxHashMD5.Checked = $False
                $checkBoxHashSHA256.Checked = $False
            }
        }
    )
    

    # Hash MD5 Checkbox
    $checkBoxHashMD5.Location = New-Object System.Drawing.Point(680, 300)
    $checkBoxHashMD5.Size = New-Object System.Drawing.Size(60, 17)
    $checkBoxHashMD5.AutoSize = $True
    $checkBoxHashMD5.Name = "checkBoxHashMD5"
    $checkBoxHashMD5.TabIndex = 4
    $checkBoxHashMD5.Text = "MD5"
    $checkBoxHashMD5.UseVisualStyleBackColor = $True
    $checkBoxHashMD5.Enabled = $False
    $checkBoxHashMD5.add_MouseHover($ShowHelp)
    $checkBoxHashMD5.Add_Click(
        {
            if($checkBoxHashMD5.Checked -eq $True)
            {
                $checkBoxHashSHA256.Checked = $False
            }
            else
            {
                $checkBoxHashSHA256.Checked = $True
            }
        }
    )
    

    # Hash SHA256 Checkbox
    $checkBoxHashSHA256.Location = New-Object System.Drawing.Point(680, 320)
    $checkBoxHashSHA256.Size = New-Object System.Drawing.Size(70, 17)
    $checkBoxHashSHA256.AutoSize = $True
    $checkBoxHashSHA256.Name = "checkBoxHashSHA256"
    $checkBoxHashSHA256.TabIndex = 4
    $checkBoxHashSHA256.Text = "SHA256"
    $checkBoxHashSHA256.UseVisualStyleBackColor = $True
    $checkBoxHashSHA256.Enabled = $False
    $checkBoxHashSHA256.add_MouseHover($ShowHelp)
    $checkBoxHashSHA256.Add_Click(
        {
            if($checkBoxHashSHA256.Checked -eq $True)
            {
                $checkBoxHashMD5.Checked = $False
            }
            else
            {
                $checkBoxHashMD5.Checked = $True
            }            
        }
    )
    

    # Button Execute/ Collect
    $buttonExecute.Location = New-Object System.Drawing.Point(425, 300)
    $buttonExecute.Size = New-Object System.Drawing.Size(150, 40)
    $buttonExecute.Font =  [System.Drawing.Font]::new("Microsoft Sans Serif", 10, [System.Drawing.FontStyle]::Bold)
    $buttonExecute.Name = "buttonExecute"
    $buttonExecute.TabIndex = 3
    $buttonExecute.Text = "EXECUTE!"
    $buttonExecute.UseVisualStyleBackColor = $True
    $buttonExecute.add_MouseHover($ShowHelp)
    $buttonExecute.Add_Click(
        {
            if($comboBoxSource.Text -ne "" -and $textBoxDestiny.Text -ne "")
            {
                Write-Host "0: $($comboBoxSource.Text)" -ForegroundColor Red
                $temp = $($($comboBoxSource.Text)).Split("\")[0] ; Write-Host "1.1: $temp" -ForegroundColor Red
                $temp = $($($comboBoxSource.Text).Split("\"))[0] ; Write-Host "1.2: $temp" -ForegroundColor Red
                $temp = $($comboBoxSource.Text).Split("\")[0] ; Write-Host "1.3: $temp" -ForegroundColor Red
                $temp = $($comboBoxSource.Text).Split("\")[0] ; Write-Host "1.4: $temp" -ForegroundColor Red
                
                Write-Host "2: $($($comboBoxSource.Text).Split("\")[1])" -ForegroundColor Red
                $Global:Source = $($($comboBoxSource.Text)).Split("\")[0]
                $Global:Destiny = $($textBoxDestiny.Text) 
                Write-Host "GLOBAL: $Global:Source" -ForegroundColor Red
                Write-Host "GLOBAL: $Global:Destiny" -ForegroundColor Red
                Write-Host "GLOBAL: -----------------------------" -ForegroundColor Red
                
                if($checkBoxRAM.Checked -eq $True) { $Global:RAM = $True }
                if($checkBoxNET.Checked -eq $True) { $Global:NET = $True }
                if($checkBoxSAP.Checked -eq $True) { $Global:SAP = $True }
                if($checkBoxSTA.Checked -eq $True) { $Global:STA = $True }
                if($checkBoxCPH.Checked -eq $True) { $Global:CPH = $True }
                if($checkBoxINS.Checked -eq $True) { $Global:INS = $True }
                if($checkBoxUGR.Checked -eq $True) { $Global:UGR = $True }
                if($checkBoxPER.Checked -eq $True) { $Global:PER = $True }
                if($checkBoxUSB.Checked -eq $True) { $Global:USB = $True }
                if($checkBoxPNP.Checked -eq $True) { $Global:PNP = $True }
                if($checkBoxSEC.Checked -eq $True) { $Global:SEC = $True }
                if($checkBoxMRU.Checked -eq $True) { $Global:MRU = $True }
                if($checkBoxSHI.Checked -eq $True) { $Global:SHI = $True }
                if($checkBoxRAP.Checked -eq $True) { $Global:RAP = $True }
                if($checkBoxBAM.Checked -eq $True) { $Global:BAM = $True }
                if($checkBoxSYS.Checked -eq $True) { $Global:SYS = $True }
                if($checkBoxLAC.Checked -eq $True) { $Global:LAC = $True }
                if($checkBoxAFI.Checked -eq $True) { $Global:AFI = $True }
                if($checkBoxHIV.Checked -eq $True) { $Global:HIV = $True }
                if($checkBoxEVT.Checked -eq $True) { $Global:EVT = $True }
                if($checkBoxFIL.Checked -eq $True) { $Global:FIL = $True }
                if($checkBoxDEX.Checked -eq $True) { $Global:DEX = $True }
                if($checkBoxPRF.Checked -eq $True) { $Global:PRF = $True }
                if($checkBoxWSE.Checked -eq $True) { $Global:WSE = $True }
                if($checkBoxEET.Checked -eq $True) { $Global:EET = $True }
                if($checkBoxJLI.Checked -eq $True) { $Global:JLI = $True }
                if($checkBoxTIC.Checked -eq $True) { $Global:TIC = $True }
                if($checkBoxFSF.Checked -eq $True) { $Global:FSF = $True }
                if($checkBoxMSF.Checked -eq $True) { $Global:MSF = $True }
                if($checkBoxTLH.Checked -eq $True) { $Global:TLH = $True }
                if($checkBoxTHA.Checked -eq $True) { $Global:THA = $True }
                if($checkBoxSRU.Checked -eq $True) { $Global:SRU = $True }
                if($checkBoxCRE.Checked -eq $True) { $Global:CRE = $True }
                if($checkBoxSFI.Checked -eq $True) { $Global:SFI = $True }
                if($checkBoxSKY.Checked -eq $True) { $Global:SKY = $True }
                if($checkBoxEMA.Checked -eq $True) { $Global:EMA = $True }
                if($checkBoxCHR.Checked -eq $True) { $Global:CHR = $True }
                if($checkBoxMFI.Checked -eq $True) { $Global:MFI = $True }
                if($checkBoxIEX.Checked -eq $True) { $Global:IEX = $True }
                if($checkBoxEDG.Checked -eq $True) { $Global:EDG = $True }
                if($checkBoxSAF.Checked -eq $True) { $Global:SAF = $True }
                if($checkBoxOPE.Checked -eq $True) { $Global:OPE = $True }
                if($checkBoxTOR.Checked -eq $True) { $Global:TOR = $True }
                if($checkBoxCOD.Checked -eq $True) { $Global:COD = $True }
                if($checkBoxCGD.Checked -eq $True) { $Global:CGD = $True }
                if($checkBoxCDB.Checked -eq $True) { $Global:CDB = $True }
                $buttonExecute.Text = "EXECUTING..."
                $buttonExecute.Enabled = $False
                Control-NOGUI
                $buttonExecute.Text = "EXECUTE!"
                $buttonExecute.Enabled = $True

            }
        }
    )


    # Label Collection Type
    $labelColType.Location = New-Object System.Drawing.Point(55, 310)
    $labelColType.Size = New-Object System.Drawing.Size(100, 13)
    $labelColType.AutoSize = $True
    $labelColType.Name = "labelColType"
    $labelColType.TabIndex = 0
    $labelColType.TabStop = $False
    $labelColType.Text = "Collection Type:"
    $labelColType.add_MouseHover($ShowHelp)

    

    # Radio Button ALL
    $radioButtonAll.Location = New-Object System.Drawing.Point(150, 310)
    $radioButtonAll.Size = New-Object System.Drawing.Size(40, 17)
    $radioButtonAll.AutoSize = $True
    $radioButtonAll.Name = "radioButtonAll"
    $radioButtonAll.TabIndex = 4
    $radioButtonAll.TabStop = $True
    $radioButtonAll.Text = "All"
    $radioButtonAll.UseVisualStyleBackColor = $True
    $radioButtonAll.add_MouseHover($ShowHelp)
    $radioButtonAll.Add_Click(
        {
        $checkBoxRAM.Checked = $True
        $checkBoxNET.Checked = $True
        $checkBoxSAP.Checked = $True
        $checkBoxSTA.Checked = $True
        $checkBoxCPH.Checked = $True
        $checkBoxINS.Checked = $True
        $checkBoxUGR.Checked = $True
        $checkBoxPER.Checked = $True
        $checkBoxUSB.Checked = $True
        $checkBoxPNP.Checked = $True
        $checkBoxSEC.Checked = $True
        $checkBoxMRU.Checked = $True
        $checkBoxSHI.Checked = $True
        $checkBoxRAP.Checked = $True
        $checkBoxBAM.Checked = $True
        $checkBoxSYS.Checked = $True
        $checkBoxLAC.Checked = $True
        $checkBoxAFI.Checked = $True
        $checkBoxHIV.Checked = $True
        $checkBoxEVT.Checked = $True
        $checkBoxFIL.Checked = $True
        $checkBoxDEX.Checked = $True
        $checkBoxPRF.Checked = $True
        $checkBoxWSE.Checked = $True
        $checkBoxEET.Checked = $True
        $checkBoxJLI.Checked = $True
        $checkBoxTIC.Checked = $True
        $checkBoxFSF.Checked = $True
        $checkBoxMSF.Checked = $True
        $checkBoxTLH.Checked = $True
        $checkBoxTHA.Checked = $True
        $checkBoxSRU.Checked = $True
        $checkBoxCRE.Checked = $True
        $checkBoxSFI.Checked = $True
        $checkBoxSKY.Checked = $True
        $checkBoxEMA.Checked = $True
        $checkBoxCHR.Checked = $True
        $checkBoxMFI.Checked = $True
        $checkBoxIEX.Checked = $True
        $checkBoxEDG.Checked = $True
        $checkBoxSAF.Checked = $True
        $checkBoxOPE.Checked = $True
        $checkBoxTOR.Checked = $True
        $checkBoxCOD.Checked = $True
        $checkBoxCGD.Checked = $True
        $checkBoxCDB.Checked = $True
        }
    )

    # Radio Button Live
    $radioButtonLive.Location = New-Object System.Drawing.Point(200, 300)
    $radioButtonLive.Size = New-Object System.Drawing.Size(70, 17)
    $radioButtonLive.AutoSize = $True
    $radioButtonLive.Name = "radioButtonLive"
    $radioButtonLive.TabIndex = 4
    $radioButtonLive.TabStop = $True
    $radioButtonLive.Text = "Live"
    $radioButtonLive.UseVisualStyleBackColor = $True
    $radioButtonLive.add_MouseHover($ShowHelp)
    $radioButtonLive.Add_Click(
        {
        $checkBoxRAM.Checked = $True
        $checkBoxNET.Checked = $True
        $checkBoxSAP.Checked = $True
        $checkBoxSTA.Checked = $True
        $checkBoxCPH.Checked = $True
        $checkBoxINS.Checked = $True
        $checkBoxUGR.Checked = $True
        $checkBoxPER.Checked = $True
        $checkBoxUSB.Checked = $True
        $checkBoxPNP.Checked = $True
        $checkBoxSEC.Checked = $True
        $checkBoxMRU.Checked = $True
        $checkBoxBAM.Checked = $True
        $checkBoxSYS.Checked = $True
        $checkBoxLAC.Checked = $True
        $checkBoxAFI.Checked = $True
        $checkBoxHIV.Checked = $False
        $checkBoxEVT.Checked = $False
        $checkBoxFIL.Checked = $False
        $checkBoxDEX.Checked = $False
        $checkBoxPRF.Checked = $False
        $checkBoxWSE.Checked = $False
        $checkBoxEET.Checked = $False
        $checkBoxJLI.Checked = $False
        $checkBoxTIC.Checked = $False
        $checkBoxFSF.Checked = $False
        $checkBoxMSF.Checked = $False
        $checkBoxTLH.Checked = $False
        $checkBoxTHA.Checked = $False
        $checkBoxSRU.Checked = $False
        $checkBoxCRE.Checked = $False
        $checkBoxSFI.Checked = $False
        $checkBoxSKY.Checked = $False
        $checkBoxEMA.Checked = $False
        $checkBoxCHR.Checked = $False
        $checkBoxMFI.Checked = $False
        $checkBoxIEX.Checked = $False
        $checkBoxEDG.Checked = $False
        $checkBoxSAF.Checked = $False
        $checkBoxOPE.Checked = $False
        $checkBoxTOR.Checked = $False
        $checkBoxCOD.Checked = $False
        $checkBoxCGD.Checked = $False
        $checkBoxCDB.Checked = $False
        }
    )

    # Radio Button Live Optimized
    $radioButtonLiveOpt.Location = New-Object System.Drawing.Point(270, 300)
    $radioButtonLiveOpt.Size = New-Object System.Drawing.Size(120, 17)
    $radioButtonLiveOpt.AutoSize = $True
    $radioButtonLiveOpt.Name = "radioButtonLiveOpt"
    $radioButtonLiveOpt.TabIndex = 4
    $radioButtonLiveOpt.TabStop = $True
    $radioButtonLiveOpt.Text = "Live Optimized"
    $radioButtonLiveOpt.UseVisualStyleBackColor = $True
    $radioButtonLiveOpt.add_MouseHover($ShowHelp)

    # Radio Button Offline
    $radioButtonOffline.Location = New-Object System.Drawing.Point(200, 320)
    $radioButtonOffline.Size = New-Object System.Drawing.Size(70, 17)
    $radioButtonOffline.AutoSize = $True
    $radioButtonOffline.Name = "radioButtonOffline"
    $radioButtonOffline.TabIndex = 4
    $radioButtonOffline.TabStop = $True
    $radioButtonOffline.Text = "Offline"
    $radioButtonOffline.UseVisualStyleBackColor = $True
    $radioButtonOffline.add_MouseHover($ShowHelp)
    $radioButtonOffline.Add_Click(
        {
        $checkBoxRAM.Checked = $False
        $checkBoxNET.Checked = $False
        $checkBoxSAP.Checked = $False
        $checkBoxSTA.Checked = $False
        $checkBoxCPH.Checked = $False
        $checkBoxINS.Checked = $False
        $checkBoxUGR.Checked = $False
        $checkBoxPER.Checked = $False
        $checkBoxUSB.Checked = $False
        $checkBoxPNP.Checked = $False
        $checkBoxSEC.Checked = $False
        $checkBoxMRU.Checked = $False
        $checkBoxSHI.Checked = $False
        $checkBoxRAP.Checked = $False
        $checkBoxBAM.Checked = $False
        $checkBoxSYS.Checked = $False
        $checkBoxLAC.Checked = $False
        $checkBoxAFI.Checked = $False
        $checkBoxHIV.Checked = $True
        $checkBoxEVT.Checked = $True
        $checkBoxFIL.Checked = $True
        $checkBoxDEX.Checked = $True
        $checkBoxPRF.Checked = $True
        $checkBoxWSE.Checked = $True
        $checkBoxEET.Checked = $True
        $checkBoxJLI.Checked = $True
        $checkBoxTIC.Checked = $True
        $checkBoxFSF.Checked = $True
        $checkBoxMSF.Checked = $True
        $checkBoxTLH.Checked = $True
        $checkBoxTHA.Checked = $True
        $checkBoxSRU.Checked = $True
        $checkBoxCRE.Checked = $True
        $checkBoxSFI.Checked = $True
        $checkBoxSKY.Checked = $True
        $checkBoxEMA.Checked = $True
        $checkBoxCHR.Checked = $True
        $checkBoxMFI.Checked = $True
        $checkBoxIEX.Checked = $True
        $checkBoxEDG.Checked = $True
        $checkBoxSAF.Checked = $True
        $checkBoxOPE.Checked = $True
        $checkBoxTOR.Checked = $True
        $checkBoxCOD.Checked = $True
        $checkBoxCGD.Checked = $True
        $checkBoxCDB.Checked = $True

        }
    )

    # Radio Button Offline Optimized
    $radioButtonOfflineOpt.Location = New-Object System.Drawing.Point(270, 320)
    $radioButtonOfflineOpt.Size = New-Object System.Drawing.Size(120, 17)
    $radioButtonOfflineOpt.AutoSize = $True
    $radioButtonOfflineOpt.Name = "radioButtonOfflineOpt"
    $radioButtonOfflineOpt.TabIndex = 4
    $radioButtonOfflineOpt.TabStop = $True
    $radioButtonOfflineOpt.Text = "Offline Optimized"
    $radioButtonOfflineOpt.UseVisualStyleBackColor = $True
    $radioButtonOfflineOpt.add_MouseHover($ShowHelp)


    # groupBox General
    $groupBoxGeneral.Location = New-Object System.Drawing.Point(50, 260)
    $groupBoxGeneral.Size = New-Object System.Drawing.Size(710, 85)                   # 924 de X
    $groupBoxGeneral.Name = "OfflineGroupBox"
    $groupBoxGeneral.Text = "General"
    $groupBoxGeneral.BringToFront()
    
    ############################################ Online groupBox #################################################################


    


    # RAM Checkbox
    $checkBoxRAM.Location = New-Object System.Drawing.Point(55, 370)
    $checkBoxRAM.Size = New-Object System.Drawing.Size(200, 17)
    $checkBoxRAM.AutoSize = $True
    $checkBoxRAM.Name = "checkBoxRAM"
    $checkBoxRAM.TabIndex = 4
    $checkBoxRAM.Text = "Random Access Memory (RAM)"
    $checkBoxRAM.UseVisualStyleBackColor = $True
    $checkBoxRAM.add_MouseHover($ShowHelp)
    $checkBoxRAM.Add_CheckStateChanged(
        {
            if($checkBoxRAM -eq $True)
            {
                $Global:RAM = $True
            }
            else
            {
                $Global:RAM = $False
            }
        }
    )

    # Network Checkbox
    $checkBoxNET.Location = New-Object System.Drawing.Point(55, 390)
    $checkBoxNET.Size = New-Object System.Drawing.Size(200, 17)
    $checkBoxNET.AutoSize = $True
    $checkBoxNET.Name = "checkBoxNET"
    $checkBoxNET.TabIndex = 4
    $checkBoxNET.Text = "Network Information"
    $checkBoxNET.UseVisualStyleBackColor = $True
    $checkBoxNET.add_MouseHover($ShowHelp)

    # Services and Processes Checkbox
    $checkBoxSAP.Location = New-Object System.Drawing.Point(55, 410)
    $checkBoxSAP.Size = New-Object System.Drawing.Size(200, 17)
    $checkBoxSAP.AutoSize = $True
    $checkBoxSAP.Name = "checkBoxSAP"
    $checkBoxSAP.TabIndex = 4
    $checkBoxSAP.Text = "Services and Processes"
    $checkBoxSAP.UseVisualStyleBackColor = $True
    $checkBoxSAP.add_MouseHover($ShowHelp)

    # Scheduled Tasks Checkbox
    $checkBoxSTA.Location = New-Object System.Drawing.Point(55, 430)
    $checkBoxSTA.Size = New-Object System.Drawing.Size(200, 17)
    $checkBoxSTA.AutoSize = $True
    $checkBoxSTA.Name = "checkBoxSTA"
    $checkBoxSTA.TabIndex = 4
    $checkBoxSTA.Text = "Scheduled Tasks"
    $checkBoxSTA.UseVisualStyleBackColor = $True
    $checkBoxSTA.add_MouseHover($ShowHelp)

    # CMD Checkbox
    $checkBoxCPH.Location = New-Object System.Drawing.Point(55, 450)
    $checkBoxCPH.Size = New-Object System.Drawing.Size(200, 17)
    $checkBoxCPH.AutoSize = $True
    $checkBoxCPH.Name = "checkBoxCPH"
    $checkBoxCPH.TabIndex = 4
    $checkBoxCPH.Text = "Command Line History"
    $checkBoxCPH.UseVisualStyleBackColor = $True
    $checkBoxCPH.add_MouseHover($ShowHelp)

    # Installed Software Checkbox
    $checkBoxINS.Location = New-Object System.Drawing.Point(55, 470)
    $checkBoxINS.Size = New-Object System.Drawing.Size(200, 17)
    $checkBoxINS.AutoSize = $True
    $checkBoxINS.Name = "checkBoxINS"
    $checkBoxINS.TabIndex = 4
    $checkBoxINS.Text = "Installed Software"
    $checkBoxINS.UseVisualStyleBackColor = $True
    $checkBoxINS.add_MouseHover($ShowHelp)

    # Users and Groups Checkbox
    $checkBoxUGR.Location = New-Object System.Drawing.Point(55, 490)
    $checkBoxUGR.Size = New-Object System.Drawing.Size(200, 17)
    $checkBoxUGR.AutoSize = $True
    $checkBoxUGR.Name = "checkBoxUGR"
    $checkBoxUGR.TabIndex = 4
    $checkBoxUGR.Text = "Users and Groups"
    $checkBoxUGR.UseVisualStyleBackColor = $True
    $checkBoxUGR.add_MouseHover($ShowHelp)

    # Persistance Checkbox
    $checkBoxPER.Location = New-Object System.Drawing.Point(55, 510)
    $checkBoxPER.Size = New-Object System.Drawing.Size(200, 17)
    $checkBoxPER.AutoSize = $True
    $checkBoxPER.Name = "checkBoxPER"
    $checkBoxPER.TabIndex = 4
    $checkBoxPER.Text = "Persistance"
    $checkBoxPER.UseVisualStyleBackColor = $True
    $checkBoxPER.add_MouseHover($ShowHelp)

    # USB Devices Checkbox
    $checkBoxUSB.Location = New-Object System.Drawing.Point(55, 530)
    $checkBoxUSB.Size = New-Object System.Drawing.Size(200, 17)
    $checkBoxUSB.AutoSize = $True
    $checkBoxUSB.Name = "checkBoxUSB"
    $checkBoxUSB.TabIndex = 4
    $checkBoxUSB.Text = "USB Devices Info"
    $checkBoxUSB.UseVisualStyleBackColor = $True
    $checkBoxUSB.add_MouseHover($ShowHelp)

    # Devices Info Checkbox
    $checkBoxPNP.Location = New-Object System.Drawing.Point(55, 550)
    $checkBoxPNP.Size = New-Object System.Drawing.Size(200, 17)
    $checkBoxPNP.AutoSize = $True
    $checkBoxPNP.Name = "checkBoxPNP"
    $checkBoxPNP.TabIndex = 4
    $checkBoxPNP.Text = "Devices Info"
    $checkBoxPNP.UseVisualStyleBackColor = $True
    $checkBoxPNP.add_MouseHover($ShowHelp)

    # Security Configuration Checkbox
    $checkBoxSEC.Location = New-Object System.Drawing.Point(55, 570)
    $checkBoxSEC.Size = New-Object System.Drawing.Size(200, 17)
    $checkBoxSEC.AutoSize = $True
    $checkBoxSEC.Name = "checkBoxSEC"
    $checkBoxSEC.TabIndex = 4
    $checkBoxSEC.Text = "Security Configuration"
    $checkBoxSEC.UseVisualStyleBackColor = $True
    $checkBoxSEC.add_MouseHover($ShowHelp)

    # MRUs Checkbox
    $checkBoxMRU.Location = New-Object System.Drawing.Point(55, 590)
    $checkBoxMRU.Size = New-Object System.Drawing.Size(200, 17)
    $checkBoxMRU.AutoSize = $True
    $checkBoxMRU.Name = "checkBoxMRU"
    $checkBoxMRU.TabIndex = 4
    $checkBoxMRU.Text = "Most Recent Used (MRUs)"
    $checkBoxMRU.UseVisualStyleBackColor = $True
    $checkBoxMRU.add_MouseHover($ShowHelp)
    $checkBoxMRU.Add_CheckStateChanged(
        {
            if($checkBoxMRU.Checked -eq $True)
            {
                $checkBoxSHI.Enabled = $False
                $checkBoxRAP.Enabled = $False
                $checkBoxSHI.Checked = $False
                $checkBoxRAP.Checked = $False
            }
            else
            {
                $checkBoxSHI.Enabled = $True
                $checkBoxRAP.Enabled = $True
            }
        }
    )

    # Shimcache Checkbox
    $checkBoxSHI.Location = New-Object System.Drawing.Point(55, 610)
    $checkBoxSHI.Size = New-Object System.Drawing.Size(200, 17)
    $checkBoxSHI.AutoSize = $True
    $checkBoxSHI.Name = "checkBoxSHI"
    $checkBoxSHI.TabIndex = 4
    $checkBoxSHI.Text = "Shimcache"
    $checkBoxSHI.UseVisualStyleBackColor = $True
    $checkBoxSHI.add_MouseHover($ShowHelp)

    # RecentAPPs Checkbox
    $checkBoxRAP.Location = New-Object System.Drawing.Point(55, 630)
    $checkBoxRAP.Size = New-Object System.Drawing.Size(200, 17)
    $checkBoxRAP.AutoSize = $True
    $checkBoxRAP.Name = "checkBoxRAP"
    $checkBoxRAP.TabIndex = 4
    $checkBoxRAP.Text = "Recent Applications"
    $checkBoxRAP.UseVisualStyleBackColor = $True
    $checkBoxRAP.add_MouseHover($ShowHelp)

    # BAM Checkbox
    $checkBoxBAM.Location = New-Object System.Drawing.Point(55, 650)
    $checkBoxBAM.Size = New-Object System.Drawing.Size(220, 17)
    $checkBoxBAM.AutoSize = $True
    $checkBoxBAM.Name = "checkBoxBAM"
    $checkBoxBAM.TabIndex = 4
    $checkBoxBAM.Text = "Background Activity Moderator (BAM)"
    $checkBoxBAM.UseVisualStyleBackColor = $True
    $checkBoxBAM.add_MouseHover($ShowHelp)

    # System Info Checkbox
    $checkBoxSYS.Location = New-Object System.Drawing.Point(55, 670)
    $checkBoxSYS.Size = New-Object System.Drawing.Size(200, 17)
    $checkBoxSYS.AutoSize = $True
    $checkBoxSYS.Name = "checkBoxSYS"
    $checkBoxSYS.TabIndex = 4
    $checkBoxSYS.Text = "System Info"
    $checkBoxSYS.UseVisualStyleBackColor = $True
    $checkBoxSYS.add_MouseHover($ShowHelp)

    # Last Activity Checkbox
    $checkBoxLAC.Location = New-Object System.Drawing.Point(55, 690)
    $checkBoxLAC.Size = New-Object System.Drawing.Size(200, 17)
    $checkBoxLAC.AutoSize = $True
    $checkBoxLAC.Name = "checkBoxLAC"
    $checkBoxLAC.TabIndex = 4
    $checkBoxLAC.Text = "Last Activity"
    $checkBoxLAC.UseVisualStyleBackColor = $True
    $checkBoxLAC.add_MouseHover($ShowHelp)

    # Autorun Files Checkbox
    $checkBoxAFI.Location = New-Object System.Drawing.Point(55, 710)
    $checkBoxAFI.Size = New-Object System.Drawing.Size(200, 17)
    $checkBoxAFI.AutoSize = $True
    $checkBoxAFI.Name = "checkBoxAFI"
    $checkBoxAFI.TabIndex = 4
    $checkBoxAFI.Text = "Autorun Files"
    $checkBoxAFI.UseVisualStyleBackColor = $True
    $checkBoxAFI.add_MouseHover($ShowHelp)

    # groupBox Online
    $groupBoxOnline.Location = New-Object System.Drawing.Point(50, 350)
    $groupBoxOnline.Size = New-Object System.Drawing.Size(250, 400)
    $groupBoxOnline.Name = "OnlineGroupBox"
    $groupBoxOnline.Text = "Live Options"

    ############################################ Offline groupBox ################################################################

    # Hives Checkbox
    $checkBoxHIV.Location = New-Object System.Drawing.Point(330, 370)
    $checkBoxHIV.Size = New-Object System.Drawing.Size(200, 17)
    $checkBoxHIV.AutoSize = $True
    $checkBoxHIV.Name = "checkBoxHIV"
    $checkBoxHIV.TabIndex = 4
    $checkBoxHIV.Text = "Hives"
    $checkBoxHIV.UseVisualStyleBackColor = $True
    $checkBoxHIV.add_MouseHover($ShowHelp)
    
    # Event Log Checkbox
    $checkBoxEVT.Location = New-Object System.Drawing.Point(330, 390)
    $checkBoxEVT.Size = New-Object System.Drawing.Size(200, 17)
    $checkBoxEVT.AutoSize = $True
    $checkBoxEVT.Name = "checkBoxEVT"
    $checkBoxEVT.TabIndex = 4
    $checkBoxEVT.Text = "Event Log Files"
    $checkBoxEVT.UseVisualStyleBackColor = $True
    $checkBoxEVT.add_MouseHover($ShowHelp)
    
    # Format Checkbox
    $checkBoxFIL.Location = New-Object System.Drawing.Point(330, 410)
    $checkBoxFIL.Size = New-Object System.Drawing.Size(200, 17)
    $checkBoxFIL.AutoSize = $True
    $checkBoxFIL.Name = "checkBoxFIL"
    $checkBoxFIL.TabIndex = 4
    $checkBoxFIL.Text = "Files Lists"
    $checkBoxFIL.UseVisualStyleBackColor = $True
    $checkBoxFIL.add_MouseHover($ShowHelp)

    # Format Checkbox
    $checkBoxDEX.Location = New-Object System.Drawing.Point(330, 430)
    $checkBoxDEX.Size = New-Object System.Drawing.Size(200, 17)
    $checkBoxDEX.AutoSize = $True
    $checkBoxDEX.Name = "checkBoxDEX"
    $checkBoxDEX.TabIndex = 4
    $checkBoxDEX.Text = "Dangerous Extensions"
    $checkBoxDEX.UseVisualStyleBackColor = $True
    $checkBoxDEX.add_MouseHover($ShowHelp)

    # Format Checkbox
    $checkBoxPRF.Location = New-Object System.Drawing.Point(330, 450)
    $checkBoxPRF.Size = New-Object System.Drawing.Size(200, 17)
    $checkBoxPRF.AutoSize = $True
    $checkBoxPRF.Name = "checkBoxPRF"
    $checkBoxPRF.TabIndex = 4
    $checkBoxPRF.Text = "Prefetch Files"
    $checkBoxPRF.UseVisualStyleBackColor = $True
    $checkBoxPRF.add_MouseHover($ShowHelp)

    # Format Checkbox
    $checkBoxWSE.Location = New-Object System.Drawing.Point(330, 470)
    $checkBoxWSE.Size = New-Object System.Drawing.Size(200, 17)
    $checkBoxWSE.AutoSize = $True
    $checkBoxWSE.Name = "checkBoxWSE"
    $checkBoxWSE.TabIndex = 4
    $checkBoxWSE.Text = "Windows Search"
    $checkBoxWSE.UseVisualStyleBackColor = $True
    $checkBoxWSE.add_MouseHover($ShowHelp)

    # Format Checkbox
    $checkBoxEET.Location = New-Object System.Drawing.Point(330, 490)
    $checkBoxEET.Size = New-Object System.Drawing.Size(200, 17)
    $checkBoxEET.AutoSize = $True
    $checkBoxEET.Name = "checkBoxEET"
    $checkBoxEET.TabIndex = 4
    $checkBoxEET.Text = "ETW and ETL Files"
    $checkBoxEET.UseVisualStyleBackColor = $True
    $checkBoxEET.add_MouseHover($ShowHelp)

    # Format Checkbox
    $checkBoxJLI.Location = New-Object System.Drawing.Point(330, 510)
    $checkBoxJLI.Size = New-Object System.Drawing.Size(200, 17)
    $checkBoxJLI.AutoSize = $True
    $checkBoxJLI.Name = "checkBoxJLI"
    $checkBoxJLI.TabIndex = 4
    $checkBoxJLI.Text = "JumpLists"
    $checkBoxJLI.UseVisualStyleBackColor = $True
    $checkBoxJLI.add_MouseHover($ShowHelp)

    # Format Checkbox
    $checkBoxTIC.Location = New-Object System.Drawing.Point(330, 530)
    $checkBoxTIC.Size = New-Object System.Drawing.Size(200, 17)
    $checkBoxTIC.AutoSize = $True
    $checkBoxTIC.Name = "checkBoxTIC"
    $checkBoxTIC.TabIndex = 4
    $checkBoxTIC.Text = "ThumbCache `& IconCache"
    $checkBoxTIC.UseVisualStyleBackColor = $True
    $checkBoxTIC.add_MouseHover($ShowHelp)

    # Format Checkbox
    $checkBoxFSF.Location = New-Object System.Drawing.Point(330, 550)
    $checkBoxFSF.Size = New-Object System.Drawing.Size(240, 17)
    $checkBoxFSF.AutoSize = $True
    $checkBoxFSF.Name = "checkBoxFSF"
    $checkBoxFSF.TabIndex = 4
    $checkBoxFSF.Text = "`$MFT, `$UsnJrnl, `$LogFile"
    $checkBoxFSF.UseVisualStyleBackColor = $True
    $checkBoxFSF.add_MouseHover($ShowHelp)

    # Format Checkbox
    $checkBoxMSF.Location = New-Object System.Drawing.Point(330, 570)
    $checkBoxMSF.Size = New-Object System.Drawing.Size(240, 17)
    $checkBoxMSF.AutoSize = $True
    $checkBoxMSF.Name = "checkBoxMSF"
    $checkBoxMSF.TabIndex = 4
    $checkBoxMSF.Text = "Hiberfil.sys, Pagefile.sys, Swapfile.sys"
    $checkBoxMSF.UseVisualStyleBackColor = $True
    $checkBoxMSF.add_MouseHover($ShowHelp)

    # Format Checkbox
    $checkBoxTLH.Location = New-Object System.Drawing.Point(330, 590)
    $checkBoxTLH.Size = New-Object System.Drawing.Size(200, 17)
    $checkBoxTLH.AutoSize = $True
    $checkBoxTLH.Name = "checkBoxTLH"
    $checkBoxTLH.TabIndex = 4
    $checkBoxTLH.Text = "Timeline"
    $checkBoxTLH.UseVisualStyleBackColor = $True
    $checkBoxTLH.add_MouseHover($ShowHelp)

    # Format Checkbox
    $checkBoxTHA.Location = New-Object System.Drawing.Point(330, 610)
    $checkBoxTHA.Size = New-Object System.Drawing.Size(200, 17)
    $checkBoxTHA.AutoSize = $True
    $checkBoxTHA.Name = "checkBoxTHA"
    $checkBoxTHA.TabIndex = 4
    $checkBoxTHA.Text = "Text Harvester"
    $checkBoxTHA.UseVisualStyleBackColor = $True
    $checkBoxTHA.add_MouseHover($ShowHelp)

    # Format Checkbox
    $checkBoxSRU.Location = New-Object System.Drawing.Point(330, 630)
    $checkBoxSRU.Size = New-Object System.Drawing.Size(240, 17)
    $checkBoxSRU.AutoSize = $True
    $checkBoxSRU.Name = "checkBoxSRU"
    $checkBoxSRU.TabIndex = 4
    $checkBoxSRU.Text = "System Resource Usage Monitor (SRUM)"
    $checkBoxSRU.UseVisualStyleBackColor = $True
    $checkBoxSRU.add_MouseHover($ShowHelp)

    # Format Checkbox
    $checkBoxCRE.Location = New-Object System.Drawing.Point(330, 650)
    $checkBoxCRE.Size = New-Object System.Drawing.Size(200, 17)
    $checkBoxCRE.AutoSize = $True
    $checkBoxCRE.Name = "checkBoxCRE"
    $checkBoxCRE.TabIndex = 4
    $checkBoxCRE.Text = "Credentials"
    $checkBoxCRE.UseVisualStyleBackColor = $True
    $checkBoxCRE.add_MouseHover($ShowHelp)
    
    # Format Checkbox
    $checkBoxSFI.Location = New-Object System.Drawing.Point(330, 670)
    $checkBoxSFI.Size = New-Object System.Drawing.Size(150, 17)
    $checkBoxSFI.AutoSize = $True
    $checkBoxSFI.Name = "checkBoxSFI"
    $checkBoxSFI.TabIndex = 4
    $checkBoxSFI.Text = "Signed Files"
    $checkBoxSFI.UseVisualStyleBackColor = $True
    $checkBoxSFI.add_MouseHover($ShowHelp)
    
    # Format Checkbox
    $checkBoxSKY.Location = New-Object System.Drawing.Point(570, 370)
    $checkBoxSKY.Size = New-Object System.Drawing.Size(150, 17)
    $checkBoxSKY.AutoSize = $True
    $checkBoxSKY.Name = "checkBoxSKY"
    $checkBoxSKY.TabIndex = 4
    $checkBoxSKY.Text = "Skype"
    $checkBoxSKY.UseVisualStyleBackColor = $True
    $checkBoxSKY.add_MouseHover($ShowHelp)

    # Format Checkbox
    $checkBoxEMA.Location = New-Object System.Drawing.Point(570, 390)
    $checkBoxEMA.Size = New-Object System.Drawing.Size(150, 17)
    $checkBoxEMA.AutoSize = $True
    $checkBoxEMA.Name = "checkBoxEMA"
    $checkBoxEMA.TabIndex = 4
    $checkBoxEMA.Text = "Email files"
    $checkBoxEMA.UseVisualStyleBackColor = $True
    $checkBoxEMA.add_MouseHover($ShowHelp)

    # Format Checkbox
    $checkBoxCHR.Location = New-Object System.Drawing.Point(570, 430)
    $checkBoxCHR.Size = New-Object System.Drawing.Size(150, 17)
    $checkBoxCHR.AutoSize = $True
    $checkBoxCHR.Name = "checkBoxCHR"
    $checkBoxCHR.TabIndex = 4
    $checkBoxCHR.Text = "Chrome"
    $checkBoxCHR.UseVisualStyleBackColor = $True
    $checkBoxCHR.add_MouseHover($ShowHelp)

    # Format Checkbox
    $checkBoxMFI.Location = New-Object System.Drawing.Point(570, 450)
    $checkBoxMFI.Size = New-Object System.Drawing.Size(150, 17)
    $checkBoxMFI.AutoSize = $True
    $checkBoxMFI.Name = "checkBoxMFI"
    $checkBoxMFI.TabIndex = 4
    $checkBoxMFI.Text = "Firefox"
    $checkBoxMFI.UseVisualStyleBackColor = $True
    $checkBoxMFI.add_MouseHover($ShowHelp)

    # Format Checkbox
    $checkBoxIEX.Location = New-Object System.Drawing.Point(570, 470)
    $checkBoxIEX.Size = New-Object System.Drawing.Size(150, 17)
    $checkBoxIEX.AutoSize = $True
    $checkBoxIEX.Name = "checkBoxIEX"
    $checkBoxIEX.TabIndex = 4
    $checkBoxIEX.Text = "Internet Explorer"
    $checkBoxIEX.UseVisualStyleBackColor = $True
    $checkBoxIEX.add_MouseHover($ShowHelp)

    # Format Checkbox
    $checkBoxEDG.Location = New-Object System.Drawing.Point(570, 490)
    $checkBoxEDG.Size = New-Object System.Drawing.Size(150, 17)
    $checkBoxEDG.AutoSize = $True
    $checkBoxEDG.Name = "checkBoxEDG"
    $checkBoxEDG.TabIndex = 4
    $checkBoxEDG.Text = "EDGE"
    $checkBoxEDG.UseVisualStyleBackColor = $True
    $checkBoxEDG.add_MouseHover($ShowHelp)

    # Format Checkbox
    $checkBoxSAF.Location = New-Object System.Drawing.Point(570, 510)
    $checkBoxSAF.Size = New-Object System.Drawing.Size(150, 17)
    $checkBoxSAF.AutoSize = $True
    $checkBoxSAF.Name = "checkBoxSAF"
    $checkBoxSAF.TabIndex = 4
    $checkBoxSAF.Text = "Safari"
    $checkBoxSAF.UseVisualStyleBackColor = $True
    $checkBoxSAF.add_MouseHover($ShowHelp)

    # Format Checkbox
    $checkBoxOPE.Location = New-Object System.Drawing.Point(570, 530)
    $checkBoxOPE.Size = New-Object System.Drawing.Size(150, 17)
    $checkBoxOPE.AutoSize = $True
    $checkBoxOPE.Name = "checkBoxOPE"
    $checkBoxOPE.TabIndex = 4
    $checkBoxOPE.Text = "Opera"
    $checkBoxOPE.UseVisualStyleBackColor = $True
    $checkBoxOPE.add_MouseHover($ShowHelp)

    # Format Checkbox
    $checkBoxTOR.Location = New-Object System.Drawing.Point(570, 550)
    $checkBoxTOR.Size = New-Object System.Drawing.Size(150, 17)
    $checkBoxTOR.AutoSize = $True
    $checkBoxTOR.Name = "checkBoxTOR"
    $checkBoxTOR.TabIndex = 4
    $checkBoxTOR.Text = "TOR"
    $checkBoxTOR.UseVisualStyleBackColor = $True
    $checkBoxTOR.add_MouseHover($ShowHelp)

    # Format Checkbox
    $checkBoxCOD.Location = New-Object System.Drawing.Point(570, 590)
    $checkBoxCOD.Size = New-Object System.Drawing.Size(150, 17)
    $checkBoxCOD.AutoSize = $True
    $checkBoxCOD.Name = "checkBoxCOD"
    $checkBoxCOD.TabIndex = 4
    $checkBoxCOD.Text = "OneDrive"
    $checkBoxCOD.UseVisualStyleBackColor = $True
    $checkBoxCOD.add_MouseHover($ShowHelp)

    # Format Checkbox
    $checkBoxCGD.Location = New-Object System.Drawing.Point(570, 610)
    $checkBoxCGD.Size = New-Object System.Drawing.Size(150, 17)
    $checkBoxCGD.AutoSize = $True
    $checkBoxCGD.Name = "checkBoxCGD"
    $checkBoxCGD.TabIndex = 4
    $checkBoxCGD.Text = "GoogleDrive"
    $checkBoxCGD.UseVisualStyleBackColor = $True
    $checkBoxCGD.add_MouseHover($ShowHelp)

    # DropBox Checkbox
    $checkBoxCDB.Location = New-Object System.Drawing.Point(570, 630)
    $checkBoxCDB.Size = New-Object System.Drawing.Size(150, 17)
    $checkBoxCDB.AutoSize = $True
    $checkBoxCDB.Name = "checkBoxCDB"
    $checkBoxCDB.TabIndex = 4
    $checkBoxCDB.Text = "DropBox"
    $checkBoxCDB.UseVisualStyleBackColor = $True
    $checkBoxCDB.add_MouseHover($ShowHelp)




    # groupBox Offline
    $groupBoxOffline.Location = New-Object System.Drawing.Point(324, 350)
    $groupBoxOffline.Size = New-Object System.Drawing.Size(436, 400)
    $groupBoxOffline.Name = "OfflineGroupBox"
    $groupBoxOffline.Text = "Live/Offline Options"
    
    ############################################ FORM Definition #################################################################

    $form = New-Object System.Windows.Forms.Form
    $form.Text = "$APPName $APPVersion"
    $form.Size = New-Object System.Drawing.Size(820,800)
    $form.MaximumSize = New-Object System.Drawing.Size(820,800)
    $form.MinimumSize = New-Object System.Drawing.Size(820,800)
    $form.StartPosition = 'CenterScreen'
    
    # Add to Form: Banner
    $form.Controls.Add($Banner)
    
    # Add to Form: General Options
    $form.Controls.Add($labelSource)
    $form.Controls.Add($comboBoxSource)
    $form.Controls.Add($labelDestiny)
    $form.Controls.Add($textBoxDestiny)
    $form.Controls.Add($buttonDestiny)
    $form.Controls.AddRange(@($checkBoxFormat,$checkBoxFormatQuick,$checkBoxFormatZero,$buttonExecute))
    $form.Controls.AddRange(@($checkBoxHash,$checkBoxHashMD5,$checkBoxHashSHA256))
    $form.Controls.AddRange(@($radioButtonAll,$radioButtonLive,$radioButtonLiveOpt,$radioButtonOffline,$radioButtonOfflineOpt))
    $form.Controls.Add($labelColType)
    $form.Controls.Add($groupBoxGeneral)

    # Add to Form: Live Options
    $form.Controls.AddRange(@($checkBoxRAM,$checkBoxNET,$checkBoxSAP,$checkBoxSTA,$checkBoxCPH,$checkBoxINS,$checkBoxUGR,$checkBoxPER,$checkBoxUSB))
    $form.Controls.AddRange(@($checkBoxPNP,$checkBoxSEC,$checkBoxMRU,$checkBoxSHI,$checkBoxRAP,$checkBoxBAM,$checkBoxSYS,$checkBoxLAC,$checkBoxAFI ))
    $form.Controls.Add($groupBoxOnline)

    # Add to Form: Offline Options
    $form.Controls.Add($checkBoxHIV)
    $form.Controls.Add($checkBoxEVT)
    $form.Controls.Add($checkBoxFIL)
    $form.Controls.Add($checkBoxDEX)
    $form.Controls.Add($checkBoxPRF)
    $form.Controls.Add($checkBoxWSE)
    $form.Controls.Add($checkBoxEET)
    $form.Controls.Add($checkBoxJLI)
    $form.Controls.Add($checkBoxTIC)
    $form.Controls.Add($checkBoxFSF)
    $form.Controls.Add($checkBoxMSF)
    $form.Controls.Add($checkBoxTLH)
    $form.Controls.Add($checkBoxTHA)
    $form.Controls.Add($checkBoxSRU)
    $form.Controls.Add($checkBoxCRE)
    $form.Controls.Add($checkBoxSKY)
    $form.Controls.Add($checkBoxEMA)
    $form.Controls.Add($checkBoxCHR)
    $form.Controls.Add($checkBoxMFI)
    $form.Controls.Add($checkBoxIEX)
    $form.Controls.Add($checkBoxEDG)
    $form.Controls.Add($checkBoxSAF)
    $form.Controls.Add($checkBoxOPE)
    $form.Controls.Add($checkBoxTOR)
    $form.Controls.Add($checkBoxCOD)
    $form.Controls.Add($checkBoxCGD)
    $form.Controls.Add($checkBoxCDB)
    $form.Controls.Add($checkBoxSFI)
    $form.Controls.Add($groupBoxOffline)

    $form.Topmost = $false

    #$form.Add_Shown({$textBox.Select()})
    $result = $form.ShowDialog()
}


<##################################################################################################################################>
<############  SEVERAL OTHER FUNCTIONS  ##############################################>
<##################################################################################################################################>

<# Given a SID it returns a username #>
Function Get-SIDUsername {
    
    param(
        [string]$sid        
    )
    try
    {
        $N = Get-ItemPropertyValue -Path "REGISTRY::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\$SID\" -Name "ProfileImagePath" 2>$null
        $NAME = $($N.Split("\")[2])
        return $NAME
    }
    catch # In case the user was deleted from the system
    {
        return "<User Not Present>"
    }
}

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
    write-host ''
    Write-Host '  ▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▒'
    Write-Host '  ▓                                                                                              ▒'
    Write-Host '  ▓    ######\                               ##\           ##\   ##\                             ▒'
    Write-Host '  ▓    \_##  _|                              \__|          \__|  ## |                            ▒'
    Write-Host '  ▓      ## |  #######\   ######\  ##\   ##\ ##\  #######\ ##\ ######\    ######\   ######\      ▒'
    Write-Host '  ▓      ## |  ##  __##\ ##  __##\ ## |  ## |## |##  _____|## |\_##  _|  ##  __##\ ##  __##\     ▒'
    Write-Host '  ▓      ## |  ## |  ## |## /  ## |## |  ## |## |\######\  ## |  ## |    ## /  ## |## |  \__|    ▒'
    Write-Host '  ▓      ## |  ## |  ## |## |  ## |## |  ## |## | \____##\ ## |  ## |##\ ## |  ## |## |          ▒'
    Write-Host '  ▓    ######\ ## |  ## |\####### |\######  |## |#######  |## |  \####  |\######  |## |          ▒'
    Write-Host '  ▓    \______|\__|  \__| \____## | \______/ \__|\_______/ \__|   \____/  \______/ \__|          ▒'
    Write-Host '  ▓                            ## |                                                              ▒'
    Write-Host '  ▓                            ## |                           Forensic artifacts collector       ▒'
    Write-Host '  ▓                            \__|                           By:      f4d0                      ▒'
    Write-Host '  ▓                                                           Version: 0.7                       ▒'
    Write-Host '  ▓                                                                                              ▒'
    Write-Host '  ▓▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒'

}

<# Show Simple Options Resume #>
Function Show-Simple-Options-Resume {

    Write-Host ""
    Write-Host "  ═══════════════════════════════════════════ "
    Write-Host "                                              "
    Write-Host "    Input resume:                             "
    Write-Host "                                              "
    Write-Host "        GUI:         $GUI                     "
    Write-Host "        Source:      $Global:Source           "
    Write-Host "        Destiny:     $Global:Destiny          "
    Write-Host "        Memory Dump: $RAM                     "
    Write-Host "        Format:      $Global:FormatType       "
    Write-Host "        Dev. Mode:   $DevMode                 "  
    Write-Host "                                              "
    Write-Host "        Collect:                              "
    Write-Host " "
    if ($Global:RAM ) {Write-Host "            • RAM - Random Access Memory."}
    if ($Global:SFI ) {Write-Host "            • SFI - Signed Files for folders %SystemDrive%\Windows and %SystemDrive%\\windows\system32. (Time Consuming)"}
    if ($Global:AFI ) {Write-Host "            • AFI - All Autorun Files. (Time Consuming)"}
    if ($Global:DEX ) {Write-Host "            • DEX - Collect list of files with potential dangerous extensions.(Time Consuming)"}
    if ($All) {Write-Host "            • ALL:"}

    if ($Global:NET ) {Write-Host "            • NET - Network Information."}
    if ($Global:SAP ) {Write-Host "            • SAP - Services and Processes."}
    if ($Global:STA ) {Write-Host "            • STA - Scheduled Tasks."}
    if ($Global:CPH ) {Write-Host "            • CPH - PowerShell Command Line History."}
    if ($Global:INS ) {Write-Host "            • INS - Installed Software."}
    if ($Global:UGR ) {Write-Host "            • UGR - Users and Groups."}
    if ($Global:PER ) {Write-Host "            • PER - Persistence."}
    if ($Global:USB ) {Write-Host "            • USB - USB devices information."}
    if ($Global:PNP ) {Write-Host "            • PNP - Plug and Play devices."}
    if ($Global:SEC ) {Write-Host "            • SEC - Security confiuration (Fierwall)."}

    if ($Global:MRU ) {Write-Host "            • MRU - Most Recent Used."}
    if ($Global:SHI ) {Write-Host "            • SHI - AppCompatCache aka Shimcache."}
        
    if ($Global:BAM ) {Write-Host "            • BAM - Background Activity Moderator."}
    
    
    if ($Global:RAP ) {Write-Host "            • RAP - Recent Applications."}
    if ($Global:SYS ) {Write-Host "            • SYS - System Information."}

    if ($Global:LAC ) {Write-Host "            • LAC - Last Activity."}

    # OFFLINE
    if ($Global:HIV ) {Write-Host "            • HIV - HIVE files."}
    if ($Global:EVT ) {Write-Host "            • EVT - Windows Event Files."}
    if ($Global:FIL ) {Write-Host "            • FIL - 3 sorted lists of all system files (Modification, Access, Creation). "}
    if ($Global:PRF ) {Write-Host "            • PRF - Prefetch Files."}
    if ($Global:WSE ) {Write-Host "            • WSE - Windows Search Engine file (Windows.edb) and conversion to CSV file."}
    if ($Global:EET ) {Write-Host "            • EET - ETW (Event Tracing for Windows) and ETL (Event Trace Logs)."}
    if ($Global:JLI ) {Write-Host "            • JLI - Automatic and Custom JumpLists."}
    if ($Global:TIC ) {Write-Host "            • TIC - Thumbcache and Iconcache db files. Extraction of images and icons inside each db file."}
    if ($Global:FSF ) {Write-Host "            • FSF - File System Files: `$MFT, `$UsnJrnl, `$LogFile."}
    if ($Global:MSF ) {Write-Host "            • MSF - Memory Support Files: Hiberfil.sys, Pagefile.sys and Swapfile.sys."}
    if ($Global:TLH ) {Write-Host "            • TLH - Timeline History.(Windows 10 only)"}

    if ($Global:THA ) {Write-Host "            • THA - TextHarvester (WaitList.dat)."}
    if ($Global:SRU ) {Write-Host "            • SRU - System Resource Usage Monitor."}
    if ($Global:CRE ) {Write-Host "            • CRE - Web and Windows Credentials stored in Credentials Manager."}
    
    if ($Global:SKY ) {Write-Host "            • SKY - Skype conversations."}
    if ($Global:EMA ) {Write-Host "            • EMA - Email files. (Outlook folders and from everywhere else in the system)."}


    if ($Global:CHR ) {Write-Host "            • CHR - Chrome Browser Artifacts."}
    if ($Global:MFI ) {Write-Host "            • MFI - Mozilla Firefox Artifacts."}
    if ($Global:IEX ) {Write-Host "            • IEX - Internet Explorer Artifacts."}
    if ($Global:EDG ) {Write-Host "            • EDG - Edge Explorer Artifacts."}
    if ($Global:SAF ) {Write-Host "            • SAF - Safari Browser Artifacts."}
    if ($Global:OPE ) {Write-Host "            • OPE - Opera Brower Artifacts."}
    if ($Global:TOR ) {Write-Host "            • TOR - TOR Artifacts."}

    if ($Global:COD ) {Write-Host "            • COD - Cloud Onedrive Artifacts."}
    if ($Global:CGD ) {Write-Host "            • CGD - Cloud Googledrive Artifacts."}
    if ($Global:CDB ) {Write-Host "            • CDB - Cloud Dropbox Artifacts."}
    
    Write-Host "  ═══════════════════════════════════════════"
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
        [parameter(Mandatory=$True)]
        [ValidateNotNullOrEmpty()]$Path,
        [parameter(Mandatory=$True)]
        [ValidateNotNullOrEmpty()]$Value
    )

    $regvalue = Get-ItemProperty $Path $Value -ErrorAction SilentlyContinue

    return ($? -and ($regvalue -ne $null))
}

Function Invoke-WCMDump{
      
      <#
      .SYNOPSIS
         Dumps Windows credentials from the Windows Credential Manager for the current user.
         Author:  Barrett Adams (@peewpw)
      .DESCRIPTION
        Enumerates Windows credentials in the Credential Manager and then extracts available
        information about each one. Passwords can be retrieved for "Generic" type credentials,
        but not for "Domain" type credentials.
      .EXAMPLE
        PS>Import-Module .\Invoke-WCMDump.ps1
        PS>Invoke-WCMDump
            Username         : testusername
            Password         : P@ssw0rd!
            Target           : TestApplication
            Description      :
            LastWriteTime    : 12/9/2017 4:46:50 PM
            LastWriteTimeUtc : 12/9/2017 9:46:50 PM
            Type             : Generic
            PersistenceType  : Enterprise
      #>

    $source = @"
    // C# modified from https://github.com/spolnik/Simple.CredentialsManager

    using Microsoft.Win32.SafeHandles;
    using System;
    using System.Collections.Generic;
    using System.Runtime.InteropServices;
    using System.Security.Permissions;

    public class Credential : IDisposable
    {
        private static readonly object LockObject = new object();
        private static readonly SecurityPermission UnmanagedCodePermission;
        private string description;
        private DateTime lastWriteTime;
        private string password;
        private PersistenceType persistenceType;
        private string target;
        private CredentialType type;
        private string username;
        static Credential()
        {
            lock (LockObject)
            {
                UnmanagedCodePermission = new SecurityPermission(SecurityPermissionFlag.UnmanagedCode);
            }
        }

        public Credential(string username, string password, string target, CredentialType type)
        {
            Username = username;
            Password = password;
            Target = target;
            Type = type;
            PersistenceType = PersistenceType.Session;
            lastWriteTime = DateTime.MinValue;
        }

        public string Username
        {
            get { return username; }
            set { username = value; }
        }

        public string Password
        {
            get { return password; }
            set { password = value; }
        }

        public string Target
        {
            get { return target; }
            set { target = value; }
        }

        public string Description
        {
            get { return description; }
            set { description = value; }
        }

        public DateTime LastWriteTime
        {
            get { return LastWriteTimeUtc.ToLocalTime(); }
        }

        public DateTime LastWriteTimeUtc
        {
            get { return lastWriteTime; }
            private set { lastWriteTime = value; }
        }

        public CredentialType Type
        {
            get { return type; }
            set { type = value; }
        }

        public PersistenceType PersistenceType
        {
            get { return persistenceType; }
            set { persistenceType = value; }
        }

        public void Dispose() { }

        public bool Load()
        {
            UnmanagedCodePermission.Demand();

            IntPtr credPointer;

            Boolean result = NativeMethods.CredRead(Target, Type, 0, out credPointer);
            if (!result)
                return false;

            using (NativeMethods.CriticalCredentialHandle credentialHandle = new NativeMethods.CriticalCredentialHandle(credPointer))
            {
                LoadInternal(credentialHandle.GetCredential());
            }

            return true;
        }

        public static IEnumerable<Credential> LoadAll()
        {
            UnmanagedCodePermission.Demand();
            
            IEnumerable<NativeMethods.CREDENTIAL> creds = NativeMethods.CredEnumerate();
            List<Credential> credlist = new List<Credential>();
            
            foreach (NativeMethods.CREDENTIAL cred in creds)
            {
                Credential fullCred = new Credential(cred.UserName, null, cred.TargetName, (CredentialType)cred.Type);
                if (fullCred.Load())
                    credlist.Add(fullCred);
            }

            return credlist;
        }

        internal void LoadInternal(NativeMethods.CREDENTIAL credential)
        {
            Username = credential.UserName;

            if (credential.CredentialBlobSize > 0)
            {
                Password = Marshal.PtrToStringUni(credential.CredentialBlob, credential.CredentialBlobSize / 2);
            }

            Target = credential.TargetName;
            Type = (CredentialType)credential.Type;
            PersistenceType = (PersistenceType)credential.Persist;
            Description = credential.Comment;
            LastWriteTimeUtc = DateTime.FromFileTimeUtc(credential.LastWritten);
        }
    }

    public class NativeMethods
    {
        [DllImport("Advapi32.dll", EntryPoint = "CredReadW", CharSet = CharSet.Unicode, SetLastError = true)]
        internal static extern bool CredRead(string target, CredentialType type, int reservedFlag, out IntPtr credentialPtr);

        [DllImport("Advapi32.dll", EntryPoint = "CredFree", SetLastError = true)]
        internal static extern void CredFree([In] IntPtr cred);

        [DllImport("Advapi32.dll", EntryPoint = "CredEnumerate", SetLastError = true, CharSet = CharSet.Unicode)]
        public static extern bool CredEnumerate(string filter, int flag, out int count, out IntPtr pCredentials);

        [StructLayout(LayoutKind.Sequential)]
        internal struct CREDENTIAL
        {
            public int Flags;
            public int Type;
            [MarshalAs(UnmanagedType.LPWStr)] public string TargetName;
            [MarshalAs(UnmanagedType.LPWStr)] public string Comment;
            public long LastWritten;
            public int CredentialBlobSize;
            public IntPtr CredentialBlob;
            public int Persist;
            public int AttributeCount;
            public IntPtr Attributes;
            [MarshalAs(UnmanagedType.LPWStr)] public string TargetAlias;
            [MarshalAs(UnmanagedType.LPWStr)] public string UserName;
        }

        internal static IEnumerable<CREDENTIAL> CredEnumerate()
        {
            int count;
            IntPtr pCredentials;
            Boolean ret = CredEnumerate(null, 0, out count, out pCredentials);

            if (ret == false)
                throw new Exception("Failed to enumerate credentials");

            List<CREDENTIAL> credlist = new List<CREDENTIAL>();
            IntPtr credential = new IntPtr();
            for (int n = 0; n < count; n++)
            {
                credential = Marshal.ReadIntPtr(pCredentials, n * Marshal.SizeOf(typeof(IntPtr)));
                credlist.Add((CREDENTIAL)Marshal.PtrToStructure(credential, typeof(CREDENTIAL)));
            }

            return credlist;
        }

        internal sealed class CriticalCredentialHandle : CriticalHandleZeroOrMinusOneIsInvalid
        {
            internal CriticalCredentialHandle(IntPtr preexistingHandle)
            {
                SetHandle(preexistingHandle);
            }

            internal CREDENTIAL GetCredential()
            {
                if (!IsInvalid)
                {
                    return (CREDENTIAL)Marshal.PtrToStructure(handle, typeof(CREDENTIAL));
                }

                throw new InvalidOperationException("Invalid CriticalHandle!");
            }

            protected override bool ReleaseHandle()
            {
                if (!IsInvalid)
                {
                    CredFree(handle);
                    SetHandleAsInvalid();
                    return true;
                }
                return false;
            }
        }
    }

    public enum CredentialType : uint
    {
        None = 0,
        Generic = 1,
        DomainPassword = 2,
        DomainCertificate = 3,
        DomainVisiblePassword = 4,
        GenericCertificate = 5,
        DomainExtended = 6,
        Maximum = 7,
        CredTypeMaximum = Maximum+1000
    }

    public enum PersistenceType : uint
    {
        Session = 1,
        LocalComputer = 2,
        Enterprise = 3
    }
"@
    $add = Add-Type -TypeDefinition $source -Language CSharp -PassThru
    $loadAll = [Credential]::LoadAll()
    Write-Output $loadAll
}

<##################################################################################################################################>
<#########################  START CONTROL  ###########################################>
<##################################################################################################################################>

Function Check-Variables {
    
    <# Check DEVELOPER MODE and apply configurations if true #>    
    if($DevMode -eq $True){
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
        echo $GUI
        Control-GUI
        exit
    }

    if( -not $GUI)
    {
        Check-Variables # In GUI the control is done in the form
        Show-Simple-Options-Resume # In GUI this is not needed, because the info is in the GUI
        Execute-Format
                
        <# Creates base folder to the collect data. The folder name is the name of the computer where the data is being collected #>
        if ( -Not ( Test-Path $Global:Destiny\$HOSTNAME ) ) { New-Item -ItemType directory -Path $Global:Destiny\$HOSTNAME > $null }
                
        Control-NOGUI
    
        exit
    }
}

Start-Execution # STARTS THE EXECUTION OF THE PROGRAM

<##################################################################################################################################>
<#########################  SCRIPT END  ###########################################>
<##################################################################################################################################>