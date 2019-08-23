<# GLOBAL VARIABLES #>
$HOSTNAME = hostname
$OS = ((Get-WmiObject win32_operatingsystem).name).split(" ")[2] <# Intead of collecting the windows version: XP, Vista, 7, 10, ... should be according to the core #>
$USERS = Get-LocalUser | ? { $_.Enabled } | Select-Object -ExpandProperty Name
$SIDS = Get-ChildItem "REGISTRY::HKEY_USERS" | ForEach-Object { ($_.Name).Split("\")[1] } # list of user SIDs
$ARCH = $env:PROCESSOR_ARCHITECTURE
$SCRIPTPATH = split-path -parent $MyInvocation.MyCommand.Definition
    
<# defines according to architecture which version of Rawcpoy and SigCheck to use #>
if($ARCH -eq "AMD64") {
    $RAW_EXE = "$SCRIPTPATH\bin\RawCopy64.exe"
    $SIG_EXE = "$SCRIPTPATH\bin\sigcheck64.exe"
    $SQL_DBX_EXE = "$SCRIPTPATH\bin\sqlite-dbx-win64.exe"
    $OPEN_SAVED_FILES_VIEW = "$SCRIPTPATH\bin\opensavefilesview-x64\OpenSaveFilesView.exe"
    
} else {
    $RAW_EXE = "$SCRIPTPATH\bin\RawCopy.exe"
    $SIG_EXE = "$SCRIPTPATH\bin\sigcheck.exe"
    $SQL_DBX_EXE = "$SCRIPTPATH\bin\sqlite-dbx-win32.exe"
    $OPEN_SAVED_FILES_VIEW = "$SCRIPTPATH\bin\opensavefilesview\OpenSaveFilesView.exe"
    
}

$UsedParameters = $PSBoundParameters.Keys <# TODO: Will use this variable to check which parameters were inserted in the command line and therefore don't need confirmation #>

$Global:Destiny = "F:\MyDOCS\TFM\tests"

Function Report-Error {

    param(
        [string]$evidence        
    )

    Write-Host "`t[-] Error Collecting $evidence . Check log file for more info."  -ForegroundColor Red
    echo "`t[-] Error Collecting $evidence :" >> $Global:Destiny\$HOSTNAME\errors.log
    $_.Exception.GetType().FullName >> $Global:Destiny\$HOSTNAME\errors.log
    $_.Exception.Message >> $Global:Destiny\$HOSTNAME\errors.log
}

$ScriptTime = [Diagnostics.Stopwatch]::StartNew();  

###################################################################


Get-ChildItem "C:\Users\Nuno Pinto\AppData\Local\Google\Chrome\User Data" | ForEach-Object {
    if($_.Name -match "Profile") { Write-Host "THIS IS ONE: $($_.Name)"}
}


















###################################################################
$ScriptTime.Stop(); 
Write-Host "`t└>Execution time: $($ScriptTime.Elapsed)"
###################################################################

<#
$ScriptTime = [Diagnostics.Stopwatch]::StartNew();  
Get-ChildItem C:\ -Recurse *.ost 2> $null
$ScriptTime.Stop(); 
Write-Host "`t└>Execution time: $($ScriptTime.Elapsed)"

#>

<#
Function Get-SIDUsername {
    
    param(
        [string]$sid        
    )

    $N = Get-ItemPropertyValue -Path "REGISTRY::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\$SID\" -Name "ProfileImagePath"
    $NAME = $($N.Split("\")[2])
    return $NAME
}
#>


<#
foreach($SID in $SIDS){

    if ($SID.Split("-")[7] -ne $null -and $SID.Split("-")[7] -notlike "*_Classes") # the ones that users removes the system and network and classes
    { 

        $N = Get-ItemPropertyValue -Path "REGISTRY::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\$SID\" -Name "ProfileImagePath"  # get's the name correspondent to the SID
        $NAME = $($N.Split("\")[2])

        if ( -Not ( Test-Path $Global:Destiny\$HOSTNAME\MRUs\$NAME ) ) { New-Item -ItemType directory -Path $Global:Destiny\$HOSTNAME\MRUs\$NAME > $null }
            
        Write-Host "`t[+] Collecting RECENT DOCS from $NAME - From Registry" -ForegroundColor Green

        echo " " >> "$Global:Destiny\$HOSTNAME\MRUs\$NAME\RecentDocs.txt"
        echo "KEY: NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs" >> "$Global:Destiny\$HOSTNAME\MRUs\$NAME\RecentDocs.txt"
        echo "INFO: Identifies recently accessed documents by extension subkeys. Values in the main RecentDocs subkey lists the last 150 objects opened in order." >> "$Global:Destiny\$HOSTNAME\MRUs\$NAME\RecentDocs.txt"
        echo "INFO: Same info as in C:\Users\[PROFILE]\Recent or C:\Users\[PROFILE]\AppData\Roaming\Microsoft\Windows\Recent " >> "$Global:Destiny\$HOSTNAME\MRUs\$NAME\RecentDocs.txt"
        echo " " >> "$Global:Destiny\$HOSTNAME\MRUs\$NAME\RecentDocs.txt"
        echo "More Info(page.20): https://www.syntricate.com/files/Registry%20Reference%20Guide%20AD%20100116.pdf" >> "$Global:Destiny\$HOSTNAME\MRUs\$NAME\RecentDocs.txt"
        echo " " >> "$Global:Destiny\$HOSTNAME\MRUs\$NAME\RecentDocs.txt"

        $list = Get-ItemPropertyValue "REGISTRY::HKEY_USERS\$SID\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs" -Name MRUListEx 2> $null

        $count = 0
        $n = 0
        foreach($pos in $list)
        {
            if( (($count % 4) -eq 0) -and (-not ($pos -eq 255)) )
            {
                echo "Count: $count | Pos: $pos"
                $entry = Get-ItemPropertyValue "REGISTRY::HKEY_USERS\$SID\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs" -Name $pos 2>$null
                
                if($entry -eq $null) 
                { 
                    #echo "(EMPTY)" >> "$Global:Destiny\$HOSTNAME\MRUs\$NAME\RecentDocs.txt"
                    #$n++
                    continue 
                } # In case the value position is empty continue to the next one
            
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
            $entry = $null
            $count++
        }
    }
}

#>


<#

$SID = "S-1-5-21-1043274734-587376806-3880736319-1001"

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

# DOESN'T EXIST
$dexists = (Test-RegistryValue -Path "REGISTRY::HKEY_USERS\$SID\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU\" -Value "MRUList" )
# EXISTS
$exists = (Test-RegistryValue -Path "REGISTRY::HKEY_USERS\$SID\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\LastVisitedPidlMRU\" -Value MRUListEx)

Write-Host "Doesn't exists: $dexists"

Write-Host "Exsits: $exists"

_______________________________

# Test if specific value exists in the registry #
Function Test-RegistryValue {
    param (
        [parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]$Path,
        [parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]$Value
    )

    try 
    {
        Get-ItemProperty -Path $Path | Select-Object -ExpandProperty $Value -ErrorAction Suspend | Out-Null
        return $true
    }
    catch 
    {
        return $false
    }
}

_______________________________

$SID = "S-1-5-21-1043274734-587376806-3880736319-1001"
$regkey = "REGISTRY::HKEY_USERS\$SID\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU\"
$name = "MRUList"

# $regvalue = Get-ItemPropertyValue "REGISTRY::HKEY_USERS\$SID\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU\" -Name MRUList -ErrorAction SilentlyContinue

# $regvalue = Get-ItemProperty $regkey $name -ErrorAction SilentlyContinue

# ($? -and ($regvalue -ne $null))


# DOESN'T EXIST

$dexists = (Test-RegistryValue -Path "REGISTRY::HKEY_USERS\$SID\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU\" -Value "MRUList" )

# EXISTS

$exists = (Test-RegistryValue -Path "REGISTRY::HKEY_USERS\$SID\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\LastVisitedPidlMRU\" -Value MRUListEx)

Write-Host "Doesn't exists: $dexists"

Write-Host "Exsits: $exists"

_____________________________________________________________________________________________
#>

<#

Get-ChildItem -Force "C:\Users\Nuno Pinto\AppData\Roaming\Microsoft\Protect\S-1-5-21-1177053623-3576167574-2408905411-1001" | ForEach-Object { 

    echo "--------------------------------------------"
    $_ | Format-Hex


}


[System.Reflection.Assembly]::Load([System.IO.File]::ReadAllBytes("$SCRIPTPATH\dependencies\JumpList.dll")) > $null
[System.Reflection.Assembly]::Load([System.IO.File]::ReadAllBytes("$SCRIPTPATH\dependencies\OleCf.dll")) > $null
[System.Reflection.Assembly]::Load([System.IO.File]::ReadAllBytes("$SCRIPTPATH\dependencies\Lnk.dll")) > $null
[System.Reflection.Assembly]::Load([System.IO.File]::ReadAllBytes("$SCRIPTPATH\dependencies\ExtensionBlocks.dll")) > $null
[System.Reflection.Assembly]::Load([System.IO.File]::ReadAllBytes("$SCRIPTPATH\dependencies\GuidMapping.dll")) > $null


echo "File Name, Full Path, Last Modified, Creation Date, Accessed Date, Modification date, File Attributes, File Size, Entry ID, Pos. MRU, Appication ID, Application Name, Mac Address, File Extension, Computer Name, Network Share Name, Drive Type, Volume Label, Volume SN, Jump List Filename " > JumplLists_Auto.csv

Get-ChildItem "C:\Users\Nuno Pinto\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations" | ForEach-Object {
    
    try
    {
        $list = [JumpList.JumpList]::LoadAutoJumplist("C:\Users\Nuno Pinto\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations\$_")

        #echo "Directory: $($list.get_Directory())"
    
        #echo "Source File: $($list.SourceFile)"
        $JLFilename = $($list.SourceFile)
    
        #echo "APP ID: $($list.AppId.AppId)"
        $AppID = $($list.AppId.AppId)
    
        #echo "Description: $($list.AppId.Description)"
        $AppName = $($list.AppId.Description)
    
        #echo "Destiny List Count: $($list.DestListCount)"
        #echo "Destiny List Version: $($list.DestListVersion)"
        #echo "Directory Count: $($list.Directory.Count)"
 
        foreach($bla in $list.DestListEntries)
        {
            #[Jumplist.Automatic.AutomaticDestination]::get_AppId($bla)
            #echo "`t----------"
            #echo "`tEntry Number: $($bla.EntryNumber)"
            $EntryID = $($bla.EntryNumber)

            #echo "`tMRU Position: $($bla.MRUPosition)"
            $PosMRU = $($bla.MRUPosition)
        
            #echo "`tPath: $($bla.Path)"
            $FullPath = $($bla.Path).Replace(","," ")
            $FileName = $($FullPath).Split("\")[-1]
            $Extension = $($FileName).Split(".")[-1]
            if($Extension.length -gt 3) { $Extension = "" }
        
            #echo "`tPinned: $($bla.Pinned)"
        
            #echo "`tCreated On: $($bla.CreatedOn)"
        
            #echo "`tLast Modified: $($bla.LastModified)"
            $LastModified = $($bla.LastModified)
        
            #echo "`tHostname: $($bla.Hostname)"
            $ComputerName = $($bla.Hostname)
        
            #echo "`tMacAddress: $($bla.MacAddress)"
            $MacAddress = $($bla.MacAddress)


            #echo "`t`tLNK Header: $($bla.Lnk.Header)"
                #echo "`t`t`tLNK DataFlags: $($bla.Lnk.Header.DataFlags)"
            
                #echo "`t`t`tLNK FileAttributes: $($bla.Lnk.Header.FileAttributes)"
                $FileAttributes = $($bla.Lnk.Header.FileAttributes).ToString().Replace(","," ")
            
                #echo "`t`t`tLNK FileSize: $($bla.Lnk.Header.FileSize)"
                $FileSize = $($bla.Lnk.Header.FileSize)

                #echo "`t`t`tLNK HotKey: $($bla.Lnk.Header.HotKey)"
                #echo "`t`t`tLNK IconIndex: $($bla.Lnk.Header.IconIndex)"
                #echo "`t`t`tLNK Reserved0: $($bla.Lnk.Header.Reserved0)"
                #echo "`t`t`tLNK Reserved1: $($bla.Lnk.Header.Reserved1)"
                #echo "`t`t`tLNK Reserved2: $($bla.Lnk.Header.Reserved2)"
                #echo "`t`t`tLNK ShowWindow: $($bla.Lnk.Header.ShowWindow)"
                #echo "`t`t`tLNK Signature: $($bla.Lnk.Header.Signature)"
            
                #echo "`t`t`tLNK TargetCreationDate: $($bla.Lnk.Header.TargetCreationDate)"
                $CreationDate = $($bla.Lnk.Header.TargetCreationDate)

                #echo "`t`t`tLNK TargetLastAccessedDate: $($bla.Lnk.Header.TargetLastAccessedDate)"
                $AccessedDate = $($bla.Lnk.Header.TargetLastAccessedDate)
            
                #echo "`t`t`tLNK TargetModificationDate: $($bla.Lnk.Header.TargetModificationDate)"
                $ModificationDate = $($bla.Lnk.Header.TargetModificationDate)

            #echo "`t`tLNK Helpers: $($bla.Lnk.Helpers)"
            #echo "`t`tLNK Lnk: $($bla.Lnk.Lnk)"
            #echo "`t`tLNK LnkFile: $($bla.Lnk.LnkFile)"
            #echo "`t`tLNK NetworkShareInfo: $($bla.Lnk.NetworkShareInfo)"
                #echo "`t`t`tLNK DeviceName: $($bla.Lnk.NetworkShareInfo.DeviceName)"
                #echo "`t`t`tLNK DeviceNameOffset: $($bla.Lnk.NetworkShareInfo.DeviceNameOffset)"
                #echo "`t`t`tLNK DeviceNameOffset: $($bla.Lnk.NetworkShareInfo.NetworkProviderType)"
            
                #echo "`t`t`tLNK NetworkShareName: $($bla.Lnk.NetworkShareInfo.NetworkShareName)"
                $NetworkShareName = $($bla.Lnk.NetworkShareInfo.NetworkShareName)
            
                #echo "`t`t`tLNK NetworkShareNameOffset: $($bla.Lnk.NetworkShareInfo.NetworkShareNameOffset)"
                #echo "`t`t`tLNK ShareFlags: $($bla.Lnk.NetworkShareInfo.ShareFlags)"
                #echo "`t`t`tLNK Size: $($bla.Lnk.NetworkShareInfo.Size)"
            #echo "`t`tLNK VolumeInfo: $($bla.Lnk.VolumeInfo)"
            
                #echo "`t`t`tLNK DriveType: $($bla.Lnk.VolumeInfo.DriveType)"
                $DriveType = $($bla.Lnk.VolumeInfo.DriveType)
            
                #echo "`t`t`tLNK Size: $($bla.Lnk.VolumeInfo.Size)"
            
                #echo "`t`t`tLNK VolumeLabel: $($bla.Lnk.VolumeInfo.VolumeLabel)"
                $VolumeLabel = $($bla.Lnk.VolumeInfo.VolumeLabel)
            
                #echo "`t`t`tLNK VolumeLabelOffset: $($bla.Lnk.VolumeInfo.VolumeLabelOffset)"
            
                #echo "`t`t`tLNK VolumeSerialNumber: $($bla.Lnk.VolumeInfo.VolumeSerialNumber)"
                $VolumeSerialNumber = $($bla.Lnk.VolumeInfo.VolumeSerialNumber)

                #
                echo "$FileName, $FullPath, $LastModified, $CreationDate, $AccessedDate, $ModificationDate, $FileAttributes, $FileSize, $EntryID, $PosMRU, $AppID, $AppName, $MacAddress, $Extension, $ComputerName, $NetworkShareName, $DriveType, $VolumeLabel, $VolumeSerialNumber, $JLFilename " >> JumplLists_Auto.csv
        }
    }
    catch
    {
        echo "bla"
    }
}


echo "App ID, App Name, Creation Date, Accessed Date, Modification date, File Attributes, File Size, Network Share Name, Drive Type, Volume Label, Volume SN , Jump List Filename " > JumplLists_Custom.csv

Get-ChildItem "C:\Users\Nuno Pinto\AppData\Roaming\Microsoft\Windows\Recent\CustomDestinations" | ForEach-Object {

    try
    {
        $list = [JumpList.JumpList]::LoadCustomJumplist("C:\Users\Nuno Pinto\AppData\Roaming\Microsoft\Windows\Recent\CustomDestinations\$_")

        #echo "Directory: $($list.get_Directory())"
    
        #echo "Source File: $($list.SourceFile)"
        $SourceFilename = $($list)
    
        #echo "APP ID: $($list.AppId.AppId)"
        $AppID = $($list.AppId.AppId)
    
        #echo "Description: $($list.AppId.Description)"
        $AppName = $($list.AppId.Description)
    
        #echo "Directory Count: $($list.Directory.Count)"
 
        #echo "Directory Count: $($list.Entries.Count)"

        #$entryNum = 0;


        foreach($entry in $list.Entries)
        {
            #$entryNum += 1
            #echo "Entry Number: $entryNum "

            #echo "Lnk Count: $($entry.LnkFiles.Count)"
        
            #echo "Rank: $($entry.Rank)"

            foreach($bla in $entry.LnkFiles)
            {
                #[Jumplist.Automatic.AutomaticDestination]::get_AppId($bla)
                #echo "`t----------"

                #echo "`t`tLNK Header: $($bla.Header)"
                    #echo "`t`t`tLNK DataFlags: $($bla.Header.DataFlags)"
            
                    #echo "`t`t`tLNK FileAttributes: $($bla.Header.FileAttributes)"
                    $FileAttributes = $($bla.Header.FileAttributes).ToString().Replace(","," ")
            
                    #echo "`t`t`tLNK FileSize: $($bla.Header.FileSize)"
                    $FileSize = $($bla.Header.FileSize)

                    #echo "`t`t`tLNK HotKey: $($bla.Header.HotKey)"
                    #echo "`t`t`tLNK IconIndex: $($bla.Header.IconIndex)"
                    #echo "`t`t`tLNK Reserved0: $($bla.Header.Reserved0)"
                    #echo "`t`t`tLNK Reserved1: $($bla.Header.Reserved1)"
                    #echo "`t`t`tLNK Reserved2: $($bla.Header.Reserved2)"
                    #echo "`t`t`tLNK ShowWindow: $($bla.Header.ShowWindow)"
                    #echo "`t`t`tLNK Signature: $($bla.Header.Signature)"
            
                    #echo "`t`t`tLNK TargetCreationDate: $($bla.Header.TargetCreationDate)"
                    $CreationDate = $($bla.Header.TargetCreationDate)

                    #echo "`t`t`tLNK TargetLastAccessedDate: $($bla.Header.TargetLastAccessedDate)"
                    $AccessedDate = $($bla.Header.TargetLastAccessedDate)
            
                    #echo "`t`t`tLNK TargetModificationDate: $($bla.Header.TargetModificationDate)"
                    $ModificationDate = $($bla.Header.TargetModificationDate)

                #echo "`t`tLNK Helpers: $($bla.Helpers)"
                #echo "`t`tLNK Lnk: $($bla.Lnk)"
                #echo "`t`tLNK LnkFile: $($bla.LnkFile)"
                    #echo "`t`tLNK LnkFile: $($bla.LnkFile.Arguments)"
                    #echo "`t`tLNK LnkFile: $($bla.LnkFile.CommonPath)"
                    #echo "`t`tLNK LnkFile: $($bla.LnkFile.ExtraBlocks)"
                    #echo "`t`tLNK LnkFile: $($bla.LnkFile.Header)"
                    #echo "`t`tLNK LnkFile: $($bla.LnkFile.IconLocation)"
                    #echo "`t`tLNK LnkFile: $($bla.LnkFile.LocalPath)"
                    #echo "`t`tLNK LnkFile: $($bla.LnkFile.LocationFlags)"
                    #echo "`t`tLNK LnkFile: $($bla.LnkFile.Name)"
                    #echo "`t`tLNK LnkFile: $($bla.LnkFile.NetWorkShareInfo)"
                    #echo "`t`tLNK LnkFile: $($bla.LnkFile.RawBytes)"
                    #echo "`t`tLNK LnkFile: $($bla.LnkFile.RelativePath)"
                
                    #echo "`t`tLNK LnkFile: $($bla.LnkFile.SourceFile)"
                    #echo "`t`tLNK LnkFile: $($bla.LnkFile.VolumeInfo)"
                    #echo "`t`tLNK LnkFile: $($bla.LnkFile.WorkingDirectory)"
                
                #echo "`t`tLNK NetworkShareInfo: $($bla.NetworkShareInfo)"
                    #echo "`t`t`tLNK DeviceName: $($bla.NetworkShareInfo.DeviceName)"
                    #echo "`t`t`tLNK DeviceNameOffset: $($bla.NetworkShareInfo.DeviceNameOffset)"
                    #echo "`t`t`tLNK DeviceNameOffset: $($bla.NetworkShareInfo.NetworkProviderType)"
            
                    #echo "`t`t`tLNK NetworkShareName: $($bla.NetworkShareInfo.NetworkShareName)"
                    $NetworkShareName = $($bla.NetworkShareInfo.NetworkShareName)
            
                    #echo "`t`t`tLNK NetworkShareNameOffset: $($bla.NetworkShareInfo.NetworkShareNameOffset)"
                    #echo "`t`t`tLNK ShareFlags: $($bla.NetworkShareInfo.ShareFlags)"
                    #echo "`t`t`tLNK Size: $($bla.NetworkShareInfo.Size)"
                #echo "`t`tLNK VolumeInfo: $($bla.VolumeInfo)"
            
                    #echo "`t`t`tLNK DriveType: $($bla.VolumeInfo.DriveType)"
                    $DriveType = $($bla.VolumeInfo.DriveType)
            
                    #echo "`t`t`tLNK Size: $($bla.VolumeInfo.Size)"
            
                    #echo "`t`t`tLNK VolumeLabel: $($bla.VolumeInfo.VolumeLabel)"
                    $VolumeLabel = $($bla.VolumeInfo.VolumeLabel)
            
                    #echo "`t`t`tLNK VolumeLabelOffset: $($bla.VolumeInfo.VolumeLabelOffset)"
            
                    #echo "`t`t`tLNK VolumeSerialNumber: $($bla.VolumeInfo.VolumeSerialNumber)"
                    $VolumeSerialNumber = $($bla.VolumeInfo.VolumeSerialNumber)

                <#
                lnkFile.Header.TargetCreationDate
                lnkFile.Header.TargetModificationDate
                lnkFile.Header.TargetLastAccessedDate
                lnkFile.Header.DataFlags
                lnkFile.Name
                lnkFile.RelativePath
                lnkFile.WorkingDirectory
                lnkFile.Arguments
                lnkFile.LocationFlags
                lnkFile.VolumeInfo
                
                echo "$AppID, $AppName, $CreationDate, $AccessedDate, $ModificationDate, $FileAttributes, $FileSize, $NetworkShareName, $DriveType, $VolumeLabel, $VolumeSerialNumber, $JLFilename " >> JumplLists_Custom.csv
            }
        }
    }
    catch
    {
        echo "bla"
    }
}

#>

<#
$list = [JumpList.JumpList]::LoadAutoJumplist("C:\Users\Nuno Pinto\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations\5f7b5f1e01b83767.automaticDestinations-ms");

echo "·····························································································································"
echo "····················· AUTOMATIC ·····························································································"
echo "·····························································································································"

echo "-----------------------------------------------------------"
echo "Directory: $($list.get_Directory())"
echo "-----------------------------------------------------------"
echo "AppID: $($list.get_AppId())"
echo "-----------------------------------------------------------"
echo "Dest Count: $($list.DestListCount())"
echo "-----------------------------------------------------------"
echo "Pinned Dest List Count: $($list.get_PinnedDestListCount())"
echo "-----------------------------------------------------------"
echo "Last Used Entry Number: $($list.get_LastUsedEntryNumber())"
echo "-----------------------------------------------------------"
echo "Dest List Version: $($list.get_DestListVersion())"
echo "-----------------------------------------------------------"
echo "Source File: $($list.get_SourceFile())"
echo "-----------------------------------------------------------"
echo "Dest List: $($list.get_DestList())"
echo "-----------------------------------------------------------"
echo "Get Lnk From Directory Name: $($list.GetLnkFromDirectoryName())"
echo "-----------------------------------------------------------"
echo "To String: $($list.ToString())"
echo "-----------------------------------------------------------"
echo "Dump All Lnk Files: $($list.DumpAllLnkFiles())"
echo "-----------------------------------------------------------"



$list = [JumpList.JumpList]::LoadCustomJumplist("C:\Users\Nuno Pinto\AppData\Roaming\Microsoft\Windows\Recent\CustomDestinations\7111c0ce965b7246.customDestinations-ms");

echo "·····························································································································"
echo "····················· CUSTOM ································································································"
echo "·····························································································································"

echo "-----------------------------------------------------------"
echo "Source File: $($list.get_SourceFile())"
echo "-----------------------------------------------------------"
echo "AppID: $($list.get_AppId())"
echo "-----------------------------------------------------------"
echo "Entries: $($list.get_Entries())"
echo "-----------------------------------------------------------"
echo "String: $($list.ToString())"
echo "-----------------------------------------------------------"

#>





<#

$list = [JumpList.JumpList]::LoadAutoJumplist("C:\Users\Nuno Pinto\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations\5f7b5f1e01b83767.automaticDestinations-ms");

echo "·····························································································································"
echo "····················· AUTOMATIC ·····························································································"
echo "·····························································································································"

    echo "*******************************************************************************************************************"
    echo "********************* DECLARED FIELDS *****************************************************************************"
    echo "*******************************************************************************************************************"
    ($list.getType()).DeclaredFields
    echo "*******************************************************************************************************************"
    echo "********************* DECLARED MEMBERS ****************************************************************************"
    echo "*******************************************************************************************************************"
    ($list.getType()).DeclaredMembers
    echo "*******************************************************************************************************************"
    echo "********************* DECLARED METHODS ****************************************************************************"
    echo "*******************************************************************************************************************"
    ($list.getType()).DeclaredMethods
    echo "*******************************************************************************************************************"
    echo "********************* DECLARED NESTED TYPES ***********************************************************************"
    echo "*******************************************************************************************************************"
    ($list.getType()).DeclaredNestedTypes
    echo "*******************************************************************************************************************"
    echo "********************* DECLARED PROPERTIES *************************************************************************"
    echo "*******************************************************************************************************************"
    ($list.getType()).DeclaredProperties

$list = [JumpList.JumpList]::LoadCustomJumplist("C:\Users\Nuno Pinto\AppData\Roaming\Microsoft\Windows\Recent\CustomDestinations\7111c0ce965b7246.customDestinations-ms");

echo "·····························································································································"
echo "····················· CUSTOM ································································································"
echo "·····························································································································"


    echo "*******************************************************************************************************************"
    echo "********************* DECLARED FIELDS *****************************************************************************"
    echo "*******************************************************************************************************************"
    ($list.getType()).DeclaredFields
    echo "*******************************************************************************************************************"
    echo "********************* DECLARED MEMBERS ****************************************************************************"
    echo "*******************************************************************************************************************"
    ($list.getType()).DeclaredMembers
    echo "*******************************************************************************************************************"
    echo "********************* DECLARED METHODS ****************************************************************************"
    echo "*******************************************************************************************************************"
    ($list.getType()).DeclaredMethods
    echo "*******************************************************************************************************************"
    echo "********************* DECLARED NESTED TYPES ***********************************************************************"
    echo "*******************************************************************************************************************"
    ($list.getType()).DeclaredNestedTypes
    echo "*******************************************************************************************************************"
    echo "********************* DECLARED PROPERTIES *************************************************************************"
    echo "*******************************************************************************************************************"
    ($list.getType()).DeclaredProperties

    #>











<#
echo "----------------------------------------------------------------"

$content = Get-ItemPropertyValue "REGISTRY::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache" -Name AppCompatCache
$index=[System.BitConverter]::ToInt32($content,0)
$Position = 0

echo "Position, Path, Modified"

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
    $index += $PathSize
    #echo "Path: $Path"

    $LastModifiedTimeUTC = [System.DateTimeOffset]::FromFileTime([System.BitConverter]::ToInt64($content,$index))
    $index += 8
    #echo "Modified Time: $LastModifiedTimeUTC"

    $DataSize = [System.BitConverter]::ToInt32($content, $index)
    $index += 4
    #echo "Data Size: $DataSize"

    $Data = [System.Text.Encoding]::Unicode.GetString($content, $index, $DataSize)
    $index += $DataSize
    #echo "Data: $Data"

    echo "$Position, $Path, $LastModifiedTimeUTC"

}






#>


                     
#################### O L D ###############################################
                   
# Get the date of each object
# Get-ItemProperty "REGISTRY::HKEY_USERS\S-1-5-21-1177053623-3576167574-2408905411-1001\Software\Microsoft\Windows\CurrentVersion\Search\RecentApps\*" | Select -ExpandProperty "LastAccessedTime" | foreach {[datetime]::FromFileTime($_)}

<#
foreach($SID in $SIDS)
{
    if ($SID.Split("-")[7] -ne $null -and $SID.Split("-")[7] -notlike "*_Classes") # the ones that users removes the system and network and classes
    {
        $N = Get-ItemPropertyValue -Path "REGISTRY::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\$SID\" -Name "ProfileImagePath"  # get's the name correspondent to the SID
        $NAME = $($N.Split("\")[2])

        if ( -Not ( Test-Path $Global:Destiny\$HOSTNAME\RECENTAPPS\$NAME ) ) { New-Item -ItemType directory -Path $Global:Destiny\$HOSTNAME\RECENTAPPS\$NAME > $null }
        Write-Host "[+] Collecting Recent Apps info from $NAME" -ForegroundColor Green

        $RA_SID = Get-ChildItem "REGISTRY::HKEY_USERS\$SID\Software\Microsoft\Windows\CurrentVersion\Search\RecentApps\" | Select-Object -ExpandProperty Name | foreach { $_.split("\")[8] }

        foreach($R in $RA_SID)
        {
            echo "---------------------------------------------------" >> "$Global:Destiny\$HOSTNAME\RECENTAPPS\$NAME\RecentApps.txt"
            echo "---------------------------------------------------" >> "$Global:Destiny\$HOSTNAME\RECENTAPPS\$NAME\RecentApps.txt"
            echo "SID: $R" >> "$Global:Destiny\$HOSTNAME\RECENTAPPS\$NAME\RecentApps.txt"
            $tempAppId = Get-ItemPropertyValue "REGISTRY::HKEY_USERS\$SID\Software\Microsoft\Windows\CurrentVersion\Search\RecentApps\$R" -Name AppId
            echo "AppID: $tempAppId"  >> "$Global:Destiny\$HOSTNAME\RECENTAPPS\$NAME\RecentApps.txt"
            $tempLaunchCount = Get-ItemPropertyValue "REGISTRY::HKEY_USERS\$SID\Software\Microsoft\Windows\CurrentVersion\Search\RecentApps\$R" -Name LaunchCount
            echo "LaunchCount: $tempLaunchCount"  >> "$Global:Destiny\$HOSTNAME\RECENTAPPS\$NAME\RecentApps.txt"
            $tempAppPath = Get-ItemPropertyValue "REGISTRY::HKEY_USERS\$SID\Software\Microsoft\Windows\CurrentVersion\Search\RecentApps\$R" -Name AppPath
            echo "AppPath: $tempAppPath"  >> "$Global:Destiny\$HOSTNAME\RECENTAPPS\$NAME\RecentApps.txt"
            $tempDateDec = Get-ItemPropertyValue "REGISTRY::HKEY_USERS\$SID\Software\Microsoft\Windows\CurrentVersion\Search\RecentApps\$R"-Name LastAccessedTime
            $tempDate = [datetime]::FromFileTime($tempDateDec)
            echo "Date: $tempDate" >> "$Global:Destiny\$HOSTNAME\RECENTAPPS\$NAME\RecentApps.txt"
            
            echo "--- Associated Files:" >> "$Global:Destiny\$HOSTNAME\RECENTAPPS\$NAME\RecentApps.txt"
            
            if(Test-Path "REGISTRY::HKEY_USERS\$SID\Software\Microsoft\Windows\CurrentVersion\Search\RecentApps\$R\RecentItems")
            {
                $FILE_SID = Get-ChildItem "REGISTRY::HKEY_USERS\$SID\Software\Microsoft\Windows\CurrentVersion\Search\RecentApps\$R\RecentItems\" | Select-Object -ExpandProperty Name | foreach { $_.split("\")[10] }

                foreach($F in $FILE_SID)
                {
                    $tempName = Get-ItemPropertyValue "REGISTRY::HKEY_USERS\$SID\Software\Microsoft\Windows\CurrentVersion\Search\RecentApps\$R\RecentItems\$F" -Name DisplayName
                    echo "`tName: $tempName"  >> "$Global:Destiny\$HOSTNAME\RECENTAPPS\$NAME\RecentApps.txt"
                    $tempPath = Get-ItemPropertyValue "REGISTRY::HKEY_USERS\$SID\Software\Microsoft\Windows\CurrentVersion\Search\RecentApps\$R\RecentItems\$F" -Name Path
                    echo "`tPath: $tempPath"  >> "$Global:Destiny\$HOSTNAME\RECENTAPPS\$NAME\RecentApps.txt"
                    $tempDateDec = Get-ItemPropertyValue "REGISTRY::HKEY_USERS\$SID\Software\Microsoft\Windows\CurrentVersion\Search\RecentApps\$R\RecentItems\$F" -Name LastAccessedTime
                    $tempDate = [datetime]::FromFileTime($tempDateDec)
                    echo "`tDate: $tempDate" >> "$Global:Destiny\$HOSTNAME\RECENTAPPS\$NAME\RecentApps.txt"
                }
            }
            else
            {
                echo "`tThis app doesn't have recent open files associated." >> "$Global:Destiny\$HOSTNAME\RECENTAPPS\$NAME\RecentApps.txt"
            }

        }

    }
}

#>
        <#
                $runningProcesses = Get-CimInstance -ClassName Win32_Process |
                    Select-Object CreationDate, ProcessName, ProcessId, CommandLine, ParentProcessId

                for($i=0; $i -le $runningProcesses.count; $i++)
                {
                    $runningProcesses[$i]

                    Write-Host("Parent:")`                    (Get-CimInstance -ClassName Win32_Process | where ProcessId -eq $runningProcesses[$i].ParentProcessId).ProcessName
                    Write-Host("Parent CmdLine:")`                    (Get-CimInstance -ClassName Win32_Process | where ProcessId -eq $runningProcesses[$i].ParentProcessId).CommandLine
                    Write-Host("--------------------")
                }
                #>

<#
Function Collect-OpenSavePidlMRU {

    <# TODO: Translation of the ecnripted code into readable code 
    #  [System.Text.Encoding]::Default.GetString((Get-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\OpenSavePidlMRU\docx")."9")

    Write-Host "[+] Collecting MRU's ..." -ForegroundColor Green
        
    $SIDs = Get-ChildItem "REGISTRY::HKEY_USERS" | ForEach-Object { ($_.Name).Split("\")[1] } # list of user SIDs

    foreach($SID in $SIDS){

        if ($SID.Split("-")[7] -ne $null -and $SID.Split("-")[7] -notlike "*_Classes") # the ones that users removes the system and network and classes
        { 

            $N = Get-ItemPropertyValue -Path "REGISTRY::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\$SID\" -Name "ProfileImagePath"  # get's the name correspondent to the SID
            $NAME = $($N.Split("\")[2])

            if ( -Not ( Test-Path $Global:Destiny\$HOSTNAME\MRUs\$NAME ) ) { New-Item -ItemType directory -Path $Global:Destiny\$HOSTNAME\MRUs\$NAME > $null }
            
            # COMDLG32 :: OpenSavePidlMRU
            Write-Host "`t[+] OpenSavePidlMRU from $NAME" -ForegroundColor Green

            $cnt = Get-ItemPropertyValue -LiteralPath "REGISTRY::HKEY_USERS\S-1-5-21-1177053623-3576167574-2408905411-1001\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\OpenSavePidlMRU\*" -Name MRUListEx
            $i=0
            foreach($b in $cnt){$i++} # gets the number of entries
            $max = (($i / 4) - 1)

            for($n=0; $n -lt $max; $n++)
            {
                try 
                {
                    $temp = Get-ItemPropertyValue "REGISTRY::HKEY_USERS\S-1-5-21-1177053623-3576167574-2408905411-1001\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\OpenSavePidlMRU\*" -Name $n
            
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
            # OpenSavePidlMRU
            # TODO: IMplement this: HKEY_USERS\S-1-5-21-1177053623-3576167574-2408905411-1001\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\OpenSavePidlMRU

        }
    }
        
    if($OS -eq "XP"){ <# TODO: This has to be checked
        # OLD - cmd.exe /c reg export "HKEY_CURRENT_USER\Software\Microsoft\Windows\ShellNoRoam\MUICache" "$Global:Destiny\$HOSTNAME\MRUs\MUICacheXP.reg" > $null 
        Get-ItemProperty "REGISTRY::HKEY_CURRENT_USER\Software\Microsoft\Windows\ShellNoRoam\MUICache" > "$Global:Destiny\$HOSTNAME\MRUs\MUICacheXP.reg"
        # OLD - cmd.exe /c reg export "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\LastVisitedMRU" "$Global:Destiny\$HOSTNAME\MRUs\LastVisitedMRUxp.reg" > $null 
        Get-ItemProperty "REGISTRY::HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\LastVisitedMRU" > "$Global:Destiny\$HOSTNAME\MRUs\LastVisitedMRUxp.reg"
    }

}

#>


<# It has difficulies to execute in Windows and system32 folders

# Extensions to ignore (whitelist)
$ignore_extensions = '.exe','.dll'

# Grab all items in the current directory
$mylisting = Get-ItemProperty c:\windows\system32\* 
Write-Host("Number of files/folders:")$mylisting.count
$count_suspect = 0 
for($i=0;$i -lt $mylisting.count;$i++)
{
    #for each item in the listing: ensure the item is not a directory and not an ignored extension
    if( (Test-Path $mylisting[$i] -PathType Leaf) -and ($mylisting[$i].Extension -notin $ignore_extensions) )
    {
        $magicBytes = '{0:X2}' -f (Get-Content $mylisting[$i] -Encoding Byte -ReadCount 4)
        if($magicBytes -eq '4d 5A 90 00')
        {
            Write-Host("Found atypical file:")$mylisting[$i]
            $count_suspect++
        } 
    }
}
Write-Host("Number of suspect files found:")$count_suspect

#>


<# Get binary content of a file, in this case 4 bytes

    '{0:X2}' -f (Get-Content .\tests.ps1 -Encoding Byte -ReadCount 4)

#>

<# UDP connections with process and commandline

$UDPConns = Get-NetUDPEndpoint | Select-Object CreationTime, LocalAddress, LocalPort, RemoteAddress , RemotePort, OwningProcess, State

for($i=0;$i -le $UDPConns.count;$i++)
{
    $UDPConns[$i]

    Write-Host("Process:")`    (Get-CimInstance -ClassName Win32_Process | where ProcessID -eq $UDPConns[$i].OwningProcess).ProcessName
    Write-Host("CmdLine:")`    (Get-CimInstance -ClassName Win32_Process | where ProcessID -eq $UDPConns[$i].OwningProcess).CommandLine
    Write-Host("----------------------------------------")
}

#>


<# TCP connections with process and commandline

$TCPConns = Get-NetTCPConnection | Select-Object CreationTime, LocalAddress, LocalPort, RemoteAddress, RemotePort, OwningProcess, State

for($i=0;$i -le $TCPConns.count;$i++)
{
    $TCPConns[$i]

    Write-Host("Process:")`    (Get-CimInstance -ClassName Win32_Process | where ProcessID -eq $TCPConns[$i].OwningProcess).ProcessName
    Write-Host("CmdLine:")`    (Get-CimInstance -ClassName Win32_Process | where ProcessID -eq $TCPConns[$i].OwningProcess).CommandLine
    Write-Host("----------------------------------------")
}

#>




<# Process Parent with Process Child

    $runningProcesses = Get-CimInstance -ClassName Win32_Process |
        Select-Object CreationDate, ProcessName, ProcessId, CommandLine, ParentProcessId

    for($i=0; $i -le $runningProcesses.count; $i++)
    {
        $runningProcesses[$i]

        Write-Host("Parent:")`        (Get-CimInstance -ClassName Win32_Process | where ProcessId -eq $runningProcesses[$i].ParentProcessId).ProcessName
        Write-Host("Parent CmdLine:")`        (Get-CimInstance -ClassName Win32_Process | where ProcessId -eq $runningProcesses[$i].ParentProcessId).CommandLine
        Write-Host("--------------------")
    }

#>


<########### D A N G E R O U S   E X T E N S I O N S ###########> <# NEW #> <#
Function Collect-Dangerous-Extensions {
    # Find all the scripts in the disk
    #  Get-ChildItem C: -File -Recurse *.pst
    #  Get-ChildItem C: -File -Recurse *.vbs
    #  Get-ChildItem C: -File -Recurse *.lnk | Select-Object Fullname 
    # extensions:  PIF APPLICATION GADGET SCR HTA CPL BAT CMD VB VBS JS JSE WS WSF WSC WSH PS1 PS1XML PS2 PS2XML PSC1 PSC2 MSH MSH1 MSH2 MSHXML MSH1XML MSH2XML SCF LNK INF
    # just list: COM EXE 
    # Get System: Start-Process -FilePath cmd.exe -Verb Runas -ArgumentList '/k .\bin\PsExec64.exe /accepteula -i -s powershell.exe tests.ps1'

    $extensions = "VB","VBS","PIF","BAT","CMD","JS","JSE","WS","WSF","WSC","WSH","PS1","PS1XML","PS2","PS2XML","PSC1","PSC2","MSH","MSH1","MSH2","MSHXML","MSH1XML","MSH2XML","SCF","LNK","INF","APPLICATION","GADGET","SCR","HTA","CPL"

    foreach ($extension in $extensions){
        Get-ChildItem "C:\" -File -Recurse "*.$extension" | ForEach-Object {
            $_.FullName >> file.txt
        }
    }

    


}

Collect-Dangerous-Extensions

<#

$Users = $Users | ForEach-Object {
    (($_.trim() -replace ">" -replace "(?m)^([A-Za-z0-9]{3,})\s+(\d{1,2}\s+\w+)", '$1  none  $2' -replace "\s{2,}", "," -replace "none", $null))
} | ConvertFrom-Csv

foreach ($User in $Users)
{
    [PSCustomObject]@{
        ComputerName = $Computer
        Username = $User.USERNAME
        SessionState = $User.STATE.Replace("Disc", "Disconnected")
        SessionType = $($User.SESSIONNAME -Replace '#', '' -Replace "[0-9]+", "")
    } 
}


Get-WmiObject -Query "select * from win32_process where name='explorer.exe'" -ComputerName $Computer
#>
 

<#3333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333#>
<#


    if ( -Not ( Test-Path $Global:Destiny\$HOSTNAME ) ) { New-Item -ItemType directory -Path $Global:Destiny\$HOSTNAME > $null }

    if(Test-Path REGISTRY::HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run) {
            Get-Item -Path REGISTRY::HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run > "$Global:Destiny\$HOSTNAME\Persistence.txt"
        }

#>