
#region Functions
function RequestPassword{

    $Password = Read-Host -AsSecureString -Prompt "Please enter the password for Account $User"
    $global:Cred = new-Object System.Management.Automation.PSCredential -ArgumentList $User , $Password
    VerifyPassword
}

function VerifyPassword{
    while( -not (Test-Credential $Cred)){
        Write-Error "It looks like the password you entered was invalid, please try again"
        RequestPassword
    }
}

function Write-Error($message){
        Write-Host -ForegroundColor Red $message
        [Console]::ResetColor()

}

function loadXMLConfig{

    $DefaultXMLName = "UberGADS.xml"
    $XMLPath = Join-Path -Path $PSScriptRoot -ChildPath $DefaultXMLName

    Try{

        if(-not (test-path $XMLPath)){
            throw [System.IO.FileNotFoundException]
        }

        $Hostname = [system.environment]::MachineName

        $XML = [xml] (Get-Content $XMLPath)

        $global:School = $XML.SelectSingleNode("/Schools/School[Hostname='$Hostname']")
        
        $global:SchoolName = $School.Longname
        $global:SyncCMD = $School.SyncCMD.EXE
        $global:Config = $School.GCDS.Config
        $global:Report = $School.GCDS.Report
        $global:Log = $School.GCDS.Log
        $global:User = $School.SyncCMD.User
        $global:WorkingDir = $School.GCDS.WorkingDirectory
    }
    Catch [System.Management.Automation.ItemNotFoundException],[System.IO.FileNotFoundException]{
        Write-Error "Coudln't read Configuration-XML-File from $XMLPath"

        Read-Host -Prompt "Exiting"
        exit 1
    
    }
    Catch{
        $ErrorMessage = $_.Exception.Message
        $FailedItem = $_.Exception.ItemName
        Write-Error "Something failed parsing the XML-File`n`n$ErrorMessage`n`n$FailedItem"
        Read-Host -Prompt ""
        exit 1
    }
}

function Simulate-GCDS{
Param(
    [System.Boolean]$runInBackground = $false
)


    Clear-Content -Path $Report
    try{
        $process = Start-Process -PassThru -Credential $cred -WindowStyle Minimized -WorkingDirectory $WorkingDir -FilePath $SyncCMD -ArgumentList "-c $Config -r $Report -l TRACE"
        if(-not $runInBackground){
            Process-Wait-Complete $process "Google Cloud Directory Sync" "Simulating"
        }
    }catch{
        $ErrorMessage = $_.Exception.Message
        $FailedItem = $_.Exception.ItemName
        Write-Error "Launching the Process SimulateGCDS failed`n`n$ErrorMessage`n`n$FailedItem"
        Read-Host -Prompt "Exiting"

        exit 1
    }
}

function Process-Wait-Complete {
Param(
    [System.Diagnostics.Process]$process,

    [String]$activity,

    [String]$status

)
    $i = 0
    while ( -not $process.HasExited ){
        Write-Progress -Activity $activity `
            -Status $status `
            -PercentComplete $i
        Start-Sleep -Milliseconds 50
        if($i -ge 100){
            $i = 0
        }else{
            $i++
        }
    }

    Write-Progress -Activity $activity -Completed

}

function Run-GCDS {
    try{

        $process = Start-Process -PassThru -Credential $cred -WindowStyle Minimized -WorkingDirectory $WorkingDir -FilePath $SyncCMD -ArgumentList "-c $Config -r $Log -a -o"

        Process-Wait-Complete $process "Google Cloud Directory Sync" "Running"

    }catch{
        $ErrorMessage = $_.Exception.Message
        $FailedItem = $_.Exception.ItemName
        Write-Error "Launching the Process Sync GCDS failed`n`n$ErrorMessage`n`n$FailedItem"
        Read-Host -Prompt "Exiting"

        exit 1

    }

    
}

function Create-Users ($path){

    $currentElement = 0
    $elements = Import-CSV $path | Measure-Object


    if(-Not (test-path $path)){
        Write-Error "CSV-File Not Found. Aborting"
        return
    }
    import-Csv $path | ForEach-Object{
        $currentElement++
        $samName = $_.SamAccountName;
        Write-Host $samName;

        Write-Progress -Activity "Creating Users in AD" -PercentComplete (($currentElement / $elements.Count) *100)

        if(Get-ADUser -Filter {SamAccountName -eq $samName}){
            Write-Host "User Exists, Skipping User Creation"  -ForegroundColor Yellow;
        }else{
            New-ADUser `
                -Name $_.Name `
                -DisplayName $_.Name `
                -GivenName $_.FirstName `
                -SurName $_.Surname `
                -SamAccountName $_.SamAccountName `
                -userPrincipalName $_.UPN `
                -EmailAddress $_.UPN `
                -Description $_.Description `
                -Office $_.Office `
                -Path $_.Path `
                -AccountPassword (ConvertTo-SecureString $_.Password -AsPlainText -force) `
                -Enabled $True `
                -PasswordNeverExpires $True `
                -CannotChangePassword $True `
        }
        if($groups.Length -gt 1){
            $groups = $_.Groups.Split(',')
            ForEach ($group in $groups){
                if(Get-ADGroup -Filter {samAccountname -eq $group}){
                    Add-ADGroupMember -Identity $group -Members $_.SamAccountName;
                }else{
                    Write-Host "Could not find Group" $group "for user" $samName -ForegroundColor Red;
                }
            }
        }
    } | Tee-Object $Log -Append

    Write-Progress -Activity "Creating Users in AD" -Completed

}

<#PSScriptInfo
.DESCRIPTION
    Simulates an Authentication Request in a Domain envrionment using a PSCredential Object. Returns $true if both Username and Password pair are valid.
.VERSION
    1.3
.GUID
    6a18515f-73d3-4fb4-884f-412395aa5054
.AUTHOR
    Thomas Malkewitz @dotps1
.TAGS
    PSCredential, Credential
.RELEASENOTES
    Updated $Domain default value to $Credential.GetNetworkCredential().Domain.
    Added support for multipul credential objects to be passed into $Credential.
.PROJECTURI
    http://dotps1.github.io
 #>

function Test-Credential {
    [OutputType([Bool])]

    Param (
        [Parameter(
            Mandatory = $true,
            ValueFromPipeLine = $true,
            ValueFromPipelineByPropertyName = $true
        )]
        [Alias(
            'PSCredential'
        )]
        [ValidateNotNull()]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credential,

        [Parameter()]
        [String]
        $Domain = $Credential.GetNetworkCredential().Domain
    )

    Begin {
        [System.Reflection.Assembly]::LoadWithPartialName("System.DirectoryServices.AccountManagement") |
            Out-Null

        $principalContext = New-Object System.DirectoryServices.AccountManagement.PrincipalContext(
            [System.DirectoryServices.AccountManagement.ContextType]::Domain, $Domain
        )
    }

    Process {
        foreach ($item in $Credential) {
            $networkCredential = $Credential.GetNetworkCredential()

            Write-Output -InputObject $(
                $principalContext.ValidateCredentials(
                    $networkCredential.UserName, $networkCredential.Password
                )
            )
        }
    }

    End {
        $principalContext.Dispose()
    }
}

function Get-FileName($initialDirectory = $PSScriptRoot){
    [System.Reflection.Assembly]::LoadWithPartialName("System.windows.forms") | Out-Null

    $OpenFileDialog = New-Object System.Windows.Forms.OpenFileDialog
    $OpenFileDialog.initialDirectory = $initialDirectory
    $OpenFileDialog.filter = "CSV (*.csv)| *.csv"
    $OpenFileDialog.ShowDialog() | Out-Null

    try{
        Test-Path -Path $OpenFileDialog.FileName | Out-Null
    }catch{
        Write-Host -ForegroundColor Red "It looks like you didn't select a File"
    }

    return $OpenFileDialog.FileName
}

function Reset-Passwords($path){

    Import-Csv $path | Foreach {
        $user = $_.SamAccountName
        $pw = $_.Password
        try {
            Set-ADAccountPassword -Identity $user -NewPassword (ConvertTo-SecureString $pw -AsPlainText -force) -Reset
            Set-AdUser -Identity $user -ChangePasswordAtLogon $false -PasswordNeverExpires $True -CannotChangePassword $true
            Write-Output "$user,Success"
        } catch {
            Write-Output "$user,Error"
        }
    } | Out-File $Log -Append
}

function GenerateGCDS-Password {
    $pw = Read-Host -AsSecureString "Please enter the GCDS-User password"
    ConvertTo-SecureString -String $pw -Force -AsPlainText | ConvertFrom-SecureString
}

#endregion


######################################################################################################################################################################################################

#
# Load XXML Config File
#
loadXMLConfig


Write-Host "Welcome to the D6 AD-User-Adder!"
Write-Host "You're running this at $SchoolName"



#
# Since we're not Storing the password prompt the user for it
#
RequestPassword


#
# Run GCDS Simulation to show current Status of AD > Domain Sync
#
Simulate-GCDS

Read-Host -Prompt "Here's the current Status of Google Suite Directory Sync"

notepad.exe $Report


#
# Ask user to Choose CSV for which users to add
#

Read-Host -Prompt "Please select which CSV to use"

$CSVPath = Get-FileName

#
# Show CSV-File Content
#

Read-Host -Prompt "Please Confirm CSV-File content"


Import-Csv $CSVPath | Out-GridView -Title "Users to be Added to AD"


#
# Ask user to Confirm adding Users from CSV to AD
#

$answer = Read-Host -Prompt "Would you like to Add those Users to Active Directory?`nPlease enter Y or N"

if ( $answer.ToUpper() -ne "Y" )
{
    Read-Host -Prompt "Exiting"
    exit 1
}

#
# Add users to AD
#

Create-Users $CSVPath

#
# Run GCDS Simulation to show preview of new State of Google after Sync
#

Simulate-GCDS

Write-Host "`n`nHere are the Changes GCDS will make"

notepad.exe $Report

#
# Ask User to Confirm Changes to Google
#

$answer = Read-Host -Prompt "Would you like to go ahead and sync from AD to Google?`nPlease enter Y or N"

if ( $answer.ToUpper() -ne "Y" )
{
    Read-Host -Prompt "Exiting"
    exit 1
}

#
# Sync changes to Google
#

Run-GCDS

#
# Resetting passwords so Google-passwords will be set
#

Write-Host "Copying Passwords from AD to Google"

Reset-Passwords $CSVPath

Read-Host -Prompt "All Done, thanks for using UBERGADS"