[CmdletBinding()]
Param 
(
    [switch] $DoSetUp,
    [switch] $DoInternetSetUp,
    [switch] $UpdateModule
)

$banner = "   
______               _                   _____      _          _   _         _____           _       _   
| ___ \             | |                 /  ___|    | |        | | | |       /  ___|         (_)     | |  
| |_/ /_ _ _ __   __| | ___  _ __ __ _  \ `--.  ___| |_ ______| | | |_ __   \ `--.  ___ _ __ _ _ __ | |_ 
|  __/ _` | '_ \ / _` |/ _ \| '__/ _` |  `--. \/ _ \ __|______| | | | '_ \   `--. \/ __| '__| | '_ \| __|
| | | (_| | | | | (_| | (_) | | | (_| | /\__/ /  __/ |_       | |_| | |_) | /\__/ / (__| |  | | |_) | |_ 
\_|  \__,_|_| |_|\__,_|\___/|_|  \__,_| \____/ \___|\__|       \___/| .__/  \____/ \___|_|  |_| .__/ \__|
                                                                    | |                       | |        
                                                                    |_|                       |_|        
                                        by M7 - Miguel Moreno Pastor
"

[double]$pandoraSetUpScriptVersion = 1.0


$QuickEditCodeSnippet=@" 
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Runtime.InteropServices;

 
public static class DisableConsoleQuickEdit
{
 
const uint ENABLE_QUICK_EDIT = 0x0040;

// STD_INPUT_HANDLE (DWORD): -10 is the standard input device.
const int STD_INPUT_HANDLE = -10;

[DllImport("kernel32.dll", SetLastError = true)]
static extern IntPtr GetStdHandle(int nStdHandle);

[DllImport("kernel32.dll")]
static extern bool GetConsoleMode(IntPtr hConsoleHandle, out uint lpMode);

[DllImport("kernel32.dll")]
static extern bool SetConsoleMode(IntPtr hConsoleHandle, uint dwMode);

public static bool SetQuickEdit(bool SetEnabled)
{

    IntPtr consoleHandle = GetStdHandle(STD_INPUT_HANDLE);

    // get current console mode
    uint consoleMode;
    if (!GetConsoleMode(consoleHandle, out consoleMode))
    {
        // ERROR: Unable to get console mode.
        return false;
    }

    // Clear the quick edit bit in the mode flags
    if (SetEnabled)
    {
        consoleMode &= ~ENABLE_QUICK_EDIT;
    }
    else
    {
        consoleMode |= ENABLE_QUICK_EDIT;
    }

    // set the new mode
    if (!SetConsoleMode(consoleHandle, consoleMode))
    {
        // ERROR: Unable to set console mode
        return false;
    }

    return true;
}
}

"@

Add-Type -TypeDefinition $QuickEditCodeSnippet -Language CSharp | Out-Null

function Set-QuickEdit() 
{
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$false, HelpMessage="This switch will disable Console QuickEdit option")][switch]$DisableQuickEdit=$false
    )

    try
    {
        [DisableConsoleQuickEdit]::SetQuickEdit($DisableQuickEdit) | Out-Null
    }
    catch
    {
        Write-Host "[-] Error, disabling Quick-Edit" -ForegroundColor Red
    }      
}

function .printErrorToLog
{
    Param
    (
        [string]$message
    )

    $date = Get-Date -Format "dd_MM_yyyy"

    # Check if log file exists
    if ((Test-Path -Path "C:\PandoraSetUpLogs") -eq $false)
    {
        # Create the folder
        New-Item -Type Directory -Path "C:\PandoraSetUpLogs" | Out-Null
    }

    # Check for the log file
    if ($false -eq (Test-Path -Path "C:\PandoraSetUpLogs\$date.log"))
    {
        # Create the file
        New-Item -Type File -Path "C:\PandoraSetUpLogs\$date.log" | Out-Null

        $logBanner = "           
______               _                   _____      _          _   _         _                     
| ___ \             | |                 /  ___|    | |        | | | |       | |                    
| |_/ /_ _ _ __   __| | ___  _ __ __ _  \ `--.  ___| |_ ______| | | |_ __   | |     ___   __ _ ___ 
|  __/ _` | '_ \ / _` |/ _ \| '__/ _` |  `--. \/ _ \ __|______| | | | '_ \  | |    / _ \ / _` / __|
| | | (_| | | | | (_| | (_) | | | (_| | /\__/ /  __/ |_       | |_| | |_) | | |___| (_) | (_| \__ \
\_|  \__,_|_| |_|\__,_|\___/|_|  \__,_| \____/ \___|\__|       \___/| .__/  \_____/\___/ \__, |___/
                                                                    | |                   __/ |    
                                                                    |_|                  |___/     

                                    by M7 - Miguel Moreno Pastor
        "

        # Append the banner
        Add-Content -Path "C:\PandoraSetUpLogs\$date.log" -Value $logBanner
    }

    # Append the message
    $messageToPrint = "[$(Get-Date -Format HH:mm:ss)] -> NEW ERROR DETECTED DURING INSTALL: `n`t $message`n"
    Add-Content -Path "C:\PandoraSetUpLogs\$date.log" -Value $messageToPrint
}

# @description Function that checks for the code signature of the script
# @notes The update method does not include this, to allow updates
function .checkFileSignature {

    try
    {
        $signatureCheck = (Get-AuthenticodeSignature -FilePath "$PSScriptRoot\pandoraSetUp.ps1").Status

        if (0 -lt $signatureCheck.Length)
        {
            if ($signatureCheck -eq "Valid")
            {
                Write-Host "[+] Script signature is correct!" -ForegroundColor Green
            }
            elseif ($signatureCheck -eq "NotSigned")
            {
                Write-Host "[!] Warning, this script is not signed!" -ForegroundColor Yellow

                # Ask the user if he want to continue
                $continueExeuction = [System.Management.Automation.Host.ChoiceDescription[]] ([System.Management.Automation.Host.ChoiceDescription]::new("&Yes" , "Continue executing a not signed script"), [System.Management.Automation.Host.ChoiceDescription]::new("&No", "Abort execution of the script"))

                $userResponse = $Host.UI.PromptForChoice("","[?] Want to continue the execution of the script (please double check the script is not tampered)", $continueExeuction, 1)

                # If no abort the execution
                if (1 -eq $userResponse)
                {
                    Write-Host "[i] Exiting the program"
                    Start-Sleep -Seconds 2
                    [System.Environment]::Exit(0)
                }
            }
            else
            {
                Write-Host "[-] Signatura missmatch, the signature can be spoiled, or the script can be tampered, aborting execution" -ForegroundColor Red
                Write-Host "[!] If the signature is spoiled, delete it, or wait until a new one is Uploaded" -ForegroundColor Yellow
                Write-Host "[i] Exiting program"
                Start-Sleep -Seconds 2
                [System.Environment]::Exit(0)                
            }
        }
        else
        {
            Write-Host "[-] Error checking the code signature, double-check the script can be tampered!" -ForegroundColor Red
            Write-Host "[i] Exiting the program"
            Start-Sleep -Seconds 2
            [System.Environment]::Exit(0)
        }
    }
    catch
    {
        Write-Host "[-] Failed to check for the code signature, consider aborting the execution" -ForegroundColor Red
        Write-Host "[!] This can mean that the program, may failed or is not signed" -ForegroundColor Yellow
        Write-Host "[!] If you are sure that you want to run this, comment the method .checkFileSignature, or add your own signature to the script" -ForegroundColor Yellow
        # Print error to log
        .printErrorToLog -message $Error[0]
    }    
}

# @description Checks if is need it to update the script set-up
function .pandoraSetUpUpdater 
{
    Write-Host "[i] Current pandoraSetUpVersion script: $pandoraSetUpScriptVersion"

    try
    {
        # Gets from the repo the file name with the version
        $versionUrl = "https://raw.githubusercontent.com/mimorep/PandoraBox/main/pandoraUpdatesCheck/versionCheckEndpoint.txt"
    
        $newVersion = Invoke-RestMethod $versionUrl -Method 'GET'
    
        # Check if new version is avaliable
        if ($newVersion -gt $pandoraSetUpScriptVersion)
        {
            $updateOptions = [System.Management.Automation.Host.ChoiceDescription[]] ([System.Management.Automation.Host.ChoiceDescription]::new("&Yes", "Update the pandora set-up tool"), [System.Management.Automation.Host.ChoiceDescription]::new("&No", "Do not update the pandora set-up tool"))
    
            $userResponse = $Host.UI.PromptForChoice("", "[?] A new version ($newVersion) can be downloaded want to proceed", $updateOptions, 0)
    
            if ($userResponse -eq 0)
            {
                Write-Host "[i] Starting the update of new pandoraSetUp..."

                $downloadEndpoint = "https://raw.githubusercontent.com/mimorep/PandoraBox/main/pandoraUpdatesCheck/pandoraSetUp.ps1"
    
                $newScript = Invoke-RestMethod $downloadEndpoint -Method 'GET'

                Write-Host "[!] Writting script to pandoraSetUp-updated-ps1" -ForegroundColor Yellow

                $newScript > ".\pandoraSetUp-updated.ps1"

                # Ask the user if he want to keep the old one
                $keepOldOne = [System.Management.Automation.Host.ChoiceDescription[]] ([System.Management.Automation.Host.ChoiceDescription]::new("Create a &Backup", "Creates a backup of old version with the name pandoraSetUp-back.ps1"), [System.Management.Automation.Host.ChoiceDescription]::new("&Delete the old version", "Keeps just the new download one"))

                $userResponse = $Host.UI.PromptForChoice("", "[?] Keep the old version of the script", $keepOldOne, 0)

                if (0 -eq $userResponse)
                {
                    # Create the backup
                    Write-Host "[i] Creating the backup"
                    Start-Process powershell -ArgumentList '-NonInteractive -WindowStyle Minimized Rename-Item -Path "C:\pandoraSetUp.ps1" -NewName "pandoraSetUp-back.ps1" -Force && Rename-Item -Path "C:\pandoraSetUp-updated-ps1" -NewName "pandoraSetUp.ps1" -Force'

                    Write-Host "[+] Pandora should be now updated, a backup with name pandoraSetUp-back.ps1 was created on this path" -ForegroundColor Green
                }
                else 
                {
                    # Delete the old one
                    Write-Host "[i] Deleting the old one"
                    Start-Process powershell -ArgumentList '-NonInteractive -WindowStyle Minimized Remove-Item -Path "C:\pandoraSetUp.ps1" -Force && Rename-Item -Path "C:\pandoraSetUp-updated-ps1" -NewName "pandoraSetUp.ps1" -Force'

                    Write-Host "[+] Pandora should be now updated!" -ForegroundColor Green
                }

    
            }
            else { Write-Host "[i] Update aborted!" ; [System.Environment]::Exit(1) }
        }
        else
        {
            Write-Host "[i] No new versions detected"
            Write-Host "[i] You are up to date!" -ForegroundColor Green
        }
    }
    catch
    {
        Write-Host "[-] An error was triggered, may you have no internet connection"
        
        # Print error to log
        .printErrorToLog -message $Error[0]
    }
}

function .checkUserName
{
    try
    {
        $usernameResult = Get-LocalUser -Name "PandoraUser" -ErrorAction SilentlyContinue

        if (0 -eq $usernameResult)
        {
            Write-Host "[-] Default username PandoraUser is not present on the machine, aborting installation (see log files)" -ForegroundColor Red
            .printErrorToLog -message "[-] A main username with name PandoraUser is mandatory for the set-up, if you want to use a custom name, execute the set-up with the user named PandoraUser, and later change the user name"

            [System.Environment]::Exit(0)
        }
        else
        {
            Write-Host "[+] User PandoraUser detected!" -ForegroundColor Green
        }
    }
    catch
    {
        Write-Host "[-] Error checking for the default username" -ForegroundColor Red
        
        # Print error to log
        .printErrorToLog -message $Error[0]
    }
}

# @description Zooms out two times to print the logo in small screens
function .zoomOut 
{
    function sendKeys
    {
        Param  (
            $SendKeys            
        )

        $wshell = New-Object -ComObject wscript.shell

        if ($SendKeys)
        {
            $wshell.sendKeys($SendKeys)
        }
    }

    # Call the sendkeys to zoom out
    sendKeys -SendKeys '^{-}^{-}'
}

# @description Changes the script policy execution for the machine
function .changePolicyExecution 
{
    try
    {
        Set-ExecutionPolicy Unrestricted -Force
        Write-Host "[+] Execution policy changed to unrestricted!" -ForegroundColor Green
    }
    catch 
    {
        Write-Host "[-] Exeuction policy can not be change run the set-Up (C:\pandoraSetUp.ps1) script again with root access!" -ForegroundColor Red

        # Print error to log
        .printErrorToLog -message $Error[0]
    }
}

# @description Adds all the forensic tools and reversing more used to the rigth click
function .customRighClickQuickAccessTools
{
    Write-Host "[i] Creating right click shortcuts"

    # HKCR
    $resgistryPathsToCreate = (
        "HKCR\Directory\Background\shell\ToolsForensics",
        "HKCR\Directory\Background\shell\ToolsReversing"
    )

    # First for each path test if exists
    try
    {
        foreach ($key in $resgistryPathsToCreate)
        {
            # Check if exists
            if (Test-Path -Path "Registry::$key")
            {
                $keyName = $key.Split('\')
                $keyName = $keyName[$keyName.Length - 1]
                Write-Host "[!] Shortcut for $keyName already exists" -ForegroundColor Yellow
            }
            else
            {
                # Create the main key
                New-Item -Path "Registry::$key" -Force | Out-Null
                New-Item -Path "Registry::$key\shell" -Force | Out-Null
            }
        }

        # Create the CyberChef one
        if ($false -eq (Test-Path -Path "Registry::HKCR\Directory\Background\shell\CyberChef"))
        {
            # Create the main reference            
            New-Item -Path "Registry::HKCR\Directory\Background\shell\CyberChef" -Force -ErrorAction SilentlyContinue | Out-Null

            New-ItemProperty -Path "Registry::HKCR\Directory\Background\shell\CyberChef" -Name "MUIVerb" -Value "CyberChef" -Force -ErrorAction SilentlyContinue | Out-Null
            New-ItemProperty -Path "Registry::HKCR\Directory\Background\shell\CyberChef" -Name "Icon" -Value '"C:\Reversing\CyberChef_v10.19.2\assets\aecc661b69309290f600.ico"' -Force -ErrorAction SilentlyContinue | Out-Null
       
            # Create the command to launch
            New-Item -Path "Registry::HKCR\Directory\Background\shell\CyberChef\command" -Value 'Brave.exe "C:\Reversing\CyberChef_v10.19.2\CyberChef_v10.19.2.html"' -Force -ErrorAction SilentlyContinue | Out-Null
        }

        # Create the forensics ones
        if (Test-Path -Path "Registry::HKCR\Directory\Background\shell\ToolsForensics")
        {
            # Open the folder with the forensics tools
            New-Item -Path "Registry::HKCR\Directory\Background\shell\ToolsForensics\shell\openFTools" -Force -ErrorAction SilentlyContinue | Out-Null
            New-Item -Path "Registry::HKCR\Directory\Background\shell\ToolsForensics\shell\openFTools\command" -Value '"explorer.exe C:\Forensics"' -Force -ErrorAction SilentlyContinue | Out-Null

            New-Item -Path "Registry::HKCR\Directory\Background\shell\ToolsForensics\shell\Ftk" -Force -ErrorAction SilentlyContinue | Out-Null
            New-Item -Path "Registry::HKCR\Directory\Background\shell\ToolsForensics\shell\Ftk\command" -Value '"C:\Forensics\FTK\AccessData\FTK Imager\FTKImager.exe"' -Force -ErrorAction SilentlyContinue | Out-Null

            New-Item -Path "Registry::HKCR\Directory\Background\shell\ToolsForensics\shell\Arsenal" -Force -ErrorAction SilentlyContinue | Out-Null
            New-Item -Path "Registry::HKCR\Directory\Background\shell\ToolsForensics\shell\Arsenal\command" -Value '"C:\Forensics\Arsenal Image Mounter\ArsenalImageMounter.exe"' -Force -ErrorAction SilentlyContinue | Out-Null

            New-Item -Path "Registry::HKCR\Directory\Background\shell\ToolsForensics\shell\Sql" -Force -ErrorAction SilentlyContinue | Out-Null
            New-Item -Path "Registry::HKCR\Directory\Background\shell\ToolsForensics\shell\Sql\command" -Value '"C:\Forensics\SQL lite\DB Browser for SQLite\DB Browser for SQLite.exe"' -Force -ErrorAction SilentlyContinue | Out-Null
 
            New-Item -Path "Registry::HKCR\Directory\Background\shell\ToolsForensics\shell\Zimmerman" -Force -ErrorAction SilentlyContinue | Out-Null
            New-Item -Path "Registry::HKCR\Directory\Background\shell\ToolsForensics\shell\Zimmerman\command" -Value 'explorer.exe "C:\Forensics\ZimmermanTools\net6"' -Force -ErrorAction SilentlyContinue| Out-Null

            # Generate the properties for folder
            New-ItemProperty -Path "Registry::HKCR\Directory\Background\shell\ToolsForensics" -Name "MUIVerb" -Value "Tools Forensics" -Force -ErrorAction SilentlyContinue | Out-Null
            New-ItemProperty -Path "Registry::HKCR\Directory\Background\shell\ToolsForensics" -Name "SubCommands" -Value "" -Force -ErrorAction SilentlyContinue | Out-Null
            New-ItemProperty -Path "Registry::HKCR\Directory\Background\shell\ToolsForensics" -Name "Icon" -Value "C:\Logos\Forensics.ico" -Force -ErrorAction SilentlyContinue | Out-Null

            # Generate the properties for entries

            New-ItemProperty -Path "Registry::HKCR\Directory\Background\shell\ToolsForensics\shell\openFTools" -Name "MUIVerb" -Value "Forensics Tools" -Force -ErrorAction SilentlyContinue | Out-Null
            New-ItemProperty -Path "Registry::HKCR\Directory\Background\shell\ToolsForensics\shell\openFTools" -Name "Icon" -Value '"C:\Logos\Forensics.ico"' -Force -ErrorAction SilentlyContinue | Out-Null

            New-ItemProperty -Path "Registry::HKCR\Directory\Background\shell\ToolsForensics\shell\Ftk" -Name "MUIVerb" -Value "FTK" -Force -ErrorAction SilentlyContinue | Out-Null
            New-ItemProperty -Path "Registry::HKCR\Directory\Background\shell\ToolsForensics\shell\Ftk" -Name "Icon" -Value '"C:\Forensics\FTK\AccessData\FTK Imager\FTK Imager.exe"' -Force -ErrorAction SilentlyContinue | Out-Null

            New-ItemProperty -Path "Registry::HKCR\Directory\Background\shell\ToolsForensics\shell\Arsenal" -Name "MUIVerb" -Value "Arsenal Image" -Force -ErrorAction SilentlyContinue | Out-Null
            New-ItemProperty -Path "Registry::HKCR\Directory\Background\shell\ToolsForensics\shell\Arsenal" -Name "Icon" -Value '"C:\Forensics\Arsenal Image Mounter\ArsenalImageMounter.exe"' -Force -ErrorAction SilentlyContinue | Out-Null
            
            New-ItemProperty -Path "Registry::HKCR\Directory\Background\shell\ToolsForensics\shell\Zimmerman" -Name "MUIVerb" -Value "Sql lite" -Force -ErrorAction SilentlyContinue | Out-Null
            New-ItemProperty -Path "Registry::HKCR\Directory\Background\shell\ToolsForensics\shell\Zimmerman" -Name "Icon" -Value '"C:\Forensics\SQL lite\DB Browser for SQLite\DB Browser for SQLite.exe"' -Force -ErrorAction SilentlyContinue | Out-Null

            New-ItemProperty -Path "Registry::HKCR\Directory\Background\shell\ToolsForensics\shell\Zimmerman" -Name "MUIVerb" -Value "Zimmerman Tools" -Force -ErrorAction SilentlyContinue | Out-Null
            New-ItemProperty -Path "Registry::HKCR\Directory\Background\shell\ToolsForensics\shell\Zimmerman" -Name "Icon" -Value '"C:\Forensics\ZimmermanTools\net6\RegistryExplorer\RegistryExplorer.exe"' -Force -ErrorAction SilentlyContinue | Out-Null

        }

        # Create the reversing ones
        if (Test-Path -Path "Registry::HKCR\Directory\Background\shell\ToolsReversing")
        {

            New-Item -Path "Registry::HKCR\Directory\Background\shell\ToolsReversing\shell\openRTools" -Force -ErrorAction SilentlyContinue | Out-Null
            New-Item -Path "Registry::HKCR\Directory\Background\shell\ToolsReversing\shell\openRTools\command" -Value '"explorer.exe C:\Reversing"' -Force -ErrorAction SilentlyContinue | Out-Null

            New-Item -Path "Registry::HKCR\Directory\Background\shell\ToolsReversing\shell\DetectEz" -Force -ErrorAction SilentlyContinue | Out-Null
            New-Item -Path "Registry::HKCR\Directory\Background\shell\ToolsReversing\shell\DetectEz\command" -Value '"C:\Reversing\DetectItEz\die.exe"' -Force -ErrorAction SilentlyContinue | Out-Null
            
            New-Item -Path "Registry::HKCR\Directory\Background\shell\ToolsReversing\shell\Ghidra" -Force -ErrorAction SilentlyContinue | Out-Null
            New-Item -Path "Registry::HKCR\Directory\Background\shell\ToolsReversing\shell\Ghidra\command" -Value '"C:\Reversing\Ghidra\ghidra_10.3.1_PUBLIC\ghidraRun.bat"' -Force -ErrorAction SilentlyContinue | Out-Null

            New-Item -Path "Registry::HKCR\Directory\Background\shell\ToolsReversing\shell\IDA" -Force -ErrorAction SilentlyContinue | Out-Null
            New-Item -Path "Registry::HKCR\Directory\Background\shell\ToolsReversing\shell\IDA\command" -Value '"C:\Program Files\IDA Freeware 8.4\ida64.exe"' -Force -ErrorAction SilentlyContinue | Out-Null
            
            New-Item -Path "Registry::HKCR\Directory\Background\shell\ToolsReversing\shell\x64" -Force -ErrorAction SilentlyContinue | Out-Null
            New-Item -Path "Registry::HKCR\Directory\Background\shell\ToolsReversing\shell\x64\command" -Value '"C:\Reversing\x64Debugger\release\x96dbg.exe"' -Force -ErrorAction SilentlyContinue | Out-Null

            New-Item -Path "Registry::HKCR\Directory\Background\shell\ToolsReversing\shell\dnsPy" -Force -ErrorAction SilentlyContinue | Out-Null
            New-Item -Path "Registry::HKCR\Directory\Background\shell\ToolsReversing\shell\dnsPy\command" -Value '"C:\ProgramData\chocolatey\bin\dnSpy.exe"' -Force -ErrorAction SilentlyContinue | Out-Null
            
            New-Item -Path "Registry::HKCR\Directory\Background\shell\ToolsReversing\shell\JavaD" -Force -ErrorAction SilentlyContinue | Out-Null
            New-Item -Path "Registry::HKCR\Directory\Background\shell\ToolsReversing\shell\JavaD\command" -Value 'powershell -NonInteractive -WindowStyle Minimized -command java -jar "C:\Reversing\Java_Decompiler\recaf2.21.jar"' -Force -ErrorAction SilentlyContinue | Out-Null
            
            New-Item -Path "Registry::HKCR\Directory\Background\shell\ToolsReversing\shell\ProcessH" -Force -ErrorAction SilentlyContinue | Out-Null
            New-Item -Path "Registry::HKCR\Directory\Background\shell\ToolsReversing\shell\ProcessH\command" -Value '"C:\Reversing\Processhacker\x64\ProcessHacker.exe"' -Force -ErrorAction SilentlyContinue | Out-Null

            New-Item -Path "Registry::HKCR\Directory\Background\shell\ToolsReversing\shell\SysIn" -Force -ErrorAction SilentlyContinue | Out-Null
            New-Item -Path "Registry::HKCR\Directory\Background\shell\ToolsReversing\shell\SysIn\command" -Value 'explorer.exe "C:\Reversing\SysinternalsSuite"' -Force -ErrorAction SilentlyContinue | Out-Null

            # Generate the properties for folder
            New-ItemProperty -Path "Registry::HKCR\Directory\Background\shell\ToolsReversing" -Name "MUIVerb" -Value "Tools Reversing" -Force -ErrorAction SilentlyContinue | Out-Null
            New-ItemProperty -Path "Registry::HKCR\Directory\Background\shell\ToolsReversing" -Name "SubCommands" -Value "" -Force -ErrorAction SilentlyContinue | Out-Null
            New-ItemProperty -Path "Registry::HKCR\Directory\Background\shell\ToolsReversing" -Name "Icon" -Value "C:\Logos\BugReversing.ico" -Force -ErrorAction SilentlyContinue | Out-Null

            # Generate the properties for entries

            New-ItemProperty -Path "Registry::HKCR\Directory\Background\shell\ToolsReversing\shell\openRTools" -Name "MUIVerb" -Value "Reversing Tools" -Force -ErrorAction SilentlyContinue | Out-Null
            New-ItemProperty -Path "Registry::HKCR\Directory\Background\shell\ToolsReversing\shell\openRTools" -Name "Icon" -Value '"C:\Logos\BugReversing.ico"' -Force -ErrorAction SilentlyContinue | Out-Null

            New-ItemProperty -Path "Registry::HKCR\Directory\Background\shell\ToolsReversing\shell\DetectEz" -Name "MUIVerb" -Value "Detect ez" -Force -ErrorAction SilentlyContinue | Out-Null
            New-ItemProperty -Path "Registry::HKCR\Directory\Background\shell\ToolsReversing\shell\DetectEz" -Name "Icon" -Value '"C:\Reversing\DetectItEz\die.exe"' -Force -ErrorAction SilentlyContinue | Out-Null
            
            New-ItemProperty -Path "Registry::HKCR\Directory\Background\shell\ToolsReversing\shell\Ghidra" -Name "MUIVerb" -Value "Ghidra" -Force -ErrorAction SilentlyContinue | Out-Null
            New-ItemProperty -Path "Registry::HKCR\Directory\Background\shell\ToolsReversing\shell\Ghidra" -Name "Icon" -Value '"C:\Reversing\Ghidra\ghidra_10.3.1_PUBLIC\support\ghidra.ico"' -Force -ErrorAction SilentlyContinue | Out-Null

            New-ItemProperty -Path "Registry::HKCR\Directory\Background\shell\ToolsReversing\shell\IDA" -Name "MUIVerb" -Value "IDA" -Force -ErrorAction SilentlyContinue | Out-Null
            New-ItemProperty -Path "Registry::HKCR\Directory\Background\shell\ToolsReversing\shell\IDA" -Name "Icon" -Value '"C:\Program Files\IDA Freeware 8.4\ida64.exe"' -Force -ErrorAction SilentlyContinue | Out-Null

            New-ItemProperty -Path "Registry::HKCR\Directory\Background\shell\ToolsReversing\shell\x64" -Name "MUIVerb" -Value "x64 debugger" -Force -ErrorAction SilentlyContinue | Out-Null
            New-ItemProperty -Path "Registry::HKCR\Directory\Background\shell\ToolsReversing\shell\x64" -Name "Icon" -Value '"C:\Reversing\x64Debugger\release\x96dbg.exe"' -Force -ErrorAction SilentlyContinue | Out-Null

            New-ItemProperty -Path "Registry::HKCR\Directory\Background\shell\ToolsReversing\shell\dnsPy" -Name "MUIVerb" -Value "DnSpy" -Force -ErrorAction SilentlyContinue | Out-Null
            New-ItemProperty -Path "Registry::HKCR\Directory\Background\shell\ToolsReversing\shell\dnsPy" -Name "Icon" -Value '"C:\ProgramData\chocolatey\bin\dnSpy.exe"' -Force -ErrorAction SilentlyContinue | Out-Null

            New-ItemProperty -Path "Registry::HKCR\Directory\Background\shell\ToolsReversing\shell\ProcessH" -Name "MUIVerb" -Value "ProcessHacker" -Force -ErrorAction SilentlyContinue | Out-Null
            New-ItemProperty -Path "Registry::HKCR\Directory\Background\shell\ToolsReversing\shell\ProcessH" -Name "Icon" -Value '"C:\Reversing\Processhacker\x64\ProcessHacker.exe"' -Force -ErrorAction SilentlyContinue | Out-Null

            New-ItemProperty -Path "Registry::HKCR\Directory\Background\shell\ToolsReversing\shell\SysIn" -Name "MUIVerb" -Value "SysInternals Tools" -Force -ErrorAction SilentlyContinue | Out-Null
            New-ItemProperty -Path "Registry::HKCR\Directory\Background\shell\ToolsReversing\shell\SysIn" -Name "Icon" -Value 'C:\Reversing\SysinternalsSuite\Desktops.exe' -Force -ErrorAction SilentlyContinue | Out-Null

            New-ItemProperty -Path "Registry::HKCR\Directory\Background\shell\ToolsReversing\shell\JavaD" -Name "MUIVerb" -Value "Java decompiler" -Force -ErrorAction SilentlyContinue | Out-Null
            New-ItemProperty -Path "Registry::HKCR\Directory\Background\shell\ToolsReversing\shell\JavaD" -Name "Icon" -Value '"C:\Reversing\Java_Decompiler\recaf2.21.jar"' -Force -ErrorAction SilentlyContinue | Out-Null
        }

        # Create the godMode folder
        New-Item -Type Directory -Path "C:\GodMode.{ED7BA470-8E54-465E-825C-99712043E01C}" -Force | Out-Null

        $godFolder = Get-Item -Path "C:\GodMode.{ED7BA470-8E54-465E-825C-99712043E01C}" -Force 

        $godFolder.Attributes = $godFolder.Attributes -bor [System.IO.FileAttributes]::Hidden

        # Create the open with quick access
        # Because of the recursivity of this procedure, this is performed by dropping a reg file on the temp directory
        try
        {
            $tempFile = New-TemporaryFile
            
            $regRecurseOpenWith = 'Windows Registry Editor Version 5.00

; Configure rigth-click shortcuts
[HKEY_CLASSES_ROOT\*\shell\openPandora]
@=""
"Icon"="C:\\pandora_tool_updater.exe"
"MUIVerb"="Pandora OpenWith"
"SubCommands"=""

[HKEY_CLASSES_ROOT\*\shell\openPandora\shell]
@=""

[HKEY_CLASSES_ROOT\*\shell\openPandora\shell\hxd]
@=""
"MUIVerb"="Open with hxd"
"Icon"="C:\\Program Files\\HxD\\HxD.exe"

[HKEY_CLASSES_ROOT\*\shell\openPandora\shell\hxd\command]
@="\"C:\\Program Files\\HxD\\HxD.exe\" %1"

[HKEY_CLASSES_ROOT\*\shell\openPandora\shell\die]
@=""
"MUIVerb"="Open with detectez"
"Icon"="C:\\Reversing\\DetectItEz\\die.exe"

[HKEY_CLASSES_ROOT\*\shell\openPandora\shell\die\command]
@="\"C:\\Reversing\\DetectItEz\\die.exe\" %1"

[HKEY_CLASSES_ROOT\*\shell\openPandora\shell\PEBeard]
@=""
"MUIVerb"="Open with PEBeard"
"Icon"="C:\\Reversing\\PEBear\\PE-bear.exe"

[HKEY_CLASSES_ROOT\*\shell\openPandora\shell\PEBeard\command]
@="\"C:\\Reversing\\PEBear\\PE-bear.exe\" %1"

[HKEY_CLASSES_ROOT\*\shell\openPandora\shell\Cff]
@=""
"MUIVerb"="Open with CFF"
"Icon"="C:\\Program Files\\NTCore\\Explorer Suite\\CFF Explorer.exe"

[HKEY_CLASSES_ROOT\*\shell\openPandora\shell\Cff\command]
@="\"C:\\Program Files\\NTCore\\Explorer Suite\\CFF Explorer.exe\" %1"

; Configure Everthing quickaccess
[HKEY_CLASSES_ROOT\Directory\Background\shell\FindAFile]
@="Find a file"
"NoWorkingDirectory"=""
"Icon"="C:\\Program Files\\Everything\\Everything.exe"

[HKEY_CLASSES_ROOT\Directory\Background\shell\FindAFile\command]
@="C:\\Program Files\\Everything\\Everything.exe"  

; Configure God mode
[HKEY_CLASSES_ROOT\Directory\Background\shell\GodMode]
@="God Mode"
"NoWorkingDirectory"=""
"Icon"="C:\\Logos\\godMode.ico"

[HKEY_CLASSES_ROOT\Directory\Background\shell\GodMode\command]
@="explorer.exe C:\\GodMode.{ED7BA470-8E54-465E-825C-99712043E01C}"

; Configure take ownership
[HKEY_CLASSES_ROOT\*\shell\takeown]
@="Take Ownership"
"Icon"="C:\\Logos\\takeOwner.ico"
"NoWorkingDirectory"=""

[HKEY_CLASSES_ROOT\*\shell\takeown\command]
@="cmd.exe /c takeown /f \"%1\" && icacls \"%1\" /grant *S-1-3-4:F" /C /L"
"IsolatedCommand"="cmd.exe /c takeown /f \"%1\" && icacls \"%1\" /grant *S-1-3-4:F" /C /L"

; Configure takeownership from drive (no file selected)
[HKEY_CLASSES_ROOT\Directory\shell\takeown]
@="Take Ownership"
"Icon"="C:\\Logos\\takeOwner.ico"
"NoWorkingDirectory"=""

[HKEY_CLASSES_ROOT\Directory\shell\takeown\command]
@="cmd.exe /c takeown /f \"%1\" /R /D Y && icacls \"%1\" /grant *S-1-3-4:F /T /C /L"
"IsolatedCommand"="cmd.exe /c takeown /f \"%1\" /R /D Y && icacls \"%1\" /grant *S-1-3-4:F /T /C /L"

; Kill switch buttom (to disconect internet)
[HKEY_CLASSES_ROOT\Directory\Background\shell\NetworkKill]
@="Kill network"
"NoWorkingDirectory"=""
"Icon"="C:\\Logos\\killNetwork.ico"

[HKEY_CLASSES_ROOT\Directory\Background\shell\NetworkKill\command]
@="powershell -NonInteractive -WindowStyle Minimized -command \"Start-Process cmd -Verb RunAs -ArgumentList ''/c netsh interface set interface \"Ethernet\" disable''"

; Enable switch buttom (to disconect internet)
[HKEY_CLASSES_ROOT\Directory\Background\shell\NetworkEnable]
@="Enable network"
"NoWorkingDirectory"=""
"Icon"="C:\\Logos\\enableNetwork.ico"

[HKEY_CLASSES_ROOT\Directory\Background\shell\NetworkEnable\command]
@="powershell -NonInteractive -WindowStyle Minimized -command \"Start-Process cmd -Verb RunAs -ArgumentList ''/c netsh interface set interface \"Ethernet\" enable''"   
            '

            # Create the reg file
            Add-Content -Path $tempFile -Value $regRecurseOpenWith

            Write-Host "[+] Registry file payload created!" -ForegroundColor Green

            # Rename the reg file
            Rename-Item -Path $tempFile -NewName "$($tempFile.Name).reg"

            $tempFile = "$($tempFile.Name).reg"

            $tempFile = "$env:TEMP\$tempFile"

            # Now import the registry
            reg import $tempFile

            # Restart the registry to apply changes
            Write-Host "[i] Applaying changes to registry"

            gpupdate /force

            Write-Host "[+] All right click shorcuts created!" -ForegroundColor Green
        }
        catch
        {
            Write-Host "[-] Error, an error ocurred while creating the system shorcuts (see log)" -ForegroundColor Red
            
            # Print error to log
            .printErrorToLog -message $Error[0]
        }
    }
    catch
    {
        Write-Host "[-] Error, creating a right menu shorcut" -ForegroundColor Red
        # Print error to log
        .printErrorToLog -message $Error[0]
    }

}

# @description Method to decompress tools from the C:\ volume
# @note This is only perform to get a little final ISO
function .decompressTools
{

    $foldersToCheck = (
        "C:\Forensics",
        "C:\Reversing"
    )

    Write-Host "[i] Preparing for the decompression of the tools"

    # First check for the 7z files
    if (Test-Path -Path "C:\7zip.zip")
    {
        Write-Host "[i] 7 ZIP detected on the set-up folder"

        Move-Item -Path "C:\7zip.zip" -Destination "C:\Program Files"

        Expand-Archive -Path "C:\Program Files\7zip.zip" -DestinationPath "C:\Program Files\"   
    }
    elseif (Test-Path -Path "C:\Program Files\7-Zip\7z.exe") 
    {
        # If present, just warn
        Write-Host "[!] 7 ZIP is already on the correct path" -ForegroundColor Yellow
    }
    else
    {
        Write-Host "[-] Can not locate 7 ZIP so tools can not be decompressed" -ForegroundColor Red
    }

    # Start decompression
    try
    {
        Write-Host "[i] Creating alias for 7 ZIP"

        $7zPath = "C:\Program Files\7-Zip\7z.exe"

        # Set alias for deep decompression
        Set-Alias 7zip $7zPath

        Write-Host "[i] 7 ZIP installed in Program Files, and alias added, you can now call 7zip with"

        # Start now the decompression of the files
        foreach ($folder in $foldersToCheck)
        {
            if (Test-Path -Path $folder)
            {
                Write-Host "[i] $folder folder already decompressed"
            }
            else
            {                
                # Get zip name
                $zipName = $folder.Split('\')
                $zipName = $zipName[$zipName.Length - 1] + ".zip"
                
                # Decompress the zip
                try
                {
                    if (Test-Path -Path "C:\$zipName")
                    {
                        Write-Host "[i] Decompressing C:\$zipName"
                        
                        # First create the final folder and move the zip
                        New-Item -ItemType "Directory" -Path $folder -Force

                        Move-Item -Path "C:\$zipName" -Destination $folder

                        # Move to the main location
                        Set-Location -Path "C:\"

                        # Decompress the high compression tools package (-y -> to not prompt to the user the confirmation)
                        7zip x "$folder\$zipName" -y
                        # Expand-Archive -LiteralPath "C:\$zipName" -DestinationPath "C:\$folder"
                        
                        Set-Location -Path "C:\"

                        if (Test-Path -Path $folder)
                        {
                            Write-Host "[+] Success $folder tools decompressed!" -ForegroundColor Green
    
                            # Delete the zip file from the moved folder
                            Remove-Item -Path "$folder\$zipName" -ErrorAction SilentlyContinue
                        }
                        else
                        {
                            Write-Host "[-] Error, $folder tools failed to decompress" -ForegroundColor Red
                            .printErrorToLog -message "[-] Error, $folder tools failed to decompress, try to decompress them manually" 
                        }    
                    }
                    else
                    {
                        Write-Host "[-] Can not find file $zipName, may the ISO installation had failed" -ForegroundColor Red
                        .printErrorToLog -message "[-] Can not find file $zipName, may the ISO installation had failed, look for the file, if no present on the system, re-install the image"
                    }
                }
                catch
                {
                    Write-Host "[-] Error unziping the tools, please perform this action manually" -ForegroundColor Red
                    .printErrorToLog -message "[-] Error unzipping $zipName, perform this action manually if possible"
                    .printErrorToLog -message $Error[0]
                }
            }
        }
    }
    catch
    {
        Write-Host "[-] Error installing the 7 ZIP alias, tools can not be decompressed (perform this action manually)" -ForegroundColor Red
        # Print error to log
        .printErrorToLog -message $Error[0]
    }
}

# @description launches in diferent threads silent installs for some tools
function .launchSeveralInstallations 
{
    Write-Host "[i] Creating threads to install several provided tools"

    # Local installs
    try
    {
        Write-Host "[i] Launching install for hxd"
        Start-Process powershell -ArgumentList '-NonInteractive -WindowStyle Minimized C:\Reversing\HxD\HxDSetup\HxDSetup.exe /VERYSILENT /NORESTART' -Wait
        
        Write-Host "[i] Launching install for CFF"
        & "C:\Reversing\CFF Suite\ExplorerSuite.exe" /VERYSILENT /NORESTART
        
        Write-Host "[i] Launching install for Autopsy"
        Start-Process powershell -ArgumentList '-NonInteractive -WindowStyle Minimized & "C:\Forensics\Autopsy\autopsy-4.21.0-64bit.msi" /quiet' -Wait

        Write-Host "[i] Launching install for IDA"
        Start-Process powershell -ArgumentList '-NonInteractive -WindowStyle Minimized C:\Reversing\IDA\idafree84_windows.exe --unattendedmodeui none --mode unattended' -Wait
    }
    catch
    {
        Write-Host "[-] Some of the local installs failed, this will not afect to the iso, you can install the remainin tools manually" -ForegroundColor Red
    }

    # Internet installs
    try 
    {
        Start-Process powershell { choco install apimonitor -y ; Move-Item -Path "C:\ProgramData\chocolatey\lib\apimonitor\tools\API Monitor (rohitab.com)" -Destination "C:\Reversing\API Monitor" -Force } -Wait
    }
    catch
    {
        Write-Host "[-] Some tools can not be installed (may the problem is related with choco not being installed on the machine)" -ForegroundColor Red
    }


    Write-Host "[+] All installations were runned in a separeted thread!" -ForegroundColor Green
}

# @description Creates if not exist the reg to import the taskbar configuration and places it
function .generateTaskbar
{
    try
    {
        # Check if there is need to generate the shortcuts
        $shortcuts = Get-ChildItem -Path "C:\Users\PandoraUser\AppData\Roaming\Microsoft\Internet Explorer\Quick Launch\User Pinned\TaskBar" | Select-Object -ExpandProperty Name

        if ( $shortcut -contains "Forensics-Tools.lnk" -and $shortcut -contains "Reversing-Tools.lnk")
        {
            Write-Host "[!] Taskbar already generated!, skipping" -ForegroundColor Yellow
        }
        else
        {
            Write-Host "[i] Generating taskbar shortcuts"
        
            $shell = New-Object -ComObject WScript.Shell
        
            $shortcut = $shell.CreateShortcut("C:\Users\PandoraUser\AppData\Roaming\Microsoft\Internet Explorer\Quick Launch\User Pinned\TaskBar\Forensics-Tools.lnk")
            $shortcut.TargetPath = "C:\Forensics"
            $shortcut.IconLocation = "C:\Logos\Forensics.ico"
            $shortcut.Save() | Out-Null
        
            $shortcut = $shell.CreateShortcut("C:\Users\PandoraUser\AppData\Roaming\Microsoft\Internet Explorer\Quick Launch\User Pinned\TaskBar\Reversing-Tools.lnk")
            $shortcut.TargetPath = "C:\Reversing"
            $shortcut.IconLocation = "C:\Logos\BugReversing.ico"
            $shortcut.Save() | Out-Null        

            $pandoraUpdaterName = "C:\Users\PandoraUser\AppData\Roaming\Microsoft\Internet Explorer\Quick Launch\User Pinned\TaskBar\Desktop application for pandoraBox, to update the sandbox and all of it tool" + $(0x2019 -as [char]) + "s.lnk"

            $shortcut = $shell.CreateShortcut($pandoraUpdaterName)
            $shortcut.TargetPath = "C:\pandora_tool_updater.exe"
            $shortcut.Save() | Out-Null
    
            $shortcut = $shell.CreateShortcut("C:\Users\PandoraUser\AppData\Roaming\Microsoft\Internet Explorer\Quick Launch\User Pinned\TaskBar\Brave.lnk")
            $shortcut.TargetPath = "C:\Users\PandoraUser\AppData\Local\BraveSoftware\Brave-Browser\Application\brave.exe"
            $shortcut.Save() | Out-Null
    
            $shortcut = $shell.CreateShortcut("C:\Users\PandoraUser\AppData\Roaming\Microsoft\Internet Explorer\Quick Launch\User Pinned\TaskBar\FileZilla.lnk")
            $shortcut.TargetPath = "C:\Program Files\FileZilla FTP Client\filezilla.exe"
            $shortcut.Save() | Out-Null
    
            $shortcut = $shell.CreateShortcut("C:\Users\PandoraUser\AppData\Roaming\Microsoft\Internet Explorer\Quick Launch\User Pinned\TaskBar\PuTTY.lnk")
            $shortcut.TargetPath = "C:\Program Files\PuTTY\putty.exe"
            $shortcut.Save() | Out-Null
    
            $shortcut = $shell.CreateShortcut("C:\Users\PandoraUser\AppData\Roaming\Microsoft\Internet Explorer\Quick Launch\User Pinned\TaskBar\Visual Studio Code.lnk")
            $shortcut.TargetPath = "C:\Program Files\Microsoft VS Code\Code.exe"
            $shortcut.Save() | Out-Null
    
            $shortcut = $shell.CreateShortcut("C:\Users\PandoraUser\AppData\Roaming\Microsoft\Internet Explorer\Quick Launch\User Pinned\TaskBar\Windows Sandbox.lnk")
            $shortcut.TargetPath = "C:\Windows\system32\WindowsSandbox.exe"
            $shortcut.Save() | Out-Null
    
            $shortcut = $shell.CreateShortcut("C:\Users\PandoraUser\AppData\Roaming\Microsoft\Internet Explorer\Quick Launch\User Pinned\TaskBar\WinSCP.lnk")
            $shortcut.TargetPath = "C:\Program Files (x86)\WinSCP\WinSCP.exe"
            $shortcut.Save() | Out-Null
        
            Write-Host "[i] Importing the reg file"
    
            # Re-boot explorer
            Write-Host "[i] Re-booting explorer.exe to apply changes"
            taskkill /f /im explorer.exe | Out-Null
            Start-Process explorer.exe | Out-Null
    
            Write-Host "[+] New taskbar generated!" -ForegroundColor Green
        }
    }
    catch
    {
        Write-Host "[-] Error setting-up the taskbar" -ForegroundColor Red
        Write-Host "[-] Double check if the username is named: PandoraUser"
        
        # Print error to log
        .printErrorToLog -message $Error[0]
    }

}

# @description Remove the created lnks when Ninite hits
function .removeDesktoplnk 
{
    Write-Host "[i] Removing junk lnks"

    try 
    {
        $lnks = Get-ChildItem -Path "C:\Users\PandoraUser\Desktop" -Filter *.lnk -ErrorAction SilentlyContinue
        $publiclnks = Get-ChildItem -Path "C:\Users\Public\Desktop" -Filter *.lnk -ErrorAction SilentlyContinue
    
        foreach ($lnk in $lnks)
        {
            if ($lnk -ne "Reversing-Tools.lnk" -and $lnk -ne "Forensics-Tools.lnk" -and $lnk -ne "Pandora Updater.lnk")
            {
                Remove-Item -Force $lnk.FullName -ErrorAction SilentlyContinue
            }
        }
    
        foreach ($lnk in $publiclnks)
        {
            if ($lnk -ne "Reversing-Tools.lnk" -and $lnk -ne "Forensics-Tools.lnk" -and $lnk -ne "Pandora Updater.lnk")
            {
                Remove-Item -Force $lnk.FullName -ErrorAction SilentlyContinue
            }
        }

        # Remove junk tools folder of the desktop
        if (Test-Path -Path "C:\Users\PandoraUser\Desktop\Forensics-Tools" -PathType Container)
        {
            Remove-Item -Force -Recurse -Path "C:\Users\PandoraUser\Desktop\Forensics-Tools"
        }

        if (Test-Path -Path "C:\Users\PandoraUser\Desktop\Reversing-Tools" -PathType Container)
        {
            Remove-Item -Force -Recurse -Path "C:\Users\PandoraUser\Desktop\Reversing-Tools"
        }

    
        Write-Host "[+] Junk lnks removed!" -ForegroundColor Green
    }
    catch 
    {
        Write-Host "[-] Some junk lnks can not be remmoved! (this action is not mandatory)" -ForegroundColor Red

        # Print error to log
        .printErrorToLog -message $Error[0]
    }
}

# @description Installs Chocolately on the windows machine
function .installChoco 
{

    # Check if choco is intalled
    $chocoInstall = Get-Command -Name choco -ErrorAction SilentlyContinue

    if ($chocoInstall.Length -eq 0)
    {
        Write-Host "[i] Installing choco on the machine..."
        Set-ExecutionPolicy Bypass -Scope Process -Force; [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072; Invoke-Expression ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1')) | Out-Null

        # Launch java installation (need it for some apps)
        Start-Process powershell { choco feature enable -n allowGlobalConfirmation ; choco install -y openjdk --force}
        Start-Process powershell { choco feature enable -n allowGlobalConfirmation ; choco install -y dnspy --force}
    }
    else
    {
        Write-Host "[!] Choco is already installed on the machine, aborting installation" -ForegroundColor Yellow 
    }
}

# @description Remove default pinned items from the taskbar
function .removePinnedItems 
{
    Write-Host "[i] Deleting pinned items that are not relevant"
    try 
    {
        $path = "C:\Users\PandoraUser\AppData\Roaming\Microsoft\Internet Explorer\Quick Launch\User Pinned\TaskBar"
        $pinnedItems = Get-ChildItem -Path $path
        $validPinnedItems = @(
            "File Explorer.lnk",
            "Brave.lnk",
            "Visual Studio Code.lnk"
        )
    
        foreach ($item in $pinnedItems)
        {
            if ($validPinnedItems -notcontains $item)
            {
                Remove-Item -Path $item.FullName -ErrorAction SilentlyContinue | Out-Null
            }
        }

        $shell = New-Object -ComObject WScript.Shell
        
        # Create the new pinned items
        cmd /c mklink "%USERPROFILE%\AppData\Roaming\Microsoft\Internet Explorer\Quick Launch\User Pinned\TaskBar\Pandora Updater" "C:\pandora_tool_updater.exe" | Out-Null
        
        Write-Host "[+] Updater added to the pinned items"
        
        $shortcut = $shell.CreateShortcut("C:\Users\PandoraUser\Desktop\Forensics-Tools.lnk")
        $shortcut.TargetPath = "C:\Forensics\"
        $shortcut.IconLocation = "C:\Logos\Forensics.ico"
        $shortcut.Save() | Out-Null

        # cmd /c mklink /D "%USERPROFILE%\AppData\Roaming\Microsoft\Internet Explorer\Quick Launch\User Pinned\TaskBar\Forensics-Tools" "C:\Forensics" | Out-Null
        Write-Host "[+] Forensics Tools added to pinned items" 

        $shortcut = $shell.CreateShortcut("C:\Users\PandoraUser\Desktop\Reversing-Tools.lnk")
        $shortcut.TargetPath = "C:\Reversing\"
        $shortcut.IconLocation = "C:\Logos\BugReversing.ico"
        $shortcut.Save() | Out-Null

        # cmd /c mklink /D "%USERPROFILE%\AppData\Roaming\Microsoft\Internet Explorer\Quick Launch\User Pinned\TaskBar\Reversing-Tools" "C:\Reversing" | Out-Null
        Write-Host "[+] Reversing tools added to the pinned items"

        Write-Host "[i] Creating the Taskbar"

        .generateTaskbar
    
        # Kill and restart explorer
        taskkill /f /im explorer.exe | Out-Null
        Start-Process explorer.exe | Out-Null

        Write-Host "[+] Pinned items deleted!" -ForegroundColor Green
    }
    catch 
    {
        Write-Host "[!] Error, error creating the pinned elements of the taskbar"  
        
        # Print error to log
        .printErrorToLog -message $Error[0]  
    }

}

# @description Make persistance for the custom wallpaper
function .persistWallpaperOverWrite 
{
    try
    {
        # Launch the wallpaper set-up several times
        cmd /c reg add "HKEY_CURRENT_USER\control panel\desktop" /v wallpaper /t REG_SZ /d  C:\M7Logo3Upscaled.jpg /f ; 1..100 | ForEach-Object { rundll32.exe user32.dll, UpdatePerUserSystemParameters }
        cmd /c reg add "HKEY_CURRENT_USER\control panel\desktop" /v wallpaper /t REG_SZ /d  C:\M7Logo3Upscaled.jpg /f ; 1..100 | ForEach-Object { rundll32.exe user32.dll, UpdatePerUserSystemParameters }
        cmd /c reg add "HKEY_CURRENT_USER\control panel\desktop" /v wallpaper /t REG_SZ /d  C:\M7Logo3Upscaled.jpg /f ; 1..100 | ForEach-Object { rundll32.exe user32.dll, UpdatePerUserSystemParameters }
    }
    catch
    {
        Write-Host "[!], Error wallpaper can not persist (may be already done)" -ForegroundColor Red
    }
}

# @description Make persitance for the automation to change the IP direction
function .persistIPChanger 
{
    try
    {
        $trigger = New-ScheduledTaskTrigger -AtLogOn  
        $action = New-ScheduledTaskAction -Execute "Powershell" -Argument "-NoExit -ExecutionPolicy Bypass -WindowStyle hidden `"C:\setStaticIp.ps1`""
    
        Register-ScheduledTask -Action $action -TaskName "PandoraAutomation\Pandora IP static automation" -Trigger $trigger -RunLevel Highest -ErrorAction SilentlyContinue | Out-Null
    }
    catch
    {
        Write-Host "[!] Error, IP persistance can not be set (it may be already be present)" -ForegroundColor Red

        # Print error to log
        .printErrorToLog -message $Error[0]
    }
}

# @description Create folders on the desktop
function .createFoldersLnks 
{
    try
    {
        Write-Host "[i] Creating Forensics quick access"
        cmd /c mklink /D "C:\Users\PandoraUser\Desktop\Forensics-Tools" "C:\Forensics" | Out-Null
        
        Write-Host "[i] Creating Reversing quick access"
        cmd /c mklink /D "C:\Users\PandoraUser\Desktop\Reversing-Tools" "C:\Reversing" | Out-Null

        Write-Host "[i] Creating lnk for updater tool"
        cmd /c mklink "C:\Users\PandoraUser\Desktop\Pandora Updater" "C:\pandora_tool_updater.exe" | Out-Null

        Write-Host "[+] Lnk creation done" -ForegroundColor Green
    }
    catch
    {
        Write-Host "[!] Main folder lnks can not be created (this is not mandatory)" -ForegroundColor Yellow
        
        # Print error to log
        .printErrorToLog -message $Error[0]
    }
}

# @description Installs Git for powershell
function .installGit 
{
    Write-Host "[i] Starting Git installation"

    try
    {
        Set-Location "C:\"

        Start-Process -FilePath ".\Git-2.44.0-64-bit.exe" -ArgumentList "/SP- /VERYSILENT /SUPPRESSMSGBOXES /NORESTART" -Wait

        if (-not ($env:Path -like "*Git*"))
        {
            $env:Path += ";C:\Program Files\Git\bin\git.exe"
        }
        else
        {
            Write-Host "[!] Git already present on the path!" -ForegroundColor Yellow
        }

        Write-Host "[+] Git installed and added to the powershell path" -ForegroundColor Green
    }
    catch
    {
        Write-Host "[-] Error, Error installing Git or Grep (they are non mandatory files)!" -ForegroundColor Red

        # Print error to log
        .printErrorToLog -message $Error[0]
    }

}

# @description Removes co-pilot from the machine
function .disableCopilot 
{
    Write-Host "[i] Removing Microsoft Co-pilot from the machine"

    try
    {
        cmd /c reg add HKCU\Software\Policies\Microsoft\Windows\WindowsCopilot /v TurnOffWindowsCopilot /t REG_DWORD /d 1 /f | Out-Null
        cmd /c reg add HKLM\Software\Policies\Microsoft\Windows\WindowsCopilot /v TurnOffWindowsCopilot /t REG_DWORD /d 1 /f | Out-Null
        Write-Host "[+] Success, Microsoft Co-pilot is now removed from the machine" -ForegroundColor Green 
    }
    catch 
    {
        Write-Host "[-] Error removing Microsoft Co-pilot from the machine (this machine may not have a windows copilot update)" -ForegroundColor Red
    }

}

# @description Looks for processes with the given names and waits execution till completes
function selfDetectAndWaitForProcess 
{
    Param
    (
        [String] $processName
    )

    try 
    {
        # NOTE: If launched from a wt.exe not able to detect itself (always launch it from powershell)

        $currentProcessId = [System.Diagnostics.Process]::GetCurrentProcess() | Select-Object -ExpandProperty 'Id'

        Write-Host "[i] Current PID: $currentProcessId"
    
        # Get all process names
        $processToFind = Get-Process $processName
    
        if ($processToFind.Length -gt 0)
        {
            # Check the processes
            if ($processToFind.Length -eq 1 -and $processToFind[0].Id -eq $currentProcessId)
            {
                Write-Host "[-] Error, no process with name $processName was found to attatach a listener" -ForegroundColor Red
            }
            else
            {
                Write-Host "[i] $($processToFind.Length) detected, attatching listeners..."
    
                # Iterate the processes
                foreach ($process in $processToFind)
                {
                    try
                    {
                        if ($currentProcessId -ne $process.Id)
                        {
                            # The process id to wait
                            Write-Host "[!] Waiting for process $processName with PID $($process.Id) to finish, do not close the terminal" -ForegroundColor Yellow
                            Wait-Process $process.Id -ErrorAction SilentlyContinue
                            Write-Host "[+] Process $processName with PID $($process.Id) now liberated!, resuming the execution" -ForegroundColor Green
                        }
                    }
                    catch
                    {
                        #
                        # Print error to log
                        .printErrorToLog -message $Error[0]
                    }
                }
            }
        }
        else
        {
            # No process found
            Write-Host "[-] Error, no process with name $processName was found to attatach a listener" -ForegroundColor Red
        }        
    }
    catch 
    {
        Write-Host "[-] No process with name $processName found!" -ForegroundColor Red

        # Print error to log
        .printErrorToLog -message $Error[0]
    }
}

function .iterateRegistryCollection
{
    Param
    (
        [System.Array]$collection
    )

    foreach ($entry in $collection)
    {
        $registryCurrentValue = Get-ItemProperty -Path "Registry::$($entry.registryPath)" -ErrorAction SilentlyContinue | Select-Object $entry.registryPropertyName -ErrorAction SilentlyContinue

        # If not empty check the registry
        if ("" -ne $registryCurrentValue)
        {
            # Now get the value of the reg
            $registryCurrentValue = $registryCurrentValue | Select-Object $entry.registryPropertyName

            if (1 -eq $registryCurrentValue)
            {
                try
                {
                    # Change the registry value
                    New-ItemProperty -Path "Registry::$($entry.registryPath)" -Name $entry.registryPropertyName -Value $entry.registryValue -PropertyType DWORD -Force -ErrorAction SilentlyContinue
                }
                catch
                {
                    Write-Host "[-] Error updating a registry value" -ForegroundColor Red
                    .printErrorToLog -message "[-] Error updating the registry key: $($entry.registryPath)/$($entry.registryPropertyName) with the value $($entry.registryValue)"
                }
            }
        }
    }

    # Re-boot the registry
    gpupdate /force | Out-Null
}

# @description Function to force change some registry values, in order to successfully remove some features
function  .registryModifications
{
    # All registry entrys to edit to zero
    $registryToEditZero = @(
        @{
            "registryPath" = "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo"
            "registryPropertyName" = "Enabled"
            "registryValue" = '0'
        },
        @{
            "registryPath" = "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Privacy"
            "registryPropertyName" = "TailoredExperiencesWithDiagnosticDataEnabled"
            "registryValue" = '0'
        },
        @{
            "registryPath" = "HKEY_CURRENT_USER\Software\Microsoft\Speech_OneCore\Settings\OnlineSpeechPrivacy"
            "registryPropertyName" = "HasAccepted"
            "registryValue" = '0'
        },
        @{
            "registryPath" = "HKEY_CURRENT_USER\Software\Microsoft\Input\TIPC"
            "registryPropertyName" = "Enabled"
            "registryValue" = '0'
        },
        @{
            "registryPath" = "HKEY_CURRENT_USER\Software\Microsoft\InputPersonalization\TrainedDataStore"
            "registryPropertyName" = "HarvestContacts"
            "registryValue" = '0'
        },
        @{
            "registryPath" = "HKEY_CURRENT_USER\Software\Microsoft\Personalization\Settings"
            "registryPropertyName" = "AcceptedPrivacyPolicy"
            "registryValue" = '0'
        },
        @{
            "registryPath" = "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection"
            "registryPropertyName" = "AllowTelemetry"
            "registryValue" = '0'
        },
        @{
            "registryPath" = "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced"
            "registryPropertyName" = "Start_TrackProgs"
            "registryValue" = '0'
        },
        @{
            "registryPath" = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\System"
            "registryPropertyName" = "PublishUserActivities"
            "registryValue" = '0'
        },
        @{
            "registryPath" = "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Siuf\Rules"
            "registryPropertyName" = "NumberOfSIUFInPeriod"
            "registryValue" = '0'
        }
    )

    # All registry entrys to edit to one
    $registryToEditOne = @(

    )

    try
    {
        Write-Host "[i] Persisting debloap features..."
        
        .iterateRegistryCollection -collection $registryToEditZero
        Write-Host "[+] Some parts of the registry are now updated" -ForegroundColor Green

        .iterateRegistryCollection -collection $registryToEditOne
        Write-Host "[+] Debloaped process completed!" -ForegroundColor Green
        
    }
    catch
    {
        Write-Host "[!] Skipping one registry edit"
        printErrorToLog -message "[!] Skipping registry: $registry"
    }

}

# @description Installs the custom oh-my-posh console
function .installOhMyPosh 
{
    if (Test-Path -Path $PROFILE)
    {
        $profileContent = Get-Content $PROFILE
    
        if ($profileContent.Contains("oh-my-posh.exe init pwsh --config"))
        {
            # Ask the user to proceed or not
            Write-Host "[!] Oh my posh is already installed on the machine" -ForegroundColor Yellow
    
            $ohmyposhAskConfig = [System.Management.Automation.Host.ChoiceDescription[]] ([System.Management.Automation.Host.ChoiceDescription]::new("&Yes", "Re-Apply oh-my-posh installation"), [System.Management.Automation.Host.ChoiceDescription]::new("&No", "Do not re-apply the oh my posh installation (recommended)"))
    
            $userResponse = $Host.UI.PromptForChoice("", "[?] Re-Apply the oh my posh installation? (Not recommended)", $ohmyposhAskConfig, 1)
    
            if (1 -eq $userResponse)
            {
                return ""              
            }
    
            Write-Host "[!] Re-applaying oh my posh installation..." -ForegroundColor Yellow
        }
    }

    
    $Error.Clear()

    Write-Host "[i] Creating the temp ps1 payload..."

    # Test the internet connection
    if (Test-Connection -ComputerName www.google.com -Quiet)
    {
        try
        {
            $tempFile = New-TemporaryFile
            $scriptPayload = "    
    Write-Host `"[i] Preparing for download of oh-my-posh console`"
    
    try 
    {
    
    # First test if the font is already present on the machine
    
    # Load font assambly
    [System.Reflection.Assembly]::LoadWithPartialName(`"System.Drawing`") | Out-Null
    
    `$loadedFonts = (New-Object System.Drawing.Text.InstalledFontCollection).Families
    
    if ((`$loadedFonts -like `"*Fira*`").Length -eq 0)
    {
        # Install the font
        Set-Location `"C:\FiraCode`"
        
        `$fonts = (New-Object -ComObject Shell.Application).Namespace(0x14)
    
        foreach (`$file in Get-ChildItem *.ttf) 
        {
            `$fileName = `$file.Name
            if (-Not (Test-Path -Path `"C:\Windows\fonts\`$fileName`") )
            {
                Get-ChildItem `$file | ForEach-Object { `$fonts.CopyHere(`$_.FullName, 0x10) }
            }
            
            Write-Host `"[i] `$fileName installed!`"
        }
    }
    else
    {
        Write-Host `"[!] Fira font is already installed on the machine!`" -ForegroundColor Yellow
    }
    
    Set-Location `"C:\`"
    
    Write-Host `"[+] Terminal custom fonts installed!`" -ForegroundColor Green
    
    # Change the terminal theme
    `$settingsPath = `"C:\Users\PandoraUser\AppData\Local\Packages\Microsoft.WindowsTerminal_8wekyb3d8bbwe\LocalState`"

    # Move the config to the final PATH
    Move-Item `"C:\customConsoleConfig.json`" `"`$settingsPath\settings.json`" -Force -ErrorAction SilentlyContinue
    
    Write-Host `"[+] Basic console info updated!`" -ForegroundColor Green
    
    if (Test-Connection -ComputerName www.google.com -Quiet)
    {
        try 
        {
            winget source reset --force | Out-Null
            winget source update | Out-Null
            winget install oh-my-posh --verbose-logs --silent --accept-package-agreements --accept-source-agreements --source msstore | Out-Null
            
            Write-Host `"[+] Download completed!`" -ForegroundColor Green
            
            Write-Host `"[i] Adding the oh-my-posh to main windows PATH`"
            
            if (-Not (`$env:Path -like `"*oh-my-posh*`"))
            {
                `$env:Path += `";C:\Users\user\AppData\Local\Programs\oh-my-posh\bin`"
            }
            else
            {
                Write-Host `"[!] oh my posh already present on the path`" -ForegroundColor Yellow
            }
        
            Write-Host `"[i] Re-launching on a new context to detect oh-my-posh`"
        
            # Continue the code execution in a new powershell instance
        
            # Check if the command alias is working
            `$ohPoshInstall = Get-Command -Name oh-my-posh -ErrorAction SilentlyContinue
        
            `$ohMyPoshPath = `"C:\Users\PandoraUser\AppData\Local\Programs\oh-my-posh\bin\oh-my-posh.exe`"
          
            try
            {
                # Create the file with the theme for the console
                Invoke-Expression `"try {`$ohMyPoshPath init pwsh --config 'C:\ohmyposhPandoraTheme.json' | Invoke-Expression -ErrorAction SilentlyContinue | Out-Null} catch { Write-Host '[!] Oh-py-posh command falied, it can already be installed' -ForegroundColor Yellow }`" -ErrorAction SilentlyContinue
                
                New-Item -Path `$PROFILE -Type File -Force | Out-Null
                
                # Launch the next configurations in a diferent terminal
                if (Test-Path `$PROFILE) 
                { 
                    if ((Get-Content `$PROFILE).Length -eq 0) 
                    { 
                        `"`$ohMyPoshPath init pwsh --config 'C:\ohmyposhPandoraTheme.json' | Invoke-Expression`" > `$PROFILE 
                    } 
                }
                
                Write-Host `"[!] Reloading profile, do not close the terminal`" -ForegroundColor Yellow
                
                . `$PROFILE        
            }
            catch
            {
                Write-Host `"[!] Oh My Posh may already be installed, if not re-launch the script with  pandoraSetUp.ps1 -DoInternetSetUp`" -ForegroundColor Yellow

                Start-Sleep -Seconds 1

                [System.Environment]::Exit(0)
            }
        }
        catch 
        {
            # Ignore PS error
            if (`$Error[0] -like `"*A parameter cannot be found that matches parameter name 'Key'.*`")
            {
                # Ignore this error
                `$Error.Clear()
            }
            else
            {
                Write-Host `"[!] Error installing oh-my-posh, you need to have internet to make this download (but is not mandatory)`" -ForegroundColor Red
        
                [System.Environment]::Exit(0)
            }
        }
    } else { Write-Host `"[-] Connection error with oh my posh installation`" -ForegroundColor Red }
    }
    catch 
    {
        # Ignore PS error
        if (`$Error[0] -like `"*A parameter cannot be found that matches parameter name 'Key'.*`")
        {
            # Ignore this error
            `$Error.Clear()
        }
        else
        {
            Write-Host `"[-] Error the oh-my-posh download and installation failed, please try again or perform it manually`" -ForegroundColor Red
        }
    }
    
    Write-Host `"[+] All done this terminal will close by itself`" -ForegroundColor Green
    
    Start-Sleep -Seconds 2
    
    [System.Environment]::Exit(0)
    "      
            # Write script content to the new file
            Add-Content -Path $tempFile -Value $scriptPayload
    
            Write-Host "[+] Oh my posh installation payload created on: $tempFile" -ForegroundColor Green
    
            # Start process for the windows terminal and load the script content in memory
    
            Write-Host "[!] Launching new instance for installation do not close either of the instancies!" -ForegroundColor Yellow
    
            Start-Sleep -Seconds 1
            
            # Full path to the program C:\Program Files\WindowsApps\Microsoft.WindowsTerminal_1.15.3466.0_x64__8wekyb3d8bbwe\wt.exe
            
            $terminalPossiblePaths = Get-ChildItem -Path 'C:\Program Files\WindowsApps\*WindowsTerminal*x64*' | Select-Object -ExpandProperty Name
            
            # Rename the tmp file to ps1 (otherwise will not execute)
            Rename-Item -Path $tempFile -NewName "$($tempFile.Name).ps1"

            # Launch the execution of oh-my-posh on the windows terminal
            & "C:\Program Files\WindowsApps\$terminalPossiblePaths\wt.exe" --window 0 -p "Windows Powershell" -d "$pwd" powershell -noExit "& '$tempFile'"
    
            # Wait to process to pop-up
            Start-Sleep -Seconds 3
    
            # Wait the process to end (will be a powershell process)
            selfDetectAndWaitForProcess -processName powershell
            
            Write-Host "[+] Oh my posh should now be installed on the machine if no errors were prompted! (if new console is not close wait until finish)" -ForegroundColor Green
        }
        catch
        {
            Write-Host "[-] Error creating the tmp payload for oh my posh installation" -ForegroundColor Red

            # Print error to log
            .printErrorToLog -message $Error[0]
        }
    }
    else
    {
        Write-Host "[-] Error, no internet connection found!, aborting oh my posh install" -ForegroundColor Red
    }

}

# @description Adds to global path, some linux ports that came with GIT
function .installLinuxSortcuts 
{
    Write-Host "[i] Installing Linux shortcuts (grep, cat...)"
    try
    {
        # Because of the creation of the oh-my-posh profile, we have to append the command to the exisiting string
        $profileContent = Get-Content $PROFILE
    
        if (-not $profileContent.Contains(";C:\Program Files\Git\usr\bin\"))
        {
            # Add the string to the content
            # Add a line jump to concat with the oh my posh install
            $profileContent += "`n`n`$env:Path += `";C:\Program Files\Git\usr\bin\`""
    
            $profileContent | Set-Content $profile | Out-Null
    
            Write-Host "[+] Linux tools (grep, awk...) are now installed on the machine" -ForegroundColor Green
        }
        else
        {
            Write-Host "[i] Linux tools are already installed"
        }
    }
    catch
    {
        Write-Host "[-] Error, powershell profile is not found, this may be an error with oh-my-posh installation, reboot the machine and launch again the script"
        
        # Print error to log
        .printErrorToLog -message $Error[0]
    }
}

# @description Generates an Easter Egg on the machine
function .createEasterEgg 
{
    try
    {
        $secret = "DQoNCkBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQA0KQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBADQpAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEANCkBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQA0KQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBADQpAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEANCkBAQEBAQEBAQEBAQEApKSlAKSkpKEBAQEBAQEBAQEBAQEBAQEBAQEBAQCN9QCkpKSkpKSkpQEBAQEBAQEBAQEBAQA0KQEBAQEBAQEBAQEBAQCV+LX5+LS1+fnste0BAQEBAQEBAQEBAQEBAQEAufip+fi1+fn4tPUBAQEBAQEBAQEBAQEBADQpAQEBAQEBAQEBAQEBAQD5ePCheOiMjPig8fUBAQEBAQEBAQEBAQEBAXn08KEB+LT49Kz4pQEBAQEBAQEBAQEBAQEANCkBAQEBAQEBAQEBAQEBAPj57fSg8Kl1APDwpJUBAQEBAQEBAQEBAQCgpPHtAKz4pXX1dPilAQEBAQEBAQEBAQEBAQA0KQEBAQEBAQEBAQEBAQEA+PkBAQD5ePTxAKD4uKUBAQEBAQEBAQEAuKzxAQF4rKkBAXSM+KUBAQEBAQEBAQEBAQEBADQpAQEBAQEBAQEBAQEBAQDw+QEBAQFsjfXtAez4tKkBAQEBAQEBALl48QHtbeyVAfX0lJT4pQEBAQEBAQEBAQEBAQEANCkBAQEBAQEBAQEBAQEBAPDxAQEBAQEBAXSojQDwrPUBAQEBAQDo8PEA+QEBAQCUpQCV7PClAQEBAQEBAQEBAQEBAQA0KQEBAQEBAQEBAQEBAQEA8PEBAfUB7XStAQEAoQClefkBAQEB+PChAXUBAJSk+QEB7QCU8KEBAQEBAQEBAQEBAQEBADQpAQEBAQEBAQEBAQEBAQDw8QEBAJVtbXj1AQEA8QCk8fkB7PSlbQCNAQF1ePFsjXSMjJTwoQEBAQEBAQEBAQEBAQEANCkBAQEBAQEBAQEBAQEBAKTxAQEAle0BbPipAQEBdQCgpPSopIyVAQEA+Pl1bQCVdQEAlKShAQEBAQEBAQEBAQEBAQA0KQEBAQEBAQEBAQEBAQEApKSVAQEB7QEBbKT5AQEB7QH0oKEB7QEBAKjxbW0BAJVtAQCUpKEBAQEBAQEBAQEBAQEBADQpAQEBAQEBAQEBAQEBAQCkpJUBAQCNAe0BbXTxbQEBAJSVAfUBAQF4pW31AfUBAW0BAJSkoQEBAQEBAQEBAQEBAQEANCkBAQEBAQEBAQEBAQEBAKSlAQEBAI0BbQEBbWykpQEBAJUBAQEA+KFt7QEApQEB9JXsjKShAQEBAQEBAQEBAQEBAQA0KQEBAQEBAQEBAQEBAQEApKUBAQEAlQChbQEBbWyg8QEBAQEBAPF1bJUBAWylAQHtAIyUoXUBAQEBAQEBAQEBAQEBADQpAQEBAQEBAQEBAQEBAQCkpQEBAQCVAKFtAQEB7W108QEBAJShbW0BAQEBbKEBAe0AjJShdQEBAQEBAQEBAQEBAQEANCkBAQEBAQEBAQEBAQEBAKShAQEBAJUAoW0BAQEAjW1spQHtdW1tAQEBAQFsoQHtdQCMlKF1AQEBAQEBAQEBAQEBAQA0KQEBAQEBAQEBAQEBAQEApKEBAQEAlQF1bQEBAQEAlW1tdW1tbQEBAQEBAWyhAQHtAIyUoXUBAQEBAQEBAQEBAQEBADQpAQEBAQEBAQEBAQEBAQCgoQEBAQCVAXVtAQEBAQEBAW1tbW0BAQEBAQEBbXUBAe0BAQChdQEBAQEBAQEBAQEBAQEANCkBAQEBAQEBAQEBAQEBAXV1AQHtAW0BdW0BAQEBAQEBAW1tAQEBAQEBAQFtdQFtAfUAlXVtAQEBAQEBAQEBAQEBAQA0KQEBAQEBAQEBAQEBAQEBbW31AW10lQFtbQEBAQEBAQEBAQEBAQEBAQEBAW11AW11bQFtbW0BAQEBAQEBAQEBAQEBADQpAQEBAQEBAQEBAQEBAQHtAfVtbQEBAW1tAQEBAQEBAQEBAQEBAQEBAQEBbW0BAQFtbI0B7QEBAQEBAQEBAQEBAQEANCkBAQEBAQEBAQEBAQEBAfVtbI0BAQEBbW0BAQEBAQEBAQEBAQEBAQEBAQFtbQEBAQH1bWyNAQEBAQEBAQEBAQEBAQA0KQEBAQEBAQEBAQEBAQEBbW1sje1tbW1tbQEBAQEBAQEBAQEBAQEBAQEBAW1tbW1tAe1tbW0BAQEBAQEBAQEBAQEBADQpAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEANCkBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQA0KQEBAQEBAQEBAQEBAQEBAQEAgTmV2ZXIgZ2l2ZSB1cCEgYW5kIHRoYW5rcyBmb3IgQEBAQEBAQEBAQEBAQEBAQEBADQpAQEBAQEBAQEBAQEBAQEBAQCAgICAgIGRvd2xvYWRpbmcgdGhlIElTT0AgICAgICBAQEBAQEBAQEBAQEBAQEBAQEANCkAgaHR0cHM6Ly93d3cubGlua2VkaW4uY29tL2luL21pZ3VlbC1tb3Jlbm8tcGFzdG9yLz9sb2NhbGU9ZW5fVVMgQA0KQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBADQpAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEANCg0K"

        New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\EasterEgg" -ErrorAction SilentlyContinue | Out-Null
        New-Item -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\EasterEgg" -ErrorAction SilentlyContinue | Out-Null

        # Create the easter egg
        New-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\EasterEgg" -Name "DecodeMe" -Value $secret -PropertyType String -ErrorAction SilentlyContinue | Out-Null
        New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\EasterEgg" -Name "DecodeMe" -Value $secret -PropertyType String -ErrorAction SilentlyContinue | Out-Null
    }  
    catch {}
}

# @description Main function of the program
function .PandoraSetUp {
    
    Param 
    (
        [switch] $doSetUp,
        [switch] $doInternetSetUp,
        [switch] $updateSetUp

    )

    if ($updateSetUp) { $option = "updateModule" }
    if ($doInternetSetUp) { $option = "internetSetUp" }
    if ($doSetUp) { $option = "setup" }

    try
    {
        # Print the banner
        Write-Host $banner -ForegroundColor Cyan
        Write-Host "[i] Do not close this window, when done it will close itself"
        
        # Zoom out the console to print well the logo
        .zoomOut

        switch ($option)
        {
            'updateModule'
            {
                .pandoraSetUpUpdater
            }
            'setup'
            {
                Write-Host "[i] Offline setup started"

                .checkFileSignature

                Set-QuickEdit -DisableQuickEdit

                .checkUserName
                .changePolicyExecution
                .persistWallpaperOverWrite
                .persistIPChanger
                .decompressTools
                .createFoldersLnks
                .removeDesktoplnk
                .removePinnedItems
                .createEasterEgg
                .disableCopilot
                .customRighClickQuickAccessTools

                .installOhMyPosh

                Write-Host "[i] Offline set-up completed!, consider doing the online set-up with flag -DoInternetSetUp"

                # Re-enable quick-edit
                Set-QuickEdit
            }
            'internetSetUp'
            {                 
                Write-Host "[i] Online set-up started!, performing  internet checks"

                .checkFileSignature

                # Check if the machine has internet connection
                $connectionCheck = Test-Connection -ComputerName www.google.com -Quiet
                
                if ($true -eq $connectionCheck)
                {
                    Write-Host "[i] Performing internet connection Set-Up"
                    
                    Set-QuickEdit -DisableQuickEdit
                    
                    .checkUserName
                    .installChoco 
                    .launchSeveralInstallations 
                    .removeDesktoplnk
                    .installOhMyPosh
                    .installGit
                    .installLinuxSortcuts

                    # Re-enable quickedit
                    Set-QuickEdit

                    Write-Host "[+] Internet set-up completed!" -ForegroundColor Green
                }
                else
                {
                    Write-Host "[-] Error, the internet part instalation can not be completed due to network connection not avaliable" -ForegroundColor Red
                    Write-Host "[-] Configure your internet connection and re-launch the script with pandoraSetUp.ps1 -DoInternetSetUp" -ForegroundColor Yellow
                }
            }
        }
    
        Write-Host "[+] All done!, you are free to use the machine, happy huting!" -ForegroundColor Green
        Write-Host "[!] Remember to follow me on LinkedIn: https://www.linkedin.com/in/miguel-moreno-pastor/ or GitHub: https://github.com/mimorep" -ForegroundColor Yellow
        
        Write-Host "[+] All done!, please reboot the PC before using to apply updates" -ForegroundColor Green

        # try
        # {
        #     Add-Type -AssemblyName PresentationFramework
        #     Add-Type -AssemblyName System.Windows.Forms
        #     $msgBox = [System.Windows.MessageBox]
        #     $window = New-Object System.Windows.Window
        #     $window.Topmost = $true
        #     $msgBoxResult = $msgBox::Show($window,'Please, remmember to re-boot the machine after the set-up ends!')
        #     $msgBoxResult
        # }
        # catch
        # {}
    
        # Start sleep and close the script
        Write-Host "[i] Exiting the program..."
        Start-Sleep -Seconds 5
        [System.Environment]::Exit(0)
    }
    catch 
    {
        Write-Host "[-] Some erros were raised during set-up, you can still use the machine but is recommended to re-do the installation" -ForegroundColor Red    

        # Print error to log
        .printErrorToLog -message $Error[0]
    }
}

if ($DoSetUp -eq $true) { .PandoraSetUp -doSetUp ; [System.Environment]::Exit(0) }

if ($DoInternetSetUp -eq $true) { .PandoraSetUp -doInternetSetUp ; [System.Environment]::Exit(0) }

if ($UpdateModule -eq $true) { .PandoraSetUp -updateSetUp ; [System.Environment]::Exit(0) }

[System.Environment]::Exit(0)
# SIG # Begin signature block
# MIIFxwYJKoZIhvcNAQcCoIIFuDCCBbQCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUkHP3OlURlJN2RO0FeKzPIjaw
# 8UCgggNPMIIDSzCCAjOgAwIBAgIQFO9ll8EXlLlKtyBrmceFMDANBgkqhkiG9w0B
# AQUFADAtMSswKQYDVQQDDCJQYW5kb3JhIEZyYW1ld29yayBSb290IENlcnRpZmlj
# YXRlMB4XDTI0MTAxNzA5MDQ0NFoXDTI5MTAxNzA5MTQ0NVowLTErMCkGA1UEAwwi
# UGFuZG9yYSBGcmFtZXdvcmsgUm9vdCBDZXJ0aWZpY2F0ZTCCASIwDQYJKoZIhvcN
# AQEBBQADggEPADCCAQoCggEBAMB78nUFxRII3VYP6Ed2C0JRC/em6tLkoD1ENz4b
# KEeYUdwTb/Z8Hv+Fte2NiqzxUHUA5aoqQd6rphhF1PG3EK+mDjlKVEdYuclnqlF4
# 7ObNAYKR1WqrjH+ZLrU28Zy3HsK50HgEq8xSFJuA//oG3o5lV8vZGRxgV78tfIs7
# g5Q131hLw76VmIHrp1gTCaskgo1kVCy+CVCnGmujnIap40bSxM1wEqk/94twj98j
# zSlZJq1mUtjimUgzCt9ERRulqlF282dhKU3aS2ZvegKZyst6mIu5ciIdZCl70sCj
# rdf1zG2jpzIvxcymk631nndCse7TV3vR6d5kmY9p99sV8C0CAwEAAaNnMGUwDgYD
# VR0PAQH/BAQDAgeAMBMGA1UdJQQMMAoGCCsGAQUFBwMDMB8GA1UdEQQYMBaCFHBh
# bmRvcmEuZnJhbWV3b3JrLm03MB0GA1UdDgQWBBRSOyzlDZvO5/GIRLyH5KzTE8My
# jDANBgkqhkiG9w0BAQUFAAOCAQEAky4aycMdFtzHDmGZNWRhDvDZtBwTuN6x1Fa2
# MBlslul5K6L1LRbKnXRAwZ3JM6Pb3aqf+yzYqciqLRbmlsDogKj1aQ/BRsgJ4a/3
# 0FIVvBnY5VzbefLLp40lxAsB2nP9UhKx7PETaQwYAfMSc7tEJMlnH+TTC2aQxt3e
# NuKOd/7Yza8uMpa9kOlGaV642HxCW5XtyDTXG9jHVEEvT8Zgz4Y1dqwDBuoXSYSd
# m36SjSmKJdLKJW5UbN6lnJGxMc0Rbp6TG5/GtHfPdV0FcVQMzMDFyMmO2xlFuz5b
# fXclXO0/h0QI+5Fq2lA6IlPAh0oUkxbAza7q8+dBJ0Z4WKmi+zGCAeIwggHeAgEB
# MEEwLTErMCkGA1UEAwwiUGFuZG9yYSBGcmFtZXdvcmsgUm9vdCBDZXJ0aWZpY2F0
# ZQIQFO9ll8EXlLlKtyBrmceFMDAJBgUrDgMCGgUAoHgwGAYKKwYBBAGCNwIBDDEK
# MAigAoAAoQKAADAZBgkqhkiG9w0BCQMxDAYKKwYBBAGCNwIBBDAcBgorBgEEAYI3
# AgELMQ4wDAYKKwYBBAGCNwIBFTAjBgkqhkiG9w0BCQQxFgQUasrQDWM5OY0aQaw6
# JFi7m36NcpwwDQYJKoZIhvcNAQEBBQAEggEAUSjoMZS3ke/y2JRzb1dsRZDLurxr
# n3Bj9r+3eqMNc50gMVoPld7TbZmmCHKAVpQdefZGzS0v58uhJHJZT9O7qr4pfbPN
# IyTUUZKg/bmJIiX1KkWCNrPfVuyqwoctDO5TDIjRtzMzjfUvk8svyiWAyqV/ZsrE
# IQvJ1jqAMB+i9Abon5WQjeNuegpt99T/wkJMuIvEzNilLfwpo94lHaP3Kjs7hfLG
# 1AyZDvR9Wovozz3Ki9mNwKkf4aNmdCsqzLhyjF/rEikR6eqdAqgtPau+pCdZAJhm
# acW6zIIIlnUcP8gn0xdJrutpl55qe9ivVMIzTCsOglpgKY21fIfK4hblKQ==
# SIG # End signature block
