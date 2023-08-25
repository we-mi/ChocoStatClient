[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [String]$Server,

    [Parameter()]
    [ValidateRange(1,65535)]
    [int]$Port = 2306,

    [Parameter()]
    [ValidateSet("https","http")]
    [String]$Protocol = "http",

    [Parameter()]
    [switch]$SkipCertificateCheck,

    # apikey write-access for adding new computers. Is sent, but not needed for updating a computer
    [Parameter(Mandatory)]
    [String]$APIToken,

    [Parameter()]
    [switch]$IgnorePackages,

    [Parameter()]
    [switch]$IgnoreFailedPackages,

    [Parameter()]
    [switch]$IgnoreSources,

	[Parameter()]
    [switch]$Force
)
$ErrorActionPreference = "Stop"

if ($SkipCertificateCheck.IsPresent -and $Host.Version.Major -le 5) {
    add-type @"
    using System.Net;
    using System.Security.Cryptography.X509Certificates;
    public class TrustAllCertsPolicy : ICertificatePolicy {
        public bool CheckValidationResult(
            ServicePoint srvPoint, X509Certificate certificate,
            WebRequest request, int certificateProblem) {
            return true;
        }
    }
"@
    [System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy
}

function Start-Choco {
    <#
    .SYNOPSIS
    Chocolatey Output Parserfunction

    .DESCRIPTION
    This function behaves like the normal choco.exe, except that it interepretes the given results of some commands and parses them to PSCustomObjects.
    This should make working with chocolatey alot easier if you really want to integrate it into your scripts.

    .PARAMETER command
    Chocolatey Command - basically the same command you would write after `choco`.
    Original Documentation to Chocolatey Commands: https://github.com/chocolatey/choco/wiki/CommandsList

    .PARAMETER options
    Chocolatey Options - the same options that you would write after the command of an `choco`-Invoke
    Original Documentation to Chocolatey Options and Switches: https://github.com/chocolatey/choco/wiki/CommandsReference#default-options-and-switches

    .INPUTS
    Options can be given through the pipeline. Further explained in Example 4.

    .OUTPUTS
    [System.Management.Automation.PSCustomObject], PSCustomObject of all important informations returned by the `choco` call

    .EXAMPLE
    PS C:\>Start-Choco -Command "list" -Option "-lo"
    Runs `choco list -lo` and parses the output to an object with the Attributes `PackageName` and `Version`.
    The options parameter has to be written in `"` or `'` so that powershell doesn't interpret the Value as an extra Parameter for this function

    .EXAMPLE
    PS C:\>Start-Choco info vscode
    Runs `choco info vscode` and parses the output to an PSCustomObject

    .EXAMPLE
    PS C:\>pschoco outdated
    Runs `choco outdated` over the function alias and parses the output like explained in the first example.

    .EXAMPLE
    PS C:\>@("vscode","firefox") | Start-Choco info
    Options can be passed through the pipeline. Thisway each entry will be given as the option: `Start-Choco info <PipeElement>`.

    .LINK
    https://github.com/chocolatey/choco/wiki/CommandsList
    https://github.com/chocolatey/choco/wiki/CommandsReference#default-options-and-switches

    .NOTES
    Currently Supported Chocolatey Commands (everything else works like the default `choco.exe`):
        - outdated
        - search|list|find
        - source|sources
        - info
        - config
        - feature
        - pin
    #>

    [CmdletBinding()]
    [alias("schoco","pschoco")]
    param (
        [Parameter(
            Mandatory=$true,
            ValueFromPipelineByPropertyName=$true,
            Position=0
        )]
        [ValidateNotNullOrEmpty()]
        [string]
        $command,

        [Parameter(
            Mandatory=$false,
            ValueFromPipelineByPropertyName=$true,
            ValueFromPipeline=$true,
            Position=1
        )]
        [string[]]
        $options = @()
    )

    begin {
		function Get-ChocolateySavedPackageArguments {
			[CmdletBinding()]
			param (
				[Parameter(Mandatory = $true)]
				[String]
				$Package,

				[Parameter(Mandatory = $true)]
				[String]
				$Version
			)

			$ArgsFile = Join-Path $env:ChocolateyInstall ".chocolatey\$($Package).$($Version)/.arguments"

			if ( Test-Path -PathType Leaf -Path $ArgsFile ) {

				try {
					Add-Type -AssemblyName System.Security
					$entropyBytes = [System.Text.Encoding]::UTF8.GetBytes("Chocolatey")

					$ArgsBase64 = Get-Content -Encoding UTF8 -Path $ArgsFile
					if ( -not [String]::IsNullOrWhiteSpace($ArgsBase64)) {
						$ArgsEncrypted = [System.Convert]::FromBase64String($ArgsBase64)

						$UnprotectedByteArray = [System.Security.Cryptography.ProtectedData]::Unprotect($ArgsEncrypted, $entropyBytes, [System.Security.Cryptography.DataProtectionScope]::LocalMachine)

						[System.Text.Encoding]::UTF8.GetString($UnprotectedByteArray)
					}
				} catch {
					return $null
				}
			}
		}

    }

    process {
        switch -Regex ($command) {
            '^(outdated)$' {
                & choco $command @options | Select-String -Pattern '^([\w-.]+)\|.*\|(.*)\|.*$' | ForEach-Object {
                    [PSCustomObject]@{
                        PackageName = $_.matches.groups[1].value
                        currentVersion = $_.matches.groups[2].value
                        newVersion = $_.matches.groups[3].value
                    }
                }
            }

            '^(search|find)$' {
                & choco $command @options | Select-String -Pattern '^([\w-.]+) ([\d.]+)' | ForEach-Object {
                    [PSCustomObject]@{
                        PackageName = $_.matches.groups[1].value
                        Version = $_.matches.groups[2].value
                    }
                }
            }

            '^(list)$' {
                $chocoVersion = [Version]( (Get-Item -Path (Join-Path $env:ChocolateyInstall "choco.exe") ).VersionInfo.FileVersion )
                if ($chocoVersion -gt [Version]"2.0.0") { # choco > 2.0.0 does not support "--lo" or "--local-only" parameter for list command and instead throw an error
                    $options = $options | Where-Object { $_ -notin @("--lo","--local-only") }
                }
                & choco $command @options | Select-String -Pattern '^([\w-.]+) ([\d.]+)' | ForEach-Object {
                    $name = $_.matches.groups[1].value
                    $version = $_.matches.groups[2].value

                    [PSCustomObject]@{
                        PackageName = $name
                        Version = $version
                        InstalledOn = ( Get-Item -Path (Join-Path $env:ChocolateyInstall "lib/$name") ).LastWriteTime
                        Parameters = Get-ChocolateySavedPackageArguments -Package $name -Version $Version
                    }
                }
            }

            '^(source[s]*)$' {
                if($options -notcontains 'add|disable|enable|remove') {
                    & choco $command @options | Select-String -Pattern '^([\w-.]+)( \[Disabled\])? - (\S+) \| Priority (\d)\|Bypass Proxy - (\w+)\|Self-Service - (\w+)\|Admin Only - (\w+)\.$' | ForEach-Object {
                        if ($_.matches.groups[2].value -eq ' [Disabled]') {
                            $Enabled = $False
                        } else {
                            $Enabled = $True
                        }
                        [PSCustomObject]@{
                            SourceName = $_.matches.groups[1].value
                            Enabled = $Enabled
                            Url = $_.matches.groups[3].value
                            Priority = $_.matches.groups[4].value
                            "Bypass Proxy" = $_.matches.groups[5].value
                            "Self-Service" = $_.matches.groups[6].value
                            "Admin Only" = $_.matches.groups[7].value
                        }
                    }
                }
                else {
                    & choco $command @options
                }
            }

            '^(info)$' {
                $infoArray = (((& choco $command @options) -split '\|') | Where-Object {$_ -match '.*: .*'}).trim() -replace ': ','=' | ConvertFrom-StringData

                $infoReturn = New-Object PSObject
                foreach ($infoItem in $infoArray) {
                    Add-Member -InputObject $infoReturn -MemberType NoteProperty -Name $infoItem.Keys -Value ($infoItem.Values -as [string])
                }
                return $infoReturn
            }

            '^(config)$' {
                if($options -notcontains 'get|set|unset') {
                    $chocoResult = & choco $command @options

                    $Settings = foreach ($line in $chocoResult) {
                        Select-String -InputObject $line -Pattern "^(\w+) = (\w+|) \|.*"| ForEach-Object {
                            [PSCustomObject]@{
                                "Setting" = $_.matches.groups[1].value
                                "Value" = $_.matches.groups[2].value
                            }
                        }
                    }

                    $Features = foreach ($line in $chocoResult) {
                        Select-String -InputObject $line -Pattern "\[([x ])\] (\w+).*" | ForEach-Object {
                            if($_.matches.groups[1].value -eq "x") {
                                $value = $true
                            }
                            else {
                                $value = $false
                            }
                            [PSCustomObject]@{
                                "Setting" = $_.matches.groups[2].value
                                "Enabled" = $value
                            }
                        }
                    }

                    return [PSCustomObject]@{
                        Settings = $Settings
                        Features = $Features
                    }
                }
                else {
                    & choco $command $options
                }
            }

            '^(feature[s]*)$' {
                if($options -notcontains 'disable|enable') {
                    & choco $command @options | Select-String -Pattern '\[([x ])\] (\w+).*' | ForEach-Object {
                        if($_.matches.groups[1].value -eq "x") {
                            $value = $true
                        }
                        else {
                            $value = $false
                        }
                        [PSCustomObject]@{
                            "Setting" = $_.matches.groups[2].value
                            "Enabled" = $value
                        }
                    }
                }
            }

            '^(pin)$' {
                if($options -notcontains 'add|remove') { # options enthält nicht add oder remove
                    & choco $command @options | Select-String -Pattern '^(.+)\|(.+)' | ForEach-Object {
                        [PSCustomObject]@{
                            packageName = $_.matches.groups[1].value
                            pinnedVersion = $_.matches.groups[2].value
                        }
                    }
                }
                else {
                    & choco $command @options
                }
            }

            '^(failed)$' {
                $FailedPackages = Get-ChildItem -Directory -Path (Join-Path $env:ChocolateyInstall "lib-bad") -ErrorAction SilentlyContinue
                foreach ($package in $FailedPackages) {
                    try {
                        $xml = [xml](Get-Content -Encoding UTF8 -Path (Join-Path $package.FullName "$($package.Name).nuspec"))
                        [PSCustomObject]@{
                            PackageName = $package.name
                            Version = $xml.package.metadata.version
                            FailedOn = $package.LastWriteTime
                        }
                    } catch {
                        Write-Error "Could not read failed package $($package.Name)"
                    }
                }
            }

            Default {
                & choco $command @options
            }
        }
    }

    end {
    }
}

function Get-Hash {
    [CmdletBinding()]
    param (
        # String to be converted to a hash
        [Parameter(Mandatory)]
        [AllowEmptyString()][AllowNull()]
        [String]
        $InputString
    )

    begin {

    }

    process {
        if ( [String]::IsNullOrWhiteSpace($InputString) ) {
            return $null
        } else {
            $pwstream = [IO.MemoryStream]::new([byte[]][char[]]$InputString)
            $HashedPassword = Get-FileHash -InputStream $pwstream -Algorithm SHA512 | Select-Object -ExpandProperty Hash

            return $HashedPassword
        }
    }

    end {

    }
}

function Save-ComputerSecret($file, $secret) {
    Write-Host "Saving computersecret"

    $HashedSecret = Get-Hash -InputString $secret | ConvertTo-SecureString -AsPlainText -Force

    $null = New-Item -ItemType Directory -Path (Split-Path $file) -ErrorAction SilentlyContinue

    $HashedSecret | Export-Clixml -Path $file
}

function Read-ComputerSecret($file) {
    Write-Host "Reading computersecret"

    try {
        $secureString = Import-Clixml -Path $file

        $cred = New-Object System.Management.Automation.PSCredential ('dummy', $secureString)

        return $cred.GetNetworkCredential().Password
    } catch {
        return $null
    }
}

$APIUrl = "$($Protocol)://$($Server):$($Port)/api/v1.0"

# Request Headers for API calls. The API-Key can only be used for updating a computer if it is an "admin"-apikey. The computer secret is used instead. The secret is retrieved only when creating a new computer, it is not shown afterwards
$Headers = @{
    "Content-Type" = "application/json"
    "X-API-KEY" = $APIToken
}

if (-not $IgnorePackages.IsPresent) {
    $Packages = Start-Choco -command "list" -options "--lo"
}

if (-not $IgnoreFailedPackages.IsPresent) {
    $FailedPackages = Start-Choco -command "Failed"
}

if (-not $IgnoreSources.IsPresent) {
    $Sources = Start-Choco -command "source" | Select-Object SourceName,
                            @{N='SourceURL';E={$_.Url}},
                            @{N='Enabled';E={$_.Enabled}},
                            Priority,
                            @{N='ByPassProxy';E={ if ($_.'Bypass Proxy' -eq "False") { $False } else { $True } } },
                            @{N='SelfService';E={ if ($_.'Self-Service' -eq "False") { $False } else { $True } } },
                            @{N='AdminOnly';E={ if ($_.'Admin Only' -eq "False") { $False } else { $True } } }
}

# Request Body. Contains the computername and all packages which are installed on this computer. Can be used for creating or updating a computer
$Body = @{
    ComputerName = [System.Net.Dns]::GetHostByName($env:COMPUTERNAME).HostName

    #Config = Start-Choco -command "config" | Select-Object -ExpandProperty Settings
    #Features = Start-Choco -command "features"
}

if ($Packages) {
    $Body.Packages = $Packages
}

if ($FailedPackages) {
    $Body.FailedPackages = $FailedPackages
}

if ($Sources) {
    $Body.Sources = $Sources
}

# Where the secret computer key is stored
$baseDir = Join-Path $env:ProgramData "ChocoStatClient"
$keyfile = Join-Path $baseDir "secret.xml"

$BasicRestSplat = @{
	TimeoutSec = 10
	Headers = $Headers
}

if ($SkipCertificateCheck.IsPresent) {

    if ($PSVersionTable.PSVersion -gt [version]"6.0") {
        $BasicRestSplat.SkipCertificateCheck = $True
    } else {
        if (-not ([System.Management.Automation.PSTypeName]'ServerCertificateValidationCallback').Type) {
            $certCallback = @"
            using System;
            using System.Net;
            using System.Net.Security;
            using System.Security.Cryptography.X509Certificates;
            public class ServerCertificateValidationCallback
            {
                public static void Ignore()
                {
                    if(ServicePointManager.ServerCertificateValidationCallback ==null)
                    {
                        ServicePointManager.ServerCertificateValidationCallback +=
                            delegate
                            (
                                Object obj,
                                X509Certificate certificate,
                                X509Chain chain,
                                SslPolicyErrors errors
                            )
                            {
                                return true;
                            };
                    }
                }
            }
"@
            Add-Type $certCallback
        }

        [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12;
        [ServerCertificateValidationCallback]::Ignore()
    }
}

# Fetch our own computername from the database

try {
    $ownComputer = ( Invoke-RestMethod @BasicRestSplat -Uri "$APIUrl/computers" -Method GET -ErrorAction SilentlyContinue ) | Where-Object { $_.ComputerName -eq $Body.ComputerName }
} catch {}

if ($ownComputer) {
    # Own computername found. Let's hope the secret matches, or else it gets funny :>

    # Read computer secret (username is the computer id)
    $HashedComputerSecret = Read-ComputerSecret $keyfile

    if ($null -ne $HashedComputerSecret) {
        $ComputerSecretMatch = $False
        try {
            $SecretBody = @{
                Secret = $HashedComputerSecret
            }
            $result = Invoke-RestMethod @BasicRestSplat -Uri "$APIUrl/computers/$($ownComputer.ComputerID)/self" -Method Post -Body ( $SecretBody | ConvertTo-Json) -ErrorAction SilentlyContinue

            $ComputerSecretMatch = $result.Authenticated
        } catch {}

        if ($ComputerSecretMatch) {
            Write-Host "Computer secret matches. This is good. Phew"
            try {
                $result = Invoke-RestMethod @BasicRestSplat -Uri "$APIUrl/computers/$($ownComputer.ComputerID)" -Method PUT -Body ( ($Body + @{ Secret = $HashedComputerSecret }) | ConvertTo-Json)
            } catch {}

            if ($result) {
                Write-Host "Computer was updated"
            } else {
                Write-Error "Computer was not updated. Result was $($result)"
            }
        } else {
            # this is getting funny :>
            if ($Force.IsPresent) {
                Write-Host "Computer secret does not match. Sigh...Let's try to recreate our computer...what can go wrong?"

                Write-Host "Deleting computer with name '$($Body.ComputerName)'"
                try {
                    $result = Invoke-RestMethod @BasicRestSplat -Uri "$APIUrl/computers/$($ownComputer.ComputerID)" -Method Delete -ErrorAction SilentlyContinue
                } catch {}

                if ($result) {
                    Write-Host "Creating new computer with name '$($Body.ComputerName)'"
                    $result = Invoke-RestMethod @BasicRestSplat -Uri "$APIUrl/computers" -Method POST -Body ($Body | ConvertTo-Json)

                    # save the secret back to a file for updating the client later
                    Save-ComputerSecret $keyfile $result.Secret
                }
            } else {
                Write-Host "Computer secret does not match. Use the 'Force'-Parameter and sufficient permissions to create a new computer"
            }
        }
    } else {
        if ($Force.IsPresent) {
            Write-Host "Computersecret not available. Let's try to recreate our computer...what can go wrong?"

            Write-Host "Deleting computer with name '$($Body.ComputerName)'"
            try {
                $result = Invoke-RestMethod @BasicRestSplat -Uri "$APIUrl/computers/$($ownComputer.ComputerID)" -Method Delete -ErrorAction SilentlyContinue
            } catch {}

            if ($result) {
                Write-Host "Creating new computer with name '$($Body.ComputerName)'"
                $result = Invoke-RestMethod @BasicRestSplat -Uri "$APIUrl/computers" -Method POST -Body ($Body | ConvertTo-Json)

                # save the secret back to a file for updating the client later
                Save-ComputerSecret $keyfile $result.Secret
            }
        } else {
            Write-Host "Computer secret was not found. Use the 'Force'-Parameter and sufficient permissions to create a new computer"
        }
    }

} else {
    # No computer for our DNS-Name found. Create a new one

    Write-Host "Creating new computer with name '$($Body.ComputerName)'"
    try {
        $result = Invoke-RestMethod @BasicRestSplat -Uri "$APIUrl/computers" -Method POST -Body ($Body | ConvertTo-Json)
    } catch {
        Write-Error $_
        return
    }

    # save the secret back to a file for updating the client later
    Save-ComputerSecret $keyfile $result.Secret
}
