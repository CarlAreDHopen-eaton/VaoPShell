# ------------------------------------------------------------------------------------------------------------------------
# VAO PowerShell Module 
#
# API documentation: https://github.com/CarlAreDHopen-eaton/VaoPShell
# ------------------------------------------------------------------------------------------------------------------------
# Installation:
# ------------------------------------------------------------------------------------------------------------------------
#   - Open the following folder: C:\Windows\System32\WindowsPowerShell\v1.0\Modules
#   - Make a folder named VAOModule
#   - Copy VAOModule.psm1 to the VAOModule folder
#   - Start a new PowerShell terminal window.
#   - Use the exported functions.
#
# ------------------------------------------------------------------------------------------------------------------------

# ------------------------------------------------------------------------------------------------------------------------
# Exported functions
# ------------------------------------------------------------------------------------------------------------------------

<#
.SYNOPSIS
   Parses a URL to extract Vao parameters and pipes them to the next method.
.DESCRIPTION
   The Invoke-VaoFromUrl function takes a URL as input, parses the URL to extract Vao-related parameters,
   and returns these parameters in a hashtable for piping to the next method.
.PARAMETER Url
   The URL containing Vao-related parameters.
.EXAMPLE
   $params = Invoke-VaoFromUrl -Url "https://user:pass@remotehost:444?IgnoreCertificarteErrors=true"
   Start-VaoVideoDownload @params
#>
function Invoke-VaoFromUrl {
    param(
        [Parameter(Mandatory=$true)]
        [string]$Url
    )

    $uri = [System.Uri]::new($Url)
    
    # Determine if the connection is secure based on the scheme
    $Secure = $uri.Scheme -eq "https"

    # Extract user info (username and password)
    $userInfo = $uri.UserInfo.Split(':')
    $User = $userInfo[0]
    $Password = $userInfo[1]

    # Extract host and port
    $RemoteHost = $uri.Host
    $RemotePort = if ($uri.Port -ne -1) { $uri.Port } else { 444 }


    # Manually parse the query string parameters
    $queryParameters = @{}
    if ($uri.Query) {
        $queryString = $uri.Query.TrimStart('?')
        $pairs = $queryString.Split('&')
        foreach ($pair in $pairs) {
            $kv = $pair.Split('=')
            $key = $kv[0]
            $value = if ($kv.Count -gt 1) { $kv[1] } else { $true }
            $queryParameters[$key] = $value
        }
    }
    $ignorCert = if ($queryParameters["IgnoreCertificarteErrors"]) { $true } else { $false }

    $params = [PSCustomObject]@{
        RemoteHost = $RemoteHost
        User = $User
        Password = $Password
        RemotePort = $RemotePort
        Secure = $Secure
        IgnoreCertificarteErrors = $ignorCert
    }

    return $params
}

<#
.SYNOPSIS
   Sets the HERNIS FLEX REST API authentication URL in the environment variables.
.DESCRIPTION
   The Set-VaoAuthentication function stores the URL containing authentication details into the user's environment variables. 
   This allows other API functions to retrieve and use these details for authentication when interacting with the API.
.PARAMETER Url
   The URL containing authentication details (e.g., username, password, host, port, etc.).
.EXAMPLE
   Set-VaoAuthentication -Url "https://user:pass@remotehost:444?IgnoreCertificarteErrors=true"
   This example sets the VAO URL with the specified authentication details into the user's environment variables.
.NOTES
   The stored URL is set in the user's environment variables under the key "VAO_URL". 
   Other functions in the VAO PowerShell module can retrieve this URL to perform authenticated requests to the VAO API.
#>
function Set-VaoAuthentication {
    param(
        [Parameter(Mandatory=$true)]
        [string]$Url
    )

    [System.Environment]::SetEnvironmentVariable("VAO_URL", $Url, [System.EnvironmentVariableTarget]::User)    
}

<#
.SYNOPSIS
   Retrieves the HERNIS FLEX REST API authentication URL from the environment variables.
.DESCRIPTION
   The Get-VaoAuthentication function fetches the URL containing authentication details from the user's environment variables. 
   This URL is used by other API functions for authentication when interacting with the API.
.EXAMPLE
   Get-VaoAuthentication | Get-VaoCameraList
   This example retrieves the VAO URL with the authentication details and pipes it into the Get-VaoCameraList function to
   fetch the list of cameras using the authenticated URL.
.NOTES
   The URL is retrieved from the user's environment variables under the key "VAO_URL". 
   Other functions in the VAO PowerShell module can use this URL to perform authenticated requests to the VAO API.
#>
function Get-VaoAuthentication {
    # Retrieve the URL from the environment variable
    $url = [System.Environment]::GetEnvironmentVariable("VAO_URL", [System.EnvironmentVariableTarget]::User)

    if (-not $url) {
        Write-Error "The FLEX REST API authentication details has not been loaded into the enviroment settings"
        return
    }

    # Use the URL as input for other commands
    return  Invoke-VaoFromUrl -Url $url
}

<#
.SYNOPSIS
   Initiates download of video footage from the HERNIS FLEX system.
.DESCRIPTION
   The Start-VaoVideoDownload function starts the process of downloading video footage from the HERNIS FLEX system. 
   The function allows specifying parameters such as camera, start time, and duration to retrieve the desired footage.
.PARAMETER CameraNumber
   The camera number of the camera from which the video footage will be downloaded.
.PARAMETER StartTime
   The start time of the video footage to be downloaded, specified in ISO 8601 date-time format.
   For example:
   - "yyyy-MM-dd HH:mm:ss" (e.g., "2024-07-25 13:30:00")
.PARAMETER Duration
   The duration of the video footage to be downloaded max 1 hour, specified in ISO 8601 duration format.
   For example:
   - "PT60S" for 60 seconds
   - "PT30M" for 30 minutes
   - "PT1H" for 1 hour
.PARAMETER DestinationPath
   The path where the downloaded video footage will be saved.
.PARAMETER FtpUser
   The username for FTP access to the HERNIS FLEX system.
.PARAMETER FtpPassword
   The password for FTP access to the HERNIS FLEX system.
.EXAMPLE
   Start-VaoVideoDownload -CameraNumber 1 -StartTime "2024-07-25 13:30:00" -Duration "PT30M" -DestinationPath "C:\Download" -FtpUser username -FtpPassword password
   This example initiates the download of video footage from camera 1 starting at 1:30 PM on July 25, 2024, for a duration of 30 minutes, and saves the footage to "C:\Download".
.NOTES
   Ensure that the specified destination path has write permissions and enough space to store the downloaded video footage.
   The function require atleast API version 1.1 (FLEX 6.5.1.0 or higher)
   The function interacts with the HERNIS FLEX REST API to fetch the video footage and save it locally.
#>
function Start-VaoVideoDownload {
    param(
        # Connection specific parameters
        [Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$true)]
        [string]$RemoteHost,
        [Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$true)]
        [string]$User,
        [Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$true)]
        [string]$Password,
        [Parameter(ValueFromPipelineByPropertyName=$true)]
        [int]$RemotePort = 444,
        [Parameter(ValueFromPipelineByPropertyName=$true)]
        [switch]$Secure = $false,
        [Parameter(ValueFromPipelineByPropertyName=$true)]
        [switch]$IgnoreCertificarteErrors = $false,

        # Function specific parameters
        [Parameter(Mandatory=$true)]
        [int]$CameraNumber,
        [Parameter(Mandatory=$true)]
        [string]$Stream,
        [Parameter(Mandatory=$true)]
        [string]$Start,
        [Parameter(Mandatory=$true)]
        [string]$Duration = "PT10M",
        [Parameter(Mandatory=$false)]
        [string]$FtpUser,
        [Parameter(Mandatory=$true)]
        [string]$FtpPassword,
        [Parameter(Mandatory=$true)]
        [string]$Path)

    process {
        if ($CameraNumber -le 0) {
            throw "CameraNumber must be larger than zero."
        }

        # Check that the API version is at least 1.1 (majorversion.minorversion)
        $apiVersion = Get-VaoApiVersion -RemoteHost $RemoteHost -User $User -Password $Password -RemotePort $RemotePort -Secure:$Secure.IsPresent -IgnoreCertificarteErrors:$IgnoreCertificarteErrors.IsPresent 
        if ($apiVersion.majorversion -lt 1 -or ($apiVersion.majorversion -eq 1 -and $apiVersion.minorversion -lt 1)) {
            Write-Error "API version must be at least 1.1. Current version is $apiVersion"
            return
        }

        # Ensure the local directory exists
        if (!(Test-Path $Path -PathType Container))
        {
            Write-Error "Folder $Path missing"
            return
        }

        $cameraRecorders = Get-VaoCameraRecorders -RemoteHost $RemoteHost -User $User -Password $Password -RemotePort $RemotePort -Secure:$Secure.IsPresent -IgnoreCertificarteErrors:$IgnoreCertificarteErrors.IsPresent -CameraNumber $CameraNumber 

        $foundRecorder = $false
        $recorderAddress = ""

        # Iterate through each recording to find the recorder.
        foreach ($recording in $cameraRecorders) {
            if ($recording.stream -eq $Stream) {
                $foundRecorder = $true
                $recorderAddress = $recording.recorderAddress
                break
            }
        }

        if ($foundRecorder -eq $false) {
            return
        }

        $headers = GetRestHeaders -User $User -Password $Password

        $url = InitRestApiUrl -RemoteHost $RemoteHost -RemotePort $RemotePort -Secure $Secure
        $url += "/inputs/$CameraNumber/downloads"

        $jsonData = @{
            recorderAddress = $recorderAddress
            stream = $Stream
            start = $Start
            duration = $Duration
        } | ConvertTo-Json

        if ($true -eq $IgnoreCertificarteErrors) {
            [System.Net.ServicePointManager]::CertificatePolicy = GetAcceptAllCertificatesPolicyObject
        }

        $result = Invoke-RestMethod -Method 'POST' -Uri $url -headers $headers -Body $jsonData -ContentType "application/json"
        $downloadId = $result.downloadId
        Write-Host "File extraction of file with id $($result.downloadId) started on HVR $recorderAddress"

        Write-Host "Waiting for HVR to complete extraction" -NoNewline
        $maxAttempts = 60 # With 2 second interval about 2 minute wait max.
        $attempt = 0
        $downloadOk = $false
        $downloadUrl = ""
        $fileName = ""

        while ($attempt -lt $maxAttempts) {
            Start-Sleep -Seconds 2
            Write-Host "." -NoNewline

            #TODO consider this.
            $requestDateTime = (Get-Date).AddHours(-3)

            # Format the date and time explicitly using the invariant culture to avoid locale issues
            $formattedDateTime = $requestDateTime.ToString("ddd, dd MMM yyyy HH:mm:ss 'GMT'", [System.Globalization.CultureInfo]::InvariantCulture)

            $messages = Get-VaoStatusMessages -RemoteHost $RemoteHost -User $User -Password $Password -RemotePort $RemotePort -Secure:$Secure.IsPresent -IgnoreCertificarteErrors:$IgnoreCertificarteErrors.IsPresent -IfModifiedSince "$formattedDateTime"

            $downloadOk = $false
            $downloadUrl = ""
            $fileName = ""

            # Iterate through each message to find the downloadId.
            foreach ($message in $messages) {
                if ($message.downloadNotification -ne $null) {
                    if ($message.downloadNotification.downloadId -eq $downloadId) {
                        if ($message.downloadNotification.status -eq "ok") {
                            $downloadUrl = $message.downloadNotification.downloadUrl
                            $fileName = $message.downloadNotification.name
                            $downloadOk = $true
                            break
                        }
                    }
                }
            }

            if ($downloadOk) {
                Write-Host "(Done)"
                break
            }

            $attempt++
        }

        if ($true -eq $downloadOk) {
            Write-Host "File ready for FTP download ($downloadUrl)"
            DownloadFtpFile -FtpUrl $downloadUrl -FtpUser $FtpUser -FtpPassword $FtpPassword -Path $Path -FileName $fileName
        } else {
            Write-Host "(Timeout)"
            Write-Error "Download failed."
        }
    }
}

function Get-VaoCameraRecorders {
    param(
        # Connection specific parameters
        [Parameter(Mandatory=$true)]
        [string]$RemoteHost,
        [Parameter(Mandatory=$true)]
        [string]$User,
        [Parameter(Mandatory=$true)]
        [string]$Password,
        [Parameter()]
        [int]$RemotePort = 444,
        [Parameter()]
        [switch]$Secure = $false,
        [Parameter()]
        [switch]$IgnoreCertificarteErrors = $false,

        # Function specific parameters
        [Parameter(Mandatory=$true)]
        [int]$CameraNumber    )

    if ($CameraNumber -le 0) {
        throw "CameraNumber must be larger than zero."
    }

    $viewerId = New-Guid
    $headers = GetRestHeaders -User $User -Password $Password

    $url = InitRestApiUrl -RemoteHost $RemoteHost -RemotePort $RemotePort -Secure $Secure
    $url += "/inputs/$CameraNumber/recordings"

    $jsonData = @{
        viewerId = $viewerId
    } | ConvertTo-Json
   
    if ($true -eq $IgnoreCertificarteErrors) {
        [System.Net.ServicePointManager]::CertificatePolicy = GetAcceptAllCertificatesPolicyObject
    }

    $result = Invoke-RestMethod -Method 'POST' -Uri $url -headers $headers -Body $jsonData -ContentType "application/json"

    return $result
}

function Get-VaoStatusMessages{
    param(
        # Connection specific parameters
        [Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$true)]
        [string]$RemoteHost,
        [Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$true)]
        [string]$User,
        [Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$true)]
        [string]$Password,
        [Parameter(ValueFromPipelineByPropertyName=$true)]
        [int]$RemotePort = 444,
        [Parameter(ValueFromPipelineByPropertyName=$true)]
        [switch]$Secure = $false,
        [Parameter(ValueFromPipelineByPropertyName=$true)]
        [switch]$IgnoreCertificarteErrors = $false,

        # Function specific parameters
        [Parameter(Mandatory=$false)]
        [string]$IfModifiedSince
    )

    $headers = GetRestHeaders -User $User -Password $Password -IfModifiedSince $IfModifiedSince

    $url = InitRestApiUrl -RemoteHost $RemoteHost -RemotePort $RemotePort -Secure $Secure
    $url += "/status"

    if ($true -eq $IgnoreCertificarteErrors) {
        [System.Net.ServicePointManager]::CertificatePolicy = GetAcceptAllCertificatesPolicyObject
    }

    $result = Invoke-RestMethod -Method 'GET' -Uri $url -headers $headers -ContentType "application/json"

    return $result
}

<#
.SYNOPSIS
   Retrieves the API version information of the HERNIS FLEX REST API
.DESCRIPTION
   The Get-VaoApiVersion function fetches the version of the HERNIS FLEX REST API. 
   This information can be useful for compatibility and troubleshooting purposes.
   Version 1.0 : Supports cameras, camera control, etc.
   Version 1.1 : Supports download.
.EXAMPLE
   Get-VaoApiVersion
   This example retrieves and displays the version information of the HERNIS FLEX REST API.
   Example VaoRApi version 1.1
.EXAMPLE
   Get-VaoApiVersion | Format-Table -Property Version, ReleaseDate
   This example retrieves the API version information and formats the output to display only the version and release date properties in a table.
#>
function Get-VaoApiVersion
{
    param(
        # Connection specific parameters
        [Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$true)]
        [string]$RemoteHost,
        [Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$true)]
        [string]$User,
        [Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$true)]
        [string]$Password,
        [Parameter(ValueFromPipelineByPropertyName=$true)]
        [int]$RemotePort = 444,
        [Parameter(ValueFromPipelineByPropertyName=$true)]
        [switch]$Secure = $false,
        [Parameter(ValueFromPipelineByPropertyName=$true)]
        [switch]$IgnoreCertificarteErrors = $false
    )

    $headers = GetRestHeaders -User $User -Password $Password
    
    $url = InitRestApiUrl -RemoteHost $RemoteHost -RemotePort $RemotePort -Secure $Secure
    $url += "/version/api"
  
    if ($true -eq $IgnoreCertificarteErrors)
    {
        [System.Net.ServicePointManager]::CertificatePolicy = GetAcceptAllCertificatesPolicyObject
    }

    Invoke-RestMethod -Method 'OPTIONS' -Uri $url -headers $headers
    
}

<#
.SYNOPSIS
   Retrieves the version information of the HERNIS FLEX system.
.DESCRIPTION
   The Get-VaoVendorVersion function fetches the version details of the REST Module in the HERNIS FLEX system. 
   This information is useful for ensuring compatibility and for troubleshooting purposes.
.EXAMPLE
   Get-VaoVendorVersion
   This example retrieves and displays the version information of the vendor-specific components in the HERNIS FLEX system.
.EXAMPLE
   Get-VaoVendorVersion | Format-Table -Property ComponentName, Version, ReleaseDate
   This example retrieves the vendor version information and formats the output to display only the component name, version, and release date properties in a table.
#>
function Get-VaoVendorVersion
{
    param(
        # Connection specific parameters
        [Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$true)]
        [string]$RemoteHost,
        [Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$true)]
        [string]$User,
        [Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$true)]
        [string]$Password,
        [Parameter(ValueFromPipelineByPropertyName=$true)]
        [int]$RemotePort = 444,
        [Parameter(ValueFromPipelineByPropertyName=$true)]
        [switch]$Secure = $false,
        [Parameter(ValueFromPipelineByPropertyName=$true)]
        [switch]$IgnoreCertificarteErrors = $false
    )

    $headers = GetRestHeaders -User $User -Password $Password
    
    $url = InitRestApiUrl -RemoteHost $RemoteHost -RemotePort $RemotePort -Secure $Secure
    $url += "/version/implementation"
  
    if ($true -eq $IgnoreCertificarteErrors)
    {
        [System.Net.ServicePointManager]::CertificatePolicy = GetAcceptAllCertificatesPolicyObject
    }

    Invoke-RestMethod -Method 'OPTIONS' -Uri $url -headers $headers    
}

<#
.SYNOPSIS
   Retrieves a list of available cameras from the HERNIS FLEX system.
.DESCRIPTION
   The Get-VaoCameraList function fetches and returns a list of cameras that are registered and available in the HERNIS FLEX system. 
   The list includes details such as camera ID, name, streaming urls, ptz features, etc.
.EXAMPLE
   Get-VaoCameraList
   This example retrieves and displays a list of all available cameras from the HERNIS FLEX system.
.NOTES
   The function interacts with the HERNIS FLEX REST API to fetch the camera list. 
   The list of cameras depends on what camera the current user have access to.   
#>
function Get-VaoCameraList
{
    param(
        # Connection specific parameters
        [Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$true)]
        [string]$RemoteHost,
        [Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$true)]
        [string]$User,
        [Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$true)]
        [string]$Password,
        [Parameter(ValueFromPipelineByPropertyName=$true)]
        [int]$RemotePort = 444,
        [Parameter(ValueFromPipelineByPropertyName=$true)]
        [switch]$Secure = $false,
        [Parameter(ValueFromPipelineByPropertyName=$true)]
        [switch]$IgnoreCertificarteErrors = $false
    )
    
    $headers = GetRestHeaders -User $User -Password $Password
    
    $url = InitRestApiUrl -RemoteHost $RemoteHost -RemotePort $RemotePort -Secure $Secure
    $url += "/inputs"
  
    if ($true -eq $IgnoreCertificarteErrors)
    {
        [System.Net.ServicePointManager]::CertificatePolicy = GetAcceptAllCertificatesPolicyObject
    }

    Invoke-RestMethod -Method 'GET' -Uri $url -headers $headers
}

<#
.SYNOPSIS
   Selects a camera to a specific monitor.
.DESCRIPTION
   The Invoke-VaoCameraToMonitor function selects a specified camera to a designated monitor. 
   This can be used to remote control a monitor in the HERNIS FLEX system.
.PARAMETER CameraNumber
   The camera number on the camera in the HERNIS FLEX System
.PARAMETER MonitorNumber
   The monitor number on the monitor in the HERNIS FLEX System
.EXAMPLE
   Invoke-VaoCameraToMonitor -CameraNumber 1 -MonitorNumber 2
   This example starts streaming live video footage from camera with ID 1 to monitor with ID 2.
.NOTES
   Ensure that the HERNIS FLEX authentication URL is set in the environment variables using the Set-VaoAuthentication function before calling this function.
   The function interacts with the HERNIS FLEX REST API to manage video streams and monitor displays.
#>
function Invoke-VaoCameraToMonitor
{
    param(
        # Connection specific parameters
        [Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$true)]
        [string]$RemoteHost,
        [Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$true)]
        [string]$User,
        [Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$true)]
        [string]$Password,
        [Parameter(ValueFromPipelineByPropertyName=$true)]
        [int]$RemotePort = 444,
        [Parameter(ValueFromPipelineByPropertyName=$true)]
        [switch]$Secure = $false,
        [Parameter(ValueFromPipelineByPropertyName=$true)]
        [switch]$IgnoreCertificarteErrors = $false,

        # Function specific parameters
        [Parameter(Mandatory=$true)]
        [int]$CameraNumber,
        [Parameter(Mandatory=$true)]
        [int]$MonitorNumber
    )    

    $headers = GetRestHeaders -User $User -Password $Password

    $url = InitRestApiUrl -RemoteHost $RemoteHost -RemotePort $RemotePort -Secure $Secure
    $url += "/video-output/" + $MonitorNumber

    $jsonData = "{ ""camera"" : """ + $CameraNumber + """}"

    if ($true -eq $IgnoreCertificarteErrors)
    {
        [System.Net.ServicePointManager]::CertificatePolicy = GetAcceptAllCertificatesPolicyObject
    }

    Invoke-RestMethod -Method 'PUT' -Uri $url -headers $headers -body $jsonData -ContentType "application/json"
}

function Get-VaoCamera
{
    param(
        # Connection specific parameters
        [Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$true)]
        [string]$RemoteHost,
        [Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$true)]
        [string]$User,
        [Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$true)]
        [string]$Password,
        [Parameter(ValueFromPipelineByPropertyName=$true)]
        [int]$RemotePort = 444,
        [Parameter(ValueFromPipelineByPropertyName=$true)]
        [switch]$Secure = $false,
        [Parameter(ValueFromPipelineByPropertyName=$true)]
        [switch]$IgnoreCertificarteErrors = $false,

        # Function specific parameters
        [Parameter(Mandatory=$true)]
        [int]$CameraNumber
    )
                  
    $headers = GetRestHeaders -User $User -Password $Password

    $url = InitRestApiUrl -RemoteHost $RemoteHost -RemotePort $RemotePort -Secure $Secure
    $url += "/inputs/" + $CameraNumber    
    
    if ($true -eq $IgnoreCertificarteErrors)
    {
        [System.Net.ServicePointManager]::CertificatePolicy = GetAcceptAllCertificatesPolicyObject
    }

    Invoke-RestMethod -Method 'GET' -Uri $url -headers $headers
}

function Get-VaoCameraPresetList
{
    param(
        # Connection specific parameters
        [Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$true)]
        [string]$RemoteHost,
        [Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$true)]
        [string]$User,
        [Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$true)]
        [string]$Password,
        [Parameter(ValueFromPipelineByPropertyName=$true)]
        [int]$RemotePort = 444,
        [Parameter(ValueFromPipelineByPropertyName=$true)]
        [switch]$Secure = $false,
        [Parameter(ValueFromPipelineByPropertyName=$true)]
        [switch]$IgnoreCertificarteErrors = $false,

         # Function specific parameters
         [Parameter(Mandatory=$true)]
         [int]$CameraNumber
    )
                  
    $headers = GetRestHeaders -User $User -Password $Password

    $url = InitRestApiUrl -RemoteHost $RemoteHost -RemotePort $RemotePort -Secure $Secure
    $url += "/inputs/$CameraNumber/presets"
    
    if ($true -eq $IgnoreCertificarteErrors)
    {
        [System.Net.ServicePointManager]::CertificatePolicy = GetAcceptAllCertificatesPolicyObject
    }

    Invoke-RestMethod -Method 'GET' -Uri $url -headers $headers
}

function Get-VaoCameraPreset
{
    param(
        # Connection specific parameters
        [Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$true)]
        [string]$RemoteHost,
        [Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$true)]
        [string]$User,
        [Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$true)]
        [string]$Password,
        [Parameter(ValueFromPipelineByPropertyName=$true)]
        [int]$RemotePort = 444,
        [Parameter(ValueFromPipelineByPropertyName=$true)]
        [switch]$Secure = $false,
        [Parameter(ValueFromPipelineByPropertyName=$true)]
        [switch]$IgnoreCertificarteErrors = $false,

        # Function specific parameters
        [Parameter(Mandatory=$true)]
        [int]$CameraNumber,
        [Parameter(Mandatory=$true)]
        [int]$PresetNumber
    )
                  
    $headers = GetRestHeaders -User $User -Password $Password

    $url = InitRestApiUrl -RemoteHost $RemoteHost -RemotePort $RemotePort -Secure $Secure
    $url += "/inputs/$CameraNumber/presets/$PresetNumber"
    
    if ($true -eq $IgnoreCertificarteErrors)
    {
        [System.Net.ServicePointManager]::CertificatePolicy = GetAcceptAllCertificatesPolicyObject
    }

    Invoke-RestMethod -Method 'GET' -Uri $url -headers $headers
}

function Get-VaoCameraOnMonitor
{
    param(
        # Connection specific parameters
        [Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$true)]
        [string]$RemoteHost,
        [Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$true)]
        [string]$User,
        [Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$true)]
        [string]$Password,
        [Parameter(ValueFromPipelineByPropertyName=$true)]
        [int]$RemotePort = 444,
        [Parameter(ValueFromPipelineByPropertyName=$true)]
        [switch]$Secure = $false,
        [Parameter(ValueFromPipelineByPropertyName=$true)]
        [switch]$IgnoreCertificarteErrors = $false,

        # Function specific parameters
        [Parameter(Mandatory=$true)]
        [int]$MonitorNumber
    )
                  
    $headers = GetRestHeaders -User $User -Password $Password

    $url = InitRestApiUrl -RemoteHost $RemoteHost -RemotePort $RemotePort -Secure $Secure
    $url += "/video-output/" + $MonitorNumber    
    
    if ($true -eq $IgnoreCertificarteErrors)
    {
        [System.Net.ServicePointManager]::CertificatePolicy = GetAcceptAllCertificatesPolicyObject
    }

    Invoke-RestMethod -Method 'GET' -Uri $url -headers $headers
}

function Rename-VaoCamera
{
    param(
        # Connection specific parameters
        [Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$true)]
        [string]$RemoteHost,
        [Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$true)]
        [string]$User,
        [Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$true)]
        [string]$Password,
        [Parameter(ValueFromPipelineByPropertyName=$true)]
        [int]$RemotePort = 444,
        [Parameter(ValueFromPipelineByPropertyName=$true)]
        [switch]$Secure = $false,
        [Parameter(ValueFromPipelineByPropertyName=$true)]
        [switch]$IgnoreCertificarteErrors = $false,

        # Function specific parameters
        [Parameter(Mandatory=$true)]
        [int]$CameraNumber,
        [Parameter(Mandatory=$true)]
        [string]$CameraName

   )
                  
    $headers = GetRestHeaders -User $User -Password $Password

    $url = InitRestApiUrl -RemoteHost $RemoteHost -RemotePort $RemotePort -Secure $Secure
    $url += "/inputs/" + $CameraNumber    
    
    if ($true -eq $IgnoreCertificarteErrors)
    {
        [System.Net.ServicePointManager]::CertificatePolicy = GetAcceptAllCertificatesPolicyObject
    }

    $jsonData = "{ ""name"" : """ + $CameraName + """}"

    Invoke-RestMethod -Method 'POST' -Uri $url -headers $headers -body $jsonData -ContentType "application/json"
}

function Add-VaoCameraPreset
{
  param(
        # Connection specific parameters
        [Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$true)]
        [string]$RemoteHost,
        [Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$true)]
        [string]$User,
        [Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$true)]
        [string]$Password,
        [Parameter(ValueFromPipelineByPropertyName=$true)]
        [int]$RemotePort = 444,
        [Parameter(ValueFromPipelineByPropertyName=$true)]
        [switch]$Secure = $false,
        [Parameter(ValueFromPipelineByPropertyName=$true)]
        [switch]$IgnoreCertificarteErrors = $false,

        # Function specific parameters
        [Parameter(Mandatory=$true)]
        [int]$CameraNumber,
        [Parameter(Mandatory=$true)]
        [string]$PresetName
    )

    $headers = GetRestHeaders -User $User -Password $Password

    $url = InitRestApiUrl -RemoteHost $RemoteHost -RemotePort $RemotePort -Secure $Secure
    $url += "/inputs/$CameraNumber/presets"

    $jsonData = "{ ""name"" : """ + $PresetName + """}"

    if ($true -eq $IgnoreCertificarteErrors)
    {
        [System.Net.ServicePointManager]::CertificatePolicy = GetAcceptAllCertificatesPolicyObject
    }

    Invoke-RestMethod -Method 'POST' -Uri $url -headers $headers -body $jsonData -ContentType "application/json"
}

function Rename-VaoCameraPreset
{
    param(
        # Connection specific parameters
        [Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$true)]
        [string]$RemoteHost,
        [Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$true)]
        [string]$User,
        [Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$true)]
        [string]$Password,
        [Parameter(ValueFromPipelineByPropertyName=$true)]
        [int]$RemotePort = 444,
        [Parameter(ValueFromPipelineByPropertyName=$true)]
        [switch]$Secure = $false,
        [Parameter(ValueFromPipelineByPropertyName=$true)]
        [switch]$IgnoreCertificarteErrors = $false,

         # Function specific parameters
        [Parameter(Mandatory=$true)]
        [int]$CameraNumber,
        [Parameter(Mandatory=$true)]
        [int]$PresetNumber,
        [Parameter(Mandatory=$true)]
        [string]$PresetName
    )
                  
    $headers = GetRestHeaders -User $User -Password $Password

    $url = InitRestApiUrl -RemoteHost $RemoteHost -RemotePort $RemotePort -Secure $Secure
    $url += "/inputs/$CameraNumber/presets/$PresetNumber"
    
    if ($true -eq $IgnoreCertificarteErrors)
    {
        [System.Net.ServicePointManager]::CertificatePolicy = GetAcceptAllCertificatesPolicyObject
    }

    $jsonData = "{ ""name"" : """ + $PresetName + """}"

    Invoke-RestMethod -Method 'PUT' -Uri $url -headers $headers -body $jsonData -ContentType "application/json"
}

function Remove-VaoCameraPreset
{
    param(
        # Connection specific parameters
        [Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$true)]
        [string]$RemoteHost,
        [Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$true)]
        [string]$User,
        [Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$true)]
        [string]$Password,
        [Parameter(ValueFromPipelineByPropertyName=$true)]
        [int]$RemotePort = 444,
        [Parameter(ValueFromPipelineByPropertyName=$true)]
        [switch]$Secure = $false,
        [Parameter(ValueFromPipelineByPropertyName=$true)]
        [switch]$IgnoreCertificarteErrors = $false,

        # Function specific parameters
        [Parameter(Mandatory=$true)]
        [int]$CameraNumber,
        [Parameter(Mandatory=$true)]
        [int]$PresetNumber
    )
                  
    $headers = GetRestHeaders -User $User -Password $Password

    $url = InitRestApiUrl -RemoteHost $RemoteHost -RemotePort $RemotePort -Secure $Secure
    $url += "/inputs/$CameraNumber/presets/$PresetNumber"
    
    if ($true -eq $IgnoreCertificarteErrors)
    {
        [System.Net.ServicePointManager]::CertificatePolicy = GetAcceptAllCertificatesPolicyObject
    }

    Invoke-RestMethod -Method 'DELETE' -Uri $url -headers $headers
}

function Invoke-VaoCameraPreset
{
    param(
        # Connection specific parameters
        [Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$true)]
        [string]$RemoteHost,
        [Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$true)]
        [string]$User,
        [Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$true)]
        [string]$Password,
        [Parameter(ValueFromPipelineByPropertyName=$true)]
        [int]$RemotePort = 444,
        [Parameter(ValueFromPipelineByPropertyName=$true)]
        [switch]$Secure = $false,
        [Parameter(ValueFromPipelineByPropertyName=$true)]
        [switch]$IgnoreCertificarteErrors = $false,

        # Function specific parameters
        [Parameter(Mandatory=$true)]
        [int]$CameraNumber,
        [Parameter(Mandatory=$true)]
        [int]$PresetNumber
    )
                  
    $headers = GetRestHeaders -User $User -Password $Password

    $url = InitRestApiUrl -RemoteHost $RemoteHost -RemotePort $RemotePort -Secure $Secure
    $url += "/inputs/$CameraNumber/presets/$PresetNumber"
    
    if ($true -eq $IgnoreCertificarteErrors)
    {
        [System.Net.ServicePointManager]::CertificatePolicy = GetAcceptAllCertificatesPolicyObject
    }

    Invoke-RestMethod -Method 'POST' -Uri $url -headers $headers
}


# ------------------------------------------------------------------------------------------------------------------------
# Private support functions
# ------------------------------------------------------------------------------------------------------------------------

function DownloadFtpFile()
{
    param(
        [Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$true)]
        [string]$FtpUrl,
        [Parameter(Mandatory=$true)]
        [string]$FtpUser,
        [Parameter(Mandatory=$true)]
        [string]$FtpPassword,
        [Parameter(Mandatory=$true)]
        [string]$Path,
        [Parameter(Mandatory=$true)]
        [string]$FileName

    )

    # Prepare the download request
    Write-Host "Downloading ftp file to $Path\$FileName"
    $downloadRequest = [System.Net.FtpWebRequest]::Create($FtpUrl)
    $downloadRequest.Method = [System.Net.WebRequestMethods+Ftp]::DownloadFile
    $credentials = New-Object System.Net.NetworkCredential($FtpUser, $FtpPassword)
    $downloadRequest.Credentials = $credentials
    $downloadRequest.EnableSsl = $true # Enable SSL/TLS

    # Execute the download request
    try {
        $downloadResponse = $downloadRequest.GetResponse()
        $sourceStream = $downloadResponse.GetResponseStream()
        # TODO add handling in case file already exists, for exapmple same way windows do.
        $targetStream = [System.IO.File]::Create("$Path\$FileName")
        $buffer = New-Object byte[] 10240
        while (($read = $sourceStream.Read($buffer, 0, $buffer.Length)) -gt 0)
        {
            $targetStream.Write($buffer, 0, $read)
        }
        Write-Host "Download complete."
    }
    catch {
        Write-Error "Failed to download file: $_"
    }
    finally {
        $targetStream.Dispose()
        $sourceStream.Dispose()
        $downloadResponse.Dispose()
    }
}

function InitRestApiUrl
{
    param(
        [Parameter()]
        [string]$RemoteHost,
        [Parameter()]
        [int]$RemotePort,
        [Parameter()]
        [bool]$Secure = $false
    )        
    if ($true -eq $Secure)
    {
        return "https://" + $RemoteHost + ":" + $RemotePort
    }
    return "http://" + $RemoteHost + ":" + $RemotePort 
}

function GetRestHeaders
{
    param(
        [Parameter(Mandatory=$true)]
        [string]$User,
        [Parameter(Mandatory=$true)]
        [string]$Password,
        [Parameter(Mandatory=$false)]
        [string]$IfModifiedSince
    )

    $authenticationInfo = [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes("$User`:$Password"))    

    # Create the base headers
    $headers = @{
        "X-Requested-With" = "powershell"
        "Authorization" = "Basic $authenticationInfo"
        "Accept" = "application/json"
    }

    # Add the If-Modified-Since header if the parameter is provided
    if (-not [string]::IsNullOrEmpty($IfModifiedSince)) {
        $headers["If-Modified-Since"] = $IfModifiedSince
    }

    return $headers
}

function GetAcceptAllCertificatesPolicyObject
{
   Add-Type @"
   using System.Net;
   using System.Security.Cryptography.X509Certificates;
   
   public class AcceptAllCertificatesPolicy : ICertificatePolicy {
       public AcceptAllCertificatesPolicy() {}
       public bool CheckValidationResult(ServicePoint sPoint, X509Certificate cert, WebRequest wRequest, int certProb) 
       {
           return true;
       }
   }
"@
   return New-Object AcceptAllCertificatesPolicy 
}

# ------------------------------------------------------------------------------------------------------------------------
# Exports
# ------------------------------------------------------------------------------------------------------------------------
Export-ModuleMember -Function Get-VaoCameraList
Export-ModuleMember -Function Get-VaoCamera
Export-ModuleMember -Function Get-VaoCameraPresetList
Export-ModuleMember -Function Get-VaoCameraPreset
Export-ModuleMember -Function Get-VaoCameraOnMonitor
Export-ModuleMember -Function Get-VaoApiVersion
Export-ModuleMember -Function Get-VaoVendorVersion
Export-ModuleMember -Function Invoke-VaoCameraToMonitor
Export-ModuleMember -Function Invoke-VaoCameraPreset
Export-ModuleMember -Function Rename-VaoCamera
Export-ModuleMember -Function Rename-VaoCameraPreset
Export-ModuleMember -Function Add-VaoCameraPreset
Export-ModuleMember -Function Remove-VaoCameraPreset
Export-ModuleMember -Function Invoke-VaoFromUrl
Export-ModuleMember -Function Start-VaoVideoDownload
Export-ModuleMember -Function Get-VaoAuthentication
Export-ModuleMember -Function Set-VaoAuthentication
Export-ModuleMember -Function Get-VaoStatusMessages
Export-ModuleMember -Function Get-VaoCameraRecorders