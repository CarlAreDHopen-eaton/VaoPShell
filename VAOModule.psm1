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

function Set-VaoAuthentication {
    param(
        [Parameter(Mandatory=$true)]
        [string]$Url
    )

    [System.Environment]::SetEnvironmentVariable("VAO_URL", $Url, [System.EnvironmentVariableTarget]::User)
    Write-Host "The FLEX REST API authentication details was loaded into enviroment settings."
}

function Get-VaoAuthentication {
    # Retrieve the URL from the environment variable
    $url = [System.Environment]::GetEnvironmentVariable("VAO_URL", [System.EnvironmentVariableTarget]::User)

    if (-not $url) {
        Write-Host "The FLEX REST API authentication details has not been loaded into the enviroment settings"
        return
    }

    # Use the URL as input for other commands
    return  Invoke-VaoFromUrl -Url $url
}

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
        [string]$Duration
    )

    process {
        if ($CameraNumber -le 0) {
            throw "CameraNumber must be larger than zero."
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

        # TODO Implement a loop to wait 
        Write-Host "Waiting for HVR to complete extraction..."
        Start-Sleep -Seconds 10

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

        if ($true -eq $downloadOk) {
            Write-Host "File ready for FTP download ($downloadUrl)"
        } else {
            Write-Host "Download failed."
        }
    }
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