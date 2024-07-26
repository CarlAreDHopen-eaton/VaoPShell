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

function Get-VaoApiVersion
{
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

        # Connection specific parameters
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

function Start-VaoVideoDownload {
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
        [int]$CameraNumber,
        [Parameter(Mandatory=$true)]
        [string]$Stream,
        [Parameter(Mandatory=$true)]
        [string]$Start,
        [Parameter(Mandatory=$true)]
        [string]$Duration
    )

    if ($CameraNumber -le 0) {
        throw "CameraNumber must be larger than zero."
    }

    #Invoke-VaoVideoDownload -RemoteHost 192.168.101.150 -User Service -Password Default333 -RemotePort 4433 -Secure -IgnoreCertificarteErrors -CameraNumber 7 -Stream 1 -RecorderAddress 1
    $cameraRecorders = Get-VaoCameraRecorders -RemoteHost 192.168.101.150 -User Service -Password Default333 -RemotePort 4433 -Secure -IgnoreCertificarteErrors -CameraNumber 1 

    $foundRecorder = $false
    $recorderAddress = ""

    # Iterate through each recording to find the recorder.
    foreach ($recording in $jsonResponse) {
        if ($recording.stream -eq $Stream)
        {
            $foundRecorder = $true;
            $recorderAddress = $recording.recorderAddress;
            #Skipping test on $recording.recordingLimit
            break
        }
    }

    if ($foundRecorder -eq $false)
    {
        return;
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

    #TODO start checking status messages to see when the download is ready for download.    
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
        [string]$Password
    )

    $authenticationInfo = [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes("$User`:$Password"))    
    $headers = @{"X-Requested-With"="powershell";"Authorization"="Basic $authenticationInfo"}            
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
Export-ModuleMember -Function Get-VaoCameraRecorders
Export-ModuleMember -Function Invoke-VaoCameraToMonitor
Export-ModuleMember -Function Invoke-VaoCameraPreset
Export-ModuleMember -Function Rename-VaoCamera
Export-ModuleMember -Function Rename-VaoCameraPreset
Export-ModuleMember -Function Add-VaoCameraPreset
Export-ModuleMember -Function Remove-VaoCameraPreset
Export-ModuleMember -Function Invoke-VaoVideoDownload
