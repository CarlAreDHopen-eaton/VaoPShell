# ------------------------------------------------------------------------------------------------------------------------
# VAO PowerShell Module
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

function Get-CameraList
{
    param(
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
  
    Invoke-RestMethod -Method 'GET' -Uri $url -headers $headers
}

function Invoke-CameraToMonitor
{
    param(
         [Parameter(Mandatory=$true)]
         [string]$RemoteHost,
         [Parameter(Mandatory=$true)]
         [string]$User,
         [Parameter(Mandatory=$true)]
         [string]$Password,
         [Parameter(Mandatory=$true)]
         [int]$CameraNumber,
         [Parameter(Mandatory=$true)]
         [int]$MonitorNumber,
         [Parameter()]
         [int]$RemotePort = 444,
         [Parameter()]
         [switch]$Secure = $false,
         [Parameter()]
         [switch]$IgnoreCertificarteErrors = $false
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

function Get-Camera
{
    param(
         [Parameter(Mandatory=$true)]
         [string]$RemoteHost,
         [Parameter(Mandatory=$true)]
         [string]$User,
         [Parameter(Mandatory=$true)]
         [string]$Password,
         [Parameter(Mandatory=$true)]
         [int]$CameraNumber,
         [Parameter()]
         [int]$RemotePort = 444,
         [Parameter()]
         [switch]$Secure = $false,
         [Parameter()]
         [switch]$IgnoreCertificarteErrors = $false
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
Export-ModuleMember -Function Get-CameraList
Export-ModuleMember -Function Get-Camera
Export-ModuleMember -Function Invoke-CameraToMonitor
