# VaoPShell
VAO API PowerShell Script Module
This PowerShell Script Module allows interaction with Video Servers that supports the VAO REST API (https://vao.docs.apiary.io/).
The primary function of the VAO API is to get and control cameras.

# Installation
Installation requires administrative rights.
- Open the **C:\Windows\System32\WindowsPowerShell\v1.0\Modules** folder
- Make a new folder named VAOModule
- Copy VAOModule.psm1 to the VAOModule folder

# Usage
- Start a new PowerShell terminal window.
- May need to use Set-ExecutionPolicy command (administrative rights required)
- Use any of the functions listed below. 

# Functions
- **Camera Functions**
  - Get-VaoCameraList - Gets the list of avaliable cameras the user has access to.
  - Get-VaoCamera     - Gets information about a cameras.
  - Rename-VaoCamera  - Sets the name of a camera
- **Preset Functions**
  - Get-VaoCameraPresetList - Gets the list of preset positions on a camera.
  - Get-VaoCameraPreset - Gets information about a camera preset positon.
  - Invoke-VaoCameraPreset - Changes the position of the camera to the specified preset postion.
  - Rename-VaoCameraPreset - Changes the name of the preset position.
  - Add-VaoCameraPreset - Add a preset position.
  - Remove-VaoCameraPreset - Removes/deletes a preset position.
- **Monitor functions**
  - Get-VaoCameraOnMonitor  - Get the current camera on the specified monitor.
  - Invoke-VaoCameraToMonitor - Selects the specified camera to the specified monitor.
- **Other functions**
  - Get-VaoStatusMessages  - Gets the status messages
- **Download functions**
  - Start-VaoVideoDownload - Starts downloading a recording from a HVR
- **Information functions**
  - Get-VaoApiVersion - Gets the API version 
  - Get-VaoVendorVersion - Gets the vendor information and version
- **Support functions**
  - Set-VaoAuthentication - Sets the authentication details to the current enviroment settings using a URI 
  - Get-VaoAuthentication - Gets the authentication details from the current enviroment settings and pipes these into one of the other functions.

# Example
Get information about camera number **1** using the **Get-VaoCamera** function.
![image](https://user-images.githubusercontent.com/14876765/170988708-7de440cb-cda1-456b-b3a2-dce941b5f044.png)

Example of using envirment variable for API connection
![image](https://github.com/user-attachments/assets/d6e715aa-fab6-49c2-a073-a67bd7dc16a0)

