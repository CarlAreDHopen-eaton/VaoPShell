# VaoPShell
VAO API PowerShell Script Module
This PowerShell Script Module allows interaction with Video Servers that supports the VAI REST API (https://vao.docs.apiary.io/)
The primary function of the API is to get and control cameras.

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
- Get-CameraList - Gets a list of cameras avaliable from the video server.
- Get-Camera - Gets information about a single cameras from the video server.
- Invoke-CameraToMonitor - Selects a camera to a monitor
- Get-VaoApiVersion - Gets the API version 
- Set-CameraName - Sets the name of a camera

# Example
Get information about camera number **1** using the **Get-Camera** function.
![image](https://user-images.githubusercontent.com/14876765/170988708-7de440cb-cda1-456b-b3a2-dce941b5f044.png)
