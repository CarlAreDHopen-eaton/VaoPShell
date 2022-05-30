# VaoPShell
VAO API PowerShell Script Module
This PowerShell Script Module allows interaction with Video Servers that supports the VAI API (https://vao.docs.apiary.io/) 

# Installation
- Open the **C:\Windows\System32\WindowsPowerShell\v1.0\Modules** folder
- Make a new folder named VAOModule
- Copy VAOModule.psm1 to the VAOModule folder
- Start a new PowerShell terminal window.

# Functions
- Get-CameraList - Gets a list of cameras avaliable from the video server.
- Get-Camera - Gets information about a single cameras from the video server.
- Invoke-CameraToMonitor - Selects a camera(input) to a monitor(output)

# Example
Get information about camera number **1** using the **Get-Camera** function.
![image](https://user-images.githubusercontent.com/14876765/170988708-7de440cb-cda1-456b-b3a2-dce941b5f044.png)

