<#
      .COPYRIGHT
      Copyright (c) Microsoft Corporation. All rights reserved. Licensed under the MIT license.
      See LICENSE in the project root for license information.
#>

####################################################

function Get-AuthToken 
{
   <#
         .SYNOPSIS
         This function is used to authenticate with the Graph API REST interface

         .DESCRIPTION
         The function authenticate with the Graph API Interface with the tenant name

         .EXAMPLE
         Get-AuthToken
         Authenticates you with the Graph API interface

         .NOTES
         NAME: Get-AuthToken
   #>
   [cmdletbinding()]

   param
   (
      [Parameter(Mandatory,HelpMessage = 'Add help message for user')]
      $User
   )

   $userUpn = New-Object -TypeName 'System.Net.Mail.MailAddress' -ArgumentList $User
   $tenant = $userUpn.Host

   Write-Host -Object 'Checking for AzureAD module...'

   $AadModule = Get-Module -Name 'AzureAD' -ListAvailable

   if ($AadModule -eq $null) 
   {
      Write-Host -Object 'AzureAD PowerShell module not found, looking for AzureADPreview'
      $AadModule = Get-Module -Name 'AzureADPreview' -ListAvailable
   }

   if ($AadModule -eq $null) 
   {
      Write-Host
      Write-Host -Object 'AzureAD Powershell module not installed...' -ForegroundColor Red
      Write-Host -Object "Install by running 'Install-Module AzureAD' or 'Install-Module AzureADPreview' from an elevated PowerShell prompt" -ForegroundColor Yellow
      Write-Host -Object "Script can't continue..." -ForegroundColor Red
      Write-Host

      exit
   }

   # Getting path to ActiveDirectory Assemblies
   # If the module count is greater than 1 find the latest version
   if($AadModule.count -gt 1)
   {
      $Latest_Version = ($AadModule | Select-Object -Property version | Sort-Object)[-1]
      $AadModule = $AadModule | Where-Object -FilterScript {
         $_.version -eq $Latest_Version.version 
      }

      # Checking if there are multiple versions of the same module found
      if($AadModule.count -gt 1)
      {
         $AadModule = $AadModule | Select-Object -Unique
      }

      $adal = Join-Path -Path $AadModule.ModuleBase -ChildPath 'Microsoft.IdentityModel.Clients.ActiveDirectory.dll'
      $adalforms = Join-Path -Path $AadModule.ModuleBase -ChildPath 'Microsoft.IdentityModel.Clients.ActiveDirectory.Platform.dll'
   }
   else 
   {
      $adal = Join-Path -Path $AadModule.ModuleBase -ChildPath 'Microsoft.IdentityModel.Clients.ActiveDirectory.dll'
      $adalforms = Join-Path -Path $AadModule.ModuleBase -ChildPath 'Microsoft.IdentityModel.Clients.ActiveDirectory.Platform.dll'
   }

   $null = [Reflection.Assembly]::LoadFrom($adal)
   $null = [Reflection.Assembly]::LoadFrom($adalforms)
   $clientId = 'd1ddf0e4-d672-4dae-b554-9d5bdfd93547'
   $redirectUri = 'urn:ietf:wg:oauth:2.0:oob'
   $resourceAppIdURI = 'https://graph.microsoft.com'
   $authority = "https://login.microsoftonline.com/$tenant"

   try 
   {
      $authContext = New-Object -TypeName 'Microsoft.IdentityModel.Clients.ActiveDirectory.AuthenticationContext' -ArgumentList $authority

      # https://msdn.microsoft.com/en-us/library/azure/microsoft.identitymodel.clients.activedirectory.promptbehavior.aspx
      # Change the prompt behaviour to force credentials each time: Auto, Always, Never, RefreshSession
      $platformParameters = New-Object -TypeName 'Microsoft.IdentityModel.Clients.ActiveDirectory.PlatformParameters' -ArgumentList 'Auto'
      $userId = New-Object -TypeName 'Microsoft.IdentityModel.Clients.ActiveDirectory.UserIdentifier' -ArgumentList ($User, 'OptionalDisplayableId')
      $authResult = $authContext.AcquireTokenAsync($resourceAppIdURI,$clientId,$redirectUri,$platformParameters,$userId).Result

      # If the accesstoken is valid then create the authentication header
      if($authResult.AccessToken)
      {
         # Creating header for Authorization token
         $authHeader = @{
            'Content-Type' = 'application/json'
            'Authorization' = 'Bearer ' + $authResult.AccessToken
            'ExpiresOn'   = $authResult.ExpiresOn
         }

         return $authHeader
      }
      else 
      {
         Write-Host
         Write-Host -Object 'Authorization Access Token is null, please re-run authentication...' -ForegroundColor Red
         Write-Host

         break
      }
   }
   catch 
   {
      Write-Host -Object $_.Exception.Message -ForegroundColor Red
      Write-Host -Object $_.Exception.ItemName -ForegroundColor Red
      Write-Host

      break
   }
}

Function Get-ManagedAppPolicy()
{
   <#
         .SYNOPSIS
         This function is used to get managed app policies from the Graph API REST interface

         .DESCRIPTION
         The function connects to the Graph API Interface and gets any managed app policies

         .EXAMPLE
         Get-ManagedAppPolicy
         Returns any managed app policies configured in Intune

         .NOTES
         NAME: Get-ManagedAppPolicy
   #>
   [cmdletbinding()]

   param
   (
      $Name
   )

   $graphApiVersion = 'Beta'
   $Resource = 'deviceAppManagement/managedAppPolicies'

   try 
   {
      if($Name)
      {
         $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)"
         (Invoke-RestMethod -Uri $uri -Headers $authToken -Method Get).Value | Where-Object -FilterScript {
            ($_.'displayName').contains("$Name") 
         }
      }
      else 
      {
         $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)"
         (Invoke-RestMethod -Uri $uri -Headers $authToken -Method Get).Value | Where-Object -FilterScript {
            ($_.'@odata.type').contains('ManagedAppProtection') -or ($_.'@odata.type').contains('InformationProtectionPolicy') 
         }
      }
   }
   catch 
   {
      $ex = $_.Exception
      $errorResponse = $ex.Response.GetResponseStream()
      $reader = New-Object -TypeName System.IO.StreamReader -ArgumentList ($errorResponse)
      $reader.BaseStream.Position = 0
      $reader.DiscardBufferedData()
      $responseBody = $reader.ReadToEnd()
      Write-Host -Object "Response content:`n$responseBody" -ForegroundColor Red
      Write-Error -Message "Request to $uri failed with HTTP Status $($ex.Response.StatusCode) $($ex.Response.StatusDescription)"
      Write-Host

      break
   }
}

Function Get-ManagedAppProtection()
{
   <#
         .SYNOPSIS
         This function is used to get managed app protection configuration from the Graph API REST interface

         .DESCRIPTION
         The function connects to the Graph API Interface and gets any managed app protection policy

         .EXAMPLE
         Get-ManagedAppProtection -id $id -OS "Android"
         Returns a managed app protection policy for Android configured in Intune
         Get-ManagedAppProtection -id $id -OS "iOS"
         Returns a managed app protection policy for iOS configured in Intune
         Get-ManagedAppProtection -id $id -OS "WIP_WE"
         Returns a managed app protection policy for Windows 10 without enrollment configured in Intune

         .NOTES
         NAME: Get-ManagedAppProtection
   #>
   [cmdletbinding()]

   param
   (
      [Parameter(Mandatory,HelpMessage = 'Add help message for user')]
      $id,
      [Parameter(Mandatory,HelpMessage = 'Add help message for user')]
      [ValidateSet('Android','iOS','WIP_WE','WIP_MDM')]
      $OS    
   )

   $graphApiVersion = 'Beta'

   try 
   {
      if($id -eq '' -or $id -eq $null)
      {
         Write-Host -Object 'No Managed App Policy id specified, please provide a policy id...' -ForegroundColor Red

         break
      }
      else 
      {
         if($OS -eq '' -or $OS -eq $null)
         {
            Write-Host -Object 'No OS parameter specified, please provide an OS. Supported value are Android,iOS,WIP_WE,WIP_MDM...' -ForegroundColor Red
            Write-Host

            break
         }
         elseif($OS -eq 'Android')
         {
            $Resource = "deviceAppManagement/androidManagedAppProtections('$id')/?`$expand=apps"
            $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)"
            Invoke-RestMethod -Uri $uri -Headers $authToken -Method Get
         }
         elseif($OS -eq 'iOS')
         {
            $Resource = "deviceAppManagement/iosManagedAppProtections('$id')/?`$expand=apps"
            $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)"
            Invoke-RestMethod -Uri $uri -Headers $authToken -Method Get
         }
         elseif($OS -eq 'WIP_WE')
         {
            $Resource = "deviceAppManagement/windowsInformationProtectionPolicies('$id')?`$expand=protectedAppLockerFiles,exemptAppLockerFiles,assignments"
            $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)"
            Invoke-RestMethod -Uri $uri -Headers $authToken -Method Get
         }
         elseif($OS -eq 'WIP_MDM')
         {
            $Resource = "deviceAppManagement/mdmWindowsInformationProtectionPolicies('$id')?`$expand=protectedAppLockerFiles,exemptAppLockerFiles,assignments"
            $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)"
            Invoke-RestMethod -Uri $uri -Headers $authToken -Method Get
         }
      }
   }
   catch 
   {
      $ex = $_.Exception
      $errorResponse = $ex.Response.GetResponseStream()
      $reader = New-Object -TypeName System.IO.StreamReader -ArgumentList ($errorResponse)
      $reader.BaseStream.Position = 0
      $reader.DiscardBufferedData()
      $responseBody = $reader.ReadToEnd()
      Write-Host -Object "Response content:`n$responseBody" -ForegroundColor Red
      Write-Error -Message "Request to $uri failed with HTTP Status $($ex.Response.StatusCode) $($ex.Response.StatusDescription)"
      Write-Host

      break
   }
}

Function Export-JSONData()
{
   <#
         .SYNOPSIS
         This function is used to export JSON data returned from Graph

         .DESCRIPTION
         This function is used to export JSON data returned from Graph

         .EXAMPLE
         Export-JSONData -JSON $JSON
         Export the JSON inputted on the function

         .NOTES
         NAME: Export-JSONData
   #>
   [CmdletBinding()]
   param (
      $JSON,
      $ExportPath
   )

   try 
   {
      if($JSON -eq '' -or $JSON -eq $null)
      {
         Write-Host -Object 'No JSON specified, please specify valid JSON...' -ForegroundColor Red
      }
      elseif(!$ExportPath)
      {
         Write-Host -Object 'No export path parameter set, please provide a path to export the file' -ForegroundColor Red
      }
      elseif(!(Test-Path -Path $ExportPath))
      {
         Write-Host -Object "$ExportPath doesn't exist, can't export JSON Data" -ForegroundColor Red
      }
      else 
      {
         $JSON1 = ConvertTo-Json -InputObject $JSON -Depth 5
         $JSON_Convert = $JSON1 | ConvertFrom-Json
         $displayName = $JSON_Convert.displayName

         # Updating display name to follow file naming conventions - https://msdn.microsoft.com/en-us/library/windows/desktop/aa365247%28v=vs.85%29.aspx
         $displayName = $displayName -replace '\<|\>|:|"|/|\\|\||\?|\*', '_'
         $Properties = ($JSON_Convert | Get-Member | Where-Object -FilterScript {
               $_.MemberType -eq 'NoteProperty' 
         }).Name
         $FileName_JSON = "$displayName" + '_' + $(Get-Date -Format dd-MM-yyyy-H-mm-ss) + '.json'

         Write-Host 'Export Path:' "$ExportPath"

         $JSON1 | Set-Content -LiteralPath "$ExportPath\$FileName_JSON"

         Write-Host -Object "JSON created in $ExportPath\$FileName_JSON..." -ForegroundColor cyan
      }
   }
   catch 
   {
      $_.Exception
   }
}

#region Authentication
Write-Host

# Checking if authToken exists before running authentication
if($global:authToken)
{
   # Setting DateTime to Universal time to work in all timezones
   $DateTime = (Get-Date).ToUniversalTime()

   # If the authToken exists checking when it expires
   $TokenExpires = ($authToken.ExpiresOn.datetime - $DateTime).Minutes

   if($TokenExpires -le 0)
   {
      Write-Host 'Authentication Token expired' $TokenExpires 'minutes ago' -ForegroundColor Yellow
      Write-Host

      # Defining User Principal Name if not present
      if($User -eq $null -or $User -eq '')
      {
         $User = Read-Host -Prompt 'Please specify your user principal name for Azure Authentication'

         Write-Host
      }

      $global:authToken = Get-AuthToken -User $User
   }
}
else 
{
   # Authentication doesn't exist, calling Get-AuthToken function
   if($User -eq $null -or $User -eq '')
   {
      $User = Read-Host -Prompt 'Please specify your user principal name for Azure Authentication'

      Write-Host
   }

   # Getting the authorization token
   $global:authToken = Get-AuthToken -User $User
}
#endregion

$ExportPath = Read-Host -Prompt 'Please specify a path to export the policy data to e.g. C:\IntuneOutput'

# If the directory path doesn't exist prompt user to create the directory
if(!(Test-Path -Path "$ExportPath"))
{
   Write-Host
   Write-Host -Object "Path '$ExportPath' doesn't exist, do you want to create this directory? Y or N?" -ForegroundColor Yellow

   $Confirm = Read-Host

   if($Confirm -eq 'y' -or $Confirm -eq 'Y')
   {
      $null = New-Item -ItemType Directory -Path "$ExportPath"

      Write-Host
   }
   else 
   {
      Write-Host -Object 'Creation of directory path was cancelled...' -ForegroundColor Red
      Write-Host

      break
   }
}

Write-Host
Write-Host -Object 'Running query against Microsoft Graph for App Protection Policies' -ForegroundColor Yellow

$ManagedAppPolicies = Get-ManagedAppPolicy | Where-Object -FilterScript {
   ($_.'@odata.type').contains('ManagedAppProtection') 
}

Write-Host

if($ManagedAppPolicies)
{
   foreach($ManagedAppPolicy in $ManagedAppPolicies)
   {
      Write-Host 'Managed App Policy:'$ManagedAppPolicy.displayName -ForegroundColor Cyan

      if($ManagedAppPolicy.'@odata.type' -eq '#microsoft.graph.androidManagedAppProtection')
      {
         $AppProtectionPolicy = Get-ManagedAppProtection -id $ManagedAppPolicy.id -OS 'Android'
         $AppProtectionPolicy | Add-Member -MemberType NoteProperty -Name '@odata.type' -Value '#microsoft.graph.androidManagedAppProtection'
         $AppProtectionPolicy
         Export-JSONData -JSON $AppProtectionPolicy -ExportPath "$ExportPath"
      }
      elseif($ManagedAppPolicy.'@odata.type' -eq '#microsoft.graph.iosManagedAppProtection')
      {
         $AppProtectionPolicy = Get-ManagedAppProtection -id $ManagedAppPolicy.id -OS 'iOS'
         $AppProtectionPolicy | Add-Member -MemberType NoteProperty -Name '@odata.type' -Value '#microsoft.graph.iosManagedAppProtection'
         $AppProtectionPolicy
         Export-JSONData -JSON $AppProtectionPolicy -ExportPath "$ExportPath"
      }

      Write-Host
   }
}
