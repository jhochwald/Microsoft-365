<#
      This is slightly modified from Microsoft Graph scripts located at:
      https://github.com/microsoftgraph/powershell-intune-samples/

      You must specify two variables:
      1. The full path to the JSON file for import under the $ImportPath varaible
      e.g. C:\Intune\AppProtection-iOS.json
      2. The admin user account who can authenticate to perform the import
      e.g. intuneadmin@itpromentor.com

      Copyright (c) Microsoft Corporation. All rights reserved. Licensed under the MIT license.
      See LICENSE in the project root for license information.
#> 
[CmdletBinding()]

Param (
   $ImportPath,
   $User
)

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

Function Test-JSON()
{
   <#
         .SYNOPSIS
         This function is used to test if the JSON passed to a REST Post request is valid

         .DESCRIPTION
         The function tests if the JSON passed to the REST Post is valid

         .EXAMPLE
         Test-JSON -JSON $JSON
         Test if the JSON is valid before calling the Graph REST interface

         .NOTES
         NAME: Test-JSON
   #>
   [CmdletBinding()]
   param (
      $JSON
   )

   try 
   {
      $TestJSON = ConvertFrom-Json -InputObject $JSON -ErrorAction Stop
      $validJson = $true
   }
   catch 
   {
      $validJson = $false
      $_.Exception
   }

   if (!$validJson)
   {
      Write-Host -Object "Provided JSON isn't in valid JSON format" -ForegroundColor Red
      break
   }
}

Function Add-ManagedAppPolicy()
{
   <#
         .SYNOPSIS
         This function is used to add an Managed App policy using the Graph API REST interface

         .DESCRIPTION
         The function connects to the Graph API Interface and adds a Managed App policy

         .EXAMPLE
         Add-ManagedAppPolicy -JSON $JSON
         Adds a Managed App policy in Intune

         .NOTES
         NAME: Add-ManagedAppPolicy
   #>
   [cmdletbinding()]

   param
   (
      $JSON
   )

   $graphApiVersion = 'Beta'
   $Resource = 'deviceAppManagement/managedAppPolicies'

   try 
   {
      if($JSON -eq '' -or $JSON -eq $null)
      {
         Write-Host -Object 'No JSON specified, please specify valid JSON for a Managed App Policy...' -ForegroundColor Red
      }
      else 
      {
         Test-JSON -JSON $JSON
         $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)"
         Invoke-RestMethod -Uri $uri -Headers $authToken -Method Post -Body $JSON -ContentType 'application/json'
      }
   }
   catch 
   {
      Write-Host
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

if ($ImportPath -eq $null -or $ImportPath -eq '') 
{
   $ImportPath = Read-Host -Prompt 'Please specify a path to a JSON file to import data from e.g. C:\IntuneOutput\Policies\policy.json'
}

# Replacing quotes for Test-Path
$ImportPath = $ImportPath.replace('"','')

if(!(Test-Path -Path "$ImportPath"))
{
   Write-Host -Object "Import Path for JSON file doesn't exist..." -ForegroundColor Red
   Write-Host -Object "Script can't continue..." -ForegroundColor Red
   Write-Host

   break
}

$JSON_Data = Get-Content -Path "$ImportPath"

# Excluding entries that are not required - id,createdDateTime,lastModifiedDateTime,version
$JSON_Convert = $JSON_Data | ConvertFrom-Json | Select-Object -Property * -ExcludeProperty id, createdDateTime, lastModifiedDateTime, version, '@odata.context', apps@odata.context, deployedAppCount
$JSON_Apps = $JSON_Convert.apps | Select-Object -Property * -ExcludeProperty id, version
$JSON_Convert | Add-Member -MemberType NoteProperty -Name 'apps' -Value @($JSON_Apps) -Force
$DisplayName = $JSON_Convert.displayName
$JSON_Output = $JSON_Convert | ConvertTo-Json -Depth 5
            
Write-Host
Write-Host -Object "App Protection Policy '$DisplayName' Found..." -ForegroundColor Cyan
Write-Host

$JSON_Output

Write-Host
Write-Host -Object "Adding App Protection Policy '$DisplayName'" -ForegroundColor Yellow

Add-ManagedAppPolicy -JSON $JSON_Output
