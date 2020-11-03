
<#
      http://www.scconfigmgr.com/2019/01/17/use-intune-graph-api-export-and-import-intune-admx-templates/
      Version 1.0			 2019 Jan.17 First version
      Version 1.0.1		 2019 Jan.21 Fixed bug enable value was wrong
#>

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
   if ($AadModule.count -gt 1)
   {
      $Latest_Version = ($AadModule | Select-Object -Property version | Sort-Object)[-1]
      $AadModule = $AadModule | Where-Object -FilterScript {
         $_.version -eq $Latest_Version.version 
      }
		
      # Checking if there are multiple versions of the same module found
      if ($AadModule.count -gt 1)
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
      $authResult = $authContext.AcquireTokenAsync($resourceAppIdURI, $clientId, $redirectUri, $platformParameters, $userId).Result
		
      # If the accesstoken is valid then create the authentication header
      if ($authResult.AccessToken)
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

Function Get-GroupPolicyConfigurations()
{
   <#
         .SYNOPSIS
         This function is used to get device configuration policies from the Graph API REST interface

         .DESCRIPTION
         The function connects to the Graph API Interface and gets any device configuration policies

         .EXAMPLE
         Get-DeviceConfigurationPolicy
         Returns any device configuration policies configured in Intune

         .NOTES
         NAME: Get-GroupPolicyConfigurations
   #>
   [cmdletbinding()]
	
   $graphApiVersion = 'Beta'
   $DCP_resource = 'deviceManagement/groupPolicyConfigurations'
	
   try
   {
      $uri = "https://graph.microsoft.com/$graphApiVersion/$($DCP_resource)"
      (Invoke-RestMethod -Uri $uri -Headers $authToken -Method Get).Value
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

Function Get-GroupPolicyConfigurationsDefinitionValues()
{
   <#
         .SYNOPSIS
         This function is used to get device configuration policies from the Graph API REST interface

         .DESCRIPTION
         The function connects to the Graph API Interface and gets any device configuration policies

         .EXAMPLE
         Get-DeviceConfigurationPolicy
         Returns any device configuration policies configured in Intune

         .NOTES
         NAME: Get-GroupPolicyConfigurations
   #>
   [cmdletbinding()]
   Param (
      [Parameter(Mandatory,HelpMessage = 'Add help message for user')]
      [string]$GroupPolicyConfigurationID
   )
	
   $graphApiVersion = 'Beta'
   #$DCP_resource = "deviceManagement/groupPolicyConfigurations/$GroupPolicyConfigurationID/definitionValues?`$filter=enabled eq true"
   $DCP_resource = "deviceManagement/groupPolicyConfigurations/$GroupPolicyConfigurationID/definitionValues"

   try
   {
      $uri = "https://graph.microsoft.com/$graphApiVersion/$($DCP_resource)"
      (Invoke-RestMethod -Uri $uri -Headers $authToken -Method Get).Value
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

Function Get-GroupPolicyConfigurationsDefinitionValuesPresentationValues()
{
   <#
         .SYNOPSIS
         This function is used to get device configuration policies from the Graph API REST interface

         .DESCRIPTION
         The function connects to the Graph API Interface and gets any device configuration policies

         .EXAMPLE
         Get-DeviceConfigurationPolicy
         Returns any device configuration policies configured in Intune

         .NOTES
         NAME: Get-GroupPolicyConfigurations
   #>
   [cmdletbinding()]
   Param (
		
      [Parameter(Mandatory,HelpMessage = 'Add help message for user')]
      [string]$GroupPolicyConfigurationID,
      [string]$GroupPolicyConfigurationsDefinitionValueID
		
   )

   $graphApiVersion = 'Beta'
   $DCP_resource = "deviceManagement/groupPolicyConfigurations/$GroupPolicyConfigurationID/definitionValues/$GroupPolicyConfigurationsDefinitionValueID/presentationValues"
	
   try
   {
      $uri = "https://graph.microsoft.com/$graphApiVersion/$($DCP_resource)"
      (Invoke-RestMethod -Uri $uri -Headers $authToken -Method Get).Value
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

Function Get-GroupPolicyConfigurationsDefinitionValuesdefinition ()
{
   <#
         .SYNOPSIS
         This function is used to get device configuration policies from the Graph API REST interface

         .DESCRIPTION
         The function connects to the Graph API Interface and gets any device configuration policies

         .EXAMPLE
         Get-DeviceConfigurationPolicy
         Returns any device configuration policies configured in Intune

         .NOTES
         NAME: Get-GroupPolicyConfigurations
   #>
   [cmdletbinding()]

   Param (
		
      [Parameter(Mandatory,HelpMessage = 'Add help message for user')]
      [string]$GroupPolicyConfigurationID,
      [Parameter(Mandatory,HelpMessage = 'Add help message for user')]
      [string]$GroupPolicyConfigurationsDefinitionValueID
		
   )

   $graphApiVersion = 'Beta'
   $DCP_resource = "deviceManagement/groupPolicyConfigurations/$GroupPolicyConfigurationID/definitionValues/$GroupPolicyConfigurationsDefinitionValueID/definition"
	
   try
   {
      $uri = "https://graph.microsoft.com/$graphApiVersion/$($DCP_resource)"
      $responseBody = Invoke-RestMethod -Uri $uri -Headers $authToken -Method Get
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

   $responseBody
}

Function Get-GroupPolicyDefinitionsPresentations ()
{
   <#
         .SYNOPSIS
         This function is used to get device configuration policies from the Graph API REST interface

         .DESCRIPTION
         The function connects to the Graph API Interface and gets any device configuration policies

         .EXAMPLE
         Get-DeviceConfigurationPolicy
         Returns any device configuration policies configured in Intune

         .NOTES
         NAME: Get-GroupPolicyConfigurations
   #>
   [cmdletbinding()]

   Param (
      [Parameter(Mandatory,HelpMessage = 'Add help message for user')]
      [string]$groupPolicyDefinitionsID,
      [Parameter(Mandatory,HelpMessage = 'Add help message for user')]
      [string]$GroupPolicyConfigurationsDefinitionValueID
   )

   $graphApiVersion = 'Beta'
   $DCP_resource = "deviceManagement/groupPolicyConfigurations/$groupPolicyDefinitionsID/definitionValues/$GroupPolicyConfigurationsDefinitionValueID/presentationValues?`$expand=presentation"

   try
   {
      $uri = "https://graph.microsoft.com/$graphApiVersion/$($DCP_resource)"
      (Invoke-RestMethod -Uri $uri -Headers $authToken -Method Get).Value.presentation
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

#region Authentication
Write-Host

# Checking if authToken exists before running authentication
if ($global:authToken)
{
   # Setting DateTime to Universal time to work in all timezones
   $DateTime = (Get-Date).ToUniversalTime()
	
   # If the authToken exists checking when it expires
   $TokenExpires = ($authToken.ExpiresOn.datetime - $DateTime).Minutes
	
   if ($TokenExpires -le 0)
   {
      Write-Host 'Authentication Token expired' $TokenExpires 'minutes ago' -ForegroundColor Yellow
      Write-Host
		
      # Defining User Principal Name if not present
      if ($User -eq $null -or $User -eq '')
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
   if ($User -eq $null -or $User -eq '')
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
$ExportPath = $ExportPath.replace('"', '')

if (!(Test-Path -Path "$ExportPath"))
{
   Write-Host
   Write-Host -Object "Path '$ExportPath' doesn't exist, do you want to create this directory? Y or N?" -ForegroundColor Yellow
	
   $Confirm = Read-Host
	
   if ($Confirm -eq 'y' -or $Confirm -eq 'Y')
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

$DCPs = Get-GroupPolicyConfigurations

foreach ($DCP in $DCPs)
{
   $FolderName = $($DCP.displayName) -replace '\<|\>|:|"|/|\\|\||\?|\*', '_'
   New-Item -Path "$ExportPath\$($FolderName)" -ItemType Directory -Force
	
   $GroupPolicyConfigurationsDefinitionValues = Get-GroupPolicyConfigurationsDefinitionValues -GroupPolicyConfigurationID $DCP.id
   $i = 0

   foreach ($GroupPolicyConfigurationsDefinitionValue in $GroupPolicyConfigurationsDefinitionValues)
   {
      $GroupPolicyConfigurationsDefinitionValue
      $i += 1
      $DefinitionValuePresentationValues = Get-GroupPolicyConfigurationsDefinitionValuesPresentationValues -GroupPolicyConfigurationID $DCP.id -GroupPolicyConfigurationsDefinitionValueID $GroupPolicyConfigurationsDefinitionValue.id
      $DefinitionValuedefinition = Get-GroupPolicyConfigurationsDefinitionValuesdefinition -GroupPolicyConfigurationID $DCP.id -GroupPolicyConfigurationsDefinitionValueID $GroupPolicyConfigurationsDefinitionValue.id
      $DefinitionValuedefinitionID = $($DefinitionValuedefinition.id)
      $DefinitionValuedefinitionDisplayName = $($DefinitionValuedefinition.displayName)
      $FileName = $DefinitionValuedefinitionDisplayName + [string]$i
      $FileName = $($FileName) -replace '\<|\>|:|"|/|\\|\||\?|\*', '_'
      $GroupPolicyDefinitionsPresentations = Get-GroupPolicyDefinitionsPresentations -groupPolicyDefinitionsID $DCP.id -GroupPolicyConfigurationsDefinitionValueID $GroupPolicyConfigurationsDefinitionValue.id
		
      if ($GroupPolicyConfigurationsDefinitionValue.enabled -match $true -and $DefinitionValuePresentationValues)
      {
         $JSON_Convert = ConvertTo-Json -InputObject $DefinitionValuePresentationValues -Depth 5 | ConvertFrom-Json | Select-Object -Property * -ExcludeProperty id, createdDateTime, lastModifiedDateTime, version
         $JSON_Output = $JSON_Convert | ConvertTo-Json
			
         #If settings is set as Enabled
         if ($DefinitionValuePresentationValues.value -match 'True')
         {
            $jsonCode = @"
{
   "enabled":$($GroupPolicyConfigurationsDefinitionValue.enabled.tostring().Replace('True', 'true')),
   "presentationValues":[  
      {  
         <!PLACEHOLDER!>,
         "presentation@odata.bind":"https://graph.microsoft.com/beta/deviceManagement/groupPolicyDefinitions('$($DefinitionValuedefinitionID)')/presentations('$($GroupPolicyDefinitionsPresentations.id)')"
      }
   ],
   "definition@odata.bind":"https://graph.microsoft.com/beta/deviceManagement/groupPolicyDefinitions('$($DefinitionValuedefinitionID)')"
}
"@

            $jsonCodePLACEHOLDER = $JSON_Output.Substring(1)
            $jsonCodePLACEHOLDER = $jsonCodePLACEHOLDER.Replace('<!PLACEHOLDER!>', $_).Substring(0, $jsonCodePLACEHOLDER.Length - 1)
            $jsonCode = $jsonCode.Replace('<!PLACEHOLDER!>', $jsonCodePLACEHOLDER).Replace('True', 'true')

            Write-Host -Object "Exporting setting $($DefinitionValuedefinitionDisplayName) to folder $ExportPath\$($FolderName)\$FileName.json" -ForegroundColor Yellow

            New-Item -Path "$ExportPath\$($FolderName)\$FileName.json" -ItemType File -Force
            $jsonCode | Set-Content -LiteralPath "$ExportPath\$($FolderName)\$FileName.json" -Force
         }
         else
         {
            $jsonCode = @"
{
   "enabled":$($GroupPolicyConfigurationsDefinitionValue.enabled.tostring().Replace('True', 'true')),
   "presentationValues":[  
      {  
         <!PLACEHOLDER!>,
         "presentation@odata.bind":"https://graph.microsoft.com/beta/deviceManagement/groupPolicyDefinitions('$($DefinitionValuedefinitionID)')/presentations('$($GroupPolicyDefinitionsPresentations.id)')"
      }
   ],
   "definition@odata.bind":"https://graph.microsoft.com/beta/deviceManagement/groupPolicyDefinitions('$($DefinitionValuedefinitionID)')"
}
"@
				
            $jsonCodePLACEHOLDER = $JSON_Output.Substring(1)
            $jsonCodePLACEHOLDER = $jsonCodePLACEHOLDER.Replace('<!PLACEHOLDER!>', $_).Substring(0, $jsonCodePLACEHOLDER.Length - 1)
            $jsonCode = $jsonCode.Replace('<!PLACEHOLDER!>', $jsonCodePLACEHOLDER)

            Write-Host -Object "Exporting setting $($DefinitionValuedefinitionDisplayName) to folder $ExportPath\$($FolderName)\$FileName.json" -ForegroundColor Yellow

            New-Item -Path "$ExportPath\$($FolderName)\$FileName.json" -ItemType File -Force
            $jsonCode | Set-Content -LiteralPath "$ExportPath\$($FolderName)\$FileName.json" -Force
         }
      }
      else
      {
         $jsonCode = @"
{
   "enabled":$($GroupPolicyConfigurationsDefinitionValue.enabled.tostring().Replace('True', 'true').Replace('False', 'false')),
    "definition@odata.bind":"https://graph.microsoft.com/beta/deviceManagement/groupPolicyDefinitions('$($DefinitionValuedefinitionID)')"
}
"@

         Write-Host -Object "Exporting setting $($DefinitionValuedefinitionDisplayName) to folder $ExportPath\$($FolderName)\$FileName.json" -ForegroundColor Yellow

         New-Item -Path "$ExportPath\$($FolderName)\$FileName.json" -ItemType File -Force
         $jsonCode | Out-File -FilePath "$ExportPath\$($FolderName)\$FileName.json" -Encoding ascii -Force
      }
   }
}

Write-Host
