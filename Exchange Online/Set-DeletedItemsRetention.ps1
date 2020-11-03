﻿#requires -Version 1.0
<#
      Script by Alex Fields, ITProMentor.com

      Description:
      This script will max out the retention period for deleted items in all Exchange Online mailboxes (the maximum configurable value is 30 days)

      Prerequisites:
      The tenant will require any Exchange Online plan
      Connect to Exchange Online via PowerShell using MFA:
      https://docs.microsoft.com/en-us/powershell/exchange/exchange-online/connect-to-exchange-online-powershell/mfa-connect-to-exchange-online-powershell?view=exchange-ps

      WARNING: Script provided as-is. Author is not responsible for its use and application. Use at your own risk.
#>

$MessageColor = 'cyan'
$AssessmentColor = 'magenta'

Write-Host 

$Answer = Read-Host -Prompt 'By default Exchange Online retains deleted items for 14 days; would you like to enforce the maximum allowed value of 30 days for all mailboxes? Type Y or N and press Enter to continue'

if ($Answer -eq 'y' -or $Answer -eq 'yes') 
{
   Get-Mailbox -ResultSize Unlimited | Set-Mailbox -RetainDeletedItemsFor 30

   Write-Host 
   Write-Host -ForegroundColor $MessageColor -Object 'Deleted items will be retained for the maximum of 30 days for all mailboxes'
}
else 
{
   Write-Host 
   Write-Host -ForegroundColor $AssessmentColor -Object 'The deleted items retention value has not been modified on any mailboxes'
}
