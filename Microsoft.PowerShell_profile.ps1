oh-my-posh init pwsh --config "$env:POSH_THEMES_PATH/amro.omp.json" | Invoke-Expression

Import-Module -Name Terminal-Icons
Import-Module posh-git

Set-PSReadLineOption -PredictionSource History
Set-PSReadLineOption -PredictionViewStyle ListView
Set-PSReadlineOption -EditMode vi

function ping ($count = 10)
{
 Test-Connection -Ping 8.8.8.8 -Count $count
}
function coreToken
{
	curl https://sit-hamkari.saminray.com/auth/Auth/LoginWithPassword -H "Content-Type: application/json" -d '{"username": "core", "password": "0!9@8#7$6%"}' --ssl-no-revoke | Select-String -Pattern '(?<="accessToken":")[^"]+' | ForEach-Object {$_.Matches.Value} | Set-Clipboard
}
function microserviceToken
{
	curl https://sit-hamkari.saminray.com/auth/Auth/LoginWithPassword -H "Content-Type: application/json" -d '{"username": "Api.core", "password": "a`123456"}' --ssl-no-revoke | Select-String -Pattern '(?<="accessToken":")[^"]+' | ForEach-Object {$_.Matches.Value} | Set-Clipboard
}
function centerToken
{
	curl https://sit-hamkari.saminray.com/auth/Auth/LoginWithPassword -H "Content-Type: application/json" -d '{"username": "99887766", "password": "123456"}' --ssl-no-revoke | Select-String -Pattern '(?<="accessToken":")[^"]+' | ForEach-Object {$_.Matches.Value} | Set-Clipboard
}
function consultantTokne
{
	curl https://sit-hamkari.saminray.com/auth/Auth/LoginWithPassword -H "Content-Type: application/json" -d '{"username": "2050669615", "password": "09376997370"}' --ssl-no-revoke | Select-String -Pattern '(?<="accessToken":")[^"]+' | ForEach-Object {$_.Matches.Value} | Set-Clipboard
}

function token
{
  param (
       [string]$username,
       [string]$password
   )
  $data = @{ password = "$password";username= "$username" }| ConvertTo-Json
  curl https://sit-hamkari.saminray.com/auth/Auth/LoginWithPassword -H "Content-Type: application/json"  -d $data --ssl-no-revoke | Select-String -Pattern '(?<="accessToken":")[^"]+' | ForEach-Object {$_.Matches.Value} | Set-Clipboard
}

function get-token
{
  param (
       [string]$username,
       [string]$password
   )
  $data = @{ password = "$password";username= "$username" }| ConvertTo-Json
  curl https://auth-api.23055.ir/Auth/LoginWithPassword -H "Content-Type: application/json"  -d $data --ssl-no-revoke | Select-String -Pattern '(?<="accessToken":")[^"]+' | ForEach-Object {$_.Matches.Value} | Set-Clipboard
}

function Get-AuthToken {
    param (
        [string]$username,
        [string]$password
    )
    $json = @{
        username = $username
        password = $password
    } | ConvertTo-Json
    $headers = @{
        'Content-Type' = 'application/json'
    }
    $uri = 'https://sit-hamkari.saminray.com/auth/Auth/LoginWithPassword'
    $response = Invoke-RestMethod -Uri $uri -Method Post -Body $json -Headers $headers -UseBasicParsing -SkipCertificateCheck 
    return $response }
# NatinalCode 
function Generate-NationalCode {
    $numbers = @()
    $sum = 0
    for ($i = 10; $i -ge 2; $i--) {
        $j = Get-Random -Minimum 0 -Maximum 10
        $numbers += $j
        $sum += $j * $i
    }
    $m = $sum % 11
    $numbers += if ($m -lt 2) { $m } else { 11 - $m }
    return $numbers -join '' | Set-Clipboard
}
# Download 
function Download-File {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true, Position = 0)]
        [string]$Url,
        [Parameter(Mandatory = $false, Position = 1)]
        [string]$OutputPath = [System.IO.Path]::GetTempPath() + "file.ext"
    )

    try {
        Invoke-WebRequest -Uri $Url -OutFile $OutputPath
        Write-Host "File downloaded successfully to: $OutputPath"
    } catch {
        Write-Error "Failed to download file from $Url. $_"
    }
}
# DNS
function shecan {
    $dns = "178.22.122.100","185.51.200.2" #Replace these with the DNS servers you want to use
    Set-DnsClientServerAddress -InterfaceAlias "Ethernet" -ServerAddresses $dns   }

function shecan-Wifi {
  $dns = "178.22.122.100","185.51.200.2" #Replace these with the DNS servers you want to use
    Set-DnsClientServerAddress -InterfaceAlias "Wi-Fi" -ServerAddresses $dns   }

function dns403 {
    $dns = "10.202.10.202","10.202.10.102" #Replace these with the DNS servers you want to use
    Set-DnsClientServerAddress -InterfaceAlias "Ethernet" -ServerAddresses $dns   }

function dns403-Wifi {
  $dns = "10.202.10.202","10.202.10.102" #Replace these with the DNS servers you want to use
    Set-DnsClientServerAddress -InterfaceAlias "Wi-Fi" -ServerAddresses $dns   }


function Disable-DNS {
    Set-DnsClientServerAddress -InterfaceAlias "Ethernet" -ResetServerAddresses
    Set-DnsClientServerAddress -InterfaceAlias "Wi-Fi" -ResetServerAddresses
   }

# Generate Random Number
function Get-RandomNumber {
       [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [int]$NumberOfDigits
    )

    $min = [math]::Pow(10, $NumberOfDigits - 1)
    $max = [math]::Pow(10, $NumberOfDigits) - 1

    [int](Get-Random -Minimum $min -Maximum $max) | Set-Clipboard
    }

# My Card
function card {
   $creditCardNumber = "6037 6915 0555 8460"
    Write-Host $creditCardNumber
    $creditCardNumber | Set-Clipboard
}
function card2 {
   $creditCardNumber = "6037 6976 7905 3154"
    Write-Host $creditCardNumber
    $creditCardNumber | Set-Clipboard
}
# Some MobileNumber
function mobile1 {
    $mobileNumber = "09301130346"
    $mobileNumber | Set-Clipboard
}
function mobile2 {
    $mobileNumber = "09337852343"
    $mobileNumber | Set-Clipboard
}
function mobile3 {
    $mobileNumber = "09336548762"
    $mobileNumber | Set-Clipboard
}
function mobile4 {
    $mobileNumber = "09335131222"
    $mobileNumber | Set-Clipboard
}

function PostalCode {
    $code = ""
    for ($i = 0; $i -lt 10; $i++) {
        if ($i -eq 0) {
            # First digit should be between 1 and 9
            $code += Get-Random -Minimum 1 -Maximum 9
        }
        elseif ($i -eq 1) {
            # Second digit should be either 0 or 1
            $code += Get-Random -Minimum 0 -Maximum 2
        }
        elseif ($i -eq 2) {
            # Third digit should be between 0 and 8
            $code += Get-Random -Minimum 0 -Maximum 9
        }
        else {
            # Fourth to tenth digits can be any number between 0 and 9
            $code += Get-Random -Minimum 0 -Maximum 10
        }
    }
       Write-Host $code 
       $code | Set-Clipboard
       }
