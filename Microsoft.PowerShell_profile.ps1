oh-my-posh init pwsh --config "$env:POSH_THEMES_PATH/amro.omp.json" | Invoke-Expression

#Alias
Set-Alias vi nvim 
Set-Alias grep Select-String

Import-Module -Name Terminal-Icons
Import-Module posh-git

Set-PSReadLineOption -PredictionSource History
Set-PSReadLineOption -PredictionViewStyle ListView
Set-PSReadlineOption -EditMode vi

function gpull
{
  git commit -am 'add' && git pull origin master && git push origin master
}
function gpush
{
  git commit -am 'add' && git pull origin master && git push origin master
}
function ping ($count = 10)
{
 Test-Connection -Ping 8.8.8.8 -Count $count
}
function coreToken
{
	curl https://auth-api.23055.ir/Auth/LoginWithPassword -H "Content-Type: application/json" -d '{"username": "core", "password": "0!9@8#7$6%"}' --ssl-no-revoke | Select-String -Pattern '(?<="accessToken":")[^"]+' | ForEach-Object {$_.Matches.Value} | Set-Clipboard
}
function microserviceToken
{
	curl https://auth-api.23055.ir/Auth/LoginWithPassword -H "Content-Type: application/json" -d '{"username": "Api.core", "password": "a`123456"}' --ssl-no-revoke | Select-String -Pattern '(?<="accessToken":")[^"]+' | ForEach-Object {$_.Matches.Value} | Set-Clipboard
}
function centerToken
{
	curl  https://auth-api.23055.ir/Auth/LoginWithPassword -H "Content-Type: application/json" -d '{"username": "3232, "password": "123456"}' --ssl-no-revoke | Select-String -Pattern '(?<="accessToken":")[^"]+' | ForEach-Object {$_.Matches.Value} | Set-Clipboard
}
function consultantTokne
{
	curl  https://auth-api.23055.ir/Auth/LoginWithPassword -H "Content-Type: application/json" -d '{"username": "0043186904, "password": "09376997370"}' --ssl-no-revoke | Select-String -Pattern '(?<="accessToken":")[^"]+' | ForEach-Object {$_.Matches.Value} | Set-Clipboard
}
function token
{
  param (
       [string]$username,
       [string]$password
   )
  $data = @{ password = "$password";username= "$username" }| ConvertTo-Json
  curl  https://auth-api.23055.ir/Auth/LoginWithPassword -H "Content-Type: application/json"  -d $data --ssl-no-revoke | Select-String -Pattern '(?<="accessToken":")[^"]+' | ForEach-Object {$_.Matches.Value} | Set-Clipboard
}

function mtnToken
{
  param (
       [string]$username,
       [string]$password
   )
  $data = @{ password = "$password";username= "$username" }| ConvertTo-Json
  curl http://10.222.253.116:8014/idn/Auth/LoginWithPassword_V2 -H "Content-Type: application/json"  -d $data --ssl-no-revoke | Select-String -Pattern '(?<="accessToken":")[^"]+' | ForEach-Object {$_.Matches.Value} | Set-Clipboard
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

function MerchantToken
{
	curl https://sit-merchants.saminray.com/auth/Auth/LoginWithPassword -H "Content-Type: application/json" -d '{"username": "2050669615", "password": "a`12345"}' --ssl-no-revoke | Select-String -Pattern '(?<="accessToken":")[^"]+' | ForEach-Object {$_.Matches.Value} | Set-Clipboard
}

function IrancellToken
{
	curl http://10.222.253.116:8014/idn/Auth/LoginWithPassword_V2 -H "Content-Type: application/json" -d '{"username": "mtnicl_core", "password": "123456"}' --ssl-no-revoke | Select-String -Pattern '(?<="accessToken":")[^"]+' | ForEach-Object {$_.Matches.Value} | Set-Clipboard
}
function IrancellToken_live
{
	curl http://10.222.253.119:8020/Auth/BasicLoginWithPassword -H "Content-Type: application/json" -d '{"username": "mtnicl_core", "password": "123456"}' --ssl-no-revoke | Select-String -Pattern '(?<="accessToken":")[^"]+' | ForEach-Object {$_.Matches.Value} | Set-Clipboard
}

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
function GetRandomNumber {
   [int][double]::Parse((Get-Date -UFormat %s))}

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
function Generate-MobileNumber {
  $prefix = "0938"
  $suffix = -join (1..9 | Get-Random -Count 8 | % {"$_"})
  $result = $prefix + $suffix
  $result | Set-Clipboard
}
#PostalCode
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

#irancell
function irancell {
    $irancell = "mohammadhossein.ro 
0ynGPW4ke@7G"
Write-Host $irancell
}

#Get-ShamsiDate
function sDate {
    # Get the current date
    $currentDate = Get-Date

    # Determine the Shamsi year, month, and day
    $culture = New-Object System.Globalization.PersianCalendar
    $year = $culture.GetYear($currentDate)
    $month = $culture.GetMonth($currentDate)
    $day = $culture.GetDayOfMonth($currentDate)

    # Return the Shamsi date
    $shamsiDate = "$year/$month/$day"
    Write-Host  "$shamsiDate"
}

function Generate-Password {
    param (
        [int]$Length = 12
    )

    # Define character sets for the password
    $UpperCaseLetters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
    $LowerCaseLetters = 'abcdefghijklmnopqrstuvwxyz'
    $Numbers = '0123456789'
    $SpecialCharacters = '!@#$%^&*()-_+='

    # Combine character sets
    $AllCharacters = $UpperCaseLetters + $LowerCaseLetters + $Numbers + $SpecialCharacters

    # Initialize a secure random number generator
    $Random = New-Object -TypeName System.Security.Cryptography.RNGCryptoServiceProvider
    $RandomBytes = New-Object byte[] ($Length * 4)
    $Random.GetBytes($RandomBytes)

    # Build the random password
    $Password = ''
    1..$Length | ForEach-Object {
        $RandomIndex = [BitConverter]::ToUInt32($RandomBytes, ($_ - 1) * 4) % $AllCharacters.Length
        $Password += $AllCharacters[$RandomIndex]
    }

 Write-Host $Password 
       $Password | Set-Clipboard

}

#mtnPassword
function mtnPassword {
    $password = 'DIB^s7rlfxPi'
    Write-Host $password | Set-Clipboard
  }

function sheba {
param ($sheba)
$number = $sheba.Substring(4,3)

  if ($number -like "*013*") {
    "Refah"
  } elseif ($number -like "*056*") {
    "Saman"
  } elseif ($number -like "*015*") {
    "Sepah"
  } elseif ($number -like "*062*") {
    "Taat"
  } elseif ($number -like "*021*") {
    "Post IRan"
  } elseif ($number -like "*061*") {
    "Shahr"
  } elseif ($number -like "*017*") {
    "Melli"
  } elseif ($number -like "*012*") {
    "Mellat"
  } elseif ($number -like "*018*") {
    "tejarat"
  } elseif ($number -like "*055*") {
    "eghtesad novin"
  } elseif ($number -like "*059*") {
    "sina"
  } elseif ($number -like "*020*") {
    "tosee saderat"
  } elseif ($number -like "*016*") {
    "kashavarsi"
  } elseif ($number -like "*019*") {
    "saderat"
  } elseif ($number -like "*014*") {
    "maskan"
  } elseif ($number -like "*054*") {
    "parsian"
  } elseif ($number -like "*062*") {
    "Ayandeh"
  } elseif ($number -like "*060*") {
    "Meher"
  } elseif ($number -like "*057*") {
    "Pasargard"
  } else {
    "Unknown"
  }
}
function Decode-JwtToken {
  param (
    [string]$Token
  )

  $tokenHeader = $Token.Split(".")[0].Replace('-', '+').Replace('_', '/')
  while ($tokenHeader.Length % 4) {
    $tokenHeader += "="
  }

  $tokenPayload = $Token.Split(".")[1].Replace('-', '+').Replace('_', '/')
  while ($tokenPayload.Length % 4) {
    $tokenPayload += "="
  }

  $headerJson = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($tokenHeader)) | ConvertFrom-Json
  $payloadJson = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($tokenPayload)) | ConvertFrom-Json

  [PSCustomObject]@{
    Header = $headerJson
    Payload = $payloadJson
  }
}

function Decode-Token {
    param (
        [Parameter(Mandatory=$true)]
        [string]$Token
    )

    try {
        $decodedToken = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($Token))
        return $decodedToken
    } catch {
        Write-Host "Error decoding token: $_"
        return $null
    }
}

function Generate-Guid{
    [guid]::NewGuid().ToString() | Set-Clipboard
  }
