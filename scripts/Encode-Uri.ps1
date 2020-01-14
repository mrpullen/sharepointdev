$URL = "https://raw.githubusercontent.com/mrpullen/SharePointDev/master/template.json"
$Encode = [System.Web.HttpUtility]::UrlEncode($URL) 
Write-Host "This is the Encoded URL" $Encode -ForegroundColor Green