# Credit for the CreateTheHiveAlert function - https://github.com/vi-or-die/TheHive4PS/blob/master/CreateTheHiveAlert

Function CreateTheHiveAlert {
	param(
		[Parameter(mandatory=$True)] [string]$AlertTitle,
		[Parameter(mandatory=$True)] [string]$AlertDescription,
		[Parameter(mandatory=$True)] [string]$Source,
		[Parameter(mandatory=$True)] [int]$Severity = 1
	)
   	[int]$tlp = 1
    	[string]$API_Uri = "http://192.168.70.128:9000/api/alert"
    	[string]$API_Method = "Post"
   	$Alert_Description = $Description -replace '<[^>]+>',''
	$APIToken = "<YOUR TOKEN HERE>"
   	$API_headers = @{Authorization = "Bearer $APIToken"}
	$SourceRef = New-Guid
	
    	$body = @{
        title = "$AlertTitle"
        description = "$AlertDescription"
        type = "external"
        source = "$Source"
        sourceRef = "$SourceRef"
        severity = $Severity
        tlp = $tlp
    }
    $JsonBody = $body | ConvertTo-Json
write-host $JsonBody
Invoke-RestMethod -Uri $API_Uri -Headers $API_headers -Body $JsonBody -Method $API_Method -ContentType 'application/json' -Verbose
}
$dir = get-location
#Define matches in the Search.txt file as below
#---Internationalised Domain Names---
#xn-- .*
#---Google spoofs---
#.*g[0o]{2}gle.*
$search = New-Object -TypeName "System.Collections.ArrayList"
[void]$search.Add("%Google%")
[void]$search.Add(".*[g9][o0u]{1,8}[g9][l7i][3e].*")
[void]$search.Add("%Amazon%")
[void]$search.Add(".*[a4](m|rn){1,3}[a4][zs52][0oua]n.*")
#Add other searches in the same way as above
$link = "http://whoisdownload.com/download-panel/free-download-file/"
$currentDate = Get-Date;
$date = $currentDate.AddDays(-1)
$date = $date.ToString("yyyy-MM-dd")
$file = $date + ".zip"
$bytes = [System.Text.Encoding]::UTF8.GetBytes($file)
$encodedFile = [System.Convert]::ToBase64String($bytes)
#/nrd/home is required by this site for some reason
$url = $encodedFile.trimend("=") + "=/nrd/home"
	try{
	$uri = $link + $url
		$Response = Invoke-WebRequest -Uri $uri -OutFile "$dir\$file" -ErrorAction Stop
		$Status = $Response.StatusCode
	}
	catch{
		$Status2 = $_.Exception.Response.StatusCode.value__
		Write-Host "Something went wrong. HTTP Response code = $Status2."
	}	
Expand-Archive -Path "$dir\$file"
Move-Item -Path "$dir\$date\domain-names.txt" -Destination $dir -Force
Remove-Item -Path "$dir\$file" -recurse
Remove-Item -Path "$dir\$date\" -recurse
$bool = Test-Path -Path "$dir\$date-domain-names.txt"
if ($bool -eq $true){
	Remove-Item -Path "$dir\$date-Domain-Names.txt"
	}
Rename-Item -Path "$dir\domain-names.txt" -NewName "$date-Domain-Names.txt" -Force
$outFile = "$dir\$date-Detections.txt"
$bool2 = Test-Path -Path "$dir\$date-Detections.txt"
if ($bool2 -eq $true){
    Remove-Item -Path "$dir\$date-Detections.txt"
    }
$date | Set-Content -Path "$outFile" -Force
[int]$count = -1
ForEach ($s in $search){
    if($s -notcontains "%"){
        foreach($domain in Get-Content "$dir\$date-Domain-Names.txt") {
            if($domain -match $s){
                $name = $count-1
				$searchName = $search[$name].trim("%")
                $out = "Match found: $searchName --- $domain"
                $out | Add-Content -Path $outFile
                CreateTheHiveAlert -AlertTitle "Suspicious Domain Registration Identified: $domain" -AlertDescription "The domain $domain was registered on $date and has the potential to be used as a phishing domain." -Source "Newly Registered Domains" -Severity 1
			}
        }
    }
    $count++
}
