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
	$APIToken = Get-Content "$dir\TheHiveAPI"
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
    Invoke-RestMethod -Uri $API_Uri -Headers $API_headers -Body $JsonBody -Method $API_Method -ContentType 'application/json' -Verbose
}
$dir = Split-Path -Path $PSCommandPath
#Define matches in the Search.txt file as below
#---Internationalised Domain Names---
#xn-- .*
#---Google spoofs---
#.*g[0o]{2}gle.*

$search = New-Object -TypeName "System.Collections.ArrayList"
foreach ($l in Get-Content "$dir\Search.txt"){
[void]$search.Add($l)
}
Write-Host "---Spoofind---"
[int]$days = 0

#Check input
do {
                $days = Read-Host -Prompt 'How many days should be checked? Choose 1-4'
                Write-Host ""
} until ($days -gt 0 -and $days -lt 5)

$currentDate = Get-Date;
Write-Host "Checking new domain registrations for '$days' day(s)."
$link = "http://whoisds.com//whois-database/newly-registered-domains/"

#Progress bar stats
[float]$percent = 1/([int]$search.Count * [int]$days)
$percent = $percent * 100
$prog = [math]::Round($percent,2)
Write-Progress -Activity "Search in Progress" -Id 1 -Status "$prog% Complete" -PercentComplete $prog

Write-Host "."
Write-Host "."
Write-Host "."

#Loop through required number of days
for($i=[int]$days; $i -gt 0; $i--){
    #Set the date of the match to the current date minus the number of days to match
    $date = $currentDate.AddDays(-$i)
    $date = $date.ToString("yyyy-MM-dd")
    $file = $date + ".zip"
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($file)
    $encodedFile = [System.Convert]::ToBase64String($bytes)
    #/nrd is required by this site for some reason
    $url = $encodedFile.trimend("=") + "=/nrd"
    Write-Host "Fetching domains for $date and saving in $dir\$date-Detections.txt"
	try{
		$Response = Invoke-WebRequest -Uri $link$url -OutFile "$dir\$file.zip" -ErrorAction Stop
		$Status = $Response.StatusCode
	}
	catch{
		$Status2 = $_.Exception.Response.StatusCode.value__
		Write-Host "Something went wrong. HTTP Response code = $Status2."
	}
    Expand-Archive -Path "$dir\$file.zip"
    Move-Item -Path "$dir\$file\domain-names.txt" -Destination $dir -Force
    Remove-Item -Path "$dir\$file\" -recurse
    $bool = Test-Path -Path "$dir\$date-Domain-Names.txt"
    if ($bool -eq $true){
		Remove-Item -Path "$dir\$date-Domain-Names.txt"
		}
    Rename-Item -Path "$dir\domain-names.txt" -NewName "$date-Domain-Names.txt" -Force
    Remove-Item -Path "$dir\$file.zip"
    $outFile = "$dir\$date-Detections.txt"
    $bool2 = Test-Path -Path "$dir\$date-Detections.txt"
    if ($bool2 -eq $true){
        Remove-Item -Path "$dir\$date-Detections.txt"
        }
    $date | Set-Content -Path "$outFile" -Force
    [int]$count = -1
    ForEach ($s in $search){
        if($s -notcontains "---"){
            foreach($domain in Get-Content "$dir\$date-Domain-Names.txt") {
                if($domain -match $s){
                    $out = $search[$count] + ":-----$StatusCode-----" + $domain
                    $out | Add-Content -Path $outFile
                    CreateTheHiveAlert -AlertTitle "Suspicious Domain Registration: $domain" -AlertDescription "The domain $domain was registered on $date and has the potential to be used as a phishing domain." -Source "Newly Registered Domains" -Severity 1
				}
            }
        }
        $count++
        $prog = [float]$prog + [float]$percent
        $prog = [math]::Round($prog,2)
        if ($prog -gt 100){
            $prog = 100
            }
        Write-Progress -Activity "Search in Progress" -Id 1 -Status "$prog% Complete" -PercentComplete $prog
    }
}
