<#
.SYNOPSIS
Given a vRops server and proper credentials, script will collect all vcenter clusters, organize them by vcenter, and
find the highest and lowest workload cluster and calculate the average.  Then will determine if workload is caused by
CPU or memory, collect stats on vms that reside on highest workload cluster.  Then migrate those vms to the lowest 
workload cluster.

.DESCRIPTION
Balance workload across clusters in a vcenter.

.PARAMETER vRopsFQDN
Specify the vRops server.

.PARAMETER CredentialPath
Looking for the path to the XML file with credenital for vRops and vCenter.

.PARAMETER LogFilePath
Specify a path for the log file, if not specified it will go to Logs in the directory script is executed from.

.PARAMETER VCExclusionList
Text file of vCenters that are to be excluded from process.

.PARAMETER ClusterExclusionList
Text file of cluster names to be excluded from process.

.PARAMETER PercentDiff
Integer to designate the percent difference between max and min workload clusters.  If the difference is greater than number specified moves will occur.  Default value is 20 percent.

.PARAMETER VMsToMove
Specify the number of VMs to migrate from max to min workload cluster.  Default value is 5

.PARAMETER SlackURL
Specify the URL of the webhook app you setup in Slack if you would like to get notifications in a slack channel

.PARAMETER TestOnly
To run through entire script, but skip the move part.

.PARAMETER Interactive
To run script and write all log entries to the screen.

.EXAMPLE
vulkrum.ps1 -vRopsFQDN vrops.yourdomain.com -CredentialPath vmbalance_cred.xml

.EXAMPLE
vulkrum.ps1 -vRopsFQDN vrops.yourdomain.com -CredentialPath vmbalance_cred.xml -VCExclusionList vcexclusionlist.txt -ClusterExclusionList clusterexclusionlist.txt -Interactive -TestOnly

.EXAMPLE
vulkrum.ps1 -vRopsFQDN vrops.yourdomain.com -CredentialPath vmbalance_cred.xml -VCExclusionList vcexclusionlist.txt -ClusterExclusionList clusterexclusionlist.txt -Interactive -TestOnly -SlackURL "https://hooks.slack.com/services/ABCDEFGHIJ/KLMNOPQRS/TUVWXYZ1234567890"

.EXAMPLE
vulkrum.ps1 -vRopsFQDN vrops.yourdomain.com -CredentialPath vmbalance_cred.xml -VCExclusionList vcexclusionlist.txt -ClusterExclusionList clusterexclusionlist.txt -Interactive -TestOnly -VMsToMove 10 -PercentDiff 15

.NOTES
AUTHOR: Tim Kalligonis, Comcast
DATE  : 3/20/2017
Version: 1.6
=================================================================================
Copyright 2017 Comcast Cable Communications Management, LLC
=================================================================================
Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
=================================================================================
Requirements:
	1.  PowerCli - Tested with v6.5
	2.  vRops - Tested with v6.3
	3.  vSphere/vCenter - tested with v5.5
	4.  PowerShell - Tested with v5.1
	5.  XML credenitals file created with desired credentials
		ie.: 	$credential = Get-Credential
			$credential | Export-Clixml vmbalance_cred.xml
	6.  Run As Admin
=================================================================================
Modifications:
Version X.X(increment by # of changes) - <Date MM/DD/YYYY> - <Name of Modifier> - <Description of changes>
Version 1.6 - 3/30/2017 - Tim Kalligonis - 	
	Added parameter input to be able to specify the percent difference between max and min workload clusters.  Default value is 20.
	Added parameter input to be able to specify the number of vms to move.  Default value is 5.
	If CD Mounted, it gets disconnected.  If VM tools installer is connected, gets disconnected.  These will prevent a move.
	Removed hardcoded regex to clude specific clusters in the environment.  Added intelligence to use of cluster exclusion list.
	Moved storage capacity check out of Migrate-VM function.  Each VM is moved after all checks pass versus batching them together.
	Make use of Slack notification an optional input parameter
#>
    
param(
	[Parameter(Mandatory=$true)][String] $vRopsFQDN = $null,
	[Parameter(Mandatory=$true)][String] $CredentialPath,
	[Parameter(Mandatory=$false)][String] $LogFilePath = $null,
	[Parameter(Mandatory=$false)][String] $VCExclusionList = $null,
	[Parameter(Mandatory=$false)][String] $ClusterExclusionList = $null,
	[Parameter(Mandatory=$false)][int] $PercentDiff = 20,
	[Parameter(Mandatory=$false)][int] $VMsToMove = 5,
	[Parameter(Mandatory=$false)][String] $SlackURL = $null,
	[switch] $TestOnly,
	[switch] $Interactive
)

function global:Test-Administrator
{
	# =================================================================================
	# Function to check if PS is running as Admin
	# =================================================================================
	
    $user = [Security.Principal.WindowsIdentity]::GetCurrent();
    (New-Object Security.Principal.WindowsPrincipal $user).IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)  
}

function global:Create-LogFile
{
	# =================================================================================
	# Function to create a global log file for event logging
	# =================================================================================
	
	Param (
		[Parameter(Mandatory=$false)][String] $LogPath = $null
	)
	
	# Create a log file and put it in the same directory specified in the input file path.
	$timestamp = "{0:yyyyMMdd-hhmmssfff}" -f (get-date)
	$time = "{0:yyyy-MM-dd hh:mm:ss.fff}" -f (get-date)

	if ($LogPath){
		$LogFilePath = $LogPath.trimend('\')
	}
	else{
		$LogFilePath = Split-Path -Parent $PSCommandPath
	}
	
	if( -Not (Test-Path -Path "$LogFilePath\Log\")){
		New-Item -ItemType directory -Path "$LogFilePath\Log\" | Out-Null
	}
		
	$global:logfile = "$LogFilePath\Log\ClusterBalancing-$timestamp.log"
	
	Get-Date | %{"[$_]`: Logfile Created" | Out-File $logfile -Append}
}

function global:Post-Message
{
	# =================================================================================
	# Function to post messages to screen and/or log files
	# =================================================================================
	
	Param (
		[Parameter(Mandatory=$true)][String] $Message,
		[Parameter(Mandatory=$false)][String] $Color = "white",
		[Parameter(Mandatory=$false)][Boolean] $Quit = $false,
		[Parameter(Mandatory=$false)][String] $WriteToLog = $null,
		[Parameter(ParameterSetName='Slack',Mandatory=$false)][String] $SlackWebHook = $null,
		#[Parameter(ParameterSetName='Slack',Mandatory=$false)][Boolean] $SlackPost = $false,
		[Parameter(ParameterSetName='Slack',Mandatory=$false)][String] $SlackCriticality = $null,
		[Parameter(Mandatory=$false)][Boolean] $Interactive = $false
	)
	
  	# Write message to screen
	if ($Interactive){
		Write-Host $Message -ForegroundColor $Color
	}
	
	# Write message to logfile if true
	if ($WriteToLog){
		Get-Date | %{"[$_]`: $message" | Out-File $WriteToLog -Append}
	}
	
	# Write message to Slack if true
	if($SlackWebHook){ PostTo-Slack -webhook $SlackWebHook -notification $Message -criticality $SlackCriticality}
	
	# Break out of the script if true
	if ($quit){
		Post-Message -Message "Processing Complete - ERROR - Terminating Script" -Color red -WriteToLog $logfile -SlackWebHook $SlackURL -SlackCriticality "critical" -Interactive $Interactive
		Clear-Variable logfile -Scope Global
		break
	}
}

function global:PostTo-Slack
{
# Function to post messages to Steel Cloud Sink Slack channel
	Param (
		[Parameter(Mandatory=$true)][String] $webhook,
		[Parameter(Mandatory=$true)][String] $notification,
		[Parameter(Mandatory=$true)][String] $criticality
	)
	
	# Given the notification, post the message to the appropriate Slack Channel
	# Escape out characters that create problems when posting the notifications
	$notification = $notification -replace '[[+*?()\\]','\$&' 

	# Criticality can be one of the following values "Critical, Warning, OK"
	# If any other value is provided for criticality, it will default to Warning
	if (@('critical','warning','ok') -notcontains $criticality) { $criticality = 'warning' }

	# Displaying the notification as a block with appropriate coloring for criticality
	$color_choices = @{'critical' = '#ff0000'; 'warning' = '#ffa500'; 'ok' = '#00ff00'}
	$slackpost_color = $color_choices.get_item($criticality)

	# Collect the scriptname and host running it is for posting so that it can aid in troubleshooting
	$hostname = $env:computername
	$scriptname = $(($MyInvocation.ScriptName).Split("\"))[-1]
	$username = $env:username

	# Format the Slack message to post in the channel
	$slack_payload = '{ "attachments":[{"fallback":"' + $scriptname + ' (' + $hostname + '): Message from ' + $username + ' - ' + $notification + '","color":"' + $slackpost_color + '","fields":[{ "value":"' + $scriptname + ' (' + $hostname + '): Message from ' + $username + ' - ' + $notification + '" }]}] }'
		
	try {
		# Post to Slack
		$response = Invoke-WebRequest -UseBasicParsing -Uri $webhook -Method "POST" -Body $slack_payload -ErrorAction SilentlyContinue
		Post-Message -Message "`tPOST to Slack succeeded" -Color green -Interactive $Interactive
	}
	catch {
		Post-Message -Message "`tPOST to Slack failed with HTTP Response Code $($_.Exception.Response.StatusCode.Value__)" -Color red -Interactive $Interactive
	}
}

function global:Prepare-VMware
{
	# =================================================================================
	# Function loads the VMware module
	# =================================================================================
		
	$modulename = "vmware.vimautomation.core"
	Post-Message -Message "Preparing for vSphere connectivity - importing module $($modulename)" -WriteToLog $logfile -Interactive $Interactive
	
	if (Get-Module -ListAvailable -Name $modulename) {
		#Import necessary VMware snap-in
        try{
        	Import-Module $modulename -ErrorAction Stop
        }
        catch{
        	Post-Message -Message "  ERROR:  Unable to import module $modulename" -Color red -WriteToLog $logfile -SlackWebHook $SlackURL -SlackCriticality "critical" -Interactive $Interactive -Quit $true
		}
		
		#Remove the FailoverClusters module if it is loaded to prevent conflict with VMware cmdlets
		Remove-Module -Name FailoverClusters -ErrorAction SilentlyContinue
	
		# Set the PowerCli Configuration to ignore the warning about the cert
		Set-PowerCLIConfiguration -InvalidCertificateAction ignore -Confirm:$false | Out-Null
		
		# Set the PowerCli Configuration to Single Deafult VI Server Mode - otherwise script will fail on the hardware checks
		Set-PowerCLIConfiguration -DefaultVIServerMode single -Confirm:$false | Out-Null
	}
	else{
		# Module did not load
		# Log something and exit script
		Post-Message -Message "  ERROR:  Unable to import module $modulename" -Color red -WriteToLog $logfile -SlackWebHook $SlackURL -SlackCriticality "critical" -Interactive $Interactive -Quit $true
	}
}

function global:Prepare-VRops
{
	# =================================================================================
	# Function loads the VRops module
	# =================================================================================
	
	$modulename = "vmware.vimautomation.vrops"
	Post-Message -Message "Preparing for vRops connectivity - importing module $($modulename)" -WriteToLog $logfile -Interactive $Interactive
	#Load necessary VMware snap-in, but if the PowerCLI terminal is being used, need to continue gracefully.
	
	if (Get-Module -ListAvailable -Name $modulename) {
		#Import necessary VMware snap-in
        try{
        	Import-Module $modulename -ErrorAction Stop
        }
        catch{
        	Post-Message -Message "  ERROR:  Unable to import module $modulename" -Color red -WriteToLog $logfile -SlackWebHook $SlackURL -SlackCriticality "critical" -Interactive $Interactive -Quit $true
		}
	}
	else{
		# Module did not load
		# Log something and exit script
		Post-Message -Message "  ERROR:  Unable to import module $modulename" -Color red -WriteToLog $logfile -SlackWebHook $SlackURL -SlackCriticality "critical" -Interactive $Interactive -Quit $true
	}
}

function global:Connect-VRops
{
	Param (
		[Parameter(Mandatory=$true)][String] $vRopsServer,
		[Parameter(Mandatory=$true)][PSCredential] $Credential
		
	)
	
	Post-Message -Message "`tConnecting to vRops" -WriteToLog $logfile -Interactive $Interactive
	try{
		Connect-OMServer -Server $vRopsServer -Credential $Credential -ErrorAction Stop | Out-Null
	}
	catch {
		Post-Message -Message "`tERROR: Connect-VRops $($vRopsServer): $($error[0])" -Color red -WriteToLog $logfile -SlackWebHook $SlackURL -SlackCriticality "critical" -Interactive $Interactive -Quit $true
	} # catch
}

function global:Build-ClusterDataTable
{
	Post-Message -Message "Creating Datatable of ClusterComputeResource data" -WriteToLog $logfile -Interactive $Interactive
	
	#Build DataTable for Clusters
	$global:ClusterTable = New-Object system.Data.DataTable "ClustersTable"
	
	$col1 = New-Object system.Data.DataColumn ClusterID,([string])
	$col2 = New-Object system.Data.DataColumn ClusterName,([string])
	$col3 = New-Object system.Data.DataColumn ClusterWorkload,([string])
	$col4 = New-Object system.Data.DataColumn ClusterCpu,([string])
	$col5 = New-Object system.Data.DataColumn ClusterMemory,([string])
	$col6 = New-Object system.Data.DataColumn DataCenter,([string])
	$col7 = New-Object system.Data.DataColumn vCenter,([string])
	$col8 = New-Object system.Data.DataColumn AffinityVMs,([array])
	
	$ClusterTable.columns.add($col1)
	$ClusterTable.columns.add($col2)
	$ClusterTable.columns.add($col3)
	$ClusterTable.columns.add($col4)
	$ClusterTable.columns.add($col5)
	$ClusterTable.columns.add($col6)
	$ClusterTable.columns.add($col7)
	$ClusterTable.columns.add($col8)
	
	$ClusterTable.PrimaryKey = $ClusterTable.Columns[0]
	
	# Get Clusters but exclude Paas and ICM clusters - using Regex 
	try{
		Post-Message -Message "`tGathering data from vRops for ClusterComputeResource" -WriteToLog $logfile -Interactive $Interactive
		$AllClusters = Get-OMResource -ResourceKind ClusterComputeResource -ErrorAction Stop #| ?{$_.name -match '\w{2,6}[^LAB]\s(UCS-)\d\d'}
	}
	catch{
		# Unable to get cluster information so log it and kill script
		Post-Message -Message "`tERROR:  Unable to get ClusterComputeResource information from vRops" -Color red -WriteToLog $logfile -SlackWebHook $SlackURL -SlackCriticality "critical" -Quit $true -Interactive $Interactive
	}
	
	Post-Message -Message "`tLooping through each cluster found in vRops and poplating datatable" -WriteToLog $logfile -Interactive $Interactive
	foreach($cluster in $AllClusters){
		Post-Message -Message "`tWorking on $($cluster) data gathering" -WriteToLog $logfile -Interactive $Interactive
		
		$row=$ClusterTable.NewRow()
		$row.ClusterID = $cluster.ID
		$row.ClusterName = $cluster.Name
		$row.DataCenter = $cluster.ExtensionData.getresourceproperties().property | ?{$_.name -eq "summary|parentDatacenter"} | select value -ExpandProperty value
		
		$vcenter = $cluster.ExtensionData.getresourceproperties().property | ?{$_.name -eq "summary|parentVcenter"} | select value -ExpandProperty value
		if($vcenter.substring(0,3) -eq "vc_"){
			$vcenter = $vcenter.Substring(3,$vcenter.Length-3)
		}
		$row.vCenter = $vcenter
		
		$affinityrules = $cluster.ExtensionData.GetResourceProperties().property | ?{$_.name -eq "configuration|drsconfig|affinityRules"} | select value -ExpandProperty value
		[array]$affinityVMs = $affinityrules | ConvertFrom-Json | select rules -ExpandProperty rules | select virtualmachines -ExpandProperty virtualmachines
		$row.AffinityVMs = $affinityVMs
		
		try{
			Post-Message -Message "`tGathering $($cluster) stats - Workload, CPU, Memory" -WriteToLog $logfile -Interactive $Interactive
			$clusterStats = $cluster | Get-OMStat -RollupType Avg -IntervalCount 5 -IntervalType DAYS -From ([DateTime]::Now).AddDays(-4) -To ([DateTime]::Now) | ?{($_.Key -eq 'mem|workload') -or ($_.Key -eq 'cpu|workload') -or ($_.Key -eq 'badge|workload')} -ErrorAction Stop
		}
		catch{
			# Unable to get cluster stat data log it and kill script
			Post-Message -Message "`tERROR:  Unable to get ClusterComputeResource stats from vRops" -Color red -WriteToLog $logfile -SlackWebHook $SlackURL -SlackCriticality "critical" -Quit $true -Interactive $Interactive
		}
		$row.ClusterWorkload = $clusterStats | ?{$_.Key -eq "badge|workload"} | select value -ExpandProperty value
		$row.ClusterCpu = $clusterStats | ?{$_.Key -eq "cpu|workload"} | select value -ExpandProperty value
		$row.ClusterMemory = $clusterStats | ?{$_.Key -eq "mem|workload"} | select value -ExpandProperty value
		
		Post-Message -Message "`tAdding row to datatable for $($cluster)" -WriteToLog $logfile -Interactive $Interactive
		$ClusterTable.Rows.Add($row)
	}
}

function global:Get-HashMaxValue
{
	Param (
		[Parameter(Mandatory=$true)][hashtable] $hashTable,
		[Parameter(Mandatory=$false)][int]$highestPlace = 1,
		[Parameter(Mandatory=$true)][int]$howMany
	)
	
	$position = $highestPlace - 1
	return $hashTable.GetEnumerator() | sort value -Descending | Select-Object -Skip $position | select -First $howMany
}

function global:Get-HashMinValue
{
	Param (
		[Parameter(Mandatory=$true)][hashtable] $hashTable,
		[Parameter(Mandatory=$false)][int]$lowestPlace = 1,
		[Parameter(Mandatory=$true)][int]$howMany
	)
	
	$position = $lowestPlace - 1
	return $hashTable.GetEnumerator() | sort value | Select-Object -Skip $position | Select-Object -First $howMany
}

function global:Get-VMStats
{
	Param (
		[Parameter(Mandatory=$true)][Array] $VMsToGet,
		[Parameter(Mandatory=$true)][String] $ResourceType
	)
	
	$VMStatsHash = @{}
	foreach($VM in $VMsToGet){
		$VMStats = (Get-OMStat -Resource $VM -RollupType Avg -IntervalCount 5 -IntervalType DAYS -From ([DateTime]::Now).AddDays(-4) -To ([DateTime]::Now) | ?{$_.Key -eq $ResourceType}).value
		if(!($VMStatsHash.get_item($VM))){
			$VMStatsHash.Add($VM, $VMStats)
		}
	}
	return $VMStatsHash
}

function global:Validate-Resource
{
	Param (
		[Parameter(Mandatory=$true)][String] $checkResource,
		[Parameter(Mandatory=$true)][String] $resourceVCenter,
		[Parameter(Mandatory=$true)][String] $viewType
	)
	
	Post-Message -Message "`tValidating Resource - $checkResource - $viewType" -WriteToLog $logfile -Interactive $Interactive
		
	$resourceCheck = Get-View -Server $resourceVCenter -ViewType $viewType -Filter @{"Name" = "$($checkResource)"}
	If ($resourceCheck -eq $null){
		return "no good"
	}
	else{
		return "good"
	}
}

function global:Validate-HWCompatability
{
	# =================================================================================
	# Check vms against hosts in destination cluster for compatability
	# Needs: VMs, destination cluster, vcenter
	# Return: good hosts available on destination cluster
	# =================================================================================
	
	Param (
		[Parameter(Mandatory=$true)][Object] $VM,
		[Parameter(Mandatory=$true)][String] $VCenter,
		[Parameter(Mandatory=$true)][String] $DestinationCluster
	)
	
	# Connect to the vCenter server specified
	Post-Message -Message "`tValidating Hardware Compatability between $($VM.name) and each cluster host" -WriteToLog $logfile -Interactive $Interactive
		
	[System.Collections.ArrayList]$goodHosts = @()
	[System.Collections.ArrayList]$badHosts = @()
	
	# Collect all hosts for the given cluster			
	$hosts = try{
				get-vmhost -Server $VCenter -ErrorAction Stop | ?{($_.Parent).tostring() -eq $DestinationCluster}
			}
			catch{
				Post-Message -Message "`tERROR: Failed to get Destination Cluster Hosts - $($error[0])" -Color red -WriteToLog $logfile -Interactive $Interactive
				continue
			}
	
	$viewSI = Get-View 'ServiceInstance' -Server $VCenter
	$viewVmProvChecker = Get-View $viewSI.Content.VmProvisioningChecker -Server $VCenter
	
	# Loop through each host and check hardware compatability
	foreach ($clusterHost in $hosts){
		$Results = try{$viewVmProvChecker.QueryVMotionCompatibilityEx($VM.Id, $clusterHost.Id)}catch{"Compatability Query Failed"}
		if ($Results -eq "Compatability Query Failed"){
			Post-Message -Message "`t`tERROR: Failure during Compatability Check - $($error[0])" -Color red -WriteToLog $logfile -Interactive $Interactive
		}
		else{
				foreach ($Record in $Results) {
					if ($Record.Error.localizedMessage -like '*CPUID details: incompatibility*') {
						if($goodHosts -contains $clusterHost){
							$goodHosts.remove($clusterHost)
							Post-Message -Message "`t`tRemoving from good host list - Bad Host $clusterHost - CPUID Incompatibility" -Color red -WriteToLog $logfile -Interactive $Interactive
						}
						if($badHosts -notcontains $clusterHost){
							$badHosts += $clusterHost
							Post-Message -Message "`t`tBad Host $clusterHost - CPUID Incompatibility" -Color red -WriteToLog $logfile -Interactive $Interactive
						}
					}
					else{
						if($clusterHost.ConnectionState -eq "Connected"){
							if(($goodHosts -notcontains $clusterHost) -and ($badHosts -notcontains $clusterHost)){
								$goodHosts += $clusterHost
								Post-Message -Message "`t`tGood Host $clusterHost" -Color green -WriteToLog $logfile -Interactive $Interactive
							}
						}
						else{
							if($badHosts -notcontains $clusterHost){
								$badHosts += $clusterHost
								Post-Message -Message "`t`tBad Host $clusterHost - Connection State not Connected" -Color red -WriteToLog $logfile -Interactive $Interactive
							} # if connected state
						} # else not in connected state
					} # else compatible
				} # foreach Record in results
			} # else compatibility query came back ok
	} # foreach host
	return $goodHosts
} 

function global:Connect-VCenter
{
	# =================================================================================
	# Function to connect to vcenter, checks for existing session
	# =================================================================================

	Param (
		[Parameter(Mandatory=$true)][String] $vcenter,
		[Parameter(Mandatory=$true)][PSCredential] $Credential
	)
 
  	try {
		Post-Message -Message "`tConnecting to VCenter $vcenter" -Color white -Interactive $Interactive
		$vcsession = ($global:DefaultVIServers | Where-Object -FilterScript {$_.name -eq $vcenter})
		$sessionID = $vcsession.sessionId
		$sessionState = $vcsession.IsConnected
		
		# If there is an existing session for give vCenter, use it.
		if (($SessionID) -and ($SessionState)) { 
			#Post-Message -Message "`tFound an active existing session for $vcenter. Attempting to connect using sessionID" -Color green -WriteToLog $logfile -Interactive $Interactive
			Connect-VIServer $vcenter -Session $sessionID -ErrorAction Stop | Out-Null
			#Post-Message -Message "`tSUCCESS: Connection to $vcenter successful using sessionID" -Color green -WriteToLog $logfile -Interactive $Interactive
		} # if
		# Else create a new session
		else {
			#Post-Message -Message "`tCreating a new session for $vcenter" -Color green -WriteToLog $logfile -Interactive $Interactive
			Connect-VIServer $vcenter -Credential $Credential -ErrorAction Stop | Out-Null
			#Post-Message -Message "`tSUCCESS: Connection to $vcenter successful" -Color green -WriteToLog $logfile -Interactive $Interactive
		} # else
	} # try
	catch {
		Post-Message -Message "`tERROR: ConnectTo-VCenter $($vcenter): $($error[0])" -Color red -WriteToLog $logfile -SlackWebHook $SlackURL -SlackCriticality "critical" -Interactive $Interactive
		Post-Message -Message "`tSkipping to next item" -Color red -WriteToLog $logfile -Interactive $Interactive
		# Failed to connect to vCenter, move on to next one in the loop
		continue
	} # catch
}

function global:Get-StorageCluster
{
	# =================================================================================
	# Given a VM and the destination system cluster,
	# get the available storage clusters associated with it.
	# Find which datastore cluster is the least used.
	# Remove the provisioned space of vm value from the datastore cluster free space.
	# If the result is less then 25% available free space, do not migrate the VM.
	# Returns two values:  The cluster name to use and the % free space remaining after move.
	# =================================================================================
	
	Param (
		[Parameter(Mandatory=$true)][Object] $VMObject,
		[Parameter(Mandatory=$true)][String] $DestinationCluster
	)
	
	Post-Message -Message "`tGet Storage Cluster to use for - $($VMObject.name)" -WriteToLog $logfile -Interactive $Interactive
	$DSClusterToUse = $null
	
	# Collect Available DataStore Clusters for the give System Cluster
	# Collect System Clusters
	$ComputeCluster = get-view -viewtype ClusterComputeResource
	# Collect Storage Clusters
  	$StoragePod = get-view -viewType StoragePod
	
	# set variables with storage info
	$StoragePod | % {Set-Variable -name $_.name -value $_.childentity.value}
	foreach ($cluster in $ComputeCluster) {
		$DSClist = @()
		foreach ($vol in $cluster.datastore.value) { 
			$match = $null
			$match = $StoragePod | ?{$_.childentity.value -contains $vol} | select -expand name
			if ($match) {$DSClist += $match}
		} #close foreach vol
		Set-Variable -name $cluster.name -value $DSClist
	} #close foreach cluster

	$ComputeCluster.name | foreach{
		if ($_ -eq $DestinationCluster){
			$DSCNames = (Get-Variable $_).value | select -unique
		}
	}

	# Determine which Datastore Cluster has the most available space
	$DSClusters = $DSCNames | %{Get-DatastoreCluster $_}
	$DSCPercentSpace = 0
	$DSCFreeSpace = 0
	# Loop through each DS Cluster to find the one with the most space available.
	foreach ($dsc in $DSClusters){
		$DSCPercentFreeSpace = [math]::round(($dsc.FreeSpaceGB/$dsc.CapacityGB)*100,2)
		
		if ($DSCPercentFreeSpace -gt $DSCPercentSpace){
			# Now check to see if this cluster will have 25% free space after VM is added
			#Gather the total provisioned space for vms to move
			$SpaceProvisioned = ($VMObject | Measure-Object -Property ProvisionedSpaceGB -sum).sum
			$DSCPercentAfterMove = [math]::round((($dsc.FreeSpaceGB-$SpaceProvisioned)/$dsc.CapacityGB)*100,2)
			
			if ($DSCPercentAfterMove -gt 25){
				$DSClusterToUse = $dsc.Name
				$DSCFreeSpace = [math]::round($dsc.FreeSpaceGB,2)
				$DSCPercentSpace = $DSCPercentFreeSpace
			}
		}
	}
	Return $DSClusterToUse, $DSCPercentAfterMove
	# =================================================================================
}    

function global:Migrate-VM
{
	# =================================================================================
	# Needs: VMs, destination cluster, vcenter, and validated hosts on cluster
	# =================================================================================
	
	Param (
		[Parameter(Mandatory=$true)][Object] $VM,
		[Parameter(Mandatory=$true)][String] $VCenter,
		[Parameter(Mandatory=$true)][String] $DestinationCluster,
		[Parameter(Mandatory=$true)][Object] $Hosts
	)
		
	$countHosts = $Hosts | measure
			
	# Move the VM to a random host in the desired cluster
	Post-Message -Message "`tMoving $($VM.name) to destination storage cluster $($DSCluster[0])" -Color white -WriteToLog $logfile -Interactive $Interactive

		try{
			try{
				$CDConnected = $VM | Get-CDDrive | ?{$_.ConnectionState.Connected}
				If($CDConnected){
					Set-CDDrive -Connected 0 -StartConnected 0 $CDConnected -Confirm:$false | Out-Null
					Post-Message -Message "`tDismounted CD on $($VM.name)" -WriteToLog $logfile -Interactive $Interactive	
				}

				$VMToolsMounted = get-view -ViewType virtualmachine -property name,Runtime.ToolsInstallerMounted -Filter @{"Name" = "$($VM.name)";'Runtime.ToolsInstallerMounted'='True'}
				If($VmToolsMounted){
					$VmToolsMounted.UnmountToolsInstaller()
					Post-Message -Message "`tDisconnected VM Tools Installer on $($VM.name)" -WriteToLog $logfile -Interactive $Interactive		
				}
			}
			catch{
				Post-Message -Message "`tERROR: Unable to dismount CD on $($VM.name)" -WriteToLog $logfile -Interactive $Interactive		
			}

			Move-VM -VM $VM.name -Server $VCenter -Destination $Hosts[(Get-Random($countHosts.count))] -Datastore $DSCluster[0] -ErrorAction SilentlyContinue | Out-Null
			Post-Message -Message "`tSUCCESS: Moved $($VM.name) to $DestinationCluster resource cluster" -Color green -WriteToLog $logfile -Interactive $Interactive
		}
		catch{
			Post-Message -Message "`tERROR: Failed to move $($VM.name) to destination cluster`r`n$error[0]" -Color red -WriteToLog $logfile -SlackWebHook $SlackURL -SlackCriticality "critical" -Interactive $Interactive
			continue
		} # catch

	$srvResult = get-vm $VM.name | select Name, @{N="Cluster";E={Get-Cluster -VM $_}}, @{N="ESX Host";E={Get-VMHost -VM $_}}, @{N="Datastore";E={Get-Datastore -VM $_}}
	Post-Message -Message "`tResult:  $($VM.name)`tCluster Name:$($srvResult.cluster.name)`tDatastore:$($srvResult.datastore.name)`r`n" -Color white -WriteToLog $logfile -Interactive $Interactive

}

# ======================================================================================
# Script body
# ======================================================================================
# If any thing in this section fails, break from script, nothing else will work correctly.

Create-LogFile -LogPath $LogFilePath
Post-Message -Message "$($MyInvocation.MyCommand.name) has Started" -WriteToLog $logfile -Interactive $Interactive -SlackWebHook $SlackURL -SlackCriticality "ok"

if (!(Test-Administrator)){
	# Log that its not running as admin and exit script
	Post-Message -Message "  ERROR:  $($PSCommandPath) not running as Admin on $($env:computername)" -Color red -WriteToLog $logfile -SlackWebHook $SlackURL -SlackCriticality "critical" -Interactive $Interactive -Quit $true
}

Post-Message -Message "Obtaining credentials for vSphere and vRops" -WriteToLog $logfile -Interactive $Interactive
$Credential = Import-Clixml -Path $CredentialPath
if (!($Credential.username) -or !($Credential.password)){
	# Log that creds for vcenter and vrops not available
	Post-Message -Message "  ERROR:  Missing credentials for vcenter and vrops" -Color red -WriteToLog $logfile -SlackWebHook $SlackURL -SlackCriticality "critical" -Interactive $Interactive -Quit $true
}

Prepare-VMware
Prepare-VRops
Connect-VRops -vRopsServer $vRopsFQDN -Credential $Credential
Build-ClusterDataTable

# Create hashtable grouped by vcenter
Post-Message -Message "Creating hashtable of clusters by vCenter" -WriteToLog $logfile -Interactive $Interactive
$vCenterGroups = $ClusterTable | Group-Object -AsHashTable -Property vCenter

# Get exclusion lists if provided
Post-Message -Message "Reviewing vCenter exclusion list" -WriteToLog $logfile -Interactive $Interactive
if($VCExclusionList){ $VCExclude = (Get-Content $VCExclusionList | ?{$_ -notlike '#*'}).tolower()}

Post-Message -Message "Reviewing Cluster exclusion list" -WriteToLog $logfile -Interactive $Interactive
if($ClusterExclusionList){ $CLExclude = (Get-Content $ClusterExclusionList | ?{$_ -notlike '#*'}).tolower()}

# If failure occurs from here, don't break from script.  Log and skip to next in the loop.

#Walk Through hashtable of vCenters
Post-Message -Message "Looping through each vCenter" -WriteToLog $logfile -Interactive $Interactive
$moveSummary = "`r`nSummary of VMs moved between clusters`r`n"
foreach($vc in $vCenterGroups.GetEnumerator()){
	# If number of clusters in vc is greater than 1 and it is not on the exclusion list work it
	if(($vc.value.count -gt 1) -and ($vc.name.tolower() -notin $VCExclude)){
		Post-Message -Message "Working on $($vc.name)" -WriteToLog $logfile -Interactive $Interactive
		Connect-VCenter -Vcenter $vc.name -Credential $Credential

		# Reconnect to vRops - may have taken some time to migrate and need a new connection to vRops.
		Connect-VRops -vRopsServer $vRopsFQDN -Credential $Credential
		
		# Build hashtables of Cluster stats to be able to sort and compare
		Post-Message -Message "`tBuilding utilized resources hashtable - $($vc.name)" -WriteToLog $logfile -Interactive $Interactive
		$clusterWLHash = @{}
		$clusterCpuHash = @{}
		$clusterMemHash = @{}
		for($i=0; $i -lt $vc.value.count; $i++){
			$notfound=$true
			foreach($clx in $CLExclude){
				if($vc.Value[$i].ClusterName -like $clx){
					$notfound=$false
					Post-Message -Message "`tExcluding $($vc.Value[$i].ClusterName) - on the cluster exclusion list " -WriteToLog $logfile -Interactive $Interactive
				}
			}
			# Only add clusters to hashtable if they are not on the exclude list
			if($notfound){
				$clusterWLHash.Add($vc.Value[$i].ClusterName, [decimal]$vc.Value[$i].ClusterWorkload)
				$clusterCpuHash.Add($vc.Value[$i].ClusterName, [decimal]$vc.Value[$i].ClusterCpu)
				$clusterMemHash.Add($vc.Value[$i].ClusterName, [decimal]$vc.Value[$i].ClusterMemory)
			}
		}
		Post-Message -Message "`tGetting Max, Min, and Ave workload cluster - $($vc.name)" -WriteToLog $logfile -Interactive $Interactive
		# Get max workload cluster
		$maxClWorkLoad = Get-HashMaxValue -hashTable $clusterWLHash -highestPlace 1 -howMany 1
		# Get minimum workload cluster
		$minClWorkLoad = Get-HashMinValue -hashTable $clusterWLHash -lowestPlace 1 -howMany 1
		# Get workload average across all clusters
		$avgClWorkLoad = ([decimal]$maxClWorkLoad.value + [decimal]$minClWorkLoad.value)/2
		$avgClWorkLoadTrim = "{0:N2}" -f $avgClWorkLoad
		
		# Get the CPU and Memory value for the max workload cluster	
		Post-Message -Message "`tGetting CPU and Memory for max workload cluster - $($vc.name)" -WriteToLog $logfile -Interactive $Interactive
		$maxClCpuValue = $vc.value | ?{$_.ClusterName -eq $maxClWorkload.Name} | select -ExpandProperty ClusterCpu
		$maxClMemValue = $vc.value | ?{$_.ClusterName -eq $maxClWorkload.Name} | select -ExpandProperty ClusterMemory
		
		# Max, Min, and Average Workload clusters
		Post-Message -Message "`tMaximum Workload - $($maxClWorkload.value) - $($maxClWorkLoad.name)" -WriteToLog $logfile -Interactive $Interactive
		Post-Message -Message "`tMinimum Workload - $($minClWorkload.value) - $($minClWorkLoad.name)" -WriteToLog $logfile -Interactive $Interactive
		Post-Message -Message "`tAverage Workload - $($avgClWorkLoad)" -WriteToLog $logfile -Interactive $Interactive
	
		# If the max workload cluster value is greater than $PercentDiff or default 20% compared to minimun workload cluster value, let's get to work and rebalance
		if($maxCLWorkLoad.value - $minClWorkLoad.value -gt $PercentDiff){
			Post-Message -Message "`tMax and Min cluster workloads difference is greater than $($PercentDiff)%" -WriteToLog $logfile -Interactive $Interactive
			$VMResourceToGet = $null
			
			# Determine if CPU or Mem is greater thus setting the workload value and caputre it (to be used laster to get VM stats)
			if($maxClCpuValue -ge $maxClMemValue){
				$VMResourceToGet = "cpu|workload"
				Post-Message -Message "`tCPU responsible for high workload" -WriteToLog $logfile -Interactive $Interactive
			}
			else{
				$VMResourceToGet = "mem|workload"
				Post-Message -Message "`tMemory responsible for high workload" -WriteToLog $logfile -Interactive $Interactive
			}
			
			# Get the max cluster and all extended properties - includes the hosts
			try{
				Post-Message -Message "`tGathering extended properties for max workload cluster - $($maxClWorkLoad.Name)" -WriteToLog $logfile -Interactive $Interactive
				$maxCluster = Get-OMResource -Name $maxClWorkLoad.Name -ErrorAction Stop
			}
			catch{
				Post-Message -Message "`tERROR:  Unable to get max workload cluster information from vrops" -Color red -WriteToLog $logfile -SlackWebHook $SlackURL -SlackCriticality "critical" -Interactive $Interactive
				continue
			}
			
			# Get all of the host systems properties
			$maxClusterHosts = $maxCluster.ExtensionData.GetRelationships().resource.resourcekey | ?{$_.ResourceKindKey -eq 'HostSystem'} | select -ExpandProperty Name
			
			# Hashtable of VMEntityObjectID(Key) and VM names (value) to be used to identify if VM is part of Affinity rule
			$vmObjIDs = @{}
				
			# Loop through each host and get all of the vm names on that host
			Post-Message -Message "`tLooping through each host on max workload cluster to collect VM properties" -WriteToLog $logfile -Interactive $Interactive
			foreach($eachHost in $maxClusterHosts){
				try{
					$maxClusterHost = Get-OMResource -Name $eachHost -ErrorAction Stop
				}
				catch{
					Post-Message -Message "`tERROR:  Unable to get host information from vrops" -Color red -WriteToLog $logfile -SlackWebHook $SlackURL -SlackCriticality "critical" -Interactive $Interactive
					continue
				}
				
				$maxClusterVMResourceIDs = $maxClusterHost.ExtensionData.getrelationships().resource.resourcekey | ?{$_.ResourceKindKey -eq 'VirtualMachine'}
			
				foreach($vmID in $maxClusterVMResourceIDs){
					$vmIDName = $($vmID.name)
					$vmObjectID = $vmID.resourceidentifiers | ?{$_.IdentifierType.Name -eq "VMEntityObjectID"} | select -ExpandProperty value
					$vmObjIDs.Set_Item($vmobjectID,$vmIDName)
				}		
			}
			
			# Array for maxClusterVM names
			[System.Collections.ArrayList]$maxClusterVMs = @()
						
			$ClusterData = $null
			$ClusterData = $ClusterTable.Select("ClusterName='$($maxCluster.Name)'")

			# Loop through hash table and compare to $ClusterTable AffinityVMs, if they exist do not add to array.  Exclude due to affinity rule
			foreach($key in $vmObjIDs.GetEnumerator()){
				if($key.name -notin $ClusterData.AffinityVMs){
					$maxClusterVMs.Add($key.value) | Out-Null
				}
				else{
					Post-Message -Message "`t$($key.name) - $($key.value) excluded.  In affinity rule." -WriteToLog $logfile -Interactive $Interactive
				}
			}
			
			Post-Message -Message "`tGathering resource stats for each VM on hosts" -WriteToLog $logfile -Interactive $Interactive
			$maxClusterVMsStats = Get-VMStats -VMsToGet $maxClusterVMs -ResourceType $VMResourceToGet
			#Get the top 20 to loop through until we have $VMsToMove or default 5 to work with to migrate
			$TopVMs = Get-HashMaxValue -hashTable $maxClusterVMsStats -highestPlace 1 -howMany 20
			
			$i=0
			[System.Collections.ArrayList]$VMsToProcess = @()
			do{
				$vmCheckResult = Validate-Resource -checkResource $TopVMs[$i].name -resourceVCenter $vc.name -viewType "VirtualMachine"
				if($vmCheckResult -eq "good"){
					$VMsToProcess.Add($TopVMs[$i].name) | Out-Null	
				}
				$i++
			}
			until(($VMsToProcess.count -eq $VMsToMove) -or ($i -eq $TopVMs.count - 1))
		} #Results at this point should be $VMsToMove valid VMs to move stored in $VMsToProcess
		else{
			# Difference between Max and Min workload clusters is not > $PercentDiff or default 20% move on to next vCenter
			Post-Message -Message "`tMax and Min cluster workloads difference is less than $($PercentDiff)% - no need to process" -WriteToLog $logfile -Interactive $Interactive
			continue
		}
		
		# Loop through each VM - Check HW Compatability, if ok, check Storage availability, if ok move it.  If not, try next dest cluster
		foreach($VMMove in $VMsToProcess){
			$destClusterGood = $true
			$destClusterLessAvg = $true
			$VMMoveObj = Get-VM $VMMove -Server $vc.name # Get the VM object
			$n = 1
            $minClWorkLoad = Get-HashMinValue -hashTable $clusterWLHash -lowestPlace $n -howMany 1
			Post-Message -Message "`tWorking on VM - $($VMMoveObj.name)" -WriteToLog $logfile -Interactive $Interactive
			# Do loop through clusters until it can be moved or cannot be moved
			do{
				if($minClWorkLoad.value -lt $avgClWorkLoad){
					# Validate Cluster is online
					$ClCheckResult = Validate-Resource -checkResource $minClWorkLoad.name -resourceVCenter $vc.name -viewType "ClusterComputeResource"
					
					if($ClCheckResult = "good"){
						# Cluster available, let's check hardware compatability
						# Hardware Comp check will return a list of good hosts or a null value
						$hostsToUse = Validate-HWCompatability -VM $VMMoveObj -VCenter $vc.name -DestinationCluster $minClWorkLoad.name
						# If no valid hosts to use, move to next lowest workload cluster
						if($hostsToUse){
							# Good Hosts available, let's check the storage		
							# Check available Storage on cluster
							$DSCluster = $null
							$DSCluster = Get-StorageCluster -VMObject $VMMoveObj -DestinationCluster $minClWorkLoad.name
							If ($DSCluster[0] -eq $null){
                                # VM exceeds storage capacity, try the next cluster
								Post-Message -Message "`tWARNING:  VM $($VMMoveObj.name) move would exceed storage capacity on destination DS Cluster $($minClWorkLoad.name) on $($vc.name).  Only $($DSCluster[1])% would be free after a move on $($VCenter) compute cluster $($DestinationCluster)" -Color yellow -WriteToLog $logfile -SlackWebHook $SlackURL -SlackCriticality "warning" -Interactive $Interactive
								$destClusterGood = $false
							    $n++
							    $minClWorkLoad = Get-HashMinValue -hashTable $clusterWLHash -lowestPlace $n -howMany 1
							    Post-Message -Message "`tGetting Next Minimum Workload Cluster - $($minClWorkload.value) - $($minClWorkLoad.name)" -WriteToLog $logfile -Interactive $Interactive
							}
                            else{
                                # Storage is good, let's move the VM
                                $destClusterGood = $true
                                
                                if(!($TestOnly)){
                                    # TestOnly flag not set
                                    Migrate-VM -VM $VMMoveObj -VCenter $vc.name -DestinationCluster $minClWorkLoad.name -Hosts $hostsToUse
									$moveSummary += "`tMoved $($VMMoveObj.name) from $($maxClWorkLoad.Name) to $($minClWorkLoad.name) on $($vc.name)`r`n"
                                }
                                else{
                                    # TestOnly flag is set
                                    Post-Message -Message "`tNot actually migrating $($VMMoveObj.name) - in TestOnly mode" -Color yellow -WriteToLog $logfile -Interactive $Interactive
                                    $moveSummary += "`tWould have moved $($VMMoveObj.name) from $($maxClWorkLoad.Name) to $($minClWorkLoad.name) on $($vc.name) - ran in TestOnly mode`r`n"
                                }
                            }
						}
						else{
							#No valid hosts in cluster, need to move on to the next lowest workload cluster
							Post-Message -Message "`tNo valid hosts to use on cluster - $($minClWorkLoad.name)" -WriteToLog $logfile -Interactive $Interactive
							$destClusterGood = $false
							$n++
							$minClWorkLoad = Get-HashMinValue -hashTable $clusterWLHash -lowestPlace $n -howMany 1
							Post-Message -Message "`tGetting Next Minimum Workload Cluster - $($minClWorkload.value) - $($minClWorkLoad.name)" -WriteToLog $logfile -Interactive $Interactive
						}
					}
                    else{
                        # Cluster not online/available to use, need to move on to the next lowest workload cluster
						Post-Message -Message "`tCluster not online/not available to use - $($minClWorkLoad.name)" -WriteToLog $logfile -Interactive $Interactive
						$destClusterGood = $false
						$n++
						$minClWorkLoad = Get-HashMinValue -hashTable $clusterWLHash -lowestPlace $n -howMany 1
						Post-Message -Message "`tGetting Next Minimum Workload Cluster - $($minClWorkload.value) - $($minClWorkLoad.name)" -WriteToLog $logfile -Interactive $Interactive
                    }
				}
				else{
					$destClusterLessAvg = $false
				}
			}
			until(($destClusterGood) -or (!$destClusterLessAvg)) # Search/Validate until good dest cluster found or there are no dest clusters workload less than average
			
            if(!$destClusterLessAvg){
			    # Destination Cluster workload greater than or equal to average, no moves.
			    Post-Message -Message "`tNo valid clusters to use below Average  $($avgClWorkLoadTrim)% workload to move $($VMMoveObj.name) from $($maxClWorkLoad.name) on $($vc.name)" -WriteToLog $logfile -Interactive $Interactive -SlackWebHook $SlackURL -SlackCriticality "critical"
		    }
		} # foreach $VMMove
	} # end for if($vc.value.count -gt 1)
	else{
		if($vc.value.count -lt 2){
			Post-Message -Message "Skipping $($vc.name) - less than 2 clusters - Cluster Count: $($vc.value.count)" -WriteToLog $logfile -Interactive $Interactive
		}
		if($vc.name -in $VCExclude){
			Post-Message -Message "Skipping $($vc.name) - on exclusion list" -WriteToLog $logfile -Interactive $Interactive
		}
	}
} # foreach($vc in $vCenterGroups.GetEnumerator())
$moveSummary += "Cluster Rebalancing Complete"
Post-Message -Message "$($moveSummary)" -WriteToLog $logfile -Interactive $Interactive -SlackWebHook $SlackURL -SlackCriticality "ok"
