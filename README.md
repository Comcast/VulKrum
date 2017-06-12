# VulKrum
Given a vRops server and proper credentials, script will collect all vcenter clusters, organize them by vcenter, and find the highest and lowest workload cluster and calculate the average.  Then will determine if workload is caused by CPU or memory, collect stats	on vms that reside on highest workload cluster.  Then migrate those vms to the lowest 	workload cluster.

# Copyright
Copyright 2017 Comcast Cable Communications Management, LLC

# License
Licensed under the Apache License, verison 2.0 (the "License"). See LICENSE file in the project root for full license information.

# Requirements
  - PowerCli - Tested with v6.5
  - vRops - Tested with v6.3
  - vSphere/vCenter - tested with v5.5
  - PowerShell - Tested with v5.1
  - XML credenitals file created with desired credentials
	  - $credential = Get-Credential
	  - $credential | Export-Clixml vmbalance_cred.xml
  - Run As Admin

# Parameters
  - vRopsFQDN
	- Description:  Specify the vRops server
	- Required: TRUE
	- Type:  String
	- Default Value:  $null

  - CredentialPat
	- Description:  Looking for the path to the XML file with credenital for vRops and vCenter
	- Required:  TRUE
	- Type:  String
	- Default Value:  $null

  - LogFilePath
	- Description:  Specify a path for the log file, if not specified it will go to Logs in the directory script is executed from.
	- Required:  FALSE
	- Type:  String
	- Default Value:  $null

  - VCExclustionList
	 - Description:  Text file of vCenters that are to be excluded from process.
	 - Required:  FALSE
	 - Type:  String
	 - Default Value:  $null

  - ClusterExclusionList
	- Description:  Text file of cluster names to be excluded from process.
	- Required:  FALSE
	- Type:  String
	- Default Value:  $null

  - PercentDiff
	- Description:  Integer to designate the percent difference between max and min workload clusters.  If the difference is greater than number specified moves will occur. 
	- Required:  FALSE
	- Type:  Int
	- Default Value:  20
	
  - VMsToMove
	- Description:  Specify the number of VMs to migrate from max to min workload cluster.
	- Required:  FALSE
	- Type:  Int
	- Default Value:  5
	
  - SlackURL
	- Description:  Specify the URL of the webhook app you setup in Slack if you would like to get notifications in a slack channel.
	- Required:  FALSE
	- Type:  String
	- Default Value:  $null

  - TestOnly
	- Description:  To run through entire script, but skip the move part.
	- Required:  FALSE
	- Type:  Switch
	- Default Value:  $false

  - Interactive
	- Description:  To run script and write all log entries to the screen.
	- Required:  FALSE
	- Type:  Switch
	- Default Value:  $false

# Usage
- Example:
  - Testmode and Interactive:
  	- vulkrum.ps1 -vRopsFQDN vrops-vip.cable.comcast.com -CredentialPath vmbalance_cred.xml -VCExclusionList vcexclusionlist.txt -ClusterExclusionList clusterexclusionlist.txt -Interactive -TestOnly
  - Normal Mode:
  	- vulkrum.ps1 -vRopsFQDN vrops-vip.cable.comcast.com -CredentialPath vmbalance_cred.xml -VCExclusionList vcexclusionlist.txt -ClusterExclusionList clusterexclusionlist.txt

# Logging
A log file of all actions will be created in a Log directory in the same directory where the script is executed from.

# Alerting
Script will send error alerts and script complete/summary messages to the a webhook enabled slack channel if specified in the input parameters.

# Release Notes
- Version 1.6 - 3/30/2017
	- Added parameter input to be able to specify the percent difference between max and min workload clusters.  Default value is 20.
	- Added parameter input to be able to specify the number of vms to move.  Default value is 5.
	- If CD Mounted, it gets disconnected.  If VM tools installer is connected, gets disconnected.  These will prevent a move.
	- Removed hardcoded regex to clude specific clusters in the environment.  Added intelligence to use of cluster exclusion list.
	- Moved storage capacity check out of Migrate-VM function.  Each VM is moved after all checks pass versus batching them together.
	- Make use of Slack notification an optional input parameter
