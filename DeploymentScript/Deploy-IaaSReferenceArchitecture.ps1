########################################
#                                      #
# Deploy-IaaSReferenceArchitecture.ps1 #
#                                      #
########################################

# ExecutionPolicy set to Unrestricted to run script
# Run as Administrator required
# AzureRM PoSh module required

################################################################################################################
### Verify Environment ###
################################################################################################################

# Verify AzureRM Module is installed
if (Get-Module -ListAvailable -Name AzureRM) {
    Write-Host "AzureRM Module exists... Importing into session"
    Import-Module AzureRM
    } 
    else {
        Write-Host "AzureRM Module will be installed from the PowerShell Gallery"
        Install-Module -Name AzureRM -Force
    }

################################################################################################################
### Predeployment and Orchestration Setup ###
################################################################################################################

Write-Host "`n `n AZURE BLUEPRINT MULTI-TIER IaaS WEB APPLICATION DEPLOYMENT SOLUTION FOR FEDRAMP: Deployment Script `n" -foregroundcolor green
Write-Host "This script can be used for deploying a multi-tier web application architecture with pre-configured security controls to help customers achieve compliance with FedRAMP requirements. See https://github.com/AppliedIS/azure-blueprint for more information. `n " -foregroundcolor yellow
Write-Host "This script will generate default Service Account user names and passwords for your deployment. Note these down once the script completes, and update/change these credentials at your next convenience. If you do change them, bear in mind that the Key Vault will require updating. `n " -foregroundcolor yellow
Write-Host "Press any key to continue ..."

# Global Variables to be used throughout IaaS deployment script
$global:azureUserName = $null
$global:azurePassword = $null
$global:subscriptionId = $null
$global:environmentName = "AzureUSGovernment"
$global:location = "USGov Virginia"
$global:adminUsername = $null
$global:adminPassword = $null
$global:SQLPassword = $null
$global:OMSAdminUsername = $null
$global:ResourceGroupName = "FedRAMP-WebApp-IaaS" 
$global:KeyVaultName = $null
$global:guid = New-Guid

$x = $host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")

# Azure Login
Write-Host "`n LOGIN TO AZURE `n" -foregroundcolor green

$global:azureUserName = Read-Host "Enter your Azure Username"
$global:azurePassword = Read-Host -assecurestring "Enter your Azure Password"
$global:subscriptionId = Read-Host "Enter your Azure SubscriptionID"

function LoginToAzure {
	param(
			[Parameter(Mandatory=$true)]
			[int]$lginCount
	)

	$AzureAuthCreds = New-Object System.Management.Automation.PSCredential -ArgumentList @($global:azureUserName,$global:azurePassword)
	Login-AzureRmAccount -EnvironmentName "AzureUSGovernment" -Credential $AzureAuthCreds

	if($?) {
		Write-Host "Login Successful!" -foregroundcolor green
	} 
    else {
		if ($lginCount -lt 3) {
		$lginCount = $lginCount + 1
	    Write-Host "Invalid Credentials! Please try logging in again." -foregroundcolor red
		LoginToAzure -lginCount $lginCount
		} 
        else {
		    Throw "Your credentials are incorrect or invalid, exceeding the maximum number of retries. Please make sure you are using your Azure Government account information." 
		}
	}
}

# Admin Usernames and Password Generators (randomized to meet complexity requirements)
function GenerateAdmin {
    $alpha = $null; For ($a=65;$a –le 90;$a++) {$alpha+=,[char][byte]$a}
    for ($loop=1; $loop –le 2; $loop++) {$Random+=($alpha | Get-Random)}
    return $random
}
$global:adminUsername = "Admin" + $(GenerateAdmin)
$global:OMSAdminUsername = "OMSAdmin" + $(GenerateAdmin)

function GeneratePassword {
    $ascii = $null; For ($a=48;$a –le 122;$a++) {$ascii+=,[char][byte]$a}
    for ($loop=1; $loop –le 14; $loop++) {$Random+=($ascii | Get-Random)}
    return $random
    if ($random -match " " -and $random -match "[^a-zA-Z0-9]" -and $random -match "[0-9]" -and $random -cmatch "[a-z]" -and $random -cmatch "[A-Z]") {return $random}
    else {GeneratePassword}
}
$global:adminPassword = $(GeneratePassword)
$SSAdminPassword = ConvertTo-SecureString $global:adminPassword -AsPlainText -Force

# SQL Service Account Password Generator
$global:SQLPassword = $(GeneratePassword)
$SSSQLPassword = ConvertTo-SecureString $global:SQLPassword -AsPlainText -Force

# Key Vault Name Generator
$global:KeyVaultName = $global:ResourceGroupName + "-KV"

function orchestration {
	param(
		[string]$subscriptionId = $global:subscriptionId,
        [string]$environmentName = $global:environmentName,
		[string]$location = $global:location,
		[string]$azureUserName = $global:azureUserName,
		[SecureString]$azurePassword = $global:azurePassword,
		[string]$resourceGroupName = $global:ResourceGroupName,
		[string]$keyVaultName = $global:KeyVaultName,
		[string]$adminUsername = $global:adminUsername,
		[SecureString]$adminPassword = $SSAdminPassword,
		[SecureString]$sqlServerServiceAccountPassword = $SSSQLPassword
	)

	$errorActionPreference = 'stop'
	try {
		$Exists = Get-AzureRmSubscription  -SubscriptionId $SubscriptionId
		Write-Host "Using existing authentication"
	}
	catch {
	}
	if (-not $Exists) {
		Write-Host "Authenticate to Azure subscription"
		Add-AzureRmAccount -EnvironmentName $EnvironmentName | Out-String | Write-Verbose
	}
	Write-Host "Selecting subscription as default"
	Select-AzureRmSubscription -SubscriptionId $SubscriptionId | Out-String | Write-Verbose

	########################################################################################################################
	# Create AAD app. Fill in $aadClientSecret variable if AAD app was already created
	########################################################################################################################
            $guid = [Guid]::NewGuid().toString();

            $aadAppName = "Blueprint" + $guid ;
			# Check if AAD app with $aadAppName was already created
			$SvcPrincipals = (Get-AzureRmADServicePrincipal -SearchString $aadAppName);
			if (-not $SvcPrincipals) {
					# Create a new AD application if not created before
					$identifierUri = [string]::Format("http://localhost:8080/{0}",[Guid]::NewGuid().ToString("N"));
					$defaultHomePage = 'http://contoso.com';
					$now = [System.DateTime]::Now;
					$oneYearFromNow = $now.AddYears(1);
					$aadClientSecret = [Guid]::NewGuid();
					Write-Host "Creating new AAD application ($aadAppName)";
					$ADApp = New-AzureRmADApplication -DisplayName $aadAppName -HomePage $defaultHomePage -IdentifierUris $identifierUri  -StartDate $now -EndDate $oneYearFromNow -Password $aadClientSecret;
					$servicePrincipal = New-AzureRmADServicePrincipal -ApplicationId $ADApp.ApplicationId;
					$SvcPrincipals = (Get-AzureRmADServicePrincipal -SearchString $aadAppName);
					if (-not $SvcPrincipals) {
							# AAD app wasn't created
							Write-Error "Failed to create AAD app $aadAppName. Please log-in to Azure using Login-AzureRmAccount  and try again";
							return;
					}
					$aadClientID = $servicePrincipal.ApplicationId;
					Write-Host "Created a new AAD Application ($aadAppName) with ID: $aadClientID ";
			}
			else {
					if (-not $aadClientSecret) {
							$aadClientSecret = Read-Host -Prompt "Aad application ($aadAppName) was already created, input corresponding aadClientSecret and hit ENTER. It can be retrieved from https://manage.windowsazure.com portal" ;
					}
					if (-not $aadClientSecret) {
							Write-Error "Aad application ($aadAppName) was already created. Re-run the script by supplying aadClientSecret parameter with corresponding secret from https://manage.windowsazure.com portal";
							return;
					}
					$aadClientID = $SvcPrincipals[0].ApplicationId;
			}

	########################################################################################################################
	# Create KeyVault or setup existing keyVault
	########################################################################################################################
    Write-Host "`n $resourceGroupName" -foregroundcolor yellow
	Write-Host "Creating resource group $resourceGroupName to hold the Key Vault"

	if (-not (Get-AzureRmResourceGroup -Name $resourceGroupName -Location $location -ErrorAction SilentlyContinue)) {
		New-AzureRmResourceGroup -Name $resourceGroupName -Location $location  | Out-String | Write-Verbose
	}

	# Create a new vault if vault doesn't exist
	if (-not (Get-AzureRMKeyVault -VaultName $keyVaultName -ResourceGroupName $resourceGroupName -ErrorAction SilentlyContinue )) {
		Write-Host "`n $keyVaultName" -foregroundcolor yellow
        Write-Host "Create a Key Vault $keyVaultName to store the Service Principal IDs and Passwords `n "
		New-AzureRMKeyVault -VaultName $keyVaultName -ResourceGroupName $resourceGroupName -EnabledForTemplateDeployment -Location $location | Out-String | Write-Verbose
		Write-Host "Created a new Key Vault named $keyVaultName to store encryption keys";

		# Specify privileges to the vault for the AAD application - https://msdn.microsoft.com/en-us/library/mt603625.aspx
			Write-Host "Set Azure Key Vault Access Policy."
			Write-Host "Set ServicePrincipalName: $aadClientID in Key Vault: $keyVaultName";
			Set-AzureRmKeyVaultAccessPolicy -VaultName $keyVaultName -ServicePrincipalName $aadClientID -PermissionsToKeys wrapKey -PermissionsToSecrets set;

			Set-AzureRmKeyVaultAccessPolicy -VaultName $keyVaultName -ResourceGroupName $resourceGroupName -ServicePrincipalName $aadClientID -PermissionsToKeys backup,get,list,wrapKey -PermissionsToSecrets get,list,set;
			Set-AzureRmKeyVaultAccessPolicy -VaultName $keyVaultName -EnabledForDiskEncryption;

            $keyEncryptionKeyName = $keyVaultName + "kek"

			if ($keyEncryptionKeyName) {
					try {
							$kek = Get-AzureKeyVaultKey -VaultName $keyVaultName -Name $keyEncryptionKeyName -ErrorAction SilentlyContinue;
					}
					catch [Microsoft.Azure.KeyVault.KeyVaultClientException] {
							Write-Host "Couldn't find key encryption key named : $keyEncryptionKeyName in Key Vault: $keyVaultName";
							$kek = $null;
					}
					if (-not $kek) {
							Write-Host "Creating new key encryption key named:$keyEncryptionKeyName in Key Vault: $keyVaultName";
							$kek = Add-AzureKeyVaultKey -VaultName $keyVaultName -Name $keyEncryptionKeyName -Destination Software -ErrorAction SilentlyContinue;
							Write-Host "Created key encryption key named:$keyEncryptionKeyName in Key Vault: $keyVaultName";
					}
					$keyEncryptionKeyUrl = $kek.Key.Kid;
			}

			Write-Host "Set Azure Key Vault Access Policy. Set AzureUserName in Key Vault: $keyVaultName";
			$key = Add-AzureKeyVaultKey -VaultName $keyVaultName -Name 'azureUserName' -Destination 'Software'
			$azureUserNameSecureString = ConvertTo-SecureString $azureUserName -AsPlainText -Force
		    $secret = Set-AzureKeyVaultSecret -VaultName $keyVaultName -Name 'azureUserName' -SecretValue $azureUserNameSecureString

			Write-Host "Set Azure Key Vault Access Policy. Set AzurePassword in Key Vault: $keyVaultName";
			$key = Add-AzureKeyVaultKey -VaultName $keyVaultName -Name 'azurePassword' -Destination 'Software'
		    $secret = Set-AzureKeyVaultSecret -VaultName $keyVaultName -Name 'azurePassword' -SecretValue $azurePassword

			Write-Host "Set Azure Key Vault Access Policy. Set AdminPassword in Key Vault: $keyVaultName";
		    $key = Add-AzureKeyVaultKey -VaultName $keyVaultName -Name 'adminPassword' -Destination 'Software'
		    $secret = Set-AzureKeyVaultSecret -VaultName $keyVaultName -Name 'adminPassword' -SecretValue $adminPassword

			Write-Host "Set Azure Key Vault Access Policy. Set SqlServerServiceAccountPassword in Key Vault: $keyVaultName";
		    $key = Add-AzureKeyVaultKey -VaultName $keyVaultName -Name 'sqlServerServiceAccountPassword' -Destination 'Software'
		    $secret = Set-AzureKeyVaultSecret -VaultName $keyVaultName -Name 'sqlServerServiceAccountPassword' -SecretValue $sqlServerServiceAccountPassword

			Write-Host "Set Azure Key Vault Access Policy. Set Application Client ID in Key Vault: $keyVaultName";
		    $key = Add-AzureKeyVaultKey -VaultName $keyVaultName -Name 'aadClientID' -Destination 'Software'
			$aadClientIDSecureString = ConvertTo-SecureString $aadClientID -AsPlainText -Force
		    $secret = Set-AzureKeyVaultSecret -VaultName $keyVaultName -Name 'aadClientID' -SecretValue $aadClientIDSecureString

			Write-Host "Set Azure Key Vault Access Policy. Set Application Client Secret in Key Vault: $keyVaultName";
			$key = Add-AzureKeyVaultKey -VaultName $keyVaultName -Name 'aadClientSecret' -Destination 'Software'
			$aadClientSecretSecureString = ConvertTo-SecureString $aadClientSecret -AsPlainText -Force
		    $secret = Set-AzureKeyVaultSecret -VaultName $keyVaultName -Name 'aadClientSecret' -SecretValue $aadClientSecretSecureString

			Write-Host "Set Azure Key Vault Access Policy. Set Key Encryption URL in Key Vault: $keyVaultName";
			$key = Add-AzureKeyVaultKey -VaultName $keyVaultName -Name 'keyEncryptionKeyURL' -Destination 'Software'
			$keyEncryptionKeyUrlSecureString = ConvertTo-SecureString $keyEncryptionKeyUrl -AsPlainText -Force
		    $secret = Set-AzureKeyVaultSecret -VaultName $keyVaultName -Name 'keyEncryptionKeyURL' -SecretValue $keyEncryptionKeyUrlSecureString
	}
	Write-Host "This GUID will be used for scheduling the deployment through Azure Resource Manager:" -foregroundcolor magenta;
    Write-Host "`n $($global:guid) `n " -ForegroundColor Green
}

################################################################################################################
### Generate Self-Signed Certifcate ###
################################################################################################################

$FilePath = "$PSScriptRoot\Certs"
$TestCertPath = Test-Path -Path $FilePath
if ($TestCertPath -eq $true) {Write-Host "Certs Directory exists -- Generating certificate" -ForegroundColor Yellow}
else {
    Write-Host "Certs Directory does not exist -- Generating Certs directory before creating the certificate" -ForegroundColor Yellow
    New-Item $FilePath -ItemType Directory
}

$CertPassword = GeneratePassword
$SSCertPassword = ConvertTo-SecureString "$CertPassword" -AsPlainText -Force
$Cert = New-SelfSignedCertificate -certstorelocation cert:\localmachine\my -dnsname contoso.com
$path = 'cert:\localMachine\my\' + $cert.thumbprint
$certPath = $filePath + '\cert.pfx'
$outFilePath = $filePath + '\cert.txt'
Export-PfxCertificate -cert $path -FilePath $certPath -Password $SScertPassword
$fileContentBytes = get-content $certPath -Encoding Byte
[System.Convert]::ToBase64String($fileContentBytes) | Out-File $outFilePath
$CertText = Get-Content -path $outFilePath

################################################################################################################
### Login to Azure, Run Predeployment and Orchestration ###
################################################################################################################

try {
    LoginToAzure -lginCount 1
    Write-Host "Processing automated credential creation for the Administrator and SQL Service Accounts." -foregroundcolor yellow
    Write-Host "`n CREATING CREDENTIALS `n" -foregroundcolor green
    orchestration -azureUsername $global:azureUsername -adminUsername $global:adminUsername -azurePassword $global:azurePassword -adminPassword $SSAdminPassword -sqlServerServiceAccountPassword $SSSQLPassword
}

catch {
    Write-Host $PSItem.Exception.Message
    Write-Host "Thank You"
}

################################################################################################################
### Generate Custom Parameters JSON for FedRAMP IaaS WebApp ARM Deployment ###
################################################################################################################

$JsonPath = "$PSScriptRoot\AzureDeployBlankParameters.Json"
$Json = Get-Content "$JsonPath" -raw | ConvertFrom-Json

### Update Parameters ###

$Json.parameters.adminUsername.value = "$global:adminUsername"
$Json.parameters.certData.value = "$CertText"
$Json.parameters.certPassword.value = "$CertPassword"
$Json.parameters.scheduleJobGuid.value = "$global:guid"
$Json.parameters.omsAutomationAccountName.value = "$global:OMSAdminUsername"

### Create Updated Parameters JSON object ###

$JsonParamPath = "$PSScriptRoot\AzureDeployParameters.Json"
$Json | ConvertTo-Json -Depth 10 -compress | set-content "$JsonParamPath"

################################################################################################################
### Deploy Complete FedRAMP IaaS WebApp ARM Template ###
################################################################################################################

Function RegisterRP {
    Param(
        [string]$ResourceProviderNamespace
    )

    Write-Host "Registering resource provider '$ResourceProviderNamespace'";
    Register-AzureRmResourceProvider -ProviderNamespace $ResourceProviderNamespace;
}

#***********************
# Script body
# Execution begins here
#***********************

$ErrorActionPreference = "Stop"

# select subscription
Write-Host "Selecting subscription '$global:subscriptionId'";
Select-AzureRmSubscription -SubscriptionID $global:subscriptionId;

# Register RPs
$resourceProviders = @("microsoft.resources");
if($resourceProviders.length) {
    Write-Host "Registering resource providers"
    foreach($resourceProvider in $resourceProviders) {
        RegisterRP($resourceProvider);
    }
}

# Create or check for existing resource group
$resourceGroup = Get-AzureRmResourceGroup -Name $global:ResourceGroupName -ErrorAction SilentlyContinue
if(!$resourceGroup)
{
    Write-Host "Resource group '$global:ResourceGroupName' does not exist. To create a new resource group, please enter a location.";
    if(!$global:location) {
        $global:location = Read-Host "resourceGroupLocation";
    }
    Write-Host "Creating resource group '$global:ResourceGroupName' in location '$global:location'";
    New-AzureRmResourceGroup -Name $global:ResourceGroupName -Location $global:location
}
else{
    Write-Host "Using existing resource group '$global:ResourceGroupName'";
}

# Start the deployment
Write-Host "Starting deployment...";
$TestJsonPath = Test-Path -path $JsonParamPath
if($TestJsonPath -eq $True) {
    New-AzureRmResourceGroupDeployment -ResourceGroupName $global:ResourceGroupName -TemplateFile "$PSScriptRoot\AzureDeploy.json" -TemplateParameterFile $JsonParamPath;
} else {
    Write-Host "No Parameters File Found. Verify the Parameters file exists in the script root directory and attempt the deployment again.";
}

################################################################################################################
### Print Relevant Credentials for User to Update/Change ###
################################################################################################################

Write-Host "`n `n AZURE BLUEPRINT MULTI-TIER IaaS WEB APPLICATION DEPLOYMENT SOLUTION FOR FEDRAMP COMPLETE `n" -foregroundcolor green
Write-Host "WARNING---This deployment utilizes randomly generated service accounts and service principals that meet Azure credential complexity requirements---WARNING `n " -foregroundcolor yellow
Write-Host "Please note the following details generated in this deployment. It is recommended that you should update any passwords for further securing your environment. `n " -foregroundcolor Magenta

Write-Host "Deployed in the following location within the $global:environmentName environment:"
Write-Host "`n $global:location `n" -foregroundcolor green
Write-Host "Admin Username is:"
Write-Host "`n $global:adminUsername `n" -foregroundcolor green
Write-Host "OMSAutomationAccount Username is:"
Write-Host "`n $global:OMSAdminUsername `n" -foregroundcolor green
Write-Host "Admin Password for both Admin and OMSAdmin is:"
Write-Host "`n $global:adminPassword `n" -foregroundcolor green
Write-Host "SQL Password is:" 
Write-Host "`n $global:SQLPassword `n" -foregroundcolor green
Write-Host "Your self-signed certificate is stored here:" 
Write-Host "`n $certPath `n" -foregroundcolor green
Write-Host "Certificate Password is:"
Write-Host "`n $CertPassword `n" -foregroundcolor green
Write-Host "WARNING---This deployment utilizes a self-signed certificate for completing the deployment. Though it can be used in production, it is highly recommended to acquire an SSL certificate from an SSL certifcate authority entity---WARNING `n " -foregroundcolor yellow
Write-Host "WARNING---Once this session window is closed, you will not be able to retrieve these credentials. Verify that these credentials are noted and securely stored in a safe location---WARNING `n " -foregroundcolor yellow
Write-Host "WARNING---The Management subnet can be further secured by updating the RDP rule to allow for traffic coming from a specific source. For securing your deployment, it is highly recommended you restrict inbound traffic to trusted IP Address sources only.---WARNING `n " -foregroundcolor yellow

exit