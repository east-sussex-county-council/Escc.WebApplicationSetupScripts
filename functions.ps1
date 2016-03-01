# Check for admin privileges, without which this script will not work
If (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(`
    [Security.Principal.WindowsBuiltInRole] "Administrator"))
{
    Write-Warning "You need to run this script as an Administrator."
    Break
}

# Load IIS commands into session
Import-Module WebAdministration

# Workaround for bug where IIS module takes time to load. Example error message is "Get-ChildItem : Could not load file or assembly 'Microsoft.PowerShell.Commands.Management' 
# or one of its dependencies. The system cannot find the file specified."
# http://stackoverflow.com/questions/14862854/powershell-command-get-childitem-iis-sites-causes-an-error
Sleep 1 

# Functions to ensure ASP.NET 4 is enabled on the IIS server. Script from http://www.ifunky.net/Blog/post/How-To-Enable-IIS-ISAPI-CGI-Restrictions-With-Powershell.aspx
# To use these, just call "EnableDotNet40InIIS"
function Is64Bit  
{  
      [IntPtr]::Size -eq 8  
}  
   
function EnableIsapiRestriction($isapiPath){  
      $isapiConfiguration = get-webconfiguration "/system.webServer/security/isapiCgiRestriction/add[@path='$isapiPath']/@allowed"  
   
      if (!$isapiConfiguration.value){  
           set-webconfiguration "/system.webServer/security/isapiCgiRestriction/add[@path='$isapiPath']/@allowed" -value "True" -PSPath:IIS:\  
           Write-Host "Enabled ISAPI - $isapiPath " -ForegroundColor Green  
      }  
}  
   
function EnableDotNet40Isapi($systemArchitecture){  
      $frameworkPath = "$env:windir\Microsoft.NET\Framework$systemArchitecture\v4.0.30319\aspnet_isapi.dll"  
      EnableIsapiRestriction $frameworkPath       
}  

function EnableDotNet40InIIS() {  
  Write-Host "Ensuring ASP.NET 4.0 ISAPI filter is enabled in IIS"
  if (Is64Bit){  
       EnableDotNet40Isapi "64"  
  }  
  EnableDotNet40Isapi
}

# Create an application pool if it doesn't already exist
function CreateApplicationPool($applicationPoolName, $classicMode, $dotNet2) {
  if (@(Get-ChildItem IIS:\AppPools | Where-Object {$_.Name -eq $applicationPoolName}).Length -eq 0)
  {
      Write-Host Creating application pool $applicationPoolName
      New-WebAppPool -Name $applicationPoolName
      
      if ($classicMode) {
        Set-ItemProperty "IIS:\AppPools\$applicationPoolName" -name managedPipelineMode -value 1
      }

      if ($dotNet2) {
        Set-ItemProperty "IIS:\AppPools\$applicationPoolName" managedRuntimeVersion v2.0
      } else {
        Set-ItemProperty "IIS:\AppPools\$applicationPoolName" managedRuntimeVersion v4.0
      }
  } 
  else 
  {
      Write-Host Application pool $applicationPoolName already exists
  }
}

# Create a self-signed certificate to run the site over SSL, in a way supported by IIS7. Script is from 
# http://blogs.technet.com/b/vishalagarwal/archive/2009/08/22/generating-a-certificate-self-signed-using-powershell-and-certenroll-interfaces.aspx
# The only alteration is changing the string in the second line to the $projectName variable.
function CreateSSLCertificate($certificateName) {
  $sslCertificate = Get-ChildItem 'CERT:\LocalMachine\My' | Where-Object { $_.Subject -ilike "*$certificateName*" };
  if (-not $sslCertificate) {
      
      Write-Host
      Write-Host Creating self-signed SSL certificate $certificateName

      $name = new-object -com "X509Enrollment.CX500DistinguishedName.1"
      $name.Encode("CN=$certificateName", 0)

      $key = new-object -com "X509Enrollment.CX509PrivateKey.1"
      $key.ProviderName = "Microsoft RSA SChannel Cryptographic Provider"
      $key.KeySpec = 1
      $key.Length = 1024
      $key.SecurityDescriptor = "D:PAI(A;;0xd01f01ff;;;SY)(A;;0xd01f01ff;;;BA)(A;;0x80120089;;;NS)"
      $key.MachineContext = 1
      $key.Create()

      $serverauthoid = new-object -com "X509Enrollment.CObjectId.1"
      $serverauthoid.InitializeFromValue("1.3.6.1.5.5.7.3.1")
      $ekuoids = new-object -com "X509Enrollment.CObjectIds.1"
      $ekuoids.add($serverauthoid)
      $ekuext = new-object -com "X509Enrollment.CX509ExtensionEnhancedKeyUsage.1"
      $ekuext.InitializeEncode($ekuoids)

      $cert = new-object -com "X509Enrollment.CX509CertificateRequestCertificate.1"
      $cert.InitializeFromPrivateKey(2, $key, "")
      $cert.Subject = $name
      $cert.Issuer = $cert.Subject
      $cert.NotBefore = get-date
      $cert.NotAfter = $cert.NotBefore.AddDays(90)
      $cert.X509Extensions.Add($ekuext)
      $cert.Encode()

      $enrollment = new-object -com "X509Enrollment.CX509Enrollment.1"
      $enrollment.InitializeFromRequest($cert)
      $certdata = $enrollment.CreateRequest(0)
      $enrollment.InstallResponse(2, $certdata, 0, "")
  }
  else
  {
     Write-Host SSL certificate $certificateName already exists
  }
}

# Create a web site if it doesn't already exist. 
# 3rd parameter optional. Assumes the website uses an application pool with the same name.
function CreateWebsite($websiteName, $wwwrootPath, $applicationPoolName) {

  if (@(Get-ChildItem IIS:\Sites | Where-Object {$_.Name -eq $websiteName}).Length -eq 0)
  {
      Write-Host
      Write-Host Creating web site $websiteName

      # If there are no websites, specify the ID parameter to avoid a Powershell bug
      if (@(Get-ChildItem IIS:\Sites).Length -eq 0)
      {
          New-Website -Name $websiteName -Id 0
      }
      else
      {
          New-Website -Name $websiteName 
      }
      
      Set-ItemProperty "IIS:\Sites\$websiteName" -Name PhysicalPath -Value "$wwwrootPath"
      
      if (!$applicationPoolName) {
        $applicationPoolName = $websiteName
      }
      Set-ItemProperty "IIS:\Sites\$websiteName" -Name ApplicationPool -Value $applicationPoolName

      # Remove the default binding so that we can set up our own bindings without having to clean up first
      RemoveHTTPBinding $websiteName 80
  }
  else
  {
     Write-Host Web site $websiteName already exists
  }
}


# Bind site to a custom port using the SSL certificate created earlier
function CreateHTTPSBinding($websiteName, $certificateName, $port) {

  if (@(Get-ChildItem IIS:\Sites | Where-Object {$_.Name -eq $websiteName}).Length -eq 1)
  {
      # If there are no bindings on any protocol Get-WebBinding throws an exception. This catches it, so that we can test for having no bindings.
      trap [System.Management.Automation.PSArgumentNullException] {
        continue
      }

      $httpsBindings = Get-WebBinding -Name $websiteName -Protocol https
      if (!$httpsBindings)
      {
          if (!$port) {
            Write-Host
            $port = Read-Host "What HTTPS port would you like $websiteName to use?"
            Write-Host
          }
          Write-Host Binding website $websiteName to port $port using HTTPS

          # Binding code is from comment by Dynamotion on https://social.technet.microsoft.com/Forums/lync/en-US/4f083f00-1f4c-466e-acf8-7ca8bb5baddf/unable-to-enable-https-binding-for-website-using-powershell?forum=winserverpowershell
          if (!$certificateName) {
            $certificateName = "localhost"
          }
          
          New-WebBinding -Name $websiteName -IP "*" -Port $port -Protocol https
          $cert=Get-ChildItem -Path Cert:\LocalMachine\My | where-Object {$_.subject -like "*$certificateName*"} | Select-Object -ExpandProperty Thumbprint
          get-item -Path "cert:\localmachine\my\$cert" | new-item -path IIS:\SslBindings\0.0.0.0!$port
      }
      else
      {
          $existingPort = @(Get-WebBinding -Name $websiteName -Protocol https)[0].BindingInformation -replace "[^0-9]", ""
          Write-Host "Web site $websiteName is already bound to port $existingPort"
      }
  }
  else
  {
     Write-Host Web site $websiteName does not exist
  }
}

function CreateHTTPBinding($websiteName, $port) {

  if (@(Get-ChildItem IIS:\Sites | Where-Object {$_.Name -eq $websiteName}).Length -eq 1)
  {
      # If there are no bindings on any protocol Get-WebBinding throws an exception. This catches it, so that we can test for having no bindings.
      trap [System.Management.Automation.PSArgumentNullException] {
        continue
      }

      $httpBindings = Get-WebBinding -Name $websiteName -Protocol http
      if (!$httpBindings)
      {
          if (!$port) {
            Write-Host
            $port = Read-Host "What HTTP port would you like $websiteName to use?"
            Write-Host
          }
          Write-Host Binding website $websiteName to port $port using HTTP

          # Binding code is from comment by Dynamotion on https://social.technet.microsoft.com/Forums/lync/en-US/4f083f00-1f4c-466e-acf8-7ca8bb5baddf/unable-to-enable-https-binding-for-website-using-powershell?forum=winserverpowershell
          New-WebBinding -Name $websiteName -IP "*" -Port $port -Protocol http
      }
      else
      {
          $existingPort = @(Get-WebBinding -Name $websiteName -Protocol http)[0].BindingInformation -replace "[^0-9]", ""
          Write-Host "Web site $websiteName is already bound to port $existingPort"
      }
  }
  else
  {
     Write-Host Web site $websiteName does not exist
  }
}

function RemoveHTTPBinding($websiteName, $port) {

  if (@(Get-ChildItem IIS:\Sites | Where-Object {$_.Name -eq $websiteName}).Length -eq 1)
  {
      if (@(Get-WebBinding -Name $websiteName -Protocol http -Port $port).Length -ge 1) 
      {
          Write-Host Removing HTTP binding for web site $projectName on port $port
          Remove-WebBinding -Name $websiteName -Protocol http -Port $port
      }
  }
  else
  {
     Write-Host Web site $websiteName does not exist
  }
}

function DisableAnonymousAuthentication($websiteName) {
  if (@(Get-ChildItem IIS:\Sites | Where-Object {$_.Name -eq $websiteName}).Length -eq 1)
  {
    Write-Host "Disabling anonymous authentication for $websiteName"
    Set-WebConfigurationProperty -Filter "/system.webServer/security/authentication/anonymousAuthentication" -Name Enabled -Value False -PSPath IIS:\ -Location $websiteName
  }
  else
  {
     Write-Host Web site $websiteName does not exist
  }
}

function EnableWindowsAuthentication($websiteName) {
  if (@(Get-ChildItem IIS:\Sites | Where-Object {$_.Name -eq $websiteName}).Length -eq 1)
  {
    Write-Host "Enabling Windows authentication for $websiteName"
    Set-WebConfigurationProperty -Filter "/system.webServer/security/authentication/windowsAuthentication" -Name Enabled -Value True -PSPath IIS:\ -Location $websiteName
  }
  else
  {
     Write-Host Web site $websiteName does not exist
  }
}

# Creates a virtual directory. If the optional $applicationPoolName is specified, it's setup as an application using that app pool.
function CreateVirtualDirectory($websiteName, $virtualDirectoryUrl, $virtualDirectoryPath, $allowScripts, $applicationPoolName) {
  if (@(Get-ChildItem IIS:\Sites | Where-Object {$_.Name -eq $websiteName}).Length -eq 1)
  {
    if (Test-Path "IIS:\Sites\$websiteName\$virtualDirectoryUrl") 
    {
      if ($applicationPoolName)
      {
        Write-Host "Application $virtualDirectoryUrl already exists"
      }
      else
      {
        Write-Host "Virtual directory $virtualDirectoryUrl already exists"
      }
    } 
    else 
    {
		if ((Test-Path $virtualDirectoryPath) -eq 0) 
		{
			Write-Host "Creating physical directory $virtualDirectoryPath"
			md $virtualDirectoryPath
		}

	  if ($applicationPoolName)
      {
        Write-Host "Creating application $virtualDirectoryUrl"
        New-Item "IIS:\Sites\$websiteName\$virtualDirectoryUrl" -PhysicalPath $virtualDirectoryPath -Type Application
        Set-ItemProperty "IIS:\Sites\$websiteName\$virtualDirectoryUrl" -Name applicationPool -Value $applicationPoolName
      }
      else
      {
        Write-Host "Creating virtual directory $virtualDirectoryUrl"
        New-WebVirtualDirectory -Site $websiteName -Name $virtualDirectoryUrl -PhysicalPath $virtualDirectoryPath
      }
    }
     
    if ($allowScripts) 
    {
        $accessPolicy = "Read,Script"
    }
    else
    {
        $accessPolicy = "Read"
    }
    Write-Host "Setting virtual directory feature permissions to $accessPolicy"
    Set-WebConfigurationProperty -PSPath "IIS:\Sites\$websiteName\$virtualDirectoryUrl" -Filter '/system.webserver/handlers' -Name accessPolicy -Value $accessPolicy
  }
  else
  {
     Write-Host Web site $websiteName does not exist
  }
}

# Make a copy of a folder before changing its contents
function BackupApplication($applicationFolder, $backupFolder, $comment) {

	if ((Test-Path $applicationFolder) -eq 1)
	{
		# Try to make the comment safe for a folder name
		$invalidCharacters = "[{0}]" -f ([Regex]::Escape( [System.IO.Path]::GetInvalidFileNameChars() -join '' ))
		$comment = $comment -replace $invalidCharacters, ""

		# Create a folder for this application
		$path = [System.IO.Path];
		$applicationBackupFolder = $path::GetFileName($path::GetDirectoryName($applicationFolder.Trim() + "/"))

		# Create a folder for this specific backup
		$thisBackupFolder = ("{0} {1} {2}" -f (Get-Date).ToString("s").Replace(":","."), $env:USERNAME, $comment).Trim();
		md -Force "$backupFolder\$applicationBackupFolder\$thisBackupFolder"

		# Copy the entire contents of the source folder to the backup
		robocopy $applicationFolder "$backupFolder\$applicationBackupFolder\$thisBackupFolder" /MIR 
	}
}

# Copy a *.example.config to a *.config file
function CopyConfig($from, $to) {
	if (Test-Path $to) {
		Write-Host "$to already exists"
	} else {
		Copy-Item $from $to
		Write-Host "Created $to"
	}
}

# Copy *.example.config to a *.config file, transforming it using an XDT file
function TransformConfig($from, $to, $transformFile) {

	if ((Test-Path Env:\MSBUILD_PATH) -eq 0)
	{
	  Write-Warning "The MSBUILD_PATH environment variable is not set"
	  Break
	}

	if ((Test-Path $from) -eq 0)
	{
	  Write-Warning "File not found $from"
	  Break
	}

	if ((Test-Path $transformFile) -eq 0)
	{
	  Write-Warning "File not found $transformFile"
	  Break
	}

	$scriptPath = Split-Path -Parent $PSCommandPath
	Invoke-Expression '& ${Env:MSBUILD_PATH} "$scriptPath\TransformConfig.xml" /p:TransformInputFile="$from" /p:TransformFile="$transformFile" /p:TransformOutputFile="$to"'
}

# Run nuget restore on an individual project
function NuGetRestoreForProject($parentFolderPath, $projectName) {
	if (Get-Command "nuget.exe" -ErrorAction SilentlyContinue) 
	{
		$parentFolderPath = $parentFolderPath.TrimEnd("/", "\")
    $projectFolderPath = "$parentFolderPath\$projectName"
		Write-Host "Restoring NuGet packages for $projectFolderPath"
		& nuget restore "$projectFolderPath\packages.config" -PackagesDirectory "$projectFolderPath\packages"
	} else {
		Write-Warning "Unable to restore NuGet packages because nuget.exe was not found in your path. If you get build errors, add nuget.exe to your path and run this script again."
	}
}

# Check root site is set up, so that we can set this up as an application within it
function CheckSiteExistsBeforeAddingApplication($websiteName)
{
  if (@(Get-ChildItem IIS:\Sites | Where-Object {$_.Name -eq $websiteName}).Length -eq 0)
  {
    Write-Warning "You need to set up the $websiteName website first, before adding this application to it. Run app-setup-dev.cmd in the $websiteName project, then try this script again."
    Break
  }
}

# Check another application is already present before installing this one
function CheckApplicationExists($destinationFolder, $application)
{
  if ((Test-Path "$destinationFolder/$application") -eq 0)
  {
    Write-Warning "You need to set up the $application application first, then try this script again."
    Break
  }
}

# Download a project from git if it's not already found
function DownloadProjectIfMissing($parentFolderPath, $projectName) {

  $projectPath = Join-Path -Path $parentFolderPath -ChildPath $projectName
  if (Test-Path $projectPath) {
    Write-Host "Checking $projectName is up-to-date"
    Push-Location $projectPath
    git pull origin master
    Pop-Location
    Write-Host
  } else {
    if ($env:GIT_ORIGIN_URL) {
      $repoUrl = $env:GIT_ORIGIN_URL -f $projectName
      git clone $repoUrl $projectPath
      Write-Host
    } 
    else 
    {
      Write-Warning '$projectName project not found. Please set a GIT_ORIGIN_URL environment variable on your system so that it can be downloaded.
    
  Example: C:\>set GIT_ORIGIN_URL=https://example-git-server.com/{0}"
    
  {0} will be replaced with the name of the repository to download.'
      Return
    }
  }
}

# Ensure any user-submitted paths resolve to an absolute file path
function NormaliseFolderPath($path, $defaultPath) 
{
    if (!$path) 
    {
        $path = $defaultPath 
    } 
    if ($path) 
    {
        $path = $path.Trim()
        if (!$path.StartsWith("\\"))
        {
           $path = Resolve-Path $path
        }
    }
    return $path
}