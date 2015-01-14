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
function CreateApplicationPool($applicationPoolName) {
  if (@(Get-ChildItem IIS:\AppPools | Where-Object {$_.Name -eq $applicationPoolName}).Length -eq 0)
  {
      Write-Host Creating application pool $applicationPoolName
      New-WebAppPool -Name $applicationPoolName
      Set-ItemProperty "IIS:\AppPools\$applicationPoolName" managedRuntimeVersion v4.0
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
function CreateWebsite($websiteName, $wwwroot, $applicationPoolName) {

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
      
      Set-ItemProperty "IIS:\Sites\$websiteName" -Name PhysicalPath -Value $wwwroot
      
      if (!$applicationPoolName) {
        $applicationPoolName = $websiteName
      }
      Set-ItemProperty "IIS:\Sites\$websiteName" -Name ApplicationPool -Value $applicationPoolName
  }
  else
  {
     Write-Host Web site $websiteName already exists
  }
}


# Bind site to a custom port using the SSL certificate created earlier
function CreateHTTPSBinding($websiteName, $port) {

  if (@(Get-ChildItem IIS:\Sites | Where-Object {$_.Name -eq $websiteName}).Length -eq 1)
  {
      if (@(Get-WebBinding -Name $websiteName -Protocol https).Length -eq 0)
      {
          if (!$port) {
            Write-Host
            $port = Read-Host "What HTTPS port would you like the website to use?"
            Write-Host
          }
          Write-Host Binding website $websiteName to port $port using HTTPS

          # Binding code is from comment by Dynamotion on https://social.technet.microsoft.com/Forums/lync/en-US/4f083f00-1f4c-466e-acf8-7ca8bb5baddf/unable-to-enable-https-binding-for-website-using-powershell?forum=winserverpowershell
          New-WebBinding -Name $websiteName -IP "*" -Port $port -Protocol https
          $cert=Get-ChildItem -Path Cert:\LocalMachine\My | where-Object {$_.subject -like "*$websiteName*"} | Select-Object -ExpandProperty Thumbprint
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

function RemoveHTTPBindings($websiteName) {

  if (@(Get-ChildItem IIS:\Sites | Where-Object {$_.Name -eq $websiteName}).Length -eq 1)
  {
      # Remove the default binding to port 80
      if (@(Get-WebBinding -Name $websiteName -Protocol http).Length -ge 1) 
      {
          Write-Host Removing HTTP bindings for web site $projectName
          Remove-WebBinding -Name $websiteName -Protocol http
      }
  }
  else
  {
     Write-Host Web site $websiteName does not exist
  }
}

function CreateVirtualDirectory($websiteName, $virtualDirectoryUrl, $virtualDirectoryPath, $allowScripts) {
  if (@(Get-ChildItem IIS:\Sites | Where-Object {$_.Name -eq $websiteName}).Length -eq 1)
  {
    if (Test-Path "IIS:\Sites\$websiteName\$virtualDirectoryUrl") 
    {
      Write-Host "Virtual directory $virtualDirectoryUrl already exists"
    } 
    else 
    {
      Write-Host "Creating virtual directory $virtualDirectoryUrl"
      
      if ($allowScripts) 
      {
        $accessPolicy = "Read,Script"
      }
      else
      {
        $accessPolicy = "Read"
      }
      
      New-WebVirtualDirectory -Site $projectName -Name $virtualDirectoryUrl -PhysicalPath $virtualDirectoryPath
      Set-WebConfigurationProperty -PSPath "IIS:\Sites\$websiteName\$virtualDirectoryUrl" -Filter '/system.webserver/handlers' -Name accessPolicy -Value $accessPolicy
    }
  }
  else
  {
     Write-Host Web site $websiteName does not exist
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

# Run nuget restore on an individual project
function NuGetRestoreForProject($pathToProjectFolder) {
	if (Get-Command "nuget.exe" -ErrorAction SilentlyContinue) 
	{
		$pathToProjectFolder = $pathToProjectFolder.TrimEnd("/", "\")
		Write-Host "Restoring NuGet packages for $pathToProjectFolder"
		& nuget restore "$pathToProjectFolder\packages.config" -PackagesDirectory "$pathToProjectFolder\packages"
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