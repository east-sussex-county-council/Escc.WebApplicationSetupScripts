# Escc.WebApplicationSetupScripts

A library of Powershell functions useful for setting up web applications running on IIS.

For each application, take a copy of `app-setup-dev.cmd` and `app-setup-dev.ps1` from this project and save them in the root of your application's git repository. Then add setup commands for your project to the end of your copy of `app-setup-dev.ps1`. You can use any PowerShell command as well as the following functions from this library:

## Fetching, moving and copying files

### NormaliseFolderPath($path, $defaultPath) 

Returns the value of `$path` as a valid absolute file path. When `$path` is empty `$defaultPath` is used, which is useful when a script has a path as an optional parameter.

### BackupApplication($applicationFolder, $backupFolder, $comment)

Creates a copy of the `$applicationFolder` in `$backupFolder`. The folder name will include the current time, the user and the `$comment`.

### DownloadProjectIfMissing($parentFolderPath, $projectName)

Before your application can build you may need to download dependencies from other git repositories. To download a repository into a sibling folder of your application, you can use the `$parentFolderOfThisScript` variable. 

`$projectName` is the name of your repository. The full remote URL is built by combining this with a `GIT_ORIGIN_URL` environment variable, which the script will prompt for if it can't find it. 

### NuGetRestoreForProject($parentFolderPath, $projectName)

If you use project references in Visual Studio to include dependencies which are also included in other solutions, the automatic NuGet restore run before a build in Visual Studio may not resolve their dependencies, because the `HintPath` in the project file is wrong. Use this command to restore the NuGet dependencies for those projects before attempting a build.

### CheckApplicationExists($destinationFolder, $application)

Check that application `$application` is already present in `$destinationFolder`.

### CopyConfig($from, $to)

If your git repository contains `web.example.config` files, use this to copy the example files to `web.config` files, with checks to ensure that any existing `web.config` is not overwritten.

### TransformConfig($from, $to, $transformFile)

If your git repository contains `web.example.config` files, use this to copy the example files to `web.config` files, applying an XDT transform to modify the destination file.

## IIS setup

### EnableDotNet40InIIS()

The ASP.NET 4.0 ISAPI modules aren't enabled by default in IIS. This ensures they're activated.

### CreateApplicationPool($applicationPoolName, $classicMode, $dotNet2)

Creates an application pool with the name you specify. By default it runs in Integrated mode using the .NET 4.0 CLR, but set the optional `$classsicMode` parameter to `true` to make it run in Classic mode, and set the optional `$dotNet2` parameter to `true` to make it run using the .NET 2.0 CLR (for .NET 2.0 to 3.5.x).

### CreateWebsite($websiteName, $wwwrootPath, $applicationPoolName)

Creates a new website in IIS using the given details. The `$wwwrootPath` folder will often be the same folder or a child of the folder where your `app-setup-dev.ps1` script runs from. The path to that folder is availalble in a variable called `$pathOfThisScript`. The website does not have any bindings by default.

### CreateSSLCertificate($certificateName)

Creates a self-signed SSL certificate with the name you specify. This certificate is suitable for testing only as your browser will usually display a warning before letting you access a website which uses it. 

If you want to use `localhost` as your domain, you probably don't need to create a certificate as you will already have the IIS Express Development Certificate installed. 

Whichever certificate you use, you can [trust that certificate](http://blogs.adobe.com/livecycle/2012/04/rights-management-how-to-get-windows-7-to-trust-a-self-signed-server-certificate.html) to stop browsers displaying a warning before letting you access a website that uses it.

### CreateHTTPBinding($websiteName, $port)

Use this command to add an HTTP binding to a website. 

* `$port` is optional. The script will prompt the user for a port if it is not specified.

If the website already has an HTTP binding it will report the current binding instead.

### CreateHTTPSBinding($websiteName, $certificateName, $port)

Use this command to add an HTTPS binding to a website. 

* `$certificateName` is optional. If you leave it blank it will look for the IIS Express Development Certificate bound to `localhost`. 
* `$port` is optional. The script will prompt the user for a port if it is not specified.

If the website already has an HTTPS binding it will report the current binding instead.

### RemoveHTTPBinding($websiteName, $port)

This removes an HTTP binding for the specified website on the specified port.

### DisableAnonymousAuthentication($websiteName, $directoryUrl)

Websites have anonymous authentication enabled by default. This disables it. 

`$directoryUrl` is an optional argument which changes authentication just for one part of the site.

	DisableAnonymousAuthentication "Default Web Site" "my-secure-application" 

### EnableWindowsAuthentication($websiteName, $directoryUrl)

Websites have Windows authentication disabled by default. This enables it.

`$directoryUrl` is an optional argument which changes authentication just for one part of the site.

	EnableWindowsAuthentication "Default Web Site" "my-secure-application" 

### CreateVirtualDirectory($websiteName, $virtualDirectoryUrl, $virtualDirectoryPath, $allowScripts, $applicationPoolName)

Creates a virtual directory or application within an existing website. 

* `$virtualDirectoryUrl` is relative to the root of the website. 
* `$virtualDirectoryPath` is the folder on disk the virtual directory should point to. If it doesn't exist it will be created.
* `$allowScripts` is optional. Leave it blank for Read permissions only, or set it to `true` for Read and Script permissions.
* `$applicationPoolName` is optional. Leave it blank to create a simple virtual directory. If specified the virtual directory is set up as an application.  

### CheckSiteExistsBeforeAddingApplication($websiteName)

If your application needs to be set up within an existing IIS website rather than on a website of its own, use this function to check that the site exists. If it doesn't the script will stop with a message saying the parent application needs to be set up first.