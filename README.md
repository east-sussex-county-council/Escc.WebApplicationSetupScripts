# Escc.WebApplicationSetupScripts

A library of Powershell functions useful for setting up development copies of web applications running on IIS.

For each application, take a copy of `app-setup-dev.cmd` and `app-setup-dev.ps1` from this project and save them in the root of your application's git repository. Then add setup commands for your project to the end of your copy of `app-setup-dev.ps1`. You can use any PowerShell command as well as the following functions from this library:

## Functions

### EnableDotNet40InIIS()

The ASP.NET 4.0 ISAPI modules aren't enabled by default in IIS. This ensures they're activated.

### CreateApplicationPool($applicationPoolName, $classicMode)

Creates an ASP.NET 4.0 application pool with the name you specify. By default it runs in Integrated mode, but set the optional `$classsicMode` parameter to `true` to make it run in Classic mode.

### CreateWebsite($websiteName, $wwwrootPath, $applicationPoolName)

Creates a new website in IIS using the given details. The `$wwwrootPath` folder will often be the same folder or a child of the folder where your `app-setup-dev.ps1` script runs from. The path to that folder is availalble in a variable called `$pathOfThisScript`.

### CreateSSLCertificate($certificateName)

Creates a self-signed SSL certificate with the name you specify. This certificate is suitable for testing only as your browser will usually display a warning before letting you access a website which uses it.  

### CreateHTTPSBinding($websiteName, $certificateName, $port)

When you create a new website, by default it has an HTTP binding to port 80. Use this command to add an HTTPS binding. 

* `$certificateName` is optional. If you leave it blank it will look for a certificate with the same name as the website. 
* `$port` is optional. The script will prompt the user for a port if it is not specified.

### RemoveHTTPBindings($websiteName)

When you create a new website, by default it has an HTTP binding to port 80. This removes that binding, and any other HTTP bindings which have been set up.

### CreateVirtualDirectory($websiteName, $virtualDirectoryUrl, $virtualDirectoryPath, $allowScripts, $applicationPoolName)

Creates a virtual directory or application within an existing website. 

* `$virtualDirectoryUrl` is relative to the root of the website. 
* `$virtualDirectoryPath` is the folder on disk the virtual directory should point to.
* `$allowScripts` is optional. Leave it blank for Read permissions only, or set it to `true` for Read and Script permissions.
* `$applicationPoolName` is optional. Leave it blank to create a simple virtual directory. If specified the virtual directory is set up as an application.  

### CheckSiteExistsBeforeAddingApplication($websiteName)

If your application needs to be set up within an existing IIS website rather than on a website of its own, use this function to check that the site exists. If it doesn't the script will stop with a message saying the parent application needs to be set up first.

### CopyConfig($from, $to)

If your git repository contains `web.example.config` files, use this to copy the example files to `web.config` files, with checks to ensure that any existing `web.config` is not overwritten.

### DownloadProjectIfMissing($parentFolderPath, $projectName)

Before your application can build you may need to download dependencies from other git repositories. To download a repository into a sibling folder of your application, you can use the `$parentFolderOfThisScript` variable. 

`$projectName` is the name of your repository. The full remote URL is built by combining this with a `GIT_ORIGIN_URL` environment variable, which the script will prompt for if it can't find it. 

### NuGetRestoreForProject($parentFolderPath, $projectName)

If you use project references in Visual Studio to include dependencies which are also included in other solutions, the automatic NuGet restore run before a build in Visual Studio may not resolve their dependencies, because the `HintPath` in the project file is wrong. Use this command to restore the NuGet dependencies for those projects before attempting a build.