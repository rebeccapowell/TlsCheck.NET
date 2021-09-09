# TlsCheck.NET
Checks the TLS versions in a NET Framework 4.0 app host

It is often hard to determine exactly which version of TLS is being actually used by a .NET Application.

This will help you figure out which version is actually being used if you have a .NET Framework 4.0 application(which you can't upgrade).')

The version used is dependent on a number of factors:

- The Windows Server version (and patches that have been installed)
- The .NET Framework versions that is installed
- The .NET Framework version for your app domain (which profile your application host is using)
- The ServicePointManager definition
- Server settings / registry keys

# Notes
- If you defer the application to choose it's own TLS when doing the handshake, it will prefer TLS1.0
- If you specify the TLS versions of TLS1.0, TLS1.1, and TLS1.2 using the ServicePointMAnager, then if available on the target, it will choose TLS11.2.
- In order to support TLS1.2 howver is the install of .NET Framework 4.5 or higher. https://docs.microsoft.com/en-us/dotnet/api/system.net.securityprotocoltype?view=netframework-4.5 assuming you don't want to play around with the registry.'

# Options

## Help
To see the help, run:

```
.\TlsChecker.exe --help
```

## Run in deferred mode
To run the application with no ServicePointManager setup, run:

```
.\TlsChecker.exe --defer=true --host www.google.com
```

## Run with all TLS versions
To run with all versions, TLS1.0, TLS1.1, TLS1.2, TLS1.3, then just run:

```
.\TlsChecker.exe --host www.google.com
```

N.B. If you have .NET Framework installed on the host, then you will find that this might not always work
4.8 contains Tls1.3, but 4.7.1 does not and you will recoeve an error.

## Run with a specific set of versions
To run with a specific set of TLS versions, use the following command

```
.\TlsChecker.exe --host www.google.com --tls Tls,Tl11,Tls12,Tls13
```

You can compile the application and run it run the command line or Powershell from whatever folder you have the binary saved in.

# Conclusion

IF you wish to make sure you are sending and only supporting TLS1.2, you can do the following in a .NET Framework 4.0 app host:

```
ServicePointManager.SecurityProtocol = (SecurityProtocolType)0xc00;
```

IF you want to to prefer TLS1.2, but still support TLS1.1 or TLS1.0, you can do the following:

```
ServicePointManager.SecurityProtocol = (SecurityProtocolType)(0xc0 | 0x300 | 0xc00);
```

The ServicePointManager is set per app domain. I cannot stress that enough.