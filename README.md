# TBS-Watchdog
TBS allows a developer to leverage TPM resources and services to ensure system integrity. We can leverage one aspect of the TPM via Platform Configuration Registers (PCRs) and validating values stored in these registers each time at boot.

# Getting Started
The only requirement for this tool is to be running some version of Windows 11 as that ensures the presence of a TPM.

Binaries are provided in the output folder, however, running with the Release binary is highly recommended as the debug comes with Debug dependencies. 

# Executing
Once the binary is dropped to target, one needs to run the binary with administrator privileges to ensure we can talk to the service.

## Example Output
```
C:\Users\psacc\Documents>TBS-Watchdog.exe
Connecting to TBS...
Successfully connected to TBS service!
Dumping Contents of PCR 7...
8a ed be 88 ca f7 89 bd 67 ac 2d f1 86 eb 74 06 f0 73 b5 04 36 ee bf 6e 88 27 ac 47 1f 65 87 17
Closing context to TBS service...
```

# References 
- https://support.microsoft.com/en-us/windows/security/device-security/what-s-a-trusted-platform-module-tpm
- https://learn.microsoft.com/en-us/windows/win32/tbs/using-tbs
- https://learn.microsoft.com/en-us/windows/win32/api/tbs/nf-tbs-tbsip_submit_command
- https://learn.microsoft.com/en-us/windows/win32/tbs/about-tbs
- https://learn.microsoft.com/en-us/windows/win32/tbs/resource-virtualization
- https://learn.microsoft.com/en-us/windows/win32/api/tbs/nf-tbs-tbsip_submit_command
- https://trustedcomputinggroup.org/wp-content/uploads/TPM-Rev-2.0-Part-3-Commands-01.38.pdf
- https://trustedcomputinggroup.org/wp-content/uploads/TPM-Rev-2.0-Part-2-Structures-01.38.pdf
