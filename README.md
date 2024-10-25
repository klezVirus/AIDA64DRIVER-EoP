# AIDA64DRIVER-EoP

AIDA64DRIVER Elevation of Privilege Vulnerability

## Latest Driver Tested

AIDA64 Extreme Latest Version 7.00.6742(Beta)

```
$ sha256sum kerneld.x64
eba3233869c744271d5c22e4c1011ce866987d444a00bb78e4089637b7ed794b *kerneld.x64

$ sha256sum kerneld.x32
e06e7891142eb7126893763af2ad72844ac16c7ca5ad50cdfe915f6f8ae9f494 *kerneld.x32
```

## Affected Version

All versions <= 7.00.6742 are vulnerable.

## Root Cause

Permissions to the Driver handle are enforced on user-mode instead of using the Driver Load.

## Disclaimer

The technique used to search for the EPROCESS structure, a sequential kernel memory search in a predefined area of memory (replica from a previous work by [h0mbre](https://twitter.com/h0mbre_)), causes a BSOD if an when it lands on swapped memory. As I don't have any use-case for this vulnerability, I didn't spend any time to stabilize it.

More info on the vulnerability [here](https://belong2yourself.github.io/vulnerabilities/docs/AIDA/Elevation-of-Privileges/readme/).
