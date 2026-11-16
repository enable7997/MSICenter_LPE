**English** | [한국어](README.ko.md)

# Local Privilege Escalation to SYSTEM in MSI Center's MSIAPService.exe (bypass of the CVE-2026-37452 fix)

| | |
|---|---|
| **CVE ID** | Requested, pending assignment |
| **Published** | 2026-11-16 |
| **Vendor** | Micro-Star International Co., Ltd. (MSI) |
| **Product** | MSI Center → MSI NBFoundation Service |
| **Component** | `MSIAPService.exe` (service `MSI Foundation Service`, runs as `NT AUTHORITY\SYSTEM`) |
| **Affected versions** | MSI Center 2.0.71.0 and later, before 2.0.75.0 (tested: `MSIAPService.exe` 1.1.2606.0101) |
| **Fixed version** | MSI Center **2.0.75.0** (`MSIAPService.exe` 1.1.2610.1201) |
| **Attack vector** | Local (authenticated, low-privileged user) |
| **Impact** | Arbitrary code execution as `NT AUTHORITY\SYSTEM` |
| **CVSS 3.1** | 7.8 High — `AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H` |
| **CWE** | CWE-863, CWE-427 → CWE-269 (enabling factor: CWE-732) |
| **Credit** | Ha Seungwan (@enable7_) |

## Description

MSI Center hands privileged work to its SYSTEM service, `MSIAPService.exe`, over the named pipe
`\\.\pipe\MSI_SERVICE_2`. One of the commands the service accepts, `PC:REXE`, starts any program as
SYSTEM.

To fix CVE-2026-37452, MSI Center 2.0.70.0 began checking the **Authenticode signature of the
client's executable file**. Only a process started from an MSI-signed image may send commands, and
any program requested through `PC:REXE` must pass the same check.

The problem is that this check looks at the file on disk, not at the code running inside the
process. The pipe is still open to every Authenticated User, and MSI's signed .NET programs load
assemblies that are not strong-named by their simple name from their own folder. A standard user can
therefore copy a genuine MSI-signed program into a folder they control and place their own assembly
next to it. The process image passes the signature check, but the code talking to the pipe belongs
to the attacker, who can then use `PC:REXE` to make the service run code as `NT AUTHORITY\SYSTEM`.

The root cause differs from CVE-2026-37452, which relied on a predictable 3DES key. The two issues
share only the final step, where the service launches the process.

## Vulnerable code

From `MSIAPService.exe` 1.1.2606.0101, reconstructed from IL and trimmed:

```csharp
// The pipe is writable by every Authenticated User
string sddl = "D:(A;OICI;GRGW;;;AU)(A;OICI;GA;;;BA)";

// processInputCommand: a client is trusted if its image file is signed by MSI
string path = GetProcessPathById(GetClientPid(pipe));
if (path != "" && CertificationPass(path))
{
    switch (command.ToUpper())
    {
        case "PC": return processInputCommandProcess(...);   // REXE → RunExecuable
        ...
    }
}

// CertificationPass2: Authenticode, signer thumbprint and chain policy, all checked on the file only
static bool CertificationPass2(string path)
{
    if (!VerifyAuthenticodeAndExtractCert(..., path, out var cert)) return false;
    if (!AllowedThumbprints.Contains(cert.Thumbprint))           return false;
    return VerifyCertificateChainPolicy(cert);
}

// RunExecuable: the caller picks the program; the same file check runs, then it starts as SYSTEM
ProcessStartInfo psi = ParseProperties(args);
if (CertificationPass(psi.FileName))
    StartProcessAndBypassUAC(psi, out var pi);   // winlogon token → CreateProcessAsUser
```

## Impact

A low-privileged local user can run arbitrary code as `NT AUTHORITY\SYSTEM` and take full control of
the machine. No UAC prompt, administrator credentials or user interaction is needed.

## Fix

MSI Center 2.0.75.0 keeps the signature check and puts two new checks in front of it. Both apply to
the pipe client and to the program requested through `PC:REXE`:

```csharp
// CertificationPass2 (1.1.2610.1201)
if (!IsPathInProtectedDirectory(path)) return false;   // new: must run from a trusted install folder
if (!IsInAllowedApplication(path))     return false;   // new: must be a known MSI application
// ... Authenticode, thumbprint and chain policy checks, unchanged ...
```

| Check on the client and the `PC:REXE` target | Before | After |
|---|---|---|
| Runs from a protected folder | No | **Yes** |
| Is a known MSI application | No | **Yes** |
| Valid MSI signature, approved signer, chain policy | Yes | Yes |

A signed MSI program copied into a user-writable folder is now rejected before any command is
handled, so the reported attack no longer works.

## Mitigation

Update MSI Center to **2.0.75.0** or later. Under Settings > Apps > Installed apps, "MSI NBFoundation
Service" should show version 2.0.2610.1301 or later. If you don't use the MSI Center features that
depend on it, you can also stop and disable the "MSI Foundation Service".

## Disclosure timeline

| Date | Event |
|---|---|
| 2026-08-18 | Reported to MSI PSIRT as a bypass of the CVE-2026-37452 fix |
| August 2026 | Fix coordinated with MSI by email; pre-release fix builds verified |
| 2026-10-30 | MSI released the fix in MSI Center 2.0.75.0 (Microsoft Store) |

No proof of concept is published.

## References

- MSI Product Security Advisories: <https://csr.msi.com/global/product-security-advisories>
- Related: CVE-2026-37452 (same `PC:REXE` sink, different root cause)

Thanks to MSI PSIRT for confirming the issue and shipping the fix.
