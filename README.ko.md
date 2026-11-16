[English](README.md) | **한국어**

# MSI Center MSIAPService.exe의 SYSTEM 권한 상승 취약점 (CVE-2026-37452 패치 우회)

| | |
|---|---|
| **CVE ID** | 요청 완료, 발급 대기 중 |
| **권고문 공개일** | 2026-11-16 |
| **벤더** | Micro-Star International Co., Ltd. (MSI) |
| **제품** | MSI Center → MSI NBFoundation Service |
| **구성 요소** | `MSIAPService.exe` (서비스명 `MSI Foundation Service`, `NT AUTHORITY\SYSTEM` 권한으로 실행) |
| **영향받는 버전** | MSI Center 2.0.71.0 이상, 2.0.75.0 미만 (테스트 환경: `MSIAPService.exe` 1.1.2606.0101) |
| **패치 버전** | MSI Center **2.0.75.0** (`MSIAPService.exe` 1.1.2610.1201) |
| **공격 벡터** | 로컬 (인증된 저권한 사용자) |
| **영향** | `NT AUTHORITY\SYSTEM` 권한으로 임의 코드 실행 |
| **CVSS 3.1** | 7.8 High — `AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H` |
| **CWE** | CWE-863, CWE-427 → CWE-269 (기여 요인: CWE-732) |
| **발견자** | 하승완 (@enable7_) |

## 개요

MSI Center는 관리자 권한이 필요한 작업이 있으면 Named Pipe `\\.\pipe\MSI_SERVICE_2`를 통해 SYSTEM
서비스인 `MSIAPService.exe`에 요청합니다. 서비스가 받는 명령 가운데 `PC:REXE`는 지정한
프로그램을 SYSTEM 권한으로 실행합니다.

MSI는 CVE-2026-37452를 고치면서 MSI Center 2.0.70.0부터 **클라이언트 실행 파일의 Authenticode 서명**을
확인하도록 했습니다. MSI가 서명한 실행 파일로 시작된 프로세스만 명령을 보낼 수 있고, `PC:REXE`로
실행을 요청한 프로그램도 같은 검사를 통과해야 합니다.

문제는 이 검사가 디스크에 있는 파일만 확인하고, 프로세스 안에서 실제로 돌아가는 코드는 확인하지
않는다는 점입니다. 파이프는 여전히 모든 인증된 사용자에게 열려 있습니다. 또한 MSI가 서명한 .NET
프로그램은 Strong Name이 없는 어셈블리(DLL)를 자기 폴더에서 파일 이름만 보고 불러옵니다.
그래서 표준 사용자는 정상적인 MSI 서명 프로그램을 자신이 쓸 수 있는 폴더로 복사하고, 그 옆에 자신이
만든 어셈블리를 두는 것만으로 공격을 준비할 수 있습니다. 프로세스의 실행 파일은 서명 검사를
통과하지만, 실제로 파이프와 통신하는 코드는 공격자의 것입니다. 공격자는 이어서 `PC:REXE`를 보내
서비스가 자신의 코드를 `NT AUTHORITY\SYSTEM` 권한으로 실행하게 만들 수 있습니다.

CVE-2026-37452는 예측 가능한 3DES 키가 원인이었으므로 이번 취약점과 근본 원인이 다릅니다. 두
취약점이 공유하는 것은 서비스가 프로세스를 실행하는 마지막 단계뿐입니다.

## 취약한 코드

`MSIAPService.exe` 1.1.2606.0101의 취약한 코드 부분:

```csharp
// 모든 인증된 사용자가 파이프에 쓸 수 있음
string sddl = "D:(A;OICI;GRGW;;;AU)(A;OICI;GA;;;BA)";

// processInputCommand: 실행 파일이 MSI 서명이면 클라이언트를 신뢰
string path = GetProcessPathById(GetClientPid(pipe));
if (path != "" && CertificationPass(path))
{
    switch (command.ToUpper())
    {
        case "PC": return processInputCommandProcess(...);   // REXE → RunExecuable
        ...
    }
}

// CertificationPass2: Authenticode, 서명자 지문, 인증서 체인 정책을 모두 파일에만 적용
static bool CertificationPass2(string path)
{
    if (!VerifyAuthenticodeAndExtractCert(..., path, out var cert)) return false;
    if (!AllowedThumbprints.Contains(cert.Thumbprint))           return false;
    return VerifyCertificateChainPolicy(cert);
}

// RunExecuable: 호출자가 고른 프로그램을 같은 파일 검사만 거쳐 SYSTEM 권한으로 실행
ProcessStartInfo psi = ParseProperties(args);
if (CertificationPass(psi.FileName))
    StartProcessAndBypassUAC(psi, out var pi);   // winlogon 토큰 → CreateProcessAsUser
```

## 영향

저권한 로컬 사용자가 `NT AUTHORITY\SYSTEM` 권한으로 임의 코드를 실행해 시스템 전체를 장악할 수
있습니다. UAC 확인 창, 관리자 계정 정보, 다른 사용자의 조작이 전혀 필요하지 않습니다.

## 패치 내용

MSI Center 2.0.75.0은 기존 서명 검사를 그대로 두고, 그 앞에 두 가지 검사를 새로 추가했습니다. 두
검사는 파이프 클라이언트와 `PC:REXE`로 실행을 요청한 프로그램 모두에 적용됩니다.

```csharp
// CertificationPass2 (1.1.2610.1201)
if (!IsPathInProtectedDirectory(path)) return false;   // 신규: 신뢰된 설치 폴더에서 실행되어야 함
if (!IsInAllowedApplication(path))     return false;   // 신규: 등록된 MSI 애플리케이션이어야 함
// ... Authenticode, 지문, 체인 정책 검사는 기존과 동일 ...
```

| 클라이언트와 `PC:REXE` 대상에 대한 검사 | 패치 전 | 패치 후 |
|---|---|---|
| 보호된 폴더에서 실행되는가 | 아니오 | **예** |
| 등록된 MSI 애플리케이션인가 | 아니오 | **예** |
| 유효한 MSI 서명, 승인된 서명자, 체인 정책 | 예 | 예 |

이제 사용자가 쓸 수 있는 폴더로 복사한 MSI 서명 프로그램은 명령을 처리하기 전에 거부되므로, 보고한
공격은 더 이상 통하지 않습니다.

## 대응 방법

MSI Center를 **2.0.75.0** 이상으로 업데이트하십시오. 설정 > 앱 > 설치된 앱에서 "MSI NBFoundation
Service" 버전이 2.0.2610.1301 이상이면 패치가 적용된 것입니다. 이 서비스가 필요한 MSI Center 기능을
쓰지 않는다면 "MSI Foundation Service"를 중지하고 사용 안 함으로 설정해도 됩니다.

## 공개 일정

| 날짜 | 내용 |
|---|---|
| 2026-08-18 | CVE-2026-37452 패치 우회 취약점으로 MSI PSIRT에 제보 |
| 2026년 8월 | MSI와 이메일로 패치 방향 조율, 사전 배포 패치 빌드 검증 |
| 2026-10-30 | MSI Center 2.0.75.0으로 패치 배포 (Microsoft Store) |

개념 증명(PoC) 코드는 공개하지 않습니다.

## 참고 자료

- MSI Product Security Advisories: <https://csr.msi.com/global/product-security-advisories>
- 관련 취약점: CVE-2026-37452 (`PC:REXE` 실행 지점은 같으나 근본 원인이 다름)

취약점을 확인하고 패치를 배포해 준 MSI PSIRT에 감사드립니다.
