[![CI Build](https://github.com/glennawatson/SafeSign/actions/workflows/ci.yml/badge.svg)](https://github.com/glennawatson/SafeSign/actions/workflows/ci.yml)
[![Coverage](https://sonarcloud.io/api/project_badges/measure?project=glennawatson_SafeSign&metric=coverage)](https://sonarcloud.io/summary/new_code?id=glennawatson_SafeSign)
[![Reliability Rating](https://sonarcloud.io/api/project_badges/measure?project=glennawatson_SafeSign&metric=reliability_rating)](https://sonarcloud.io/summary/new_code?id=glennawatson_SafeSign)
[![Duplicated Lines (%)](https://sonarcloud.io/api/project_badges/measure?project=glennawatson_SafeSign&metric=duplicated_lines_density)](https://sonarcloud.io/summary/new_code?id=glennawatson_SafeSign)
[![Vulnerabilities](https://sonarcloud.io/api/project_badges/measure?project=glennawatson_SafeSign&metric=vulnerabilities)](https://sonarcloud.io/summary/new_code?id=glennawatson_SafeSign)
[![Security Rating](https://sonarcloud.io/api/project_badges/measure?project=glennawatson_SafeSign&metric=security_rating)](https://sonarcloud.io/summary/new_code?id=glennawatson_SafeSign)
[![NuGet](https://img.shields.io/nuget/v/SafeSign.svg?logo=nuget&label=SafeSign)](https://www.nuget.org/packages/SafeSign/)
[![Downloads](https://img.shields.io/nuget/dt/SafeSign.svg?logo=nuget&label=downloads)](https://www.nuget.org/packages/SafeSign/)
[![GitHub stars](https://img.shields.io/github/stars/glennawatson/SafeSign?style=social)](https://github.com/glennawatson/SafeSign/stargazers)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

<br>
<a href="https://github.com/glennawatson/SafeSign">
  <img width="160" height="160" src="https://raw.githubusercontent.com/glennawatson/SafeSign/main/icons/icon.png" alt="SafeSign">
</a>
<br>

# SafeSign

**SafeSign** is a fast, cross-platform `.NET 10` and `.NET 11` code-signing command-line tool (`safesign`) and modular library suite with standalone **Native AOT** binaries for Linux, macOS, and Windows.

SafeSign implements binary format parsing, Authenticode/CMS ASN.1 DER encoding, RFC 3161 timestamping, and cloud KMS / HSM remote digest signing directly in managed C# without requiring `SignTool.exe`, Windows-only CryptoAPI/CNG Subject Interface Packages (SIPs), or native PKCS #11 middleware.

- **Digest-Only Remote Signing**: Only the cryptographic digest of the CMS signed attributes leaves your machine. Large binaries and installers are streamed locally and never uploaded over the network.
- **Atomic File Output**: Every file format is signed into a sibling temporary file and atomically moved into place only after the provider signature verifies against the X.509 public key and any RFC 3161 timestamp succeeds.
- **Zero-Allocation Hot Paths & Native AOT**: Built with SIMD-accelerated PE checksums (`Vector256<ushort>` / `Vector128<ushort>`), pooled streaming I/O, and source-generated `System.Text.Json` serialization for trimming-safe Native AOT compilation.
- **First-Class Certum SimplySign Support**: Authenticates directly with Certum SimplySign Cloud (`cloudsign.webnotarius.pl`) using user credentials and either a current 6-digit TOTP code or a base32/hex TOTP shared secret, with no desktop tray app or PKCS #11 library required.

---

## Installation

### .NET Global Tool

```bash
dotnet tool install --global SafeSign
```

Once installed, invoke the tool via `safesign`:

```bash
safesign --help
safesign providers
safesign formats
```

### Standalone Native AOT Binaries

Standalone Native AOT executables (requiring no .NET runtime installation) are published on `net11.0` for:

- `linux-x64`
- `osx-arm64`
- `win-x64`

### Library Packages

You can also embed SafeSign's signing engine directly in your own .NET applications:

| Package | Purpose |
| --- | --- |
| `SafeSign.Signing` | Core abstractions (`ISigningProvider`, `IFileFormatSigner`, `SigningSession`), ASN.1 DER CMS / Authenticode builder, RFC 3161 timestamp client, and PE32/PE32+/EFI signer |
| `SafeSign.Formats` | Native format signers for `.msi`/`.msp`/`.mst`, `.cab`, `.cat`, `.appx`/`.msix`, `.navx`, `.nupkg`/`.snupkg`, PowerShell/WSH scripts, and `.rpm` v4 |
| `SafeSign.Providers` | Local (`file`, `store`), Certum SimplySign Cloud (`certum`), and 15 cloud KMS / enterprise signing providers |

---

## Command-Line Interface

### Commands

```text
safesign sign <files>... [options]   Sign one or more files in place (or to --output)
safesign providers                   List all supported signing providers and their status
safesign formats                     List all supported file formats and their status
```

### `safesign sign` Options

| Option | Alias | Description |
| --- | --- | --- |
| `<files>...` | — | One or more files to sign. Format is auto-detected from file extension and magic bytes. |
| `--provider <name>` | `-p` | **Required.** Signing provider name (see [Supported Signing Providers](#supported-signing-providers)). |
| `--provider-option <name=value>` | `-o` | Repeatable provider-specific key/value option (e.g. `-o email=dev@example.com -o totp-secret=JBSWY3DPEHPK3PXP`). All provider options also fall back to provider environment variables. |
| `--output <path>` | — | Output file path. Only valid when signing a single input file; defaults to signing in place. |
| `--hash <alg>` | `-f` | File and CMS digest algorithm: `SHA256` (default), `SHA384`, or `SHA512`. |
| `--timestamp-url <uri>` | `-t` | RFC 3161 timestamp authority URL (e.g. `http://time.certum.pl` or `http://timestamp.digicert.com`). |
| `--timestamp-hash <alg>` | — | Digest algorithm for the RFC 3161 timestamp request: `SHA256` (default), `SHA384`, or `SHA512`. |
| `--description <text>` | `-d` | Program description embedded in Authenticode `SpcSpOpusInfo`. |
| `--description-url <uri>` | `-u` | Program URL embedded in Authenticode `SpcSpOpusInfo`. |

---

## Supported Signing Providers

Run `safesign providers` at any time to inspect the built-in provider catalog. All 18 providers below are fully implemented (`Working`) and configured via `--provider-option` (`-o`) or environment variables:

| Provider ID | Platform / Service | Options (`-o name=value`) & Environment Fallbacks |
| --- | --- | --- |
| `certum` | **Certum SimplySign Cloud** (`cloudsign.webnotarius.pl`) | `email` (`CERTUM_SIMPLYSIGN_EMAIL` / `CERTUM_USER_ID`), and `totp-secret` (`CERTUM_SIMPLYSIGN_TOTP_SECRET` / `CERTUM_OTP_URI` — Base32 seed or `otpauth://` URI) or `otp` (`CERTUM_SIMPLYSIGN_OTP`), or `refresh-token` (`CERTUM_SIMPLYSIGN_REFRESH_TOKEN`), or `access-token` (`CERTUM_SIMPLYSIGN_ACCESS_TOKEN`). Optional: `card-serial`, `certificate-chain-path`, `endpoint`. |
| `file` | **Local PKCS #12 / PFX File** (`.pfx`, `.p12`) | `path` (`SAFESIGN_FILE_PATH`), optional `password` (`SAFESIGN_FILE_PASSWORD`) |
| `store` | **Local X.509 Certificate Store** (`CurrentUser` / `LocalMachine`) | `thumbprint` (`SAFESIGN_STORE_THUMBPRINT`), optional `store-name` (`My`), `store-location` (`CurrentUser` / `LocalMachine`) |
| `aws-kms` | **AWS Key Management Service (KMS)** | `key-id` (`AWS_KMS_KEY_ID`), `certificate-path` (`AWS_KMS_CERTIFICATE_PATH`), `region` (`AWS_REGION` / `AWS_DEFAULT_REGION`), `access-key-id` (`AWS_ACCESS_KEY_ID`), `secret-access-key` (`AWS_SECRET_ACCESS_KEY`), optional `session-token` (`AWS_SESSION_TOKEN`) |
| `azure-artifact-signing` | **Azure Artifact Signing** *(formerly Azure Trusted Signing)* | `endpoint` (`AZURE_CODESIGNING_ENDPOINT`), `account` (`AZURE_CODESIGNING_ACCOUNT`), `profile` (`AZURE_CODESIGNING_PROFILE`), and `access-token` (`AZURE_CODESIGNING_ACCESS_TOKEN`) or `tenant-id` + `client-id` + `client-secret` (`AZURE_TENANT_ID`, `AZURE_CLIENT_ID`, `AZURE_CLIENT_SECRET`) |
| `azure-key-vault` | **Azure Key Vault** | `vault-url` (`AZURE_KEYVAULT_URL`), `key-name` (`AZURE_KEYVAULT_KEY_NAME`), and `access-token` (`AZURE_KEYVAULT_ACCESS_TOKEN`) or `tenant-id` + `client-id` + `client-secret`. Optional: `certificate-name`, `certificate-path`, `key-version`. |
| `google-cloud-kms` | **Google Cloud KMS** | `key-version-name` (`GOOGLE_KMS_KEY_VERSION`), `certificate-path` (`GOOGLE_KMS_CERTIFICATE_PATH`), and `access-token` (`GOOGLE_OAUTH_ACCESS_TOKEN`) |
| `hashicorp-vault` | **HashiCorp Vault Transit Engine** | `address` (`VAULT_ADDR`), `key-name` (`VAULT_TRANSIT_KEY`), `certificate-path` (`VAULT_CERTIFICATE_PATH`), and `token` (`VAULT_TOKEN`; optional `mount=transit`, `namespace`) |
| `oracle-kms` | **Oracle Cloud Infrastructure (OCI) KMS** | `crypto-endpoint` (`OCI_KMS_CRYPTO_ENDPOINT`), `key-id` (`OCI_KMS_KEY_ID`), `certificate-path` (`OCI_KMS_CERTIFICATE_PATH`), `tenancy-ocid` (`OCI_TENANCY_OCID`), `user-ocid` (`OCI_USER_OCID`), `fingerprint` (`OCI_FINGERPRINT`), `private-key-path` (`OCI_PRIVATE_KEY_PATH`) |
| `digicert-keylocker` | **DigiCert ONE / KeyLocker** | `keypair-id` (`DIGICERT_KEYPAIR_ID`), `api-key` (`DIGICERT_API_KEY`), and `certificate-id` (`DIGICERT_CERTIFICATE_ID`) or `certificate-path` (optional `endpoint`) |
| `sslcom-esigner` | **SSL.com eSigner** (CSC API) | `credential-id` (`SSLCOM_CREDENTIAL_ID`), `username` (`SSLCOM_USERNAME`), `password` (`SSLCOM_PASSWORD`), and `totp-secret` (`SSLCOM_TOTP_SECRET`) or `otp` (`SSLCOM_OTP`) |
| `csc` | **Cloud Signature Consortium (CSC) v1/v2** *(Sectigo, Entrust, GlobalSign, SwissSign, CertEurope)* | `endpoint` (`CSC_ENDPOINT`), `credential-id` (`CSC_CREDENTIAL_ID`), `access-token` (`CSC_ACCESS_TOKEN`) or `client-id` + `client-secret`, and `pin` (`CSC_PIN`) / `otp` (`CSC_OTP`) / `sad` (`CSC_SAD`) |
| `keyfactor-signserver` | **Keyfactor SignServer** | `endpoint` (`SIGNSERVER_ENDPOINT`), `worker` (`SIGNSERVER_WORKER`), `certificate-path` (`SIGNSERVER_CERTIFICATE_PATH`), optional `access-token` (`SIGNSERVER_ACCESS_TOKEN`) |
| `fortanix-dsm` | **Fortanix Data Security Manager (DSM)** | `endpoint` (`FORTANIX_ENDPOINT`), `key-id` (`FORTANIX_KEY_ID`), `certificate-path` (`FORTANIX_CERTIFICATE_PATH`), and `api-key` (`FORTANIX_API_KEY`) |
| `encryption-consulting` | **Encryption Consulting CodeSign Secure** | `endpoint` (`CODESIGNSECURE_ENDPOINT`), `key-name` (`CODESIGNSECURE_KEY_NAME`), `certificate-path` (`CODESIGNSECURE_CERTIFICATE_PATH`), `api-key` (`CODESIGNSECURE_API_KEY`) |
| `garasign` | **GaraSign (Garantir)** | `endpoint` (`GARASIGN_ENDPOINT`), `key-name` (`GARASIGN_KEY_NAME`), `username` (`GARASIGN_USERNAME`), `password` (`GARASIGN_PASSWORD`), optional `certificate-path` |
| `signpath` | **SignPath** | `organization-id` (`SIGNPATH_ORGANIZATION_ID`), `project-slug` (`SIGNPATH_PROJECT_SLUG`), `signing-policy-slug` (`SIGNPATH_SIGNING_POLICY_SLUG`), `api-token` (`SIGNPATH_API_TOKEN`), `certificate-path` (`SIGNPATH_CERTIFICATE_PATH`) |
| `venafi-codesign` | **Venafi CodeSign Protect (TPP)** | `endpoint` (`VENAFI_ENDPOINT`), `environment-dn` (`VENAFI_ENVIRONMENT_DN`), `certificate-path` (`VENAFI_CERTIFICATE_PATH`), and `access-token` (`VENAFI_ACCESS_TOKEN`) |

### Usage Examples

#### 1. Sign a Windows PE executable, MSI installer, and NuGet package with Certum SimplySign Cloud

```bash
export CERTUM_USER_ID="developer@example.com"
export CERTUM_OTP_URI="otpauth://totp/Certum:developer@example.com?secret=JBSWY3DPEHPK3PXP&algorithm=SHA256&digits=6&period=30"

safesign sign artifacts/MyApp.exe artifacts/MyAppSetup.msi artifacts/MyPackage.1.0.0.nupkg \
  --provider certum \
  --hash SHA256 \
  --timestamp-url http://time.certum.pl \
  --description "MyApp" \
  --description-url https://example.com
```

#### 2. Sign with Azure Artifact Signing (formerly Azure Trusted Signing)

```bash
safesign sign bin/Release/net11.0/win-x64/publish/MyApp.exe \
  --provider azure-artifact-signing \
  -o endpoint=https://eus.codesigning.azure.net \
  -o account=my-signing-account \
  -o profile=my-public-trust-profile \
  -o access-token="$AZURE_CODESIGNING_ACCESS_TOKEN" \
  --timestamp-url http://timestamp.acs.microsoft.com
```

#### 3. Sign a NuGet package, MSIX bundle, and PowerShell script with a local PFX certificate

```bash
safesign sign MyLibrary.1.0.0.nupkg MyApp.msix Deploy.ps1 \
  --provider file \
  -o path=certs/codesign.pfx \
  -o password="$PFX_PASSWORD" \
  --timestamp-url http://timestamp.digicert.com
```

#### 4. Sign an RPM package with AWS KMS

```bash
safesign sign dist/myapp-1.0.0-1.x86_64.rpm \
  --provider aws-kms \
  -o region=us-east-1 \
  -o key-id=arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012 \
  -o certificate-path=certs/aws-codesign.cer
```

---

## Supported File Formats

Run `safesign formats` to view all registered format handlers. SafeSign implements native format signing for each format below (never substituting detached signatures for embedded format signatures):

| Format | Extensions | Implementation Details | Status |
| --- | --- | --- | --- |
| **PE / UEFI** | `.exe`, `.dll`, `.efi` | Authenticode `SPC_PE_IMAGE_DATA` PKCS #7 signature in the PE Certificate Table (`IMAGE_DIRECTORY_ENTRY_SECURITY`) with 8-byte alignment and SIMD PE header checksum update | `Working` |
| **Windows Installer** | `.msi`, `.msp`, `.mst` | OLE Compound File Binary (CFB v3/v4) parser/writer embedding `\x05DigitalSignature` (`SPC_SIPINFO` GUID `000C10F1-0000-0000-C000-000000000046`) and `\x05MsiDigitalSignatureEx` | `Working` |
| **Cabinet** | `.cab` | Microsoft Cabinet (`MSCF`) header `CFHEADER_RESERVE_PRESENT` (20-byte reserve) and `WIN_CERTIFICATE` Authenticode `SPC_CAB_DATA` structure | `Working` |
| **Security Catalog** | `.cat` | ASN.1 DER `CertTrustList` (`1.3.6.1.4.1.311.10.1`) re-signing inside outer CMS `SignedData` while preserving catalog member hashes and attributes | `Working` |
| **AppX / MSIX** | `.appx`, `.msix`, `.appxbundle`, `.msixbundle` | `AppxBlockMap.xml`, `AppxMetadata/CodeIntegrity.cat`, and `[Content_Types].xml` `APPX_AXPC`/`APPX_AXCD`/`APPX_AXCI`/`APPX_AXCT` digest calculation and `AppxSignature.p7x` (`PKCX` prefix + Authenticode `SPC_SIPINFO`) | `Working` |
| **Dynamics 365 NAVX** | `.navx` | `NAVX` 40-byte package header + OPC ZIP payload digest and `NVSG` signature trailer (`SPC_SIPINFO` GUID `F5256E31-BA25-4468-ABA9-AB9B38F6F138`) | `Working` |
| **NuGet Package** | `.nupkg`, `.snupkg` | NuGet v1 `.signature.p7s` Primary Author Signature with RFC 5035 `SigningCertificateV2` (`1.2.840.113549.1.9.16.2.47`), `commitment-type-indication` (`1.2.840.113549.1.9.16.6.1`), and Central Directory hash | `Working` |
| **Scripts** | `.ps1`, `.psm1`, `.psd1`, `.ps1xml`, `.cdxml`, `.psc1`, `.vbs`, `.vbe`, `.js`, `.wsf` | UTF-16LE Authenticode `SPC_SIPINFO` digest and native `# SIG #` / `<!-- SIG # -->` / `'' SIG ''` / `// SIG //` base64 signature blocks preserving BOM and encoding | `Working` |
| **RPM v4** | `.rpm` | RPM v4 Lead + Signature Header reconstruction embedding CMS/PKCS #7 DER signatures in tags `268` (`RPMSIGTAG_RSA` / header-only) and `269` (`RPMSIGTAG_PGP` / header+payload) | `Working` |
| **Debian Package** | `.deb`, `.udeb` | Uses `ar` archives (`debsigs` / `dpkg-sig`) with OpenPGP (RFC 4880) signatures rather than X.509/CMS. OpenPGP is out of scope for SafeSign. | `OutOfScope` |

---

## Programmatic Usage

```csharp
using System.Security.Cryptography;
using Refit;
using SafeSign.Formats;
using SafeSign.Providers.Certum;
using SafeSign.Signing;
using SafeSign.Signing.Cms;

var provider = new CertumSimplySignProvider(
    new RefitSettings(),
    new CertumOptions
    {
        Email = "developer@example.com",
        TotpSecret = "JBSWY3DPEHPK3PXP",
    },
    TimeProvider.System);

var certificate = await provider.GetCertificateAsync(CancellationToken.None);
var timestampApi = RestService.ForGenerated<IRfc3161TimestampApi>("http://time.certum.pl");
var session = new SigningSession(
    provider,
    certificate,
    HashAlgorithmName.SHA256,
    new TimestampSettings(new Uri("http://time.certum.pl"), HashAlgorithmName.SHA256, timestampApi),
    Description: "My Application",
    DescriptionUrl: new Uri("https://example.com"),
    TimeProvider.System);

var signer = await FormatCatalog.ResolveSignerAsync("MyApp.exe", CancellationToken.None);
await signer.SignAsync(new FileSignRequest("MyApp.exe", "MyApp.exe", session), CancellationToken.None);
```

---

## Repository Layout

| Project | Purpose |
| --- | --- |
| `src/SafeSign.Signing` | Core signing abstractions, CMS / Authenticode DER encoder, RFC 3161 client, and PE/EFI signer |
| `src/SafeSign.Formats` | Native format signers for MSI, CAB, CAT, AppX/MSIX, NAVX, NuGet, Scripts, and RPM |
| `src/SafeSign.Providers` | Local (`file`, `store`), Certum SimplySign Cloud, and 15 cloud KMS / enterprise signing providers |
| `src/SafeSign` | `safesign` CLI global tool and standalone Native AOT entry point |
| `src/tests/*` | TUnit test suites across `net10.0` and `net11.0` |
| `src/benchmarks/SafeSign.Benchmarks` | BenchmarkDotNet speed benchmarks and thread/heap allocation justification audit (`--alloc`) |

---

## Building, Testing, and Benchmarking

Run these commands from `src/`:

```bash
# Build all projects across net10.0 and net11.0
dotnet build SafeSign.slnx -c Release

# Run TUnit test suites
dotnet test --project tests/SafeSign.Signing.Tests/SafeSign.Signing.Tests.csproj -c Release
dotnet test --project tests/SafeSign.Formats.Tests/SafeSign.Formats.Tests.csproj -c Release
dotnet test --project tests/SafeSign.Providers.Tests/SafeSign.Providers.Tests.csproj -c Release
dotnet test --project tests/SafeSign.Tests/SafeSign.Tests.csproj -c Release

# Run the allocation justification audit (verifies against allocations-explained.json)
dotnet run --project benchmarks/SafeSign.Benchmarks/SafeSign.Benchmarks.csproj -c Release -f net11.0 -- --alloc

# Run BenchmarkDotNet speed benchmarks
dotnet run --project benchmarks/SafeSign.Benchmarks/SafeSign.Benchmarks.csproj -c Release -f net11.0 -- --filter 'SafeSign.Benchmarks.SafeSignBenchmarks.*' --job short

# Publish a standalone Native AOT executable (net11.0)
dotnet publish SafeSign/SafeSign.csproj -c Release -f net11.0 -r linux-x64 -p:PublishAot=true
```

---

## License

MIT — see [LICENSE](LICENSE).

## Acknowledgements

SafeSign was implemented independently from Microsoft Authenticode, PKCS #7 / CMS (RFC 5652), RFC 3161, OPC, OLE CFB, RPM v4, and vendor REST API specifications. The following projects provided inspiration:

- [jsign](https://github.com/ebourg/jsign) (Apache-2.0) by Emmanuel Bourg
- [dotnet/sign](https://github.com/dotnet/sign) (MIT) by the .NET Foundation
- [ssign](https://github.com/Le-Syl21/ssign) (MIT) by Le-Syl21
