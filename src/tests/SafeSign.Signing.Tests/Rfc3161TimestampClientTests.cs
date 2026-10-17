// Copyright (c) 2026 Glenn Watson and Contributors. All rights reserved.
// Glenn Watson and Contributors licenses this file to you under the MIT license.
// See the LICENSE file in the project root for full license information.

using System.Formats.Asn1;
using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;
using Refit.Testing;
using SafeSign.Signing.Cms;

namespace SafeSign.Signing.Tests;

/// <summary>Verifies RFC 3161 timestamp requests and token validation using <see cref="StubHttp"/>.</summary>
public sealed class Rfc3161TimestampClientTests
{
    /// <summary>The RSA key size for the synthetic timestamp authority.</summary>
    private const int TsaKeySize = 2048;

    /// <summary>The timestamping extended key usage OID.</summary>
    private const string TimeStampingEkuOid = "1.3.6.1.5.5.7.3.8";

    /// <summary>The id-ct-TSTInfo OID.</summary>
    private const string TstInfoOid = "1.2.840.113549.1.9.16.1.4";

    /// <summary>The TSA policy OID used in synthetic responses.</summary>
    private const string TsaPolicyOid = "1.3.6.1.4.1.99999.1";

    /// <summary>The synthetic digest length in bytes.</summary>
    private const int SampleInputLength = 64;

    /// <summary>Sends an RFC 3161 timestamp request to a <see cref="StubHttp"/> TSA responder and verifies the returned signed token.</summary>
    /// <returns>A task representing the asynchronous test operation.</returns>
    [Test]
    public async Task RequestAsync_ValidatesAndExtractsSignedTimestampToken()
    {
        using var tsaCert = CreateTsaCertificate();
        using var http = new StubHttp
        {
            {
                Route.Post("/timestamp"),
                Reply.From(async (httpRequest, ct) =>
                {
                    var requestBytes = await httpRequest.Content!.ReadAsByteArrayAsync(ct);
                    var responseBytes = BuildTimeStampResp(requestBytes, tsaCert);
                    var response = new HttpResponseMessage(HttpStatusCode.OK) { Content = new ByteArrayContent(responseBytes) };
                    response.Content.Headers.ContentType = new("application/timestamp-reply");
                    return response;
                })
            },
        };

        var api = http.CreateGeneratedClient<IRfc3161TimestampApi>("https://tsa.example.test");
        var signatureBytes = new byte[SampleInputLength];
        RandomNumberGenerator.Fill(signatureBytes);

        var settings = new TimestampSettings(new Uri("https://tsa.example.test/timestamp"), HashAlgorithmName.SHA256, api);
        var tokenBytes = await Rfc3161TimestampClient.RequestAsync(settings, signatureBytes, CancellationToken.None);

        await http.VerifyAllCalledAsync();
        await Assert.That(http.Requests[0].Content?.Headers.ContentType?.MediaType).IsEqualTo("application/timestamp-query");
        await Assert.That(Rfc3161TimestampToken.TryDecode(tokenBytes, out var token, out _)).IsTrue();
        await Assert.That(token).IsNotNull();
    }

    /// <summary>Creates a self-signed certificate with the critical id-kp-timeStamping EKU required by RFC 3161.</summary>
    /// <returns>The TSA certificate with private key.</returns>
    private static X509Certificate2 CreateTsaCertificate()
    {
        var now = TimeProvider.System.GetUtcNow();
        using var rsa = RSA.Create(TsaKeySize);
        var req = new CertificateRequest("CN=SafeSign Test TSA", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        req.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension([new(TimeStampingEkuOid)], critical: true));
        req.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, critical: true));
        return req.CreateSelfSigned(now.AddDays(-1), now.AddYears(1));
    }

    /// <summary>Builds a DER-encoded RFC 3161 TimeStampResp for the given request bytes.</summary>
    /// <param name="requestBytes">The DER-encoded TimeStampReq.</param>
    /// <param name="tsaCert">The TSA signing certificate.</param>
    /// <returns>The DER-encoded TimeStampResp.</returns>
    /// <exception cref="InvalidOperationException">The request bytes could not be decoded.</exception>
    private static byte[] BuildTimeStampResp(byte[] requestBytes, X509Certificate2 tsaCert)
    {
        if (!Rfc3161TimestampRequest.TryDecode(requestBytes, out var request, out _))
        {
            throw new InvalidOperationException("Failed to decode RFC 3161 request.");
        }

        var tstWriter = new AsnWriter(AsnEncodingRules.DER);
        using (tstWriter.PushSequence())
        {
            tstWriter.WriteInteger(1);
            tstWriter.WriteObjectIdentifier(TsaPolicyOid);
            using (tstWriter.PushSequence())
            {
                using (tstWriter.PushSequence())
                {
                    tstWriter.WriteObjectIdentifier(request.HashAlgorithmId.Value!);
                    tstWriter.WriteNull();
                }

                tstWriter.WriteOctetString(request.GetMessageHash().Span);
            }

            tstWriter.WriteInteger(1);
            tstWriter.WriteGeneralizedTime(TimeProvider.System.GetUtcNow(), omitFractionalSeconds: true);
            if (request.GetNonce() is { } nonce)
            {
                tstWriter.WriteInteger(nonce.Span);
            }
        }

        var contentInfo = new ContentInfo(new Oid(TstInfoOid), tstWriter.Encode());
        var signedCms = new SignedCms(contentInfo, detached: false);
        var signer = new CmsSigner(SubjectIdentifierType.IssuerAndSerialNumber, tsaCert) { DigestAlgorithm = new(CmsOids.Sha256), IncludeOption = X509IncludeOption.EndCertOnly };
        _ = signer.SignedAttributes.Add(new AsnEncodedData(new Oid(CmsOids.SigningCertificateV2), CmsAttributes.EncodeSigningCertificateV2Value(tsaCert)));
        signedCms.ComputeSignature(signer);
        var tokenDer = signedCms.Encode();

        var respWriter = new AsnWriter(AsnEncodingRules.DER);
        using (respWriter.PushSequence())
        {
            using (respWriter.PushSequence())
            {
                respWriter.WriteInteger(0);
            }

            respWriter.WriteEncodedValue(tokenDer);
        }

        return respWriter.Encode();
    }
}
