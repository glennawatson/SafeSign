// Copyright (c) 2026 Glenn Watson and Contributors. All rights reserved.
// Glenn Watson and Contributors licenses this file to you under the MIT license.
// See the LICENSE file in the project root for full license information.

using System.Runtime.CompilerServices;
using System.Security.Cryptography.X509Certificates;
using SafeSign.Signing;

namespace SafeSign.Providers.Shared;

/// <summary>Picks the end-entity certificate out of an unordered set and orders its issuers nearest first.</summary>
public static class CertificateChainOrder
{
    /// <summary>Arranges certificates into a <see cref="SigningCertificate"/>.</summary>
    /// <param name="certificates">The certificates, in any order.</param>
    /// <param name="source">Where they came from, for error messages.</param>
    /// <returns>The leaf and its issuers, self-signed roots left out.</returns>
    /// <exception cref="ProviderConfigurationException">No certificate, or no leaf, was found.</exception>
    public static SigningCertificate Arrange(List<X509Certificate2> certificates, string source)
    {
        ArgumentNullException.ThrowIfNull(certificates);
        if (certificates.Count == 0)
        {
            throw new ProviderConfigurationException($"No certificates were found in '{source}'.");
        }

        var leaf = FindLeaf(certificates) ?? throw new ProviderConfigurationException($"No end-entity certificate was found in '{source}'.");
        return new(leaf, IssuersOf(certificates, leaf));
    }

    /// <summary>Orders the issuers of <paramref name="leaf"/> found in a set, nearest first, roots left out.</summary>
    /// <param name="certificates">The set.</param>
    /// <param name="leaf">The end-entity certificate.</param>
    /// <returns>The issuers.</returns>
    public static X509Certificate2[] IssuersOf(List<X509Certificate2> certificates, X509Certificate2 leaf)
    {
        ArgumentNullException.ThrowIfNull(certificates);
        ArgumentNullException.ThrowIfNull(leaf);
        List<X509Certificate2> chain = [];
        var current = leaf;
        while (FindIssuer(certificates, current, chain) is { } issuer)
        {
            chain.Add(issuer);
            current = issuer;
        }

        return [.. chain];
    }

    /// <summary>Gets whether a certificate names itself as issuer.</summary>
    /// <param name="certificate">The certificate.</param>
    /// <returns>True when self-issued.</returns>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static bool IsSelfIssued(X509Certificate2 certificate)
    {
        ArgumentNullException.ThrowIfNull(certificate);
        return certificate.SubjectName.RawData.AsSpan().SequenceEqual(certificate.IssuerName.RawData);
    }

    /// <summary>Finds the certificate that issues no other certificate in the set.</summary>
    /// <param name="certificates">The set.</param>
    /// <returns>The leaf, or null.</returns>
    private static X509Certificate2? FindLeaf(List<X509Certificate2> certificates)
    {
        foreach (var candidate in certificates)
        {
            if (!IssuesAny(certificates, candidate))
            {
                return candidate;
            }
        }

        return null;
    }

    /// <summary>Gets whether <paramref name="candidate"/> issued another certificate in the set.</summary>
    /// <param name="certificates">The set.</param>
    /// <param name="candidate">The possible issuer.</param>
    /// <returns>True when it is an issuer.</returns>
    private static bool IssuesAny(List<X509Certificate2> certificates, X509Certificate2 candidate)
    {
        foreach (var other in certificates)
        {
            if (!ReferenceEquals(other, candidate)
                && !IsSelfIssued(other)
                && other.IssuerName.RawData.AsSpan().SequenceEqual(candidate.SubjectName.RawData))
            {
                return true;
            }
        }

        return false;
    }

    /// <summary>Finds the non-root issuer of <paramref name="subject"/> that is not already in the chain.</summary>
    /// <param name="certificates">The set.</param>
    /// <param name="subject">The certificate whose issuer is wanted.</param>
    /// <param name="chain">The issuers found so far.</param>
    /// <returns>The issuer, or null.</returns>
    private static X509Certificate2? FindIssuer(List<X509Certificate2> certificates, X509Certificate2 subject, List<X509Certificate2> chain)
    {
        if (IsSelfIssued(subject))
        {
            return null;
        }

        foreach (var candidate in certificates)
        {
            if (!ReferenceEquals(candidate, subject)
                && !chain.Contains(candidate)
                && !IsSelfIssued(candidate)
                && candidate.SubjectName.RawData.AsSpan().SequenceEqual(subject.IssuerName.RawData))
            {
                return candidate;
            }
        }

        return null;
    }
}
