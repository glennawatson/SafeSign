// Copyright (c) 2026 Glenn Watson and Contributors. All rights reserved.
// Glenn Watson and Contributors licenses this file to you under the MIT license.
// See the LICENSE file in the project root for full license information.

using System.Runtime.CompilerServices;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Text.Json.Serialization.Metadata;
using Refit;

namespace SafeSign.Providers.Shared;

/// <summary>Builds source-generated Refit clients and unwraps provider responses.</summary>
public static class ProviderHttp
{
    /// <summary>The most characters of an error body quoted in an exception message.</summary>
    private const int MaxQuotedBodyLength = 512;

    /// <summary>Gets the PKCS #12 key storage flags supported on the current operating system.</summary>
    public static X509KeyStorageFlags Pkcs12StorageFlags =>
        OperatingSystem.IsMacOS()
            ? X509KeyStorageFlags.Exportable
            : X509KeyStorageFlags.Exportable | X509KeyStorageFlags.EphemeralKeySet;

    /// <summary>Creates <see cref="RefitSettings"/> configured with a source-generated JSON serializer context.</summary>
    /// <param name="context">The source-generated JSON serializer context.</param>
    /// <param name="baseSettings">Optional base Refit settings (for example from <c>StubHttp.ToSettings()</c>).</param>
    /// <returns>The configured <see cref="RefitSettings"/>.</returns>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static RefitSettings CreateSettings(JsonSerializerContext context, RefitSettings? baseSettings) =>
        CreateSettings(context, baseSettings, clientCertFile: null, clientCertPassword: null);

    /// <summary>Creates <see cref="RefitSettings"/> configured with a source-generated JSON serializer context and an optional mTLS client certificate.</summary>
    /// <param name="context">The source-generated JSON serializer context.</param>
    /// <param name="baseSettings">Optional base Refit settings (for example from <c>StubHttp.ToSettings()</c>).</param>
    /// <param name="clientCertFile">An optional PKCS #12 (<c>.p12</c>/<c>.pfx</c>) client certificate file for mutual TLS.</param>
    /// <param name="clientCertPassword">The optional password for <paramref name="clientCertFile"/>.</param>
    /// <returns>The configured <see cref="RefitSettings"/>.</returns>
    public static RefitSettings CreateSettings(
        JsonSerializerContext context,
        RefitSettings? baseSettings,
        string? clientCertFile,
        string? clientCertPassword)
    {
        ArgumentNullException.ThrowIfNull(context);
        var serializer = new SystemTextJsonContentSerializer(context.Options);
        var handlerFactory = baseSettings?.HttpMessageHandlerFactory
            ?? (clientCertFile is { Length: > 0 }
                ? () => CreateClientCertificateHandler(clientCertFile, clientCertPassword)
                : static () => new SocketsHttpHandler { AllowAutoRedirect = false, UseCookies = false });

        return new(serializer) { UrlResolution = UrlResolutionMode.Rfc3986, HttpMessageHandlerFactory = handlerFactory };
    }

    /// <summary>Gets the scheme and authority portion of <paramref name="endpoint"/>.</summary>
    /// <param name="endpoint">The service endpoint URI.</param>
    /// <returns>The scheme and authority URL string.</returns>
    public static string Authority(Uri endpoint)
    {
        ArgumentNullException.ThrowIfNull(endpoint);
        return endpoint.GetLeftPart(UriPartial.Authority);
    }

    /// <summary>Wraps bytes in content with an exact media type and no parameters.</summary>
    /// <param name="body">The body.</param>
    /// <param name="mediaType">The media type.</param>
    /// <returns>The content.</returns>
    public static ByteArrayContent Bytes(byte[] body, string mediaType)
    {
        ArgumentNullException.ThrowIfNull(body);
        ArgumentException.ThrowIfNullOrEmpty(mediaType);
        ByteArrayContent content = new(body);
        content.Headers.ContentType = new(mediaType);
        return content;
    }

    /// <summary>Unwraps a typed Refit <see cref="IApiResponse{T}"/> or throws a <see cref="ProviderRequestException"/>.</summary>
    /// <typeparam name="T">The response model type.</typeparam>
    /// <param name="response">The Refit response.</param>
    /// <param name="operation">A description of the operation for error messages.</param>
    /// <returns>The deserialized response content.</returns>
    /// <exception cref="ProviderRequestException">The service returned an error status or an empty body.</exception>
    public static T Unwrap<T>(IApiResponse<T> response, string operation)
    {
        ArgumentNullException.ThrowIfNull(response);
        if (response.IsSuccessfulWithContent)
        {
            return response.Content;
        }

        if (response.HasResponseError(out var responseError))
        {
            var detail = responseError.HasContent ? responseError.Content : responseError.ReasonPhrase ?? responseError.Message;
            throw new ProviderRequestException(
                $"{operation} failed with {(int)responseError.StatusCode} {responseError.ReasonPhrase}: {detail}",
                responseError.StatusCode,
                responseError);
        }

        if (response.HasRequestError(out var requestError))
        {
            throw new ProviderRequestException(
                $"{operation} failed before receiving a response: {requestError.Message}",
                requestError);
        }

        if (!response.IsSuccessStatusCode && response.StatusCode is { } statusCode)
        {
            throw new ProviderRequestException(
                $"{operation} failed with {(int)statusCode} {response.ReasonPhrase}.",
                statusCode);
        }

        return response.Error is { } error
            ? throw new ProviderRequestException($"{operation} returned an empty response.", error)
            : throw new ProviderRequestException($"{operation} returned an empty response.");
    }

    /// <summary>Reads a raw <see cref="HttpResponseMessage"/> and deserializes its JSON body using source-generated metadata.</summary>
    /// <typeparam name="T">The reply type.</typeparam>
    /// <param name="response">The HTTP response message.</param>
    /// <param name="typeInfo">The source-generated JSON type info.</param>
    /// <param name="operation">A description of the operation for error messages.</param>
    /// <param name="cancellationToken">Cancels reading the response body.</param>
    /// <returns>The deserialized reply.</returns>
    /// <exception cref="ProviderRequestException">The service returned an error or unreadable JSON.</exception>
    public static async ValueTask<T> ReadJsonAsync<T>(
        HttpResponseMessage response,
        JsonTypeInfo<T> typeInfo,
        string operation,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(response);
        ArgumentNullException.ThrowIfNull(typeInfo);
        var body = await ReadBytesAsync(response, operation, cancellationToken).ConfigureAwait(false);
        try
        {
            return JsonSerializer.Deserialize(body, typeInfo)
                ?? throw new ProviderRequestException($"{operation} returned an empty reply.");
        }
        catch (JsonException ex)
        {
            throw new ProviderRequestException($"{operation} returned a reply SafeSign could not read: {ex.Message}", ex);
        }
    }

    /// <summary>Reads the bytes of a successful <see cref="HttpResponseMessage"/> or throws a <see cref="ProviderRequestException"/>.</summary>
    /// <param name="response">The HTTP response message.</param>
    /// <param name="operation">A description of the operation for error messages.</param>
    /// <param name="cancellationToken">Cancels reading the response body.</param>
    /// <returns>The response body bytes.</returns>
    /// <exception cref="ProviderRequestException">The service returned a non-success status code.</exception>
    public static async ValueTask<byte[]> ReadBytesAsync(
        HttpResponseMessage response,
        string operation,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(response);
        var body = await response.Content.ReadAsByteArrayAsync(cancellationToken).ConfigureAwait(false);
        if (response.IsSuccessStatusCode)
        {
            return body;
        }

        var quoted = Encoding.UTF8.GetString(body.AsSpan(0, Math.Min(body.Length, MaxQuotedBodyLength)));
        throw new ProviderRequestException(
            $"{operation} failed with {(int)response.StatusCode} {response.ReasonPhrase}: {quoted}",
            response.StatusCode);
    }

    /// <summary>Formats a bearer <c>Authorization</c> header value.</summary>
    /// <param name="token">The access token.</param>
    /// <returns>The formatted <c>Bearer &lt;token&gt;</c> header value.</returns>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static string Bearer(string token) => $"Bearer {token}";

    /// <summary>Creates a <see cref="SocketsHttpHandler"/> configured with a PKCS #12 client certificate for mutual TLS.</summary>
    /// <param name="clientCertFile">The PKCS #12 client certificate file path.</param>
    /// <param name="clientCertPassword">The optional password for <paramref name="clientCertFile"/>.</param>
    /// <returns>The configured <see cref="HttpMessageHandler"/>.</returns>
    /// <exception cref="ProviderConfigurationException">The client certificate file does not exist.</exception>
    private static SocketsHttpHandler CreateClientCertificateHandler(string clientCertFile, string? clientCertPassword)
    {
        if (!File.Exists(clientCertFile))
        {
            throw new ProviderConfigurationException($"Client certificate file '{clientCertFile}' does not exist.");
        }

        var cert = X509CertificateLoader.LoadPkcs12FromFile(
            clientCertFile,
            clientCertPassword,
            Pkcs12StorageFlags);
        var handler = new SocketsHttpHandler { AllowAutoRedirect = false, UseCookies = false };
        handler.SslOptions.ClientCertificates = [cert];
        return handler;
    }
}
