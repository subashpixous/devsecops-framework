// Rule fixtures for framework/rules/csharp/injection-and-crypto.yml
//
// `ruleid:` asserts the rule must fire; `ok:` asserts it must not. The `ok:`
// cases are the parameterised, validated and correctly-configured forms -- the
// code a reviewer would ask for instead.

using System;
using System.Data.SqlClient;
using System.Diagnostics;
using System.IO;
using System.Net.Http;
using System.Runtime.Serialization.Formatters.Binary;
using System.Security.Cryptography;
using System.Text;
using Microsoft.IdentityModel.Tokens;

public class InjectionSamples
{
    public void SqlCases(string userId, SqlConnection conn)
    {
        // ruleid: devsecops-framework.secure-coding.csharp.sql-string-concatenation
        var bad = new SqlCommand($"SELECT * FROM Users WHERE Id = {userId}", conn);

        // ok: devsecops-framework.secure-coding.csharp.sql-string-concatenation
        var good = new SqlCommand("SELECT * FROM Users WHERE Id = @id", conn);
        good.Parameters.AddWithValue("@id", userId);
    }

    public void CommandCases(string host)
    {
        // ruleid: devsecops-framework.secure-coding.csharp.command-execution-from-variable
        Process.Start($"ping -c 1 {host}");

        // ok: devsecops-framework.secure-coding.csharp.command-execution-from-variable
        var psi = new ProcessStartInfo("ping");
        psi.ArgumentList.Add("-c");
        psi.ArgumentList.Add("1");
        psi.ArgumentList.Add(host);
        Process.Start(psi);
    }

    public void PathCases(string fileName)
    {
        // ruleid: devsecops-framework.secure-coding.csharp.path-from-request-concatenation
        var contents = File.ReadAllText($"/var/data/{fileName}");

        // ok: devsecops-framework.secure-coding.csharp.path-from-request-concatenation
        var fixedContents = File.ReadAllText("/var/data/fixed-report.csv");
    }
}

public class CryptoSamples
{
    public void CertificateCases(HttpClientHandler handler)
    {
        // ruleid: devsecops-framework.secure-coding.csharp.certificate-validation-disabled
        handler.ServerCertificateCustomValidationCallback = (a, b, c, d) => true;

        // ok: devsecops-framework.secure-coding.csharp.certificate-validation-disabled
        var safeHandler = new HttpClientHandler();
    }

    public void PasswordHashCases(byte[] password, byte[] fileBytes)
    {
        // ruleid: devsecops-framework.secure-coding.csharp.weak-hash-for-password
        var weak = MD5.Create().ComputeHash(password);

        // A checksum over file content is a legitimate use and must not fire.
        // ok: devsecops-framework.secure-coding.csharp.weak-hash-for-password
        var checksum = SHA256.Create().ComputeHash(fileBytes);
    }

    public void DeserializationCases(Stream stream)
    {
        // ruleid: devsecops-framework.secure-coding.csharp.insecure-deserialization
        var obj = new BinaryFormatter().Deserialize(stream);

        // ok: devsecops-framework.secure-coding.csharp.insecure-deserialization
        var safe = System.Text.Json.JsonSerializer.Deserialize<object>(stream);
    }

    public void JwtCases()
    {
        // ruleid: devsecops-framework.secure-coding.csharp.jwt-validation-disabled
        var bad = new TokenValidationParameters { ValidateIssuerSigningKey = false };

        // ok: devsecops-framework.secure-coding.csharp.jwt-validation-disabled
        var good = new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidateAudience = true,
            ValidateLifetime = true,
            ValidateIssuerSigningKey = true
        };
    }
}

public class CorsSamples
{
    public void Configure(object services)
    {
        // ruleid: devsecops-framework.secure-coding.csharp.cors-any-origin-with-credentials
        BuildPolicy(builder => builder.AllowAnyOrigin().AllowCredentials());

        // ok: devsecops-framework.secure-coding.csharp.cors-any-origin-with-credentials
        BuildPolicy(builder => builder.WithOrigins("https://app.example.com").AllowCredentials());
    }

    private void BuildPolicy(Action<dynamic> configure) { }
}
