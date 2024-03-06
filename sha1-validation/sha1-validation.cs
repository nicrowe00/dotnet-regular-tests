using System.Net.Security;
using System.Security.Cryptography.X509Certificates;

bool sha1RsaSignatureOnLastElementInChain = false;

HttpClientHandler handler = new HttpClientHandler { 
    CheckCertificateRevocationList = true,
    ServerCertificateCustomValidationCallback = ServerCertificateCustomValidation, 
};

HttpClient client = new HttpClient(handler);

try
{
    HttpResponseMessage response = await client.GetAsync("https://redhat.com");

    string responseBody = await response.Content.ReadAsStringAsync();
    Console.WriteLine($"{sha1RsaSignatureOnLastElementInChain}");
    Console.WriteLine("PASS");
}
catch (HttpRequestException e)
{
    Console.WriteLine("\nException Caught!");
    Console.WriteLine("Message :{0} ", e.Message);
    Console.WriteLine("FAIL");
}

handler.Dispose();
client.Dispose();

bool ServerCertificateCustomValidation(HttpRequestMessage requestMessage, X509Certificate2? certificate, X509Chain? chain, SslPolicyErrors sslErrors)
{
    foreach (var element in chain!.ChainElements)
    {
        var cert = element.Certificate;
        Console.WriteLine($"{cert.SubjectName.Name} {cert.SignatureAlgorithm.FriendlyName}");
    }
    if ( chain.ChainElements.Last().Certificate.SignatureAlgorithm.FriendlyName == "sha1RSA" )
    {
        sha1RsaSignatureOnLastElementInChain = true;
    }

    Console.WriteLine($"Errors: {sslErrors}");
    return sslErrors == SslPolicyErrors.None;
}