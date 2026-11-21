using System.Net;

namespace Pondhawk.Waf.Compatibility;

/// <summary>
/// A refusal is answered through the middleware outside the WAF: it carries the security headers and CORS-free status
/// of the app, and an exception handler or status code page outside cannot replace it with an uninspected page.
/// </summary>
[Collection(ServersCollection.Name)]
public sealed class BlockingTests(Servers servers)
{
    [Theory]
    [InlineData("/html?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E")] // phase 2: XSS in the query (CRS 941xxx)
    [InlineData("/json?id=1%27%20OR%201%3D1--")]                 // phase 2: SQL injection (CRS 942xxx)
    [InlineData("/leak")]                                       // phase 4: SQL error in the response (CRS 951xxx)
    [InlineData("/proxy/json?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E")]
    public async Task RefusalCarriesTheOuterHeaders(string path)
    {
        using var response = await servers.Client.SendAsync(Servers.Request(HttpMethod.Get, servers.Address(WafSetup.On), path));
        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
        Assert.Equal("nosniff", response.Headers.GetValues("X-Content-Type-Options").Single());
        Assert.True(response.Headers.Contains("X-Frame-Options"));

        // Not the status code page or the error page: the WAF's empty refusal.
        Assert.Empty(await response.Content.ReadAsByteArrayAsync());
    }

    [Theory]
    [InlineData(WafSetup.DetectionOnly)]
    [InlineData(WafSetup.DetectionOnlyHeld)]
    [InlineData(WafSetup.Off)]
    public async Task OtherModesDoNotBlock(WafSetup setup)
    {
        using var response = await servers.Client.SendAsync(Servers.Request(HttpMethod.Get, servers.Address(setup), "/leak"));
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
    }
}
