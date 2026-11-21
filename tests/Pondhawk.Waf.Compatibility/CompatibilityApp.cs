using System.Buffers;
using System.Net;
using System.Net.WebSockets;
using System.Runtime.CompilerServices;
using System.Security.Claims;
using System.Text;
using System.Text.Encodings.Web;
using System.Threading.RateLimiting;
using Microsoft.AspNetCore.Antiforgery;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Hosting.Server;
using Microsoft.AspNetCore.Hosting.Server.Features;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.Features;
using Microsoft.AspNetCore.HttpOverrides;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Pondhawk.Waf.AspNetCore;
using Yarp.ReverseProxy.Configuration;

namespace Pondhawk.Waf.Compatibility;

/// <summary>How the WAF runs in one instance of the app. <see cref="None"/> is the baseline: no WAF at all.</summary>
public enum WafSetup
{
    None,
    Off,
    DetectionOnly,
    DetectionOnlyHeld,
    On,
}

/// <summary>
/// A realistic application on Kestrel, with the middleware Pond Hawk apps put around the WAF (pondhawk-identity's
/// order). Outside the WAF: forwarded headers, response compression, security headers, exception handler, status code
/// pages. Inside: WebSockets, static files, routing, CORS, rate limiting, authentication, antiforgery, output cache,
/// minimal APIs and a YARP route to <see cref="Backend"/>.
/// </summary>
public static class CompatibilityApp
{
    public const string AllowedOrigin = "https://app.example.test";
    public const string LargeText = "large text line for a body over the response body limit\n";

    public static async Task<WebApplication> StartAsync(WafSetup setup, Uri backend)
    {
        var builder = WebApplication.CreateBuilder(new WebApplicationOptions
        {
            ContentRootPath = AppContext.BaseDirectory,
            EnvironmentName = "Production",
        });
        builder.WebHost.UseUrls("http://127.0.0.1:0");
        ConfigureLogging(builder.Logging, setup.ToString());

        var services = builder.Services;
        services.Configure<ForwardedHeadersOptions>(o => o.ForwardedHeaders = ForwardedHeaders.XForwardedFor | ForwardedHeaders.XForwardedProto);
        services.AddResponseCompression();
        services.AddProblemDetails();
        services.AddCors(o => o.AddDefaultPolicy(p => p.WithOrigins(AllowedOrigin).AllowAnyHeader().AllowAnyMethod()));
        services.AddRateLimiter(o => o.GlobalLimiter = PartitionedRateLimiter.Create<HttpContext, string>(_ =>
            RateLimitPartition.GetFixedWindowLimiter("all", _ => new FixedWindowRateLimiterOptions { PermitLimit = 100_000, Window = TimeSpan.FromMinutes(1) })));
        services.AddAuthentication(HeaderAuthenticationHandler.SchemeName)
            .AddScheme<AuthenticationSchemeOptions, HeaderAuthenticationHandler>(HeaderAuthenticationHandler.SchemeName, null);
        services.AddAuthorization();
        services.AddAntiforgery();
        services.AddOutputCache();
        services.AddReverseProxy().LoadFromMemory(
            [new RouteConfig { RouteId = "backend", ClusterId = "backend", Match = new RouteMatch { Path = "/proxy/{**rest}" }, Transforms = [new Dictionary<string, string> { ["PathRemovePrefix"] = "/proxy" }] }],
            [new ClusterConfig { ClusterId = "backend", Destinations = new Dictionary<string, DestinationConfig> { ["backend"] = new() { Address = backend.ToString() } } }]);

        if (setup != WafSetup.None)
        {
            services.AddPondhawkWaf(o =>
            {
                o.RuleEngine = setup switch
                {
                    WafSetup.Off => RuleEngineMode.Off,
                    WafSetup.On => RuleEngineMode.On,
                    _ => RuleEngineMode.DetectionOnly,
                };
                o.HoldResponsesInDetectionOnly = setup == WafSetup.DetectionOnlyHeld;
                o.InspectResponses = true;
                o.WarmUp = false;
                o.ReloadOnChange = false;
            });
        }

        var app = builder.Build();

        // Outside the WAF: these answer or decorate WAF refusals too.
        app.UseForwardedHeaders();
        app.UseResponseCompression();
        app.UseSecurityHeaders();
        app.UseExceptionHandler(error => error.Run(ctx =>
        {
            ctx.Response.ContentType = "text/plain";
            return ctx.Response.WriteAsync("error page");
        }));
        app.UseStatusCodePages("text/plain", "status code page {0}");

        if (setup != WafSetup.None)
        {
            app.UsePondhawkWaf();
        }

        app.UseWebSockets();
        app.UseStaticFiles();
        app.UseRouting();
        app.UseCors();
        app.UseRateLimiter();
        app.UseAuthentication();
        app.UseAuthorization();
        app.UseAntiforgery();
        app.UseOutputCache();

        MapEndpoints(app);
        app.MapReverseProxy();

        await app.StartAsync();
        return app;
    }

    /// <summary>Silent unless COMPAT_LOG=1: then warnings and errors go to the console, prefixed with the setup.</summary>
    public static void ConfigureLogging(ILoggingBuilder logging, string name)
    {
        logging.ClearProviders();
        if (Environment.GetEnvironmentVariable("COMPAT_LOG") == "1")
        {
            logging.AddSimpleConsole(o => o.SingleLine = true).SetMinimumLevel(Environment.GetEnvironmentVariable("COMPAT_LOG_LEVEL") is { } level ? Enum.Parse<LogLevel>(level) : LogLevel.Warning);
            logging.Services.Configure<Microsoft.Extensions.Logging.Console.SimpleConsoleFormatterOptions>(o => o.TimestampFormat = $"'[{name}]' ");
        }
    }

    public static Uri Address(WebApplication app) =>
        new(app.Services.GetRequiredService<IServer>().Features.GetRequiredFeature<IServerAddressesFeature>().Addresses.First());

    private static void MapEndpoints(WebApplication app)
    {
        app.MapMethods("/html", [HttpMethods.Get, HttpMethods.Head], () => Results.Content("<html><body>hello</body></html>", "text/html"));
        app.MapGet("/json", () => Results.Json(new { name = "widget", count = 3 }));
        app.MapGet("/text-chunks", async (HttpContext ctx) =>
        {
            ctx.Response.ContentType = "text/plain";
            for (var i = 0; i < 3; i++)
            {
                await ctx.Response.WriteAsync($"chunk {i}\n");
                await ctx.Response.Body.FlushAsync();
            }
        });
        app.MapGet("/sse", () => TypedResults.ServerSentEvents(Events()));
        app.MapGet("/disable-buffering", async (HttpContext ctx) =>
        {
            ctx.Features.GetRequiredFeature<IHttpResponseBodyFeature>().DisableBuffering();
            ctx.Response.ContentType = "text/plain";
            await ctx.Response.WriteAsync("first\n");
            await ctx.Response.WriteAsync("second\n");
        });
        app.MapGet("/large-text", (HttpContext ctx) => WriteLargeAsync(ctx, "text/plain"));
        app.MapGet("/large-html", (HttpContext ctx) => WriteLargeAsync(ctx, "text/html"));
        app.MapGet("/pipe", (HttpContext ctx) =>
        {
            // GetSpan/Advance without a flush: the server flushes at the end.
            ctx.Response.ContentType = "text/plain";
            var bytes = Encoding.ASCII.GetBytes("written with BodyWriter");
            bytes.CopyTo(ctx.Response.BodyWriter.GetSpan(bytes.Length));
            ctx.Response.BodyWriter.Advance(bytes.Length);
            return Task.CompletedTask;
        });
        app.MapGet("/sendfile", () => Results.File(Path.Combine(AppContext.BaseDirectory, "wwwroot", "static.txt"), "text/plain"));
        app.MapGet("/empty", (HttpContext ctx) => ctx.Response.StatusCode = StatusCodes.Status200OK);
        app.MapGet("/no-content", () => Results.NoContent());
        app.MapGet("/redirect", () => Results.Redirect("/html"));
        app.MapGet("/problem", () => Results.Problem("something failed", statusCode: StatusCodes.Status409Conflict));
        app.MapGet("/error-before", string () => throw new InvalidOperationException("before the response"));
        app.MapGet("/error-after", async (HttpContext ctx) =>
        {
            ctx.Response.ContentType = "text/plain";
            await ctx.Response.WriteAsync("partial");
            await ctx.Response.Body.FlushAsync();
            throw new InvalidOperationException("after the response started");
        });
        app.MapGet("/me", (ClaimsPrincipal user) => $"user {user.Identity!.Name}").RequireAuthorization();
        app.MapGet("/antiforgery-token", (HttpContext ctx, IAntiforgery antiforgery) =>
        {
            antiforgery.GetAndStoreTokens(ctx);
            return "token issued";
        });
        app.MapPost("/form-protected", ([FromForm] string name) => $"hello {name}");
        app.MapPost("/form", ([FromForm] string name) => $"hello {name}").DisableAntiforgery();
        app.MapPost("/json-echo", (Item item) => Results.Json(item));
        app.MapPost("/upload", async (IFormFile file) =>
        {
            using var reader = new StreamReader(file.OpenReadStream());
            return $"{file.FileName} {file.Length} {await reader.ReadToEndAsync()}";
        }).DisableAntiforgery();
        app.MapGet("/cached", () => "cached text").CacheOutput();
        app.MapGet("/whoami", (HttpContext ctx) => $"{ctx.Connection.RemoteIpAddress} {ctx.Request.Scheme}");
        app.MapGet("/inner-on-starting", async (HttpContext ctx) =>
        {
            // A callback registered inside the WAF: its header is inspected and reaches the client.
            ctx.Response.OnStarting(() =>
            {
                ctx.Response.Headers["X-Inner"] = "1";
                return Task.CompletedTask;
            });
            ctx.Response.ContentType = "text/plain";
            await ctx.Response.WriteAsync("inner");
        });
        app.MapGet("/leak", () => Results.Content(
            "Warning: mysql_fetch_array() expects parameter 1 to be resource. You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version",
            "text/html"));
        app.Map("/ws", async (HttpContext ctx) =>
        {
            if (!ctx.WebSockets.IsWebSocketRequest)
            {
                ctx.Response.StatusCode = StatusCodes.Status400BadRequest;
                return;
            }

            using var socket = await ctx.WebSockets.AcceptWebSocketAsync();
            var buffer = new byte[4096];
            while (true)
            {
                var result = await socket.ReceiveAsync(buffer, ctx.RequestAborted);
                if (result.MessageType == WebSocketMessageType.Close)
                {
                    await socket.CloseAsync(WebSocketCloseStatus.NormalClosure, null, ctx.RequestAborted);
                    return;
                }

                await socket.SendAsync(buffer.AsMemory(0, result.Count), result.MessageType, result.EndOfMessage, ctx.RequestAborted);
            }
        });
    }

    private static async IAsyncEnumerable<string> Events([EnumeratorCancellation] CancellationToken cancellationToken = default)
    {
        for (var i = 0; i < 3; i++)
        {
            await Task.Yield();
            cancellationToken.ThrowIfCancellationRequested();
            yield return $"event {i}";
        }
    }

    private static async Task WriteLargeAsync(HttpContext ctx, string contentType)
    {
        ctx.Response.ContentType = contentType;
        var line = Encoding.ASCII.GetBytes(LargeText);
        for (var i = 0; i < 40_000; i++)
        {
            await ctx.Response.Body.WriteAsync(line);
        }
    }

    public sealed record Item(string Name, int Quantity);

    /// <summary>Authenticates a request that carries X-User; challenges with 401 and WWW-Authenticate otherwise.</summary>
    private sealed class HeaderAuthenticationHandler(IOptionsMonitor<AuthenticationSchemeOptions> options, ILoggerFactory logger, UrlEncoder encoder)
        : AuthenticationHandler<AuthenticationSchemeOptions>(options, logger, encoder)
    {
        public const string SchemeName = "Header";

        protected override Task<AuthenticateResult> HandleAuthenticateAsync()
        {
            if (Request.Headers["X-User"] is not [{ Length: > 0 } name])
            {
                return Task.FromResult(AuthenticateResult.NoResult());
            }

            var identity = new ClaimsIdentity([new Claim(ClaimTypes.Name, name)], SchemeName);
            return Task.FromResult(AuthenticateResult.Success(new AuthenticationTicket(new ClaimsPrincipal(identity), SchemeName)));
        }

        protected override Task HandleChallengeAsync(AuthenticationProperties properties)
        {
            Response.StatusCode = StatusCodes.Status401Unauthorized;
            Response.Headers.WWWAuthenticate = SchemeName;
            return Task.CompletedTask;
        }
    }
}

/// <summary>The application behind the YARP route: JSON, HTML, a streamed body and a POST echo.</summary>
public static class Backend
{
    public static async Task<WebApplication> StartAsync()
    {
        var builder = WebApplication.CreateSlimBuilder();
        builder.WebHost.UseUrls("http://127.0.0.1:0");
        builder.Logging.ClearProviders();
        var app = builder.Build();
        app.MapGet("/json", () => Results.Json(new { from = "backend" }));
        app.MapGet("/html", () => Results.Content("<html><body>from backend</body></html>", "text/html"));
        app.MapGet("/stream", async (HttpContext ctx) =>
        {
            ctx.Response.ContentType = "text/plain";
            for (var i = 0; i < 3; i++)
            {
                await ctx.Response.WriteAsync($"backend chunk {i}\n");
                await ctx.Response.Body.FlushAsync();
            }
        });
        app.MapPost("/echo", async (HttpContext ctx) =>
        {
            using var reader = new StreamReader(ctx.Request.Body);
            ctx.Response.ContentType = "application/json";
            await ctx.Response.WriteAsync(await reader.ReadToEndAsync());
        });
        await app.StartAsync();
        return app;
    }

    /// <summary>Silent unless COMPAT_LOG=1: then warnings and errors go to the console, prefixed with the setup.</summary>
    public static void ConfigureLogging(ILoggingBuilder logging, string name)
    {
        logging.ClearProviders();
        if (Environment.GetEnvironmentVariable("COMPAT_LOG") == "1")
        {
            logging.AddSimpleConsole(o => o.SingleLine = true).SetMinimumLevel(Environment.GetEnvironmentVariable("COMPAT_LOG_LEVEL") is { } level ? Enum.Parse<LogLevel>(level) : LogLevel.Warning);
            logging.Services.Configure<Microsoft.Extensions.Logging.Console.SimpleConsoleFormatterOptions>(o => o.TimestampFormat = $"'[{name}]' ");
        }
    }

    public static Uri Address(WebApplication app) => CompatibilityApp.Address(app);
}
