using System.Collections.Concurrent;
using System.Net;
using System.Text;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Pondhawk.Waf.AspNetCore;

namespace Pondhawk.Waf.Tests;

/// <summary>DetectionOnly cannot block a response, so it streams the response and inspects a copy.</summary>
public sealed class DetectionOnlyResponseTests
{
    private const string SqlError = "Warning: mysql_fetch_array() expects parameter 1 to be resource. You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version";

    [Fact]
    public async Task DetectionOnlyStreamsTheResponseAndStillInspectsIt()
    {
        var release = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var matched = new ConcurrentBag<int>();
        using var host = await StartAsync(hold: false, release, matched);
        using var response = await host.GetTestClient().GetAsync("/", HttpCompletionOption.ResponseHeadersRead);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);

        // The first part arrives while the application still waits: nothing is held.
        var stream = await response.Content.ReadAsStreamAsync();
        var first = new byte[7];
        await stream.ReadExactlyAsync(first).AsTask().WaitAsync(TimeSpan.FromSeconds(60));
        Assert.Equal("part-1\n", Encoding.ASCII.GetString(first));

        release.SetResult();
        using var reader = new StreamReader(stream);
        Assert.Equal("part-2 " + SqlError, await reader.ReadToEndAsync());

        // Phase 4 saw the whole body: the SQL error leak rules (951xxx) matched and were logged.
        await WaitForAsync(() => matched.Any(id => id is >= 951000 and < 952000));
        await host.StopAsync();
    }

    [Fact]
    public async Task HoldResponsesInDetectionOnlyHoldsUntilPhase4()
    {
        var release = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var matched = new ConcurrentBag<int>();
        using var host = await StartAsync(hold: true, release, matched);
        var pending = host.GetTestClient().GetAsync("/", HttpCompletionOption.ResponseHeadersRead);

        // Held: not even the headers are sent before the application finishes.
        await Task.Delay(500);
        Assert.False(pending.IsCompleted);

        release.SetResult();
        using var response = await pending.WaitAsync(TimeSpan.FromSeconds(60));
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal("part-1\npart-2 " + SqlError, await response.Content.ReadAsStringAsync());
        await WaitForAsync(() => matched.Any(id => id is >= 951000 and < 952000));
        await host.StopAsync();
    }

    private static async Task<IHost> StartAsync(bool hold, TaskCompletionSource release, ConcurrentBag<int> matched) =>
        await new HostBuilder()
            .ConfigureWebHost(web => web
                .UseTestServer()
                .ConfigureServices(s => s.AddPondhawkWaf(o =>
                {
                    o.RuleEngine = RuleEngineMode.DetectionOnly;
                    o.WarmUp = false;
                    o.HoldResponsesInDetectionOnly = hold;
                    o.Configure = b => b.Config.ErrorCallback = m => matched.Add(m.Rule.LogId);
                }))
                .Configure(app =>
                {
                    app.UsePondhawkWaf();
                    app.Run(async ctx =>
                    {
                        ctx.Response.ContentType = "text/html";
                        await ctx.Response.WriteAsync("part-1\n");
                        await ctx.Response.Body.FlushAsync();
                        await release.Task.WaitAsync(TimeSpan.FromSeconds(60));
                        await ctx.Response.WriteAsync("part-2 " + SqlError);
                    });
                }))
            .StartAsync();

    private static async Task WaitForAsync(Func<bool> condition)
    {
        for (var i = 0; i < 600 && !condition(); i++)
        {
            await Task.Delay(50);
        }

        Assert.True(condition());
    }
}
