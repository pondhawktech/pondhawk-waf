using System.Diagnostics;
using System.Text;
using Microsoft.Extensions.Logging.Abstractions;
using Pondhawk.Waf.AspNetCore;

namespace Pondhawk.Waf.Tests;

public class ProfilePerfProbe
{
    [Fact(Skip = "Manual performance probe; writes results to the scratchpad.")]
    public void MeasureProfiles()
    {
        var body = Encoding.UTF8.GetBytes("username=alice&password=secret123&remember=on&comment=Hello+there%2C+this+is+a+normal+comment.");
        var html = Encoding.UTF8.GetBytes(string.Concat(Enumerable.Repeat("<div class=\"item\"><a href=\"/p/1\">Garden hose 25 m</a><span>19.99</span></div>\n", 130)));
        var results = new StringBuilder();
        foreach (var profile in Enum.GetValues<WafProfile>())
        {
            var load = Stopwatch.StartNew();
            var waf = WafServiceCollectionExtensions.CreateEngine(new WafOptions { Profile = profile, RuleEngine = RuleEngineMode.On }, NullLoggerFactory.Instance);
            var loadMs = load.ElapsedMilliseconds;
            double Run(int n)
            {
                var sw = Stopwatch.StartNew();
                for (var i = 0; i < n; i++)
                {
                    using var tx = waf.NewTransaction();
                    tx.ProcessConnection("10.0.0.1", 5555, "10.0.0.2", 443);
                    tx.ProcessUri("/api/login?next=%2Fhome&lang=en", "POST", "HTTP/1.1");
                    tx.AddRequestHeader("Host", "app.example.com");
                    tx.AddRequestHeader("User-Agent", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/120 Safari/537.36");
                    tx.AddRequestHeader("Accept", "text/html,application/xhtml+xml");
                    tx.AddRequestHeader("Accept-Language", "en-US,en;q=0.9");
                    tx.AddRequestHeader("Content-Type", "application/x-www-form-urlencoded");
                    tx.AddRequestHeader("Content-Length", body.Length.ToString(System.Globalization.CultureInfo.InvariantCulture));
                    tx.AddRequestHeader("Cookie", "session=abc123; theme=dark");
                    tx.ProcessRequestHeaders();
                    tx.WriteRequestBody(body);
                    tx.ProcessRequestBody();
                    tx.AddResponseHeader("Content-Type", "text/html; charset=utf-8");
                    tx.ProcessResponseHeaders(200, "HTTP/1.1");
                    tx.WriteResponseBody(html);
                    tx.ProcessResponseBody();
                    tx.ProcessLogging();
                    Assert.Null(tx.Interruption);
                }

                return sw.Elapsed.TotalMicroseconds / n;
            }

            Run(300);
            var avg = Run(3000);
            results.AppendLine($"{profile}: load={loadMs}ms avg={avg:F0}us");
        }

        File.WriteAllText("/tmp/claude-1000/-home-jmoring-repositories-pondhawk-waf/38b0d848-8464-46d6-aef4-f16c41710ac0/scratchpad/profiles-perf.txt", results.ToString());
    }
}
