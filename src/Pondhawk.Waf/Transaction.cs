// Transaction processing follows OWASP Coraza (Apache-2.0) internal/corazawaf/transaction.go.
using System.Globalization;
using System.Text.RegularExpressions;
using Pondhawk.Waf.BodyProcessors;
using Pondhawk.Waf.Collections;
using Pondhawk.Waf.Rules;
using Pondhawk.Waf.Text;

namespace Pondhawk.Waf;

/// <summary>
/// The WAF state of one HTTP request/response. Not thread-safe. Call the Process* methods in phase order and dispose it.
/// All string inputs are byte strings (see <see cref="ByteString"/>).
/// </summary>
public sealed class Transaction : IDisposable
{
    private readonly Dictionary<(int, string), string> _transformationCache = [];
    private readonly HashSet<int> _removedRuleIds = [];
    private readonly List<(int Start, int End)> _removedRuleRanges = [];
    private readonly Dictionary<int, List<(Variable Variable, VariableException Exception)>> _removedTargets = [];
    private readonly List<MatchedRule> _matchedRules = [];
    private readonly BodyBuffer _requestBody;
    private readonly BodyBuffer _responseBody;
    private readonly DateTimeOffset _started = DateTimeOffset.UtcNow;
    private bool _audit;

    internal Transaction(WafEngine waf, string id)
    {
        Waf = waf;
        Id = id;
        RuleEngine = waf.Config.RuleEngine;
        RequestBodyAccess = waf.Config.RequestBodyAccess;
        RequestBodyLimit = waf.Config.RequestBodyLimit;
        ResponseBodyAccess = waf.Config.ResponseBodyAccess;
        ResponseBodyLimit = waf.Config.ResponseBodyLimit;
        AuditEngine = waf.Config.AuditEngine;
        AuditLogParts = waf.Config.AuditLogParts;
        _requestBody = new BodyBuffer(waf.Config.RequestBodyInMemoryLimit, waf.Config.TempDirectory);
        _responseBody = new BodyBuffer(waf.Config.ResponseBodyLimit, waf.Config.TempDirectory);

        var v = Variables;
        for (var i = 0; i <= 10; i++)
        {
            v.Tx.Set(i.ToString(CultureInfo.InvariantCulture), string.Empty);
        }

        v.FilesCombinedSize.Set("0");
        v.UrlencodedError.Set("0");
        v.UriParseError.Set("0");
        v.ArgumentsLimitReached.Set("0");
        v.FullRequestLength.Set("0");
        v.MultipartDataAfter.Set("0");
        v.MultipartDuplicatePartHeader.Set("0");
        v.MultipartInvalidQuoting.Set("0");
        v.MultipartStrictError.Set("0");
        v.OutboundDataError.Set("0");
        v.InboundDataError.Set("0");
        v.ReqbodyError.Set("0");
        v.ReqbodyProcessorError.Set("0");
        v.ResBodyError.Set("0");
        v.ResBodyProcessorError.Set("0");
        v.RequestBodyLength.Set("0");
        v.Duration.Set("0");
        v.HighestSeverity.Set("255");
        v.UniqueId.Set(id);
        SetTimeVariables(v, _started);
    }

    public WafEngine Waf { get; }

    public string Id { get; }

    public TransactionVariables Variables { get; } = new();

    public RuleEngineMode RuleEngine { get; set; }

    public bool RequestBodyAccess { get; set; }

    public long RequestBodyLimit { get; set; }

    public bool ResponseBodyAccess { get; set; }

    public long ResponseBodyLimit { get; set; }

    public bool ForceRequestBodyVariable { get; set; }

    public AuditEngineMode AuditEngine { get; set; }

    public string AuditLogParts { get; set; }

    /// <summary>The last phase evaluated (0 before phase 1).</summary>
    public int LastPhase { get; private set; }

    /// <summary>The enforced interruption, or null.</summary>
    public Interruption? Interruption { get; private set; }

    /// <summary>The first interruption that would have happened with SecRuleEngine On (DetectionOnly mode).</summary>
    public Interruption? DetectionOnlyInterruption { get; private set; }

    public bool IsInterrupted => Interruption is not null;

    public bool IsRuleEngineOff => RuleEngine == RuleEngineMode.Off;

    /// <summary>Rules that matched, in order.</summary>
    public IReadOnlyList<MatchedRule> MatchedRules => _matchedRules;

    /// <summary>True when a matched rule asked for audit logging.</summary>
    public bool IsRelevantForAudit => _audit;

    internal bool Capturing { get; set; }

    internal string SkipAfter { get; set; } = string.Empty;

    internal int Skip { get; set; }

    internal AllowType AllowType { get; set; }

    /// <summary>Returns the collection for a variable.</summary>
    public IWafCollection? Collection(Variable variable) => Variables.Get(variable);

    // ----- Request -----

    public void ProcessConnection(string clientAddress, int clientPort, string serverAddress, int serverPort)
    {
        Variables.RemoteAddr.Set(clientAddress);
        Variables.RemotePort.Set(clientPort.ToString(CultureInfo.InvariantCulture));
        Variables.ServerAddr.Set(serverAddress);
        Variables.ServerPort.Set(serverPort.ToString(CultureInfo.InvariantCulture));
    }

    public void SetServerName(string serverName) => Variables.ServerName.Set(serverName);

    /// <summary>Sets the request line variables and parses the query string. <paramref name="uri"/> is the raw request target.</summary>
    public void ProcessUri(string uri, string method, string protocol)
    {
        var v = Variables;
        v.RequestMethod.Set(method);
        v.RequestProtocol.Set(protocol);
        v.RequestUriRaw.Set(uri);
        v.RequestLine.Set($"{method} {uri} {protocol}");

        var fragment = uri.IndexOf('#', StringComparison.Ordinal);
        if (fragment >= 0)
        {
            uri = uri[..fragment];
        }

        string path;
        string query;
        if (RequestTarget.TryParse(uri, out var parsedPath, out var rawQuery, out var normalizedUri))
        {
            path = parsedPath;
            query = rawQuery;
            v.RequestUri.Set(normalizedUri);
        }
        else
        {
            v.UriParseError.Set("1");
            v.RequestUri.Set(uri);
            var q = uri.IndexOf('?', StringComparison.Ordinal);
            path = q < 0 ? uri : uri[..q];
            query = q < 0 ? string.Empty : uri[(q + 1)..];
        }

        ExtractGetArguments(query);
        var slash = path.AsSpan().LastIndexOfAny('/', '\\');
        v.RequestBasename.Set(slash >= 0 && path.Length > slash + 1 ? path[(slash + 1)..] : path);
        v.RequestFilename.Set(path);
        v.QueryString.Set(query);
    }

    public void ExtractGetArguments(string query)
    {
        var truncated = UrlEncoded.Parse(query, '&', Waf.Config.ArgumentsLimit, (k, val) => AddGetRequestArgument(k, val));
        if (truncated)
        {
            Variables.ArgumentsLimitReached.Set("1");
        }
    }

    public void AddGetRequestArgument(string key, string value)
    {
        if (ArgumentLimitReached(Variables.ArgsGet))
        {
            Variables.ArgumentsLimitReached.Set("1");
            return;
        }

        Variables.ArgsGet.Add(key, value);
    }

    public void AddPostRequestArgument(string key, string value)
    {
        if (ArgumentLimitReached(Variables.ArgsPost))
        {
            Variables.ArgumentsLimitReached.Set("1");
            return;
        }

        Variables.ArgsPost.Add(key, value);
    }

    public void AddPathRequestArgument(string key, string value)
    {
        if (ArgumentLimitReached(Variables.ArgsPath))
        {
            Variables.ArgumentsLimitReached.Set("1");
            return;
        }

        Variables.ArgsPath.Add(key, value);
    }

    private bool ArgumentLimitReached(MapCollection col) =>
        Waf.Config.ArgumentsLimit > 0 && col.Count >= Waf.Config.ArgumentsLimit;

    public void AddRequestHeader(string key, string value)
    {
        if (key.Length == 0)
        {
            return;
        }

        Variables.RequestHeaders.Add(key, value);
        if (string.Equals(key, "content-type", StringComparison.OrdinalIgnoreCase))
        {
            // Only the first Content-Type header selects the body processor (GHSA-w253-m66g-rx24).
            if (Variables.RequestHeaders.Get("content-type").Count == 1)
            {
                var val = value.Trim().ToLowerInvariant();
                if (val.StartsWith("application/x-www-form-urlencoded", StringComparison.Ordinal))
                {
                    Variables.ReqbodyProcessor.Set("URLENCODED");
                }
                else if (val.StartsWith("multipart/form-data", StringComparison.Ordinal))
                {
                    Variables.ReqbodyProcessor.Set("MULTIPART");
                }
            }
        }
        else if (string.Equals(key, "cookie", StringComparison.OrdinalIgnoreCase))
        {
            foreach (var (name, val) in Cookies.Parse(value))
            {
                Variables.RequestCookies.Add(name, val);
            }
        }
    }

    public Interruption? ProcessRequestHeaders()
    {
        if (IsRuleEngineOff || LastPhase >= Phases.RequestHeaders || IsInterrupted)
        {
            return Interruption;
        }

        Eval(Phases.RequestHeaders);
        return Interruption;
    }

    /// <summary>
    /// Buffers request body bytes. Returns an interruption when the body exceeds the limit and the limit action is Reject.
    /// Returns the number of bytes accepted.
    /// </summary>
    public (Interruption? Interruption, int Written) WriteRequestBody(ReadOnlySpan<byte> data)
    {
        if (IsRuleEngineOff || !RequestBodyAccess)
        {
            return (null, 0);
        }

        if (_requestBody.Length == RequestBodyLimit)
        {
            return Waf.Config.RequestBodyLimitAction == BodyLimitAction.Reject ? (Interruption, 0) : (null, 0);
        }

        var writing = (long)data.Length;
        var processNow = false;
        if (_requestBody.Length + writing > RequestBodyLimit)
        {
            Variables.InboundDataError.Set("1");
            if (Waf.Config.RequestBodyLimitAction == BodyLimitAction.Reject)
            {
                Interruption = new Interruption(0, "deny", 413, null);
                return (Interruption, 0);
            }

            writing = RequestBodyLimit - _requestBody.Length;
            processNow = Waf.Config.RequestBodyLimitAction == BodyLimitAction.ProcessPartial;
        }

        _requestBody.Write(data[..(int)writing]);
        if (processNow)
        {
            ProcessRequestBody();
        }

        return (Interruption, (int)writing);
    }

    /// <summary>
    /// Rejects a request whose declared length exceeds the body limit, without reading it (limit action Reject only).
    /// </summary>
    public Interruption? CheckDeclaredRequestBodyLength(long length)
    {
        if (IsRuleEngineOff || !RequestBodyAccess || length <= RequestBodyLimit)
        {
            return null;
        }

        Variables.InboundDataError.Set("1");
        if (Waf.Config.RequestBodyLimitAction != BodyLimitAction.Reject)
        {
            return null;
        }

        Interruption = new Interruption(0, "deny", 413, null);
        return Interruption;
    }

    public Interruption? ProcessRequestBody()
    {
        if (IsRuleEngineOff || IsInterrupted || LastPhase != Phases.RequestHeaders)
        {
            return Interruption;
        }

        if (!RequestBodyAccess || _requestBody.Length == 0)
        {
            Eval(Phases.RequestBody);
            return Interruption;
        }

        var processor = Variables.ReqbodyProcessor.Value;
        if (ForceRequestBodyVariable)
        {
            if (processor.Length == 0)
            {
                processor = "URLENCODED";
            }

            Variables.ReqbodyProcessor.Set(processor);
        }

        if (processor.Length == 0)
        {
            Eval(Phases.RequestBody);
            return Interruption;
        }

        var mime = Variables.RequestHeaders.GetFirst("content-type") ?? string.Empty;
        try
        {
            var options = new BodyProcessorOptions(mime, Waf.Config.RequestBodyJsonDepthLimit, Waf.Config.ArgumentsLimit);
            if (!BodyProcessor.TryProcessRequest(processor, _requestBody.ReadAll(), this, options))
            {
                RequestBodyError("invalid body processor");
            }
        }
        catch (BodyProcessorException ex)
        {
            RequestBodyError(ex.Message);
        }

        Eval(Phases.RequestBody);
        return Interruption;
    }

    private void RequestBodyError(string message)
    {
        Variables.ReqbodyError.Set("1");
        Variables.ReqbodyErrorMsg.Set($"{Variables.ReqbodyProcessor.Value}: {message}");
        Variables.ReqbodyProcessorError.Set("1");
        Variables.ReqbodyProcessorErrorMsg.Set(message);
    }

    // ----- Response -----

    public void AddResponseHeader(string key, string value)
    {
        if (key.Length == 0)
        {
            return;
        }

        Variables.ResponseHeaders.Add(key, value);
        if (string.Equals(key, "content-type", StringComparison.OrdinalIgnoreCase))
        {
            var semi = value.IndexOf(';', StringComparison.Ordinal);
            Variables.ResponseContentType.Set((semi < 0 ? value : value[..semi]).Trim());
        }
    }

    public Interruption? ProcessResponseHeaders(int status, string protocol)
    {
        if (IsRuleEngineOff || LastPhase >= Phases.ResponseHeaders || IsInterrupted)
        {
            return Interruption;
        }

        Variables.ResponseStatus.Set(status.ToString(CultureInfo.InvariantCulture));
        Variables.ResponseProtocol.Set(protocol);
        Eval(Phases.ResponseHeaders);
        return Interruption;
    }

    /// <summary>
    /// True when the response body is inspected: SecResponseBodyAccess is on and the response MIME type is listed in
    /// SecResponseBodyMimeType (or ctl:forceResponseBodyVariable is on).
    /// </summary>
    public bool IsResponseBodyProcessable
    {
        get
        {
            if (IsRuleEngineOff || !ResponseBodyAccess)
            {
                return false;
            }

            if (ForceResponseBodyVariable)
            {
                return true;
            }

            var ct = Variables.ResponseContentType.Value;
            return Waf.Config.ResponseBodyMimeTypes.Contains(ct, StringComparer.OrdinalIgnoreCase);
        }
    }

    /// <summary>Set by ctl:forceResponseBodyVariable: inspect the response body whatever its MIME type.</summary>
    public bool ForceResponseBodyVariable { get; set; }

    /// <summary>
    /// Buffers response body bytes for phase 4. At the limit: with Reject, interrupts with 500; with ProcessPartial,
    /// runs phase 4 on what is buffered and accepts no more. Returns the number of bytes buffered.
    /// </summary>
    public (Interruption? Interruption, int Written) WriteResponseBody(ReadOnlySpan<byte> data)
    {
        if (IsRuleEngineOff || !ResponseBodyAccess)
        {
            return (null, 0);
        }

        var writing = (long)data.Length;
        var processNow = false;
        if (_responseBody.Length + writing > ResponseBodyLimit)
        {
            Variables.OutboundDataError.Set("1");
            if (Waf.Config.ResponseBodyLimitAction == BodyLimitAction.Reject)
            {
                Interruption = new Interruption(0, "deny", 500, null);
                return (Interruption, 0);
            }

            writing = ResponseBodyLimit - _responseBody.Length;
            processNow = true;
        }

        _responseBody.Write(data[..(int)writing]);
        if (processNow && LastPhase == Phases.ResponseHeaders)
        {
            // ProcessPartial: inspect what fits; the rest is not inspected.
            ProcessResponseBody();
        }

        return (Interruption, (int)writing);
    }

    /// <summary>Runs phase 4. Call after ProcessResponseHeaders and after all body bytes were written.</summary>
    public Interruption? ProcessResponseBody()
    {
        if (IsRuleEngineOff || IsInterrupted || LastPhase != Phases.ResponseHeaders)
        {
            return Interruption;
        }

        if (!IsResponseBodyProcessable)
        {
            Eval(Phases.ResponseBody);
            return Interruption;
        }

        var body = _responseBody.ReadAll();
        var processor = Variables.ResBodyProcessor.Value;
        if (processor.Length > 0)
        {
            try
            {
                if (!BodyProcessor.TryProcessResponse(processor, body, this, Waf.Config.RequestBodyJsonDepthLimit, Waf.Config.ArgumentsLimit))
                {
                    ResponseBodyError("invalid body processor");
                }
            }
            catch (BodyProcessorException ex)
            {
                ResponseBodyError(ex.Message);
            }
        }
        else
        {
            Variables.ResponseBody.Set(ByteString.FromBytes(body));
            Variables.ResponseContentLength.Set(body.Length.ToString(CultureInfo.InvariantCulture));
        }

        Eval(Phases.ResponseBody);
        return Interruption;
    }

    private void ResponseBodyError(string message)
    {
        Variables.ResBodyError.Set("1");
        Variables.ResBodyErrorMsg.Set($"{Variables.ResBodyProcessor.Value}: {message}");
        Variables.ResBodyProcessorError.Set("1");
        Variables.ResBodyProcessorErrorMsg.Set(message);
    }

    /// <summary>Runs phase 5 and writes the audit log entry when relevant.</summary>
    public void ProcessLogging()
    {
        if (!IsRuleEngineOff)
        {
            Eval(Phases.Logging);
        }

        Variables.Duration.Set(((long)(DateTimeOffset.UtcNow - _started).TotalMicroseconds).ToString(CultureInfo.InvariantCulture));
        if (AuditEngine == AuditEngineMode.Off || Waf.Config.AuditLogWriter is null)
        {
            return;
        }

        if (AuditEngine == AuditEngineMode.RelevantOnly)
        {
            var status = Interruption?.Status.ToString(CultureInfo.InvariantCulture)
                         ?? DetectionOnlyInterruption?.Status.ToString(CultureInfo.InvariantCulture)
                         ?? Variables.ResponseStatus.Value;
            var relevant = Waf.Config.AuditLogRelevantStatus;
            var statusRelevant = relevant is not null && relevant.IsMatch(status);
            if (!_audit && !statusRelevant)
            {
                return;
            }

            if (_audit && relevant is not null && !statusRelevant)
            {
                return;
            }
        }

        Waf.Config.AuditLogWriter.Write(AuditLog.AuditLogEntry.From(this));
    }

    public void Dispose()
    {
        _requestBody.Dispose();
        _responseBody.Dispose();
    }

    // ----- Rule engine hooks -----

    internal void Interrupt(Interruption interruption)
    {
        switch (RuleEngine)
        {
            case RuleEngineMode.On:
                Interruption = interruption;
                break;
            case RuleEngineMode.DetectionOnly:
                DetectionOnlyInterruption ??= interruption;
                break;
        }
    }

    internal void Allow(AllowType type)
    {
        if (RuleEngine == RuleEngineMode.On)
        {
            AllowType = type;
        }
    }

    internal void CaptureField(int index, string value)
    {
        if (Capturing)
        {
            Variables.Tx.Set(index.ToString(CultureInfo.InvariantCulture), value);
        }
    }

    internal void MatchVariable(MatchData match)
    {
        var name = match.FullName;
        Variables.MatchedVars.Add(name, match.Value);
        Variables.MatchedVar.Set(match.Value);
        Variables.MatchedVarName.Set(name);
    }

    internal void MatchRule(Rule rule, List<RuleMatch> matches)
    {
        _audit |= rule.Audit;
        if (rule.Severity != Severity.Unset
            && int.TryParse(Variables.HighestSeverity.Value, CultureInfo.InvariantCulture, out var current)
            && (int)rule.Severity < current)
        {
            Variables.HighestSeverity.Set(((int)rule.Severity).ToString(CultureInfo.InvariantCulture));
        }

        var disruptiveName = rule.DisruptiveActionName;
        var message = string.Empty;
        var data = string.Empty;
        // The first expanded msg and logdata of the rule or its chain links.
        foreach (var m in matches)
        {
            if (message.Length == 0 && m.Message.Length > 0)
            {
                message = m.Message;
            }

            if (data.Length == 0 && m.Data.Length > 0)
            {
                data = m.Data;
            }
        }

        var matched = new MatchedRule(
            rule,
            Id,
            Variables.RequestUri.Value,
            Variables.RemoteAddr.Value,
            Variables.ServerName.Value.Length > 0 ? Variables.ServerName.Value : Variables.RequestHeaders.GetFirst("host") ?? string.Empty,
            message,
            data,
            matches,
            disruptiveName,
            disruptiveName is not null and not "pass" && RuleEngine == RuleEngineMode.On);
        _matchedRules.Add(matched);
        if (rule.Log)
        {
            Waf.Config.ErrorCallback?.Invoke(matched);
        }
    }

    internal void RemoveRuleById(int id) => _removedRuleIds.Add(id);

    internal void RemoveRuleByIdRange(int start, int end) => _removedRuleRanges.Add((start, end));

    internal void RemoveRuleTargetById(int id, Variable variable, string key, Regex? keyRegex)
    {
        if (!_removedTargets.TryGetValue(id, out var list))
        {
            list = [];
            _removedTargets[id] = list;
        }

        list.Add((variable, new VariableException(key, keyRegex)));
    }

    internal List<(Variable Variable, VariableException Exception)>? GetRuleRemovedTargets(int id) =>
        _removedTargets.GetValueOrDefault(id);

    /// <summary>Reads the values a rule variable selects, after exceptions; &amp;VAR yields the count.</summary>
    internal void GetField(RuleVariable rv, List<(Variable Variable, VariableException Exception)>? ctlExceptions, List<MatchData> output)
    {
        var col = Collection(rv.Variable);
        if (col is null)
        {
            if (rv.IsCount)
            {
                output.Add(new MatchData(rv.Variable, rv.KeyString, "0"));
            }

            return;
        }

        var start = output.Count;
        if (rv.KeyRegex is not null && col is IKeyedCollection keyedRx)
        {
            keyedRx.FindRegex(rv.KeyRegex, output);
        }
        else if (rv.KeyString.Length > 0 && col is IKeyedCollection keyed)
        {
            keyed.FindString(rv.KeyString, output);
        }
        else
        {
            col.FindAll(output);
        }

        var hasCtl = ctlExceptions is { Count: > 0 };
        if (rv.Exceptions.Count > 0 || hasCtl)
        {
            var write = start;
            for (var i = start; i < output.Count; i++)
            {
                var lower = ByteString.ToLowerAscii(output[i].Key);
                var excluded = false;
                foreach (var ex in rv.Exceptions)
                {
                    if (ex.Matches(lower))
                    {
                        excluded = true;
                        break;
                    }
                }

                if (!excluded && hasCtl)
                {
                    foreach (var (variable, ex) in ctlExceptions!)
                    {
                        if (variable == rv.Variable && ex.Matches(lower))
                        {
                            excluded = true;
                            break;
                        }
                    }
                }

                if (!excluded)
                {
                    output[write++] = output[i];
                }
            }

            output.RemoveRange(write, output.Count - write);
        }

        if (rv.IsCount)
        {
            var count = output.Count - start;
            output.RemoveRange(start, count);
            output.Add(new MatchData(rv.Variable, rv.KeyString, count.ToString(CultureInfo.InvariantCulture)));
        }
    }

    private void Eval(int phase)
    {
        LastPhase = phase;
        _transformationCache.Clear();
        if (phase == Phases.Logging && AllowType == AllowType.All)
        {
            AllowType = AllowType.Unset;
        }

        foreach (var rule in Waf.Rules)
        {
            if (IsInterrupted && phase != Phases.Logging)
            {
                break;
            }

            if (rule.Phase != 0 && rule.Phase != phase)
            {
                continue;
            }

            if (IsRuleRemoved(rule.Id))
            {
                continue;
            }

            if (SkipAfter.Length > 0)
            {
                if (rule.SecMark == SkipAfter)
                {
                    SkipAfter = string.Empty;
                }

                continue;
            }

            if (Skip > 0)
            {
                Skip--;
                continue;
            }

            var stop = false;
            switch (AllowType)
            {
                case AllowType.Phase:
                    stop = true;
                    break;
                case AllowType.Request:
                    if (phase == Phases.RequestHeaders)
                    {
                        stop = true;
                    }
                    else if (phase == Phases.RequestBody)
                    {
                        AllowType = AllowType.Unset;
                        stop = true;
                    }

                    break;
                case AllowType.All:
                    stop = true;
                    break;
            }

            if (stop)
            {
                break;
            }

            if (Variables.MatchedVars.Count > 0)
            {
                Variables.MatchedVars.Reset();
            }

            rule.Evaluate(phase, this, _transformationCache);
            Capturing = false;

            if (IsRuleEngineOff)
            {
                break;
            }
        }

        if (AllowType == AllowType.Phase)
        {
            AllowType = AllowType.Unset;
        }

        Skip = 0;
    }

    private bool IsRuleRemoved(int id)
    {
        if (id == 0)
        {
            return false;
        }

        if (_removedRuleIds.Contains(id))
        {
            return true;
        }

        foreach (var (s, e) in _removedRuleRanges)
        {
            if (id >= s && id <= e)
            {
                return true;
            }
        }

        return false;
    }

    private static void SetTimeVariables(TransactionVariables v, DateTimeOffset now)
    {
        var local = now.ToLocalTime();
        var ci = CultureInfo.InvariantCulture;
        v.Time.Set(local.ToString("HH:mm:ss", ci));
        v.TimeDay.Set(local.Day.ToString(ci));
        v.TimeEpoch.Set(now.ToUnixTimeSeconds().ToString(ci));
        v.TimeHour.Set(local.Hour.ToString(ci));
        v.TimeMin.Set(local.Minute.ToString(ci));
        v.TimeMon.Set(local.Month.ToString(ci));
        v.TimeSec.Set(local.Second.ToString(ci));
        v.TimeWday.Set(((int)local.DayOfWeek).ToString(ci));
        v.TimeYear.Set(local.Year.ToString(ci));
    }
}
