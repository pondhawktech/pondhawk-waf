// Rule evaluation semantics follow OWASP Coraza (Apache-2.0) internal/corazawaf/rule.go.
using System.Text.RegularExpressions;
using Pondhawk.Waf.Actions;
using Pondhawk.Waf.Collections;
using Pondhawk.Waf.Operators;
using Pondhawk.Waf.Transformations;

namespace Pondhawk.Waf.Rules;

/// <summary>Rule severity (syslog levels, as in ModSecurity).</summary>
public enum Severity
{
    Unset = -1,
    Emergency = 0,
    Alert = 1,
    Critical = 2,
    Error = 3,
    Warning = 4,
    Notice = 5,
    Info = 6,
    Debug = 7,
}

/// <summary>A variable selector of a rule, e.g. ARGS:id, !ARGS:password, &amp;ARGS, ARGS:/^id_/.</summary>
public sealed class RuleVariable(Variable variable, string keyString, Regex? keyRegex, bool isCount)
{
    public Variable Variable { get; } = variable;

    public string KeyString { get; } = keyString;

    public Regex? KeyRegex { get; } = keyRegex;

    public bool IsCount { get; } = isCount;

    public List<VariableException> Exceptions { get; } = [];

    public override string ToString() =>
        (IsCount ? "&" : string.Empty) + Variable.Name() + (KeyRegex is not null ? ":/" + KeyRegex + "/" : KeyString.Length > 0 ? ":" + KeyString : string.Empty);
}

/// <summary>A key excluded from a rule variable (by !VAR:key in the rule or by ctl:ruleRemoveTargetById).</summary>
public readonly record struct VariableException(string KeyString, Regex? KeyRegex)
{
    public bool Matches(string lowerKey) =>
        KeyRegex is not null ? KeyRegex.IsMatch(lowerKey) : KeyString.Length == 0 || string.Equals(KeyString, lowerKey, StringComparison.OrdinalIgnoreCase);
}

/// <summary>A compiled SecRule, SecAction or SecMarker.</summary>
public sealed class Rule
{
    public int Id { get; set; }

    /// <summary>For chained rules: the id of the chain starter. 0 for top-level rules.</summary>
    public int ParentId { get; set; }

    public int Phase { get; set; } = 2;

    public Macro? Msg { get; set; }

    public Macro? LogData { get; set; }

    public Severity Severity { get; set; } = Severity.Unset;

    public List<string> Tags { get; } = [];

    public string Version { get; set; } = string.Empty;

    public string Revision { get; set; } = string.Empty;

    public int Maturity { get; set; }

    public int Accuracy { get; set; }

    /// <summary>HTTP status for disruptive actions (status:NNN). 0 means default.</summary>
    public int Status { get; set; }

    public string? RedirectUrl { get; set; }

    public bool Capture { get; set; }

    public bool MultiMatch { get; set; }

    public bool Log { get; set; }

    public bool Audit { get; set; }

    public bool HasChain { get; set; }

    public Rule? Chain { get; set; }

    /// <summary>The marker name for SecMarker rules.</summary>
    public string? SecMark { get; set; }

    public List<RuleVariable> Variables { get; } = [];

    public IOperator? Operator { get; set; }

    public string OperatorName { get; set; } = string.Empty;

    public string OperatorData { get; set; } = string.Empty;

    public bool OperatorNegated { get; set; }

    public List<(string Name, Transformation Function)> Transformations { get; } = [];

    /// <summary>Identifies the transformation chain for the transformation cache.</summary>
    internal int TransformationsId { get; set; }

    /// <summary>For the transformation cache: the id of each step of the chain on its own.</summary>
    internal int[] TransformationStepIds { get; set; } = [];

    public List<(string Name, IRuleAction Action)> Actions { get; } = [];

    public string File { get; set; } = string.Empty;

    public int Line { get; set; }

    public string Raw { get; set; } = string.Empty;

    /// <summary>The disruptive action name (deny, block, pass, ...), or null.</summary>
    public string? DisruptiveActionName =>
        Actions.FirstOrDefault(a => a.Action.Type == ActionType.Disruptive).Name;

    /// <summary>The id used in logs: the rule's own id, or the chain starter's.</summary>
    public int LogId => Id != 0 ? Id : ParentId;

    private static readonly string[] SeverityNames =
        ["", "EMERGENCY", "ALERT", "CRITICAL", "ERROR", "WARNING", "NOTICE", "INFO", "DEBUG"];

    private Tuple<int, string>? _logIdText;

    // RULE.id is set for every rule evaluation; format it once. Id and ParentId can change while rules load, so the
    // cached text carries the id it was made from (one reference, safe to read from many threads).
    private string LogIdString
    {
        get
        {
            var id = LogId;
            var cached = _logIdText;
            if (cached is null || cached.Item1 != id)
            {
                cached = Tuple.Create(id, id.ToString(System.Globalization.CultureInfo.InvariantCulture));
                _logIdText = cached;
            }

            return cached.Item2;
        }
    }

    public void ClearTransformations() => Transformations.Clear();

    internal void Evaluate(int phase, Transaction tx, TransformationCache cache)
    {
        DoEvaluate(phase, tx, 0, cache);
    }

    private List<RuleMatch>? DoEvaluate(int phase, Transaction tx, int chainLevel, TransformationCache cache)
    {
        tx.Capturing = Capture;

        if (tx.Waf.FillsRuleCollection)
        {
            var ruleCol = tx.Variables.Rule;
            ruleCol.Set("id", LogIdString);
            if (Msg is not null)
            {
                ruleCol.Set("msg", Msg.Expand(tx));
            }

            ruleCol.Set("rev", Revision);
            if (LogData is not null)
            {
                ruleCol.Set("logdata", LogData.Expand(tx));
            }

            ruleCol.Set("severity", SeverityNames[(int)Severity + 1]);
        }

        List<RuleMatch>? matched = null;
        if (Operator is null)
        {
            // SecAction and SecMarker always match.
            var md = new RuleMatch(new MatchData(Variable.Unknown, string.Empty, string.Empty), chainLevel);
            if (ParentId != 0 || MultiMatch)
            {
                md.Message = Msg?.Expand(tx) ?? string.Empty;
                md.Data = LogData?.Expand(tx) ?? string.Empty;
            }

            matched = [md];
            MatchVariable(tx, md);
        }
        else
        {
            var exceptions = tx.GetRuleRemovedTargets(LogId);
            var values = tx.RentMatchList();
            var args = tx.RentStringList();
            try
            {
                matched = EvaluateVariables(tx, exceptions, values, args, chainLevel, cache);
            }
            finally
            {
                tx.Return(values);
                tx.Return(args);
            }
        }

        if (matched is null)
        {
            return null;
        }

        if (ParentId == 0)
        {
            // Only the chain starter runs the chain, the disruptive and flow actions, and records the match.
            for (var nr = Chain; nr is not null; nr = nr.Chain)
            {
                if (tx.IsRuleEngineOff)
                {
                    return null;
                }

                chainLevel++;
                var chainMatches = nr.DoEvaluate(phase, tx, chainLevel, cache);
                if (chainMatches is null)
                {
                    return null;
                }

                matched.AddRange(chainMatches);
            }

            if (HasChain || Operator is null)
            {
                matched[0].Message = Msg?.Expand(tx) ?? string.Empty;
                matched[0].Data = LogData?.Expand(tx) ?? string.Empty;
            }

            foreach (var (_, action) in Actions)
            {
                if (action.Type is ActionType.Flow or ActionType.Disruptive)
                {
                    action.Evaluate(this, tx);
                }
            }

            if (Id != 0)
            {
                tx.MatchRule(this, matched);
            }
        }

        return matched;
    }

    private List<RuleMatch>? EvaluateVariables(
        Transaction tx,
        List<(Variable Variable, VariableException Exception)>? exceptions,
        List<MatchData> values,
        List<string> args,
        int chainLevel,
        TransformationCache cache)
    {
        List<RuleMatch>? matched = null;
        var op = Operator!;
        foreach (var v in Variables)
        {
            values.Clear();
            tx.GetField(v, exceptions, values);
            var useCache = !v.IsCount && v.Variable is not (Variable.Tx or Variable.ArgsCombinedSize);
            foreach (var arg in values)
            {
                args.Clear();
                if (MultiMatch)
                {
                    TransformMultiMatch(arg.Value, args, useCache ? cache : null);
                }
                else if (Transformations.Count == 0)
                {
                    args.Add(arg.Value);
                }
                else if (useCache)
                {
                    if (!cache.TryGetValue(TransformationsId, arg.Value, out var transformed))
                    {
                        transformed = Transform(arg.Value, cache);
                        cache.Add(TransformationsId, arg.Value, transformed);
                    }

                    args.Add(transformed);
                }
                else
                {
                    args.Add(Transform(arg.Value));
                }

                foreach (var carg in args)
                {
                    var result = op.Evaluate(tx, carg);
                    if (OperatorNegated)
                    {
                        result = !result;
                    }

                    if (!result)
                    {
                        continue;
                    }

                    var mr = new RuleMatch(new MatchData(arg.Variable, arg.Key, carg), chainLevel);
                    MatchVariable(tx, mr);
                    if (ParentId != 0 || !HasChain)
                    {
                        mr.Message = Msg?.Expand(tx) ?? string.Empty;
                        mr.Data = LogData?.Expand(tx) ?? string.Empty;
                    }

                    (matched ??= []).Add(mr);
                }
            }
        }

        return matched;
    }

    private void MatchVariable(Transaction tx, RuleMatch match)
    {
        tx.MatchVariable(match.Match);
        foreach (var (_, action) in Actions)
        {
            if (action.Type == ActionType.NonDisruptive)
            {
                action.Evaluate(this, tx);
            }
        }
    }

    private string Transform(string value, TransformationCache? cache = null)
    {
        for (var i = 0; i < Transformations.Count; i++)
        {
            value = TransformStep(i, value, cache);
        }

        return value;
    }

    private void TransformMultiMatch(string value, List<string> output, TransformationCache? cache)
    {
        output.Add(value);
        for (var i = 0; i < Transformations.Count; i++)
        {
            var transformed = TransformStep(i, value, cache);
            if (!ReferenceEquals(transformed, value) && !string.Equals(transformed, value, StringComparison.Ordinal))
            {
                output.Add(transformed);
                value = transformed;
            }
        }
    }

    // Long values are cached step by step, so chains that share steps (most CRS chains start with urlDecodeUni or
    // utf8toUnicode,urlDecodeUni) copy a large argument once per distinct step instead of once per chain.
    private string TransformStep(int index, string value, TransformationCache? cache)
    {
        var transformation = Transformations[index].Function;
        if (cache is null || value.Length < TransformationCache.StepCacheMinLength || index >= TransformationStepIds.Length)
        {
            return transformation(value);
        }

        var id = TransformationStepIds[index];
        if (!cache.TryGetValue(id, value, out var transformed))
        {
            transformed = transformation(value);
            cache.Add(id, value, transformed);
        }

        return transformed;
    }

    public override string ToString() => Id != 0 ? $"Rule {Id}" : $"Rule {File}:{Line}";
}

/// <summary>One value that matched a rule (or a link of its chain).</summary>
public sealed class RuleMatch(MatchData match, int chainLevel)
{
    /// <summary>The variable, key and transformed value that matched.</summary>
    public MatchData Match { get; } = match;

    public int ChainLevel { get; } = chainLevel;

    /// <summary>The expanded msg.</summary>
    public string Message { get; set; } = string.Empty;

    /// <summary>The expanded logdata.</summary>
    public string Data { get; set; } = string.Empty;
}
