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

    public List<(string Name, IRuleAction Action)> Actions { get; } = [];

    public string File { get; set; } = string.Empty;

    public int Line { get; set; }

    public string Raw { get; set; } = string.Empty;

    /// <summary>The disruptive action name (deny, block, pass, ...), or null.</summary>
    public string? DisruptiveActionName =>
        Actions.FirstOrDefault(a => a.Action.Type == ActionType.Disruptive).Name;

    /// <summary>The id used in logs: the rule's own id, or the chain starter's.</summary>
    public int LogId => Id != 0 ? Id : ParentId;

    public void ClearTransformations() => Transformations.Clear();

    internal void Evaluate(int phase, Transaction tx, Dictionary<(int, string), string> cache)
    {
        DoEvaluate(phase, tx, 0, cache);
    }

    private List<RuleMatch>? DoEvaluate(int phase, Transaction tx, int chainLevel, Dictionary<(int, string), string> cache)
    {
        tx.Capturing = Capture;

        var ruleCol = tx.Variables.Rule;
        ruleCol.Set("id", LogId.ToString(System.Globalization.CultureInfo.InvariantCulture));
        if (Msg is not null)
        {
            ruleCol.Set("msg", Msg.Expand(tx));
        }

        ruleCol.Set("rev", Revision);
        if (LogData is not null)
        {
            ruleCol.Set("logdata", LogData.Expand(tx));
        }

        ruleCol.Set("severity", Severity == Severity.Unset ? string.Empty : Severity.ToString().ToUpperInvariant());

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
            var values = new List<MatchData>();
            var args = new List<string>(4);
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
                        TransformMultiMatch(arg.Value, args);
                    }
                    else if (useCache && Transformations.Count > 0)
                    {
                        var key = (TransformationsId, arg.Value);
                        if (!cache.TryGetValue(key, out var transformed))
                        {
                            transformed = Transform(arg.Value);
                            cache[key] = transformed;
                        }

                        args.Add(transformed);
                    }
                    else
                    {
                        args.Add(Transform(arg.Value));
                    }

                    foreach (var carg in args)
                    {
                        var result = Operator.Evaluate(tx, carg);
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

    private string Transform(string value)
    {
        foreach (var (_, t) in Transformations)
        {
            value = t(value);
        }

        return value;
    }

    private void TransformMultiMatch(string value, List<string> output)
    {
        output.Add(value);
        foreach (var (_, t) in Transformations)
        {
            var transformed = t(value);
            if (!string.Equals(transformed, value, StringComparison.Ordinal))
            {
                output.Add(transformed);
                value = transformed;
            }
        }
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
