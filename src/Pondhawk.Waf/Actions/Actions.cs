// Action semantics follow OWASP Coraza (Apache-2.0) internal/actions.
using System.Globalization;
using System.Text.RegularExpressions;
using Pondhawk.Waf.Collections;
using Pondhawk.Waf.Rules;
using Pondhawk.Waf.Transformations;

namespace Pondhawk.Waf.Actions;

public enum ActionType
{
    /// <summary>Applied at parse time only (id, phase, msg, tag, ...).</summary>
    Metadata,

    /// <summary>Stops or allows the transaction (deny, drop, block, pass, allow, redirect). One per rule.</summary>
    Disruptive,

    /// <summary>Applied at parse time (status, ...).</summary>
    Data,

    /// <summary>Runs on every variable match (setvar, ctl, ...).</summary>
    NonDisruptive,

    /// <summary>Changes rule flow (chain, skip, skipAfter).</summary>
    Flow,
}

/// <summary>A SecLang action.</summary>
public interface IRuleAction
{
    ActionType Type { get; }

    /// <summary>Applies the action argument to the rule at parse time.</summary>
    void Init(Rule rule, string data);

    /// <summary>Runs the action at evaluation time.</summary>
    void Evaluate(Rule rule, Transaction tx);
}

/// <summary>The built-in actions.</summary>
public static class ActionRegistry
{
    private static readonly Dictionary<string, Func<IRuleAction>> Factories = new(StringComparer.OrdinalIgnoreCase)
    {
        // Metadata
        ["id"] = () => new MetadataAction(static (r, d) => r.Id = ParseId(d)),
        ["phase"] = () => new MetadataAction(static (r, d) => r.Phase = ParsePhase(d)),
        ["msg"] = () => new MetadataAction(static (r, d) => r.Msg = Macro.Parse(d)),
        ["tag"] = () => new MetadataAction(static (r, d) => r.Tags.Add(d)),
        ["ver"] = () => new MetadataAction(static (r, d) => r.Version = d),
        ["rev"] = () => new MetadataAction(static (r, d) => r.Revision = d),
        ["severity"] = () => new MetadataAction(static (r, d) => r.Severity = ParseSeverity(d)),
        ["maturity"] = () => new MetadataAction(static (r, d) => r.Maturity = int.Parse(d, CultureInfo.InvariantCulture)),
        ["accuracy"] = () => new MetadataAction(static (r, d) => r.Accuracy = int.Parse(d, CultureInfo.InvariantCulture)),

        // Data
        ["status"] = () => new InitOnlyAction(ActionType.Data, static (r, d) => r.Status = int.Parse(d, CultureInfo.InvariantCulture)),
        ["xmlns"] = () => new InitOnlyAction(ActionType.Data, static (_, _) => { }),

        // Non-disruptive, applied at parse time
        ["logdata"] = () => new InitOnlyAction(ActionType.NonDisruptive, static (r, d) => r.LogData = Macro.Parse(d)),
        ["capture"] = () => new InitOnlyAction(ActionType.NonDisruptive, static (r, _) => r.Capture = true),
        ["multiMatch"] = () => new InitOnlyAction(ActionType.NonDisruptive, static (r, _) => r.MultiMatch = true),
        ["log"] = () => new InitOnlyAction(ActionType.NonDisruptive, static (r, _) => { r.Log = true; r.Audit = true; }),
        ["nolog"] = () => new InitOnlyAction(ActionType.NonDisruptive, static (r, _) => { r.Log = false; r.Audit = false; }),
        ["auditlog"] = () => new InitOnlyAction(ActionType.NonDisruptive, static (r, _) => r.Audit = true),
        ["noauditlog"] = () => new InitOnlyAction(ActionType.NonDisruptive, static (r, _) => r.Audit = false),
        ["t"] = () => new TransformationAction(),

        // Non-disruptive, at evaluation time
        ["setvar"] = () => new SetVarAction(),
        ["ctl"] = () => new CtlAction(),
        ["expirevar"] = () => new InitOnlyAction(ActionType.NonDisruptive, static (_, _) => { }),
        ["initcol"] = () => new InitOnlyAction(ActionType.NonDisruptive, static (_, _) => { }),
        ["setenv"] = () => new InitOnlyAction(ActionType.NonDisruptive, static (_, _) => { }),
        ["sanitiseArg"] = () => new InitOnlyAction(ActionType.NonDisruptive, static (_, _) => { }),
        ["sanitiseMatched"] = () => new InitOnlyAction(ActionType.NonDisruptive, static (_, _) => { }),
        ["sanitiseMatchedBytes"] = () => new InitOnlyAction(ActionType.NonDisruptive, static (_, _) => { }),
        ["sanitiseRequestHeader"] = () => new InitOnlyAction(ActionType.NonDisruptive, static (_, _) => { }),
        ["sanitiseResponseHeader"] = () => new InitOnlyAction(ActionType.NonDisruptive, static (_, _) => { }),

        // Flow
        ["chain"] = () => new InitOnlyAction(ActionType.Flow, static (r, _) => r.HasChain = true),
        ["skip"] = () => new SkipAction(),
        ["skipAfter"] = () => new SkipAfterAction(),

        // Disruptive
        ["deny"] = () => new InterruptAction("deny", 403),
        ["drop"] = () => new InterruptAction("drop", 0),
        ["redirect"] = () => new RedirectAction(),
        ["block"] = () => new NoOpDisruptiveAction(),
        ["pass"] = () => new NoOpDisruptiveAction(),
        ["allow"] = () => new AllowAction(),
    };

    public static bool TryCreate(string name, out IRuleAction action)
    {
        if (Factories.TryGetValue(name, out var factory))
        {
            action = factory();
            return true;
        }

        action = null!;
        return false;
    }

    private static int ParseId(string d)
    {
        var id = int.Parse(d.Trim('\''), CultureInfo.InvariantCulture);
        if (id <= 0)
        {
            throw new FormatException("rule id must be a positive integer");
        }

        return id;
    }

    internal static int ParsePhase(string d) => d.Trim().ToLowerInvariant() switch
    {
        "1" or "request" => 1,
        "2" => 2,
        "3" => 3,
        "4" or "response" => 4,
        "5" or "logging" => 5,
        _ => throw new FormatException($"invalid phase '{d}'"),
    };

    private static Severity ParseSeverity(string d)
    {
        if (int.TryParse(d, NumberStyles.None, CultureInfo.InvariantCulture, out var n) && n is >= 0 and <= 7)
        {
            return (Severity)n;
        }

        return d.ToUpperInvariant() switch
        {
            "EMERGENCY" => Severity.Emergency,
            "ALERT" => Severity.Alert,
            "CRITICAL" => Severity.Critical,
            "ERROR" => Severity.Error,
            "WARNING" => Severity.Warning,
            "NOTICE" => Severity.Notice,
            "INFO" => Severity.Info,
            "DEBUG" => Severity.Debug,
            _ => throw new FormatException($"invalid severity '{d}'"),
        };
    }
}

internal sealed class MetadataAction(Action<Rule, string> init) : IRuleAction
{
    public ActionType Type => ActionType.Metadata;

    public void Init(Rule rule, string data) => init(rule, data);

    public void Evaluate(Rule rule, Transaction tx)
    {
    }
}

internal sealed class InitOnlyAction(ActionType type, Action<Rule, string> init) : IRuleAction
{
    public ActionType Type => type;

    public void Init(Rule rule, string data) => init(rule, data);

    public void Evaluate(Rule rule, Transaction tx)
    {
    }
}

internal sealed class TransformationAction : IRuleAction
{
    public ActionType Type => ActionType.NonDisruptive;

    public void Init(Rule rule, string data)
    {
        if (string.Equals(data, "none", StringComparison.OrdinalIgnoreCase))
        {
            rule.ClearTransformations();
            return;
        }

        if (!Transforms.TryGet(data, out var t))
        {
            throw new NotSupportedException($"unsupported transformation t:{data}");
        }

        rule.Transformations.Add((data, t));
    }

    public void Evaluate(Rule rule, Transaction tx)
    {
    }
}

internal sealed class NoOpDisruptiveAction : IRuleAction
{
    public ActionType Type => ActionType.Disruptive;

    public void Init(Rule rule, string data)
    {
        if (data.Length > 0)
        {
            throw new FormatException("unexpected argument");
        }
    }

    public void Evaluate(Rule rule, Transaction tx)
    {
    }
}

internal sealed class InterruptAction(string name, int defaultStatus) : IRuleAction
{
    public ActionType Type => ActionType.Disruptive;

    public void Init(Rule rule, string data)
    {
    }

    public void Evaluate(Rule rule, Transaction tx) =>
        tx.Interrupt(new Interruption(rule.LogId, name, rule.Status != 0 ? rule.Status : defaultStatus, null));
}

internal sealed class RedirectAction : IRuleAction
{
    private string _target = string.Empty;

    public ActionType Type => ActionType.Disruptive;

    public void Init(Rule rule, string data)
    {
        _target = data;
        rule.RedirectUrl = data;
    }

    public void Evaluate(Rule rule, Transaction tx)
    {
        var status = rule.Status is 301 or 302 or 303 or 307 ? rule.Status : 302;
        tx.Interrupt(new Interruption(rule.LogId, "redirect", status, _target));
    }
}

internal sealed class AllowAction : IRuleAction
{
    private AllowType _allow = AllowType.All;

    public ActionType Type => ActionType.Disruptive;

    public void Init(Rule rule, string data)
    {
        _allow = data switch
        {
            "" => AllowType.All,
            "phase" => AllowType.Phase,
            "request" => AllowType.Request,
            _ => throw new FormatException($"invalid allow argument '{data}'"),
        };
    }

    public void Evaluate(Rule rule, Transaction tx) => tx.Allow(_allow);
}

internal sealed class SkipAction : IRuleAction
{
    private int _count;

    public ActionType Type => ActionType.Flow;

    public void Init(Rule rule, string data) => _count = int.Parse(data, CultureInfo.InvariantCulture);

    public void Evaluate(Rule rule, Transaction tx) => tx.Skip = _count;
}

internal sealed class SkipAfterAction : IRuleAction
{
    private string _marker = string.Empty;

    public ActionType Type => ActionType.Flow;

    public void Init(Rule rule, string data) => _marker = data.Trim('\'', '"');

    public void Evaluate(Rule rule, Transaction tx) => tx.SkipAfter = _marker;
}

internal sealed class SetVarAction : IRuleAction
{
    private bool _remove;
    private Macro? _key;
    private Macro? _value;

    public ActionType Type => ActionType.NonDisruptive;

    public void Init(Rule rule, string data)
    {
        if (data.Length == 0)
        {
            throw new FormatException("setvar requires an argument");
        }

        if (data[0] == '!')
        {
            _remove = true;
            data = data[1..];
        }

        var eq = data.IndexOf('=', StringComparison.Ordinal);
        var key = eq < 0 ? data : data[..eq];
        var dot = key.IndexOf('.', StringComparison.Ordinal);
        var collection = dot < 0 ? key : key[..dot];
        if (!string.Equals(collection, "TX", StringComparison.OrdinalIgnoreCase))
        {
            throw new FormatException($"setvar supports only the TX collection: '{data}'");
        }

        var colKey = dot < 0 ? string.Empty : key[(dot + 1)..];
        if (colKey.Trim().Length == 0)
        {
            throw new FormatException("setvar syntax is TX.{key}={value}");
        }

        _key = Macro.Parse(colKey);
        var value = eq < 0 ? (_remove ? null : "1") : data[(eq + 1)..];
        if (!string.IsNullOrEmpty(value))
        {
            _value = Macro.Parse(value);
        }
    }

    public void Evaluate(Rule rule, Transaction tx)
    {
        var key = _key!.Expand(tx);
        if (key.Length == 0)
        {
            return;
        }

        key = key.ToLowerInvariant();
        var col = tx.Variables.Tx;
        if (_remove)
        {
            col.Remove(key);
            return;
        }

        var value = _value?.Expand(tx) ?? string.Empty;
        if (value.Length == 0)
        {
            col.Set(key, string.Empty);
            return;
        }

        if (value[0] is '+' or '-')
        {
            long delta = 0;
            if (value.Length > 1 && !long.TryParse(value.AsSpan(1), NumberStyles.None, CultureInfo.InvariantCulture, out delta))
            {
                if (value.AsSpan(1).StartsWith("tx.", StringComparison.Ordinal))
                {
                    return;
                }

                col.Set(key, value);
                return;
            }

            long current = 0;
            var currentValue = col.GetFirst(key);
            if (!string.IsNullOrEmpty(currentValue) && !long.TryParse(currentValue, NumberStyles.AllowLeadingSign, CultureInfo.InvariantCulture, out current))
            {
                return;
            }

            col.Set(key, (value[0] == '+' ? current + delta : current - delta).ToString(CultureInfo.InvariantCulture));
            return;
        }

        col.Set(key, value);
    }
}

internal sealed class CtlAction : IRuleAction
{
    private string _option = string.Empty;
    private string _value = string.Empty;
    private Variable _targetVariable;
    private string _targetKey = string.Empty;
    private Regex? _targetKeyRegex;

    public ActionType Type => ActionType.NonDisruptive;

    public void Init(Rule rule, string data)
    {
        var eq = data.IndexOf('=', StringComparison.Ordinal);
        if (eq < 0)
        {
            throw new FormatException($"invalid ctl '{data}'");
        }

        _option = data[..eq].Trim();
        _value = data[(eq + 1)..].Trim();

        if (_option.StartsWith("ruleRemoveTarget", StringComparison.OrdinalIgnoreCase))
        {
            // ruleRemoveTargetById=920100;ARGS:foo or ruleRemoveTargetByTag=attack-sqli;ARGS:/^json\./
            var semi = _value.IndexOf(';', StringComparison.Ordinal);
            if (semi < 0)
            {
                throw new FormatException($"invalid ctl '{data}'");
            }

            var target = _value[(semi + 1)..];
            _value = _value[..semi];
            var colon = target.IndexOf(':', StringComparison.Ordinal);
            var name = colon < 0 ? target : target[..colon];
            if (!Variables.TryParse(name, out _targetVariable))
            {
                throw new FormatException($"unknown variable '{name}' in ctl");
            }

            if (colon >= 0)
            {
                var key = target[(colon + 1)..];
                if (key.Length > 1 && key[0] == '/' && key[^1] == '/')
                {
                    _targetKeyRegex = new Regex(key[1..^1], RegexOptions.CultureInvariant);
                }
                else
                {
                    _targetKey = key.ToLowerInvariant();
                }
            }
        }
    }

    public void Evaluate(Rule rule, Transaction tx)
    {
        switch (_option.ToLowerInvariant())
        {
            case "ruleengine":
                if (TryParseEngine(_value, out var engine))
                {
                    tx.RuleEngine = engine;
                }

                break;
            case "ruleremovebyid":
                var dash = _value.IndexOf('-', StringComparison.Ordinal);
                if (dash < 0)
                {
                    if (int.TryParse(_value, CultureInfo.InvariantCulture, out var id))
                    {
                        tx.RemoveRuleById(id);
                    }
                }
                else if (int.TryParse(_value.AsSpan(0, dash), CultureInfo.InvariantCulture, out var start)
                         && int.TryParse(_value.AsSpan(dash + 1), CultureInfo.InvariantCulture, out var end))
                {
                    tx.RemoveRuleByIdRange(start, end);
                }

                break;
            case "ruleremovebytag":
                foreach (var r in tx.Waf.Rules)
                {
                    if (r.Tags.Contains(_value, StringComparer.Ordinal))
                    {
                        tx.RemoveRuleById(r.Id);
                    }
                }

                break;
            case "ruleremovebymsg":
                foreach (var r in tx.Waf.Rules)
                {
                    if (r.Msg is not null && r.Msg.Original == _value)
                    {
                        tx.RemoveRuleById(r.Id);
                    }
                }

                break;
            case "ruleremovetargetbyid":
                if (TryParseRange(_value, out var s, out var e))
                {
                    foreach (var r in tx.Waf.Rules)
                    {
                        if (r.Id >= s && r.Id <= e)
                        {
                            tx.RemoveRuleTargetById(r.Id, _targetVariable, _targetKey, _targetKeyRegex);
                        }
                    }
                }

                break;
            case "ruleremovetargetbytag":
                foreach (var r in tx.Waf.Rules)
                {
                    if (r.Tags.Contains(_value, StringComparer.Ordinal))
                    {
                        tx.RemoveRuleTargetById(r.Id, _targetVariable, _targetKey, _targetKeyRegex);
                    }
                }

                break;
            case "ruleremovetargetbymsg":
                foreach (var r in tx.Waf.Rules)
                {
                    if (r.Msg is not null && r.Msg.Original == _value)
                    {
                        tx.RemoveRuleTargetById(r.Id, _targetVariable, _targetKey, _targetKeyRegex);
                    }
                }

                break;
            case "auditengine":
                if (TryParseAuditEngine(_value, out var audit))
                {
                    tx.AuditEngine = audit;
                }

                break;
            case "auditlogparts":
                tx.AuditLogParts = _value;
                break;
            case "forcerequestbodyvariable":
                if (TryParseOnOff(_value, out var force))
                {
                    tx.ForceRequestBodyVariable = force;
                }

                break;
            case "forceresponsebodyvariable":
                if (TryParseOnOff(_value, out var forceResponse))
                {
                    tx.ForceResponseBodyVariable = forceResponse;
                }

                break;
            case "requestbodyaccess":
                if (tx.LastPhase <= 1 && TryParseOnOff(_value, out var access))
                {
                    tx.RequestBodyAccess = access;
                }

                break;
            case "requestbodylimit":
                if (tx.LastPhase <= 1 && long.TryParse(_value, CultureInfo.InvariantCulture, out var limit))
                {
                    tx.RequestBodyLimit = limit;
                }

                break;
            case "requestbodyprocessor":
                if (tx.LastPhase <= 1)
                {
                    tx.Variables.ReqbodyProcessor.Set(_value.ToUpperInvariant());
                }

                break;
            case "responsebodyaccess":
                if (tx.LastPhase <= 3 && TryParseOnOff(_value, out var resAccess))
                {
                    tx.ResponseBodyAccess = resAccess;
                }

                break;
            case "responsebodylimit":
                if (tx.LastPhase <= 3 && long.TryParse(_value, CultureInfo.InvariantCulture, out var resLimit))
                {
                    tx.ResponseBodyLimit = resLimit;
                }

                break;
            case "responsebodyprocessor":
                if (tx.LastPhase <= 3)
                {
                    tx.Variables.ResBodyProcessor.Set(_value.ToUpperInvariant());
                }

                break;
        }
    }

    internal static bool TryParseEngine(string value, out RuleEngineMode mode)
    {
        switch (value.ToLowerInvariant())
        {
            case "on":
                mode = RuleEngineMode.On;
                return true;
            case "off":
                mode = RuleEngineMode.Off;
                return true;
            case "detectiononly":
                mode = RuleEngineMode.DetectionOnly;
                return true;
            default:
                mode = default;
                return false;
        }
    }

    internal static bool TryParseAuditEngine(string value, out AuditEngineMode mode)
    {
        switch (value.ToLowerInvariant())
        {
            case "on":
                mode = AuditEngineMode.On;
                return true;
            case "off":
                mode = AuditEngineMode.Off;
                return true;
            case "relevantonly":
                mode = AuditEngineMode.RelevantOnly;
                return true;
            default:
                mode = default;
                return false;
        }
    }

    internal static bool TryParseOnOff(string value, out bool result)
    {
        switch (value.ToLowerInvariant())
        {
            case "on":
                result = true;
                return true;
            case "off":
                result = false;
                return true;
            default:
                result = false;
                return false;
        }
    }

    private static bool TryParseRange(string value, out int start, out int end)
    {
        var dash = value.IndexOf('-', StringComparison.Ordinal);
        if (dash < 0)
        {
            var ok = int.TryParse(value, CultureInfo.InvariantCulture, out start);
            end = start;
            return ok;
        }

        end = 0;
        return int.TryParse(value.AsSpan(0, dash), CultureInfo.InvariantCulture, out start)
               && int.TryParse(value.AsSpan(dash + 1), CultureInfo.InvariantCulture, out end);
    }
}
