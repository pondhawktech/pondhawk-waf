// SecLang parsing follows OWASP Coraza (Apache-2.0) internal/seclang.
using System.Globalization;
using System.Text;
using System.Text.RegularExpressions;
using Pondhawk.Waf.Actions;
using Pondhawk.Waf.Collections;
using Pondhawk.Waf.Operators;
using Pondhawk.Waf.Rules;

namespace Pondhawk.Waf.SecLang;

/// <summary>A SecLang directive could not be parsed.</summary>
public sealed class SecLangException(string message, string file, int line, Exception? inner = null)
    : Exception($"{file}:{line}: {message}", inner)
{
    public string File { get; } = file;

    public int Line { get; } = line;
}

internal sealed class SecLangParser(WafConfig config, IConfigFileSystem fs, RegexCache regexCache)
{
    private const int MaxIncludeDepth = 100;
    private const string DefaultPhase2Actions = "phase:2,log,auditlog,pass";

    private readonly List<Rule> _rules = [];
    private readonly HashSet<int> _ids = [];
    private readonly Dictionary<int, List<ParsedAction>> _defaultActions = [];
    private readonly Dictionary<string, int> _transformationIds = new(StringComparer.Ordinal);
    private Rule? _pendingChain;
    private int _includeDepth;
    private string _file = "<directives>";
    private string _dir = string.Empty;
    private int _line;

    public List<Rule> Finish()
    {
        if (_pendingChain is not null)
        {
            throw new SecLangException($"rule {_pendingChain.Id} declares chain but no chained rule follows", _file, _line);
        }

        return _rules;
    }

    public void ParseFile(string path)
    {
        var matches = path.Contains('*', StringComparison.Ordinal) || path.Contains('?', StringComparison.Ordinal)
            ? fs.Glob(path)
            : [path];
        if (matches.Count == 0)
        {
            throw new SecLangException($"no files match '{path}'", _file, _line);
        }

        foreach (var file in matches)
        {
            if (!fs.FileExists(file))
            {
                throw new SecLangException($"file not found: '{file}'", _file, _line);
            }

            ParseString(fs.ReadAllText(file), file, fs.GetDirectoryName(file));
        }
    }

    public void ParseString(string text, string fileName, string directory)
    {
        var (savedFile, savedDir, savedLine) = (_file, _dir, _line);
        _file = fileName;
        _dir = directory;
        _line = 0;
        try
        {
            var buffer = new StringBuilder();
            var inBackticks = false;
            var startLine = 0;
            foreach (var rawLine in text.Split('\n'))
            {
                _line++;
                var line = rawLine.Trim();
                if (line.Length == 0 || line[0] == '#')
                {
                    continue;
                }

                if (buffer.Length == 0)
                {
                    startLine = _line;
                }

                if (!inBackticks && line[^1] == '`')
                {
                    inBackticks = true;
                }
                else if (inBackticks && line[0] == '`')
                {
                    inBackticks = false;
                }

                if (inBackticks)
                {
                    buffer.Append(line).Append('\n');
                    continue;
                }

                if (line[^1] == '\\')
                {
                    buffer.Append(line, 0, line.Length - 1);
                    continue;
                }

                buffer.Append(line);
                var lineNumber = _line;
                _line = startLine;
                EvaluateLine(buffer.ToString());
                _line = lineNumber;
                buffer.Clear();
            }

            if (inBackticks)
            {
                throw new SecLangException("backticks left open", _file, _line);
            }
        }
        finally
        {
            (_file, _dir, _line) = (savedFile, savedDir, savedLine);
        }
    }

    private static bool HasUnescapedQuote(ReadOnlySpan<char> s)
    {
        for (var i = 0; i < s.Length; i++)
        {
            if (s[i] == '"' && (i == 0 || s[i - 1] != '\\'))
            {
                return true;
            }
        }

        return false;
    }

    private void EvaluateLine(string line)
    {
        var space = line.IndexOf(' ', StringComparison.Ordinal);
        var directive = (space < 0 ? line : line[..space]).ToLowerInvariant();
        var opts = space < 0 ? string.Empty : line[(space + 1)..];
        // Strip the quotes around a single quoted argument, but not around two ("attack-sqli" "!ARGS:foo").
        if (opts.Length >= 3 && opts[0] == '"' && opts[^1] == '"' && !HasUnescapedQuote(opts.AsSpan(1, opts.Length - 2)))
        {
            opts = opts.Trim('"');
        }

        try
        {
            Apply(directive, opts, line);
        }
        catch (SecLangException)
        {
            throw;
        }
        catch (Exception ex) when (ex is FormatException or NotSupportedException or ArgumentException or OverflowException or FileNotFoundException or RegexParseException)
        {
            throw new SecLangException($"{directive}: {ex.Message}", _file, _line, ex);
        }
    }

    private void Apply(string directive, string opts, string raw)
    {
        switch (directive)
        {
            case "include":
                if (++_includeDepth > MaxIncludeDepth)
                {
                    throw new SecLangException("too many nested includes", _file, _line);
                }

                ParseFile(fs.Combine(_dir, opts.Trim()));
                _includeDepth--;
                break;
            case "secrule":
                AddRule(ParseRule(opts, raw, withOperator: true));
                break;
            case "secaction":
                AddRule(ParseRule(opts, raw, withOperator: false));
                break;
            case "secmarker":
                RequireOpts(opts);
                _rules.Add(new Rule { SecMark = opts.Trim('"', '\''), Phase = 0, File = _file, Line = _line, Raw = raw });
                break;
            case "secdefaultaction":
                ParseDefaultActions(opts);
                break;
            case "secruleengine":
                config.RuleEngine = CtlAction.TryParseEngine(opts, out var mode) ? mode : throw new FormatException($"invalid SecRuleEngine '{opts}'");
                break;
            case "secrequestbodyaccess":
                config.RequestBodyAccess = OnOff(opts);
                break;
            case "secresponsebodyaccess":
                config.ResponseBodyAccess = OnOff(opts);
                break;
            case "secrequestbodylimit":
                config.RequestBodyLimit = long.Parse(opts, CultureInfo.InvariantCulture);
                break;
            case "secrequestbodynofileslimit":
                config.RequestBodyNoFilesLimit = long.Parse(opts, CultureInfo.InvariantCulture);
                break;
            case "secrequestbodyinmemorylimit":
                config.RequestBodyInMemoryLimit = long.Parse(opts, CultureInfo.InvariantCulture);
                break;
            case "secrequestbodylimitaction":
                config.RequestBodyLimitAction = ParseLimitAction(opts);
                break;
            case "secresponsebodylimit":
                config.ResponseBodyLimit = long.Parse(opts, CultureInfo.InvariantCulture);
                break;
            case "secresponsebodylimitaction":
                config.ResponseBodyLimitAction = ParseLimitAction(opts);
                break;
            case "secresponsebodymimetype":
                foreach (var t in opts.Split(' ', StringSplitOptions.RemoveEmptyEntries))
                {
                    if (!config.ResponseBodyMimeTypes.Contains(t, StringComparer.OrdinalIgnoreCase))
                    {
                        config.ResponseBodyMimeTypes.Add(t);
                    }
                }

                break;
            case "secresponsebodymimetypesclear":
                config.ResponseBodyMimeTypes.Clear();
                break;
            case "secrequestbodyjsondepthlimit":
                config.RequestBodyJsonDepthLimit = int.Parse(opts, CultureInfo.InvariantCulture);
                break;
            case "secargumentslimit":
                config.ArgumentsLimit = int.Parse(opts, CultureInfo.InvariantCulture);
                break;
            case "secauditengine":
                config.AuditEngine = CtlAction.TryParseAuditEngine(opts, out var audit) ? audit : throw new FormatException($"invalid SecAuditEngine '{opts}'");
                break;
            case "secauditlogparts":
                config.AuditLogParts = opts;
                break;
            case "secauditlogrelevantstatus":
                config.AuditLogRelevantStatus = new Regex(opts.Trim('"'), RegexOptions.CultureInvariant | RegexOptions.NonBacktracking);
                break;
            case "sectmpdir":
            case "secuploaddir":
                config.TempDirectory = opts;
                break;
            case "seccomponentsignature":
                config.ComponentSignatures.Add(opts);
                break;
            case "secruleremovebyid":
                foreach (var item in opts.Split(' ', StringSplitOptions.RemoveEmptyEntries))
                {
                    var (start, end) = ParseRange(item);
                    _rules.RemoveAll(r => r.Id != 0 && r.Id >= start && r.Id <= end);
                }

                break;
            case "secruleremovebytag":
                _rules.RemoveAll(r => r.Tags.Contains(opts, StringComparer.Ordinal));
                break;
            case "secruleremovebymsg":
                _rules.RemoveAll(r => r.Msg?.Original == opts);
                break;
            case "secruleupdatetargetbyid":
                UpdateTargets(opts, byTag: false);
                break;
            case "secruleupdatetargetbytag":
                UpdateTargets(opts, byTag: true);
                break;
            case "secruleupdateactionbyid":
                UpdateActions(opts);
                break;

            // Accepted and ignored: logging destinations, persistence and features the engine does not implement.
            case "secauditlog":
            case "secauditlogtype":
            case "secauditlogformat":
            case "secauditlogdir":
            case "secauditlogstoragedir":
            case "secauditlogdirmode":
            case "secauditlogfilemode":
            case "secdatadir":
            case "secdebuglog":
            case "secdebugloglevel":
            case "seccollectiontimeout":
            case "secwebappid":
            case "secserversignature":
            case "secrxprefilter":
            case "secresponsebodyjsondepthlimit":
            case "secpcrematchlimit":
            case "secpcrematchlimitrecursion":
            case "seccontentinjection":
            case "secunicodemapfile":
            case "secstatusengine":
            case "secuploadkeepfiles":
            case "secuploadfilemode":
            case "secuploadfilelimit":
            case "secargumentseparator":
            case "seccookieformat":
            case "sechashengine":
            case "secignorerulecompilationerrors":
                break;
            default:
                throw new SecLangException($"unknown directive '{directive}'", _file, _line);
        }
    }

    private void AddRule(Rule? rule)
    {
        if (rule is null)
        {
            return;
        }

        if (rule.Id != 0 && !_ids.Add(rule.Id))
        {
            throw new SecLangException($"duplicated rule id {rule.Id}", _file, _line);
        }

        _rules.Add(rule);
    }

    /// <summary>Parses a SecRule or SecAction. Returns null for a chain link (it is attached to its starter).</summary>
    private Rule? ParseRule(string data, string raw, bool withOperator)
    {
        if (data.Trim().Length == 0)
        {
            throw new FormatException("empty rule");
        }

        var rule = new Rule { File = _file, Line = _line };
        string actions;
        if (withOperator)
        {
            var (vars, op, acts) = SplitRule(data);
            ParseVariables(rule, vars);
            ParseOperator(rule, op);
            actions = acts;
        }
        else
        {
            actions = MaybeRemoveQuotes(data);
        }

        var parsed = ParseActions(actions);
        ApplyActions(rule, parsed);
        rule.TransformationsId = TransformationId(rule);

        var parent = _pendingChain;
        if (parent is not null)
        {
            if (parsed.Any(a => a.Action.Type == ActionType.Disruptive))
            {
                _pendingChain = null;
                throw new FormatException($"disruptive actions can only be specified by the chain starter rule (parent id: {parent.Id})");
            }

            rule.ParentId = parent.Id;
            rule.Phase = 0;
            var last = parent;
            while (last.Chain is not null)
            {
                last = last.Chain;
            }

            last.Chain = rule;
            parent.Raw += " \n" + raw;
            if (!rule.HasChain)
            {
                _pendingChain = null;
            }

            return null;
        }

        rule.Raw = raw;
        if (rule.Id == 0)
        {
            throw new FormatException("rules must have an id");
        }

        if (rule.HasChain)
        {
            _pendingChain = rule;
        }

        return rule;
    }

    private int TransformationId(Rule rule)
    {
        var key = string.Join(',', rule.Transformations.Select(t => t.Name.ToLowerInvariant()));
        if (!_transformationIds.TryGetValue(key, out var id))
        {
            id = _transformationIds.Count + 1;
            _transformationIds[key] = id;
        }

        return id;
    }

    // ---- variables ----

    private void ParseVariables(Rule rule, string vars)
    {
        foreach (var item in SplitVariables(vars))
        {
            var s = item;
            var negation = false;
            var count = false;
            if (s.StartsWith('!'))
            {
                negation = true;
                s = s[1..];
            }

            if (s.StartsWith('&'))
            {
                count = true;
                s = s[1..];
            }

            var colon = s.IndexOf(':', StringComparison.Ordinal);
            var name = colon < 0 ? s : s[..colon];
            var key = colon < 0 ? string.Empty : s[(colon + 1)..];
            if (!Variables.TryParse(name, out var variable))
            {
                throw new FormatException($"unknown variable '{name}'");
            }

            if (key.Length >= 2 && key[0] == '\'' && key[^1] == '\'')
            {
                key = key[1..^1];
            }

            if (key.Length > 0 && !variable.CanBeSelected())
            {
                throw new FormatException($"attempting to select a value inside a non-selectable collection: {name}");
            }

            Regex? keyRegex = null;
            if (key.Length > 2 && key[0] == '/' && key[^1] == '/' && variable is not (Variable.Xml or Variable.Json or Variable.RequestXml))
            {
                keyRegex = new Regex(key[1..^1], RegexOptions.CultureInvariant | RegexOptions.IgnoreCase | RegexOptions.NonBacktracking);
                key = string.Empty;
            }

            if (negation)
            {
                foreach (var rv in rule.Variables)
                {
                    if (rv.Variable == variable)
                    {
                        rv.Exceptions.Add(new VariableException(key.ToLowerInvariant(), keyRegex));
                    }
                }
            }
            else
            {
                rule.Variables.Add(new RuleVariable(variable, key, keyRegex, count));
            }
        }
    }

    // Splits "ARGS|!ARGS:/a|b/|XML:/*" on '|' outside /regex/ and quotes.
    private static List<string> SplitVariables(string vars)
    {
        var result = new List<string>();
        var current = new StringBuilder();
        var inRegex = false;
        var inQuote = false;
        var afterColon = false;
        for (var i = 0; i < vars.Length; i++)
        {
            var c = vars[i];
            if (inRegex)
            {
                current.Append(c);
                if (c == '\\' && i + 1 < vars.Length)
                {
                    current.Append(vars[++i]);
                }
                else if (c == '/')
                {
                    inRegex = false;
                }

                continue;
            }

            if (inQuote)
            {
                current.Append(c);
                if (c == '\'')
                {
                    inQuote = false;
                }

                continue;
            }

            switch (c)
            {
                case '|':
                    if (current.Length > 0)
                    {
                        result.Add(current.ToString());
                    }

                    current.Clear();
                    afterColon = false;
                    continue;
                case ':' when !afterColon:
                    afterColon = true;
                    current.Append(c);
                    var name = current.ToString().TrimStart('!', '&')[..^1];
                    // XML:/* and JSON keys are XPath-like, not regexes.
                    if (i + 1 < vars.Length && vars[i + 1] == '/' && !name.Equals("XML", StringComparison.OrdinalIgnoreCase)
                        && !name.Equals("JSON", StringComparison.OrdinalIgnoreCase) && !name.Equals("REQUEST_XML", StringComparison.OrdinalIgnoreCase))
                    {
                        current.Append('/');
                        i++;
                        inRegex = true;
                    }
                    else if (i + 1 < vars.Length && vars[i + 1] == '\'')
                    {
                        current.Append('\'');
                        i++;
                        inQuote = true;
                    }

                    continue;
                default:
                    current.Append(c);
                    break;
            }
        }

        if (current.Length > 0)
        {
            result.Add(current.ToString());
        }

        return result;
    }

    // ---- operator ----

    private void ParseOperator(Rule rule, string op)
    {
        if (op.Length == 0 || (op[0] != '@' && op[0] != '!'))
        {
            op = "@rx " + op;
        }
        else if (op == "!")
        {
            op = "!@rx";
        }
        else if (op.Length > 1 && op[0] == '!' && op[1] != '@')
        {
            op = "!@rx " + op[1..];
        }

        var space = op.IndexOf(' ', StringComparison.Ordinal);
        var name = (space < 0 ? op : op[..space]).Trim();
        var arg = space < 0 ? string.Empty : op[(space + 1)..].Trim();
        if (name.StartsWith("!@", StringComparison.Ordinal))
        {
            rule.OperatorNegated = true;
            name = name[2..];
        }
        else if (name.StartsWith('@'))
        {
            name = name[1..];
        }

        rule.OperatorName = name;
        rule.OperatorData = arg;
        rule.Operator = OperatorRegistry.Create(name, new OperatorOptions(arg, _dir, fs, regexCache));
    }

    // ---- actions ----

    private readonly record struct ParsedAction(string Name, string Value, IRuleAction Action);

    private static List<ParsedAction> ParseActions(string actions)
    {
        var result = new List<ParsedAction>();
        var disruptiveIndex = -1;
        foreach (var (rawKey, rawValue) in SplitActions(actions))
        {
            var key = rawKey.Trim().ToLowerInvariant();
            if (key.Length == 0)
            {
                continue;
            }

            var value = MaybeRemoveQuotes(rawValue.Trim());
            if (!ActionRegistry.TryCreate(key, out var action))
            {
                throw new NotSupportedException($"unsupported action '{key}'");
            }

            var pa = new ParsedAction(key, value, action);
            if (action.Type == ActionType.Disruptive)
            {
                // Only one disruptive action per rule: the last one wins.
                if (disruptiveIndex >= 0)
                {
                    result[disruptiveIndex] = pa;
                    continue;
                }

                disruptiveIndex = result.Count;
            }

            result.Add(pa);
        }

        return result;
    }

    // Splits "a:1,msg:'x, y',b" into key/value pairs; quotes protect commas, backslash escapes the next char.
    private static IEnumerable<(string Key, string Value)> SplitActions(string actions)
    {
        var beforeKey = -1;
        var afterKey = -1;
        var inQuotes = false;
        for (var i = 1; i < actions.Length; i++)
        {
            var c = actions[i];
            if (actions[i - 1] == '\\')
            {
                continue;
            }

            if (c == '\'')
            {
                inQuotes = !inQuotes;
                continue;
            }

            if (inQuotes)
            {
                continue;
            }

            if (c == ':')
            {
                if (afterKey == -1)
                {
                    afterKey = i;
                }
            }
            else if (c == ',')
            {
                string val;
                if (afterKey == -1)
                {
                    afterKey = i;
                    val = string.Empty;
                }
                else
                {
                    val = actions[(afterKey + 1)..i];
                }

                yield return (actions[(beforeKey + 1)..afterKey], val);
                beforeKey = i;
                afterKey = -1;
            }
        }

        if (actions.Length == 0)
        {
            yield break;
        }

        string last;
        if (afterKey == -1)
        {
            afterKey = actions.Length;
            last = string.Empty;
        }
        else
        {
            last = actions[(afterKey + 1)..];
        }

        yield return (actions[(beforeKey + 1)..afterKey], last);
    }

    private void ParseDefaultActions(string opts)
    {
        var parsed = ParseActions(opts);
        var phase = 0;
        var hasDisruptive = false;
        foreach (var a in parsed)
        {
            if (a.Name == "phase")
            {
                phase = ActionRegistry.ParsePhase(a.Value);
                continue;
            }

            if (a.Action.Type == ActionType.Metadata)
            {
                throw new FormatException("SecDefaultAction must not contain metadata actions");
            }

            if (a.Name == "t")
            {
                throw new FormatException("SecDefaultAction must not contain transformation actions");
            }

            hasDisruptive |= a.Action.Type == ActionType.Disruptive;
        }

        if (phase == 0)
        {
            throw new FormatException("SecDefaultAction must contain a phase");
        }

        if (!hasDisruptive)
        {
            throw new FormatException("SecDefaultAction must contain a disruptive action");
        }

        if (!_defaultActions.TryAdd(phase, parsed))
        {
            throw new FormatException("SecDefaultAction already defined for this phase");
        }
    }

    private void ApplyActions(Rule rule, List<ParsedAction> parsed)
    {
        foreach (var a in parsed)
        {
            if (a.Action.Type == ActionType.Metadata)
            {
                a.Action.Init(rule, a.Value);
            }
        }

        var defaults = _defaultActions.GetValueOrDefault(rule.Phase);
        if (defaults is null && rule.Phase == 2)
        {
            defaults = ParseActions(DefaultPhase2Actions);
        }

        var merged = defaults is null ? parsed : MergeActions(parsed, defaults);
        foreach (var a in merged)
        {
            if (a.Action.Type == ActionType.Metadata)
            {
                continue;
            }

            // Default actions are shared definitions; each rule gets its own instance.
            IRuleAction action = a.Action;
            if (defaults is not null && defaults.Contains(a))
            {
                ActionRegistry.TryCreate(a.Name, out action);
            }

            action.Init(rule, a.Value);
            if (a.Name == "t")
            {
                continue;
            }

            rule.Actions.Add((a.Name, action));
        }
    }

    private static List<ParsedAction> MergeActions(List<ParsedAction> origin, List<ParsedAction> defaults)
    {
        var result = new List<ParsedAction>();
        ParsedAction? defaultDisruptive = null;
        foreach (var a in defaults)
        {
            if (a.Action.Type == ActionType.Disruptive)
            {
                defaultDisruptive = a;
                continue;
            }

            if (a.Action.Type == ActionType.Metadata)
            {
                continue;
            }

            result.Add(a);
        }

        var hasDisruptive = false;
        foreach (var a in origin)
        {
            if (a.Action.Type == ActionType.Disruptive)
            {
                if (a.Name != "block")
                {
                    hasDisruptive = true;
                    result.Add(a);
                }
            }
            else
            {
                result.Add(a);
            }
        }

        if (!hasDisruptive && defaultDisruptive is { } da)
        {
            // block, or no disruptive action: use the default one.
            result.Add(da);
        }

        return result;
    }

    // ---- update directives ----

    private void UpdateTargets(string opts, bool byTag)
    {
        var fields = SplitQuotedFields(opts);
        if (fields.Count < 2)
        {
            throw new FormatException("syntax: SecRuleUpdateTargetById id \"VARIABLES\"");
        }

        var vars = fields[1];
        IEnumerable<Rule> targets;
        if (byTag)
        {
            targets = _rules.Where(r => r.Tags.Contains(fields[0], StringComparer.Ordinal));
        }
        else
        {
            var ids = fields[0].Split(' ', StringSplitOptions.RemoveEmptyEntries).Select(ParseRange).ToList();
            targets = _rules.Where(r => r.Id != 0 && ids.Any(range => r.Id >= range.Start && r.Id <= range.End)).ToList();
            if (!targets.Any())
            {
                throw new FormatException($"SecRuleUpdateTargetById: rule '{fields[0]}' not found");
            }
        }

        foreach (var r in targets.ToList())
        {
            ParseVariables(r, vars);
        }
    }

    private void UpdateActions(string opts)
    {
        var fields = SplitQuotedFields(opts);
        if (fields.Count < 2)
        {
            throw new FormatException("syntax: SecRuleUpdateActionById id \"ACTIONS\"");
        }

        var (start, end) = ParseRange(fields[0]);
        var parsed = ParseActions(fields[1]);
        foreach (var r in _rules.Where(r => r.Id >= start && r.Id <= end))
        {
            foreach (var a in parsed)
            {
                if (a.Action.Type == ActionType.Disruptive)
                {
                    r.Actions.RemoveAll(x => x.Action.Type == ActionType.Disruptive);
                }

                ActionRegistry.TryCreate(a.Name, out var action);
                action.Init(r, a.Value);
                if (a.Name != "t" && a.Action.Type != ActionType.Metadata)
                {
                    r.Actions.Add((a.Name, action));
                }
            }

            r.TransformationsId = TransformationId(r);
        }
    }

    private static List<string> SplitQuotedFields(string s)
    {
        var result = new List<string>();
        var i = 0;
        while (i < s.Length)
        {
            while (i < s.Length && s[i] == ' ')
            {
                i++;
            }

            if (i >= s.Length)
            {
                break;
            }

            if (s[i] == '"')
            {
                var end = i + 1;
                while (end < s.Length && !(s[end] == '"' && s[end - 1] != '\\'))
                {
                    end++;
                }

                result.Add(s[(i + 1)..Math.Min(end, s.Length)]);
                i = end + 1;
            }
            else
            {
                var end = s.IndexOf(' ', i);
                if (end < 0)
                {
                    end = s.Length;
                }

                result.Add(s[i..end]);
                i = end;
            }
        }

        return result;
    }

    // ---- helpers ----

    private static (string Vars, string Operator, string Actions) SplitRule(string data)
    {
        data = data.Trim(' ');
        var space = data.IndexOf(' ', StringComparison.Ordinal);
        if (space < 0)
        {
            throw new FormatException($"invalid rule format: '{data}'");
        }

        var vars = data[..space];
        var rest = data[(space + 1)..].TrimStart(' ');
        if (rest.Length == 0 || rest[0] != '"')
        {
            throw new FormatException($"invalid operator: '{data}'");
        }

        var (quoted, after) = CutQuotedString(rest);
        var op = UnescapeQuotes(MaybeRemoveQuotes(quoted));
        after = after.TrimStart(' ');
        if (after.Length == 0)
        {
            return (vars, op, string.Empty);
        }

        if (after.Length < 2 || after[0] != '"' || after[^1] != '"')
        {
            throw new FormatException($"invalid actions: '{data}'");
        }

        return (vars, op, MaybeRemoveQuotes(after));
    }

    private static (string Quoted, string Remainder) CutQuotedString(string s)
    {
        var escapes = 0;
        for (var i = 1; i < s.Length; i++)
        {
            if (s[i] != '"')
            {
                escapes = s[i] == '\\' ? escapes + 1 : 0;
                continue;
            }

            if (escapes % 2 == 1)
            {
                escapes = 0;
                continue;
            }

            return (s[..(i + 1)], s[(i + 1)..]);
        }

        throw new FormatException($"expected terminating quote: '{s}'");
    }

    private static string UnescapeQuotes(string s) =>
        s.Contains('\\', StringComparison.Ordinal) ? s.Replace("\\\"", "\"", StringComparison.Ordinal) : s;

    private static string MaybeRemoveQuotes(string s)
    {
        if (s.Length < 2)
        {
            return s;
        }

        return (s[0], s[^1]) switch
        {
            ('"', '"') or ('\'', '\'') => s[1..^1],
            _ => s,
        };
    }

    private static bool OnOff(string value) =>
        CtlAction.TryParseOnOff(value, out var result) ? result : throw new FormatException($"expected On or Off, got '{value}'");

    private static BodyLimitAction ParseLimitAction(string value) => value.ToLowerInvariant() switch
    {
        "reject" => BodyLimitAction.Reject,
        "processpartial" => BodyLimitAction.ProcessPartial,
        _ => throw new FormatException($"invalid body limit action '{value}'"),
    };

    private static (int Start, int End) ParseRange(string item)
    {
        var dash = item.IndexOf('-', StringComparison.Ordinal);
        if (dash == 0)
        {
            throw new FormatException($"invalid negative id '{item}'");
        }

        if (dash < 0)
        {
            var id = int.Parse(item, CultureInfo.InvariantCulture);
            return (id, id);
        }

        var start = int.Parse(item[..dash], CultureInfo.InvariantCulture);
        var end = int.Parse(item[(dash + 1)..], CultureInfo.InvariantCulture);
        if (start > end)
        {
            throw new FormatException($"invalid range '{item}'");
        }

        return (start, end);
    }

    private static void RequireOpts(string opts)
    {
        if (opts.Length == 0)
        {
            throw new FormatException("missing arguments");
        }
    }
}
