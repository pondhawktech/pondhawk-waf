using System.Text;
using Pondhawk.Waf.Collections;

namespace Pondhawk.Waf.Rules;

/// <summary>
/// A string with %{VARIABLE.key} placeholders, expanded against a transaction (msg, logdata, setvar, operator arguments).
/// </summary>
public sealed class Macro
{
    private readonly Token[] _tokens;

    private Macro(string original, Token[] tokens)
    {
        Original = original;
        _tokens = tokens;
    }

    public string Original { get; }

    /// <summary>True when the macro has no placeholders.</summary>
    public bool IsConstant => _tokens.All(t => t.Variable == Variable.Unknown);

    public static Macro Parse(string input)
    {
        if (input.Length == 0)
        {
            return new Macro(input, [new Token(string.Empty, Variable.Unknown, string.Empty)]);
        }

        var tokens = new List<Token>();
        var current = new StringBuilder();
        var inMacro = false;
        for (var i = 0; i < input.Length; i++)
        {
            var c = input[i];
            if (!inMacro && c == '%' && i + 1 < input.Length && input[i + 1] == '{')
            {
                if (current.Length > 0)
                {
                    tokens.Add(new Token(current.ToString(), Variable.Unknown, string.Empty));
                    current.Clear();
                }

                inMacro = true;
                i++;
                continue;
            }

            if (inMacro)
            {
                if (c == '}')
                {
                    inMacro = false;
                    var text = current.ToString();
                    current.Clear();
                    if (text.EndsWith('.'))
                    {
                        throw new FormatException($"empty variable name in macro '{input}'");
                    }

                    var dot = text.IndexOf('.', StringComparison.Ordinal);
                    var name = dot < 0 ? text : text[..dot];
                    var key = dot < 0 ? string.Empty : text[(dot + 1)..];
                    if (!Variables.TryParse(name, out var variable))
                    {
                        throw new FormatException($"unknown variable '{name}' in macro '{input}'");
                    }

                    tokens.Add(new Token(text, variable, key.ToLowerInvariant()));
                    continue;
                }

                if (!IsValidMacroChar(c))
                {
                    throw new FormatException($"malformed variable starting with '%{{{current}' in '{input}'");
                }

                current.Append(c);
                if (i + 1 == input.Length)
                {
                    throw new FormatException($"malformed variable: no closing brace in '{input}'");
                }

                continue;
            }

            current.Append(c);
        }

        if (current.Length > 0)
        {
            tokens.Add(new Token(current.ToString(), Variable.Unknown, string.Empty));
        }

        return new Macro(input, [.. tokens]);
    }

    public string Expand(Transaction tx)
    {
        if (_tokens.Length == 1)
        {
            return ExpandToken(tx, _tokens[0]);
        }

        if (_tokens.Length <= 4)
        {
            return string.Concat(
                ExpandToken(tx, _tokens[0]),
                ExpandToken(tx, _tokens[1]),
                _tokens.Length > 2 ? ExpandToken(tx, _tokens[2]) : null,
                _tokens.Length > 3 ? ExpandToken(tx, _tokens[3]) : null);
        }

        var sb = new StringBuilder();
        foreach (var t in _tokens)
        {
            sb.Append(ExpandToken(tx, t));
        }

        return sb.ToString();
    }

    public override string ToString() => Original;

    private static string ExpandToken(Transaction tx, Token token)
    {
        if (token.Variable == Variable.Unknown)
        {
            return token.Text;
        }

        switch (tx.Collection(token.Variable))
        {
            case SingleCollection single:
                return single.Value;
            case MapCollection map when token.Key.Length > 0:
                return map.GetFirst(token.Key) ?? string.Empty;
            case IKeyedCollection keyed when token.Key.Length > 0:
                var values = keyed.Get(token.Key);
                return values.Count > 0 ? values[0] : string.Empty;
            case { } col:
                var list = tx.RentMatchList();
                col.FindAll(list);
                var first = list.Count > 0 ? list[0].Value : string.Empty;
                tx.Return(list);
                return first;
            default:
                return string.Empty;
        }
    }

    private static bool IsValidMacroChar(char c) =>
        c is (>= 'a' and <= 'z') or (>= 'A' and <= 'Z') or (>= '0' and <= '9') or '.' or '_' or '-' or '[' or ']';

    private readonly record struct Token(string Text, Variable Variable, string Key);
}
