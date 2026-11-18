// Body processor semantics follow OWASP Coraza (Apache-2.0) internal/bodyprocessors.
using System.Globalization;
using System.Text;
using System.Text.Json;
using System.Xml;
using Pondhawk.Waf.Text;

namespace Pondhawk.Waf.BodyProcessors;

/// <summary>Options passed to a request body processor.</summary>
public sealed record BodyProcessorOptions(string ContentType, int JsonDepthLimit, int ArgumentsLimit);

/// <summary>A request body could not be parsed. Sets REQBODY_ERROR.</summary>
public sealed class BodyProcessorException(string message) : Exception(message);

/// <summary>Built-in request body processors: URLENCODED, MULTIPART, JSON, XML, RAW.</summary>
public static class BodyProcessor
{
    /// <summary>Runs the named processor. Returns false for an unknown processor name.</summary>
    public static bool TryProcessRequest(string name, byte[] body, Transaction tx, BodyProcessorOptions options)
    {
        switch (name.ToUpperInvariant())
        {
            case "URLENCODED":
                ProcessUrlEncoded(body, tx, options);
                return true;
            case "MULTIPART":
                Multipart.Process(body, tx, options);
                return true;
            case "JSON":
                ProcessJson(body, tx, options, tx.Variables.ArgsPost);
                return true;
            case "XML":
                ProcessXml(body, tx, tx.Variables.RequestXml);
                return true;
            case "RAW":
                SetRequestBody(body, tx);
                return true;
            default:
                return false;
        }
    }

    /// <summary>Runs a response body processor (JSON fills RESPONSE_ARGS, XML fills RESPONSE_XML). False if unknown.</summary>
    public static bool TryProcessResponse(string name, byte[] body, Transaction tx, int jsonDepthLimit, int argumentsLimit)
    {
        switch (name.ToUpperInvariant())
        {
            case "JSON":
                ProcessJson(body, tx, new BodyProcessorOptions(string.Empty, jsonDepthLimit, argumentsLimit), tx.Variables.ResponseArgs);
                return true;
            case "XML":
                ProcessXml(body, tx, tx.Variables.ResponseXml);
                return true;
            default:
                return false;
        }
    }

    private static void SetRequestBody(byte[] body, Transaction tx)
    {
        tx.Variables.RequestBody.Set(ByteString.FromBytes(body));
        tx.Variables.RequestBodyLength.Set(body.Length.ToString(CultureInfo.InvariantCulture));
    }

    private static void ProcessUrlEncoded(byte[] body, Transaction tx, BodyProcessorOptions options)
    {
        var text = ByteString.FromBytes(body);
        var truncated = UrlEncoded.Parse(text, '&', options.ArgumentsLimit, tx.AddPostRequestArgument);
        if (truncated)
        {
            tx.Variables.ArgumentsLimitReached.Set("1");
        }

        SetRequestBody(body, tx);
    }

    private static void ProcessJson(byte[] body, Transaction tx, BodyProcessorOptions options, Collections.MapCollection target)
    {
        JsonDocument doc;
        try
        {
            doc = JsonDocument.Parse(body, new JsonDocumentOptions
            {
                MaxDepth = options.JsonDepthLimit > 0 ? options.JsonDepthLimit : 1024,
                AllowTrailingCommas = false,
                CommentHandling = JsonCommentHandling.Disallow,
            });
        }
        catch (JsonException ex)
        {
            throw new BodyProcessorException("invalid JSON: " + ex.Message);
        }

        using (doc)
        {
            var state = new JsonFlattenState(options.ArgumentsLimit);
            var key = new StringBuilder("json");
            Flatten(doc.RootElement, key, target, state);
            if (state.Truncated)
            {
                tx.Variables.ArgumentsLimitReached.Set("1");
            }
        }
    }

    private sealed class JsonFlattenState(int limit)
    {
        public int Limit { get; } = limit;

        public int Count { get; set; }

        public bool Truncated { get; set; }

        public bool Full => Limit > 0 && Count >= Limit;
    }

    private static void Flatten(JsonElement element, StringBuilder key, Collections.MapCollection target, JsonFlattenState state)
    {
        switch (element.ValueKind)
        {
            case JsonValueKind.Object:
                foreach (var prop in element.EnumerateObject())
                {
                    if (state.Full)
                    {
                        state.Truncated = true;
                        return;
                    }

                    var len = key.Length;
                    key.Append('.').Append(ByteString.FromUtf16(prop.Name));
                    Flatten(prop.Value, key, target, state);
                    key.Length = len;
                }

                break;
            case JsonValueKind.Array:
                var index = 0;
                foreach (var item in element.EnumerateArray())
                {
                    if (state.Full)
                    {
                        state.Truncated = true;
                        return;
                    }

                    var len = key.Length;
                    key.Append('.').Append(index.ToString(CultureInfo.InvariantCulture));
                    Flatten(item, key, target, state);
                    key.Length = len;
                    index++;
                }

                if (index > 0 && !state.Full)
                {
                    // The array length, as Coraza records it.
                    target.Add(key.ToString(), index.ToString(CultureInfo.InvariantCulture));
                }

                break;
            default:
                if (state.Full)
                {
                    state.Truncated = true;
                    return;
                }

                var value = element.ValueKind switch
                {
                    JsonValueKind.String => ByteString.FromUtf16(element.GetString()),
                    JsonValueKind.Null => string.Empty,
                    _ => element.GetRawText(),
                };
                target.Add(key.ToString(), value);
                state.Count++;
                break;
        }
    }

    private static void ProcessXml(byte[] body, Transaction tx, Collections.MapCollection target)
    {
        var attributes = new List<string>();
        var contents = new List<string>();
        var settings = new XmlReaderSettings
        {
            // Never resolve DTDs or external entities (XXE, entity expansion).
            DtdProcessing = DtdProcessing.Ignore,
            XmlResolver = null,
            MaxCharactersFromEntities = 1024,
            IgnoreComments = true,
            IgnoreProcessingInstructions = true,
            CheckCharacters = false,
            ConformanceLevel = ConformanceLevel.Fragment,
        };

        string? error = null;
        try
        {
            using var stream = new MemoryStream(body);
            using var reader = XmlReader.Create(stream, settings);
            while (reader.Read())
            {
                switch (reader.NodeType)
                {
                    case XmlNodeType.Element:
                        if (reader.HasAttributes)
                        {
                            while (reader.MoveToNextAttribute())
                            {
                                attributes.Add(ByteString.FromUtf16(reader.Value));
                            }

                            reader.MoveToElement();
                        }

                        break;
                    case XmlNodeType.Text:
                    case XmlNodeType.CDATA:
                        var text = reader.Value.Trim();
                        if (text.Length > 0)
                        {
                            contents.Add(ByteString.FromUtf16(text));
                        }

                        break;
                }
            }
        }
        catch (XmlException ex)
        {
            error = ex.Message;
        }

        target.Set("//@*", attributes);
        target.Set("/*", contents);
        if (error is not null)
        {
            throw new BodyProcessorException("invalid XML: " + error);
        }
    }
}
