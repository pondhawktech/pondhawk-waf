using System.Collections.Frozen;

namespace Pondhawk.Waf.Collections;

/// <summary>SecLang variables (ModSecurity v2 / Coraza names).</summary>
public enum Variable
{
    Unknown = 0,
    ResponseContentType,
    UniqueId,
    ArgsCombinedSize,
    FilesCombinedSize,
    FullRequestLength,
    InboundDataError,
    MatchedVar,
    MatchedVarName,
    MultipartDataAfter,
    OutboundDataError,
    QueryString,
    RemoteAddr,
    RemoteHost,
    RemotePort,
    ReqbodyError,
    ReqbodyErrorMsg,
    ReqbodyProcessorError,
    ReqbodyProcessorErrorMsg,
    ReqbodyProcessor,
    RequestBasename,
    RequestBody,
    RequestBodyLength,
    RequestFilename,
    RequestLine,
    RequestMethod,
    RequestProtocol,
    RequestUri,
    RequestUriRaw,
    ResponseBody,
    ResponseContentLength,
    ResponseProtocol,
    ResponseStatus,
    ResBodyProcessor,
    ServerAddr,
    ServerName,
    ServerPort,
    HighestSeverity,
    StatusLine,
    Duration,
    ResponseHeadersNames,
    RequestHeadersNames,
    Args,
    ArgsGet,
    ArgsPost,
    ArgsPath,
    FilesSizes,
    FilesNames,
    FilesTmpContent,
    MultipartFilename,
    MultipartFilenameCharset,
    MultipartFilenameLanguage,
    MultipartName,
    MatchedVarsNames,
    MatchedVars,
    Files,
    RequestCookies,
    RequestHeaders,
    ResponseHeaders,
    Geo,
    RequestCookiesNames,
    FilesTmpNames,
    ArgsNames,
    ArgsGetNames,
    ArgsPostNames,
    Tx,
    Rule,
    Json,
    Env,
    UrlencodedError,
    ResponseArgs,
    ResponseXml,
    RequestXml,
    Xml,
    MultipartPartHeaders,
    ResBodyError,
    ResBodyErrorMsg,
    ResBodyProcessorError,
    ResBodyProcessorErrorMsg,
    MultipartStrictError,
    MultipartDuplicatePartHeader,
    MultipartInvalidQuoting,
    Time,
    TimeDay,
    TimeEpoch,
    TimeHour,
    TimeMin,
    TimeMon,
    TimeSec,
    TimeWday,
    TimeYear,
    UriParseError,
    ArgumentsLimitReached,
}

/// <summary>Name lookup and metadata for <see cref="Variable"/>.</summary>
public static class Variables
{
    private static readonly (Variable Variable, string Name)[] NameTable =
    [
        (Variable.ResponseContentType, "RESPONSE_CONTENT_TYPE"),
        (Variable.UniqueId, "UNIQUE_ID"),
        (Variable.ArgsCombinedSize, "ARGS_COMBINED_SIZE"),
        (Variable.FilesCombinedSize, "FILES_COMBINED_SIZE"),
        (Variable.FullRequestLength, "FULL_REQUEST_LENGTH"),
        (Variable.InboundDataError, "INBOUND_DATA_ERROR"),
        (Variable.MatchedVar, "MATCHED_VAR"),
        (Variable.MatchedVarName, "MATCHED_VAR_NAME"),
        (Variable.MultipartDataAfter, "MULTIPART_DATA_AFTER"),
        (Variable.OutboundDataError, "OUTBOUND_DATA_ERROR"),
        (Variable.QueryString, "QUERY_STRING"),
        (Variable.RemoteAddr, "REMOTE_ADDR"),
        (Variable.RemoteHost, "REMOTE_HOST"),
        (Variable.RemotePort, "REMOTE_PORT"),
        (Variable.ReqbodyError, "REQBODY_ERROR"),
        (Variable.ReqbodyErrorMsg, "REQBODY_ERROR_MSG"),
        (Variable.ReqbodyProcessorError, "REQBODY_PROCESSOR_ERROR"),
        (Variable.ReqbodyProcessorErrorMsg, "REQBODY_PROCESSOR_ERROR_MSG"),
        (Variable.ReqbodyProcessor, "REQBODY_PROCESSOR"),
        (Variable.RequestBasename, "REQUEST_BASENAME"),
        (Variable.RequestBody, "REQUEST_BODY"),
        (Variable.RequestBodyLength, "REQUEST_BODY_LENGTH"),
        (Variable.RequestFilename, "REQUEST_FILENAME"),
        (Variable.RequestLine, "REQUEST_LINE"),
        (Variable.RequestMethod, "REQUEST_METHOD"),
        (Variable.RequestProtocol, "REQUEST_PROTOCOL"),
        (Variable.RequestUri, "REQUEST_URI"),
        (Variable.RequestUriRaw, "REQUEST_URI_RAW"),
        (Variable.ResponseBody, "RESPONSE_BODY"),
        (Variable.ResponseContentLength, "RESPONSE_CONTENT_LENGTH"),
        (Variable.ResponseProtocol, "RESPONSE_PROTOCOL"),
        (Variable.ResponseStatus, "RESPONSE_STATUS"),
        (Variable.ResBodyProcessor, "RES_BODY_PROCESSOR"),
        (Variable.ServerAddr, "SERVER_ADDR"),
        (Variable.ServerName, "SERVER_NAME"),
        (Variable.ServerPort, "SERVER_PORT"),
        (Variable.HighestSeverity, "HIGHEST_SEVERITY"),
        (Variable.StatusLine, "STATUS_LINE"),
        (Variable.Duration, "DURATION"),
        (Variable.ResponseHeadersNames, "RESPONSE_HEADERS_NAMES"),
        (Variable.RequestHeadersNames, "REQUEST_HEADERS_NAMES"),
        (Variable.Args, "ARGS"),
        (Variable.ArgsGet, "ARGS_GET"),
        (Variable.ArgsPost, "ARGS_POST"),
        (Variable.ArgsPath, "ARGS_PATH"),
        (Variable.FilesSizes, "FILES_SIZES"),
        (Variable.FilesNames, "FILES_NAMES"),
        (Variable.FilesTmpContent, "FILES_TMP_CONTENT"),
        (Variable.MultipartFilename, "MULTIPART_FILENAME"),
        (Variable.MultipartFilenameCharset, "MULTIPART_FILENAME_CHARSET"),
        (Variable.MultipartFilenameLanguage, "MULTIPART_FILENAME_LANGUAGE"),
        (Variable.MultipartName, "MULTIPART_NAME"),
        (Variable.MatchedVarsNames, "MATCHED_VARS_NAMES"),
        (Variable.MatchedVars, "MATCHED_VARS"),
        (Variable.Files, "FILES"),
        (Variable.RequestCookies, "REQUEST_COOKIES"),
        (Variable.RequestHeaders, "REQUEST_HEADERS"),
        (Variable.ResponseHeaders, "RESPONSE_HEADERS"),
        (Variable.Geo, "GEO"),
        (Variable.RequestCookiesNames, "REQUEST_COOKIES_NAMES"),
        (Variable.FilesTmpNames, "FILES_TMPNAMES"),
        (Variable.ArgsNames, "ARGS_NAMES"),
        (Variable.ArgsGetNames, "ARGS_GET_NAMES"),
        (Variable.ArgsPostNames, "ARGS_POST_NAMES"),
        (Variable.Tx, "TX"),
        (Variable.Rule, "RULE"),
        (Variable.Json, "JSON"),
        (Variable.Env, "ENV"),
        (Variable.UrlencodedError, "URLENCODED_ERROR"),
        (Variable.ResponseArgs, "RESPONSE_ARGS"),
        (Variable.ResponseXml, "RESPONSE_XML"),
        (Variable.RequestXml, "REQUEST_XML"),
        (Variable.Xml, "XML"),
        (Variable.MultipartPartHeaders, "MULTIPART_PART_HEADERS"),
        (Variable.ResBodyError, "RES_BODY_ERROR"),
        (Variable.ResBodyErrorMsg, "RES_BODY_ERROR_MSG"),
        (Variable.ResBodyProcessorError, "RES_BODY_PROCESSOR_ERROR"),
        (Variable.ResBodyProcessorErrorMsg, "RES_BODY_PROCESSOR_ERROR_MSG"),
        (Variable.MultipartStrictError, "MULTIPART_STRICT_ERROR"),
        (Variable.MultipartDuplicatePartHeader, "MULTIPART_DUPLICATE_PART_HEADER"),
        (Variable.MultipartInvalidQuoting, "MULTIPART_INVALID_QUOTING"),
        (Variable.Time, "TIME"),
        (Variable.TimeDay, "TIME_DAY"),
        (Variable.TimeEpoch, "TIME_EPOCH"),
        (Variable.TimeHour, "TIME_HOUR"),
        (Variable.TimeMin, "TIME_MIN"),
        (Variable.TimeMon, "TIME_MON"),
        (Variable.TimeSec, "TIME_SEC"),
        (Variable.TimeWday, "TIME_WDAY"),
        (Variable.TimeYear, "TIME_YEAR"),
        (Variable.UriParseError, "URI_PARSE_ERROR"),
        (Variable.ArgumentsLimitReached, "ARGUMENTS_LIMIT_REACHED"),
    ];

    private static readonly FrozenDictionary<string, Variable> ByName =
        NameTable.ToFrozenDictionary(x => x.Name, x => x.Variable, StringComparer.OrdinalIgnoreCase);

    private static readonly string[] Names = BuildNames();

    private static string[] BuildNames()
    {
        var names = new string[Enum.GetValues<Variable>().Length];
        names[0] = "UNKNOWN";
        foreach (var (v, n) in NameTable)
        {
            names[(int)v] = n;
        }

        return names;
    }

    /// <summary>Returns the SecLang name of the variable, e.g. REQUEST_HEADERS.</summary>
    public static string Name(this Variable variable) => Names[(int)variable];

    /// <summary>Parses a SecLang variable name (case-insensitive).</summary>
    public static bool TryParse(string name, out Variable variable)
    {
        // FILES_TMPNAMES is also written FILES_TMP_NAMES; accept both spellings.
        if (string.Equals(name, "FILES_TMP_NAMES", StringComparison.OrdinalIgnoreCase))
        {
            variable = Variable.FilesTmpNames;
            return true;
        }

        return ByName.TryGetValue(name, out variable);
    }

    /// <summary>True when the variable is a keyed collection, so ARGS:foo is valid.</summary>
    public static bool CanBeSelected(this Variable v) => v switch
    {
        Variable.Args or Variable.ArgsGet or Variable.ArgsPost or Variable.ArgsPath or Variable.ArgsNames
            or Variable.ArgsGetNames or Variable.ArgsPostNames or Variable.FilesSizes or Variable.FilesNames
            or Variable.FilesTmpContent or Variable.MultipartFilename or Variable.MultipartFilenameCharset
            or Variable.MultipartFilenameLanguage or Variable.MultipartName or Variable.MatchedVarsNames
            or Variable.MatchedVars or Variable.Files or Variable.RequestCookies or Variable.RequestHeaders
            or Variable.ResponseHeaders or Variable.Geo or Variable.RequestCookiesNames or Variable.FilesTmpNames
            or Variable.Tx or Variable.Rule or Variable.Json or Variable.Env or Variable.ResponseArgs
            or Variable.ResponseXml or Variable.RequestXml or Variable.Xml or Variable.MultipartPartHeaders
            or Variable.RequestHeadersNames or Variable.ResponseHeadersNames => true,
        _ => false,
    };
}
