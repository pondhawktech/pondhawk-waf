namespace Pondhawk.Waf.Collections;

/// <summary>All collections of one transaction.</summary>
public sealed class TransactionVariables
{
    private readonly IWafCollection?[] _byVariable = new IWafCollection?[Enum.GetValues<Variable>().Length];

    public TransactionVariables()
    {
        Register(ArgsGet);
        Register(ArgsPost);
        Register(ArgsPath);
        ArgsGetNames = ArgsGet.Names(Variable.ArgsGetNames);
        ArgsPostNames = ArgsPost.Names(Variable.ArgsPostNames);
        Register(ArgsGetNames);
        Register(ArgsPostNames);
        Args = new ConcatCollection(Variable.Args, ArgsGet, ArgsPost, ArgsPath);
        ArgsNames = new ConcatCollection(Variable.ArgsNames, ArgsGetNames, ArgsPostNames, ArgsPath.Names(Variable.Unknown));
        Register(Args);
        Register(ArgsNames);
        ArgsCombinedSize = new SizeCollection(Variable.ArgsCombinedSize, ArgsGet, ArgsPost);
        Register(ArgsCombinedSize);

        Register(RequestHeaders);
        RequestHeadersNames = RequestHeaders.Names(Variable.RequestHeadersNames);
        Register(RequestHeadersNames);
        Register(RequestCookies);
        RequestCookiesNames = RequestCookies.Names(Variable.RequestCookiesNames);
        Register(RequestCookiesNames);
        Register(ResponseHeaders);
        ResponseHeadersNames = ResponseHeaders.Names(Variable.ResponseHeadersNames);
        Register(ResponseHeadersNames);

        Register(MatchedVars);
        MatchedVarsNames = MatchedVars.Names(Variable.MatchedVarsNames);
        Register(MatchedVarsNames);

        foreach (var map in new[]
                 {
                     Files, FilesNames, FilesSizes, FilesTmpNames, FilesTmpContent, MultipartFilename, MultipartFilenameCharset,
                     MultipartFilenameLanguage, MultipartName, MultipartPartHeaders, Tx, Rule, Env, Geo, ResponseArgs,
                     RequestXml, ResponseXml, Json,
                 })
        {
            Register(map);
        }

        // XML is an alias of REQUEST_XML.
        _byVariable[(int)Variable.Xml] = RequestXml;

        foreach (var single in new[]
                 {
                     UrlencodedError, UriParseError, ArgumentsLimitReached, ResponseContentType, UniqueId, FilesCombinedSize,
                     FullRequestLength, InboundDataError, MatchedVar, MatchedVarName, MultipartDataAfter, OutboundDataError,
                     QueryString, RemoteAddr, RemoteHost, RemotePort, ReqbodyError, ReqbodyErrorMsg, ReqbodyProcessorError,
                     ReqbodyProcessorErrorMsg, ReqbodyProcessor, RequestBasename, RequestBody, RequestBodyLength, RequestFilename,
                     RequestLine, RequestMethod, RequestProtocol, RequestUri, RequestUriRaw, ResponseBody, ResponseContentLength,
                     ResponseProtocol, ResponseStatus, ServerAddr, ServerName, ServerPort, HighestSeverity, StatusLine, Duration,
                     ResBodyProcessor, ResBodyError, ResBodyErrorMsg, ResBodyProcessorError, ResBodyProcessorErrorMsg,
                     MultipartStrictError, MultipartDuplicatePartHeader, MultipartInvalidQuoting, Time, TimeDay, TimeEpoch,
                     TimeHour, TimeMin, TimeMon, TimeSec, TimeWday, TimeYear,
                 })
        {
            Register(single);
        }
    }

    public MapCollection ArgsGet { get; } = new(Variable.ArgsGet);

    public MapCollection ArgsPost { get; } = new(Variable.ArgsPost);

    public MapCollection ArgsPath { get; } = new(Variable.ArgsPath);

    public NamesCollection ArgsGetNames { get; }

    public NamesCollection ArgsPostNames { get; }

    public ConcatCollection Args { get; }

    public ConcatCollection ArgsNames { get; }

    public SizeCollection ArgsCombinedSize { get; }

    public MapCollection RequestHeaders { get; } = new(Variable.RequestHeaders);

    public NamesCollection RequestHeadersNames { get; }

    public MapCollection RequestCookies { get; } = new(Variable.RequestCookies);

    public NamesCollection RequestCookiesNames { get; }

    public MapCollection ResponseHeaders { get; } = new(Variable.ResponseHeaders);

    public NamesCollection ResponseHeadersNames { get; }

    public MapCollection MatchedVars { get; } = new(Variable.MatchedVars);

    public NamesCollection MatchedVarsNames { get; }

    public MapCollection Files { get; } = new(Variable.Files);

    public MapCollection FilesNames { get; } = new(Variable.FilesNames);

    public MapCollection FilesSizes { get; } = new(Variable.FilesSizes);

    public MapCollection FilesTmpNames { get; } = new(Variable.FilesTmpNames);

    public MapCollection FilesTmpContent { get; } = new(Variable.FilesTmpContent);

    public MapCollection MultipartFilename { get; } = new(Variable.MultipartFilename);

    public MapCollection MultipartFilenameCharset { get; } = new(Variable.MultipartFilenameCharset);

    public MapCollection MultipartFilenameLanguage { get; } = new(Variable.MultipartFilenameLanguage);

    public MapCollection MultipartName { get; } = new(Variable.MultipartName);

    public MapCollection MultipartPartHeaders { get; } = new(Variable.MultipartPartHeaders);

    public MapCollection Tx { get; } = new(Variable.Tx);

    public MapCollection Rule { get; } = new(Variable.Rule);

    public MapCollection Env { get; } = new(Variable.Env);

    public MapCollection Geo { get; } = new(Variable.Geo);

    public MapCollection ResponseArgs { get; } = new(Variable.ResponseArgs);

    public MapCollection RequestXml { get; } = new(Variable.RequestXml);

    public MapCollection ResponseXml { get; } = new(Variable.ResponseXml);

    public MapCollection Json { get; } = new(Variable.Json);

    public SingleCollection UrlencodedError { get; } = new(Variable.UrlencodedError);

    public SingleCollection UriParseError { get; } = new(Variable.UriParseError);

    public SingleCollection ArgumentsLimitReached { get; } = new(Variable.ArgumentsLimitReached);

    public SingleCollection ResponseContentType { get; } = new(Variable.ResponseContentType);

    public SingleCollection UniqueId { get; } = new(Variable.UniqueId);

    public SingleCollection FilesCombinedSize { get; } = new(Variable.FilesCombinedSize);

    public SingleCollection FullRequestLength { get; } = new(Variable.FullRequestLength);

    public SingleCollection InboundDataError { get; } = new(Variable.InboundDataError);

    public SingleCollection MatchedVar { get; } = new(Variable.MatchedVar);

    public SingleCollection MatchedVarName { get; } = new(Variable.MatchedVarName);

    public SingleCollection MultipartDataAfter { get; } = new(Variable.MultipartDataAfter);

    public SingleCollection OutboundDataError { get; } = new(Variable.OutboundDataError);

    public SingleCollection QueryString { get; } = new(Variable.QueryString);

    public SingleCollection RemoteAddr { get; } = new(Variable.RemoteAddr);

    public SingleCollection RemoteHost { get; } = new(Variable.RemoteHost);

    public SingleCollection RemotePort { get; } = new(Variable.RemotePort);

    public SingleCollection ReqbodyError { get; } = new(Variable.ReqbodyError);

    public SingleCollection ReqbodyErrorMsg { get; } = new(Variable.ReqbodyErrorMsg);

    public SingleCollection ReqbodyProcessorError { get; } = new(Variable.ReqbodyProcessorError);

    public SingleCollection ReqbodyProcessorErrorMsg { get; } = new(Variable.ReqbodyProcessorErrorMsg);

    public SingleCollection ReqbodyProcessor { get; } = new(Variable.ReqbodyProcessor);

    public SingleCollection RequestBasename { get; } = new(Variable.RequestBasename);

    public SingleCollection RequestBody { get; } = new(Variable.RequestBody);

    public SingleCollection RequestBodyLength { get; } = new(Variable.RequestBodyLength);

    public SingleCollection RequestFilename { get; } = new(Variable.RequestFilename);

    public SingleCollection RequestLine { get; } = new(Variable.RequestLine);

    public SingleCollection RequestMethod { get; } = new(Variable.RequestMethod);

    public SingleCollection RequestProtocol { get; } = new(Variable.RequestProtocol);

    public SingleCollection RequestUri { get; } = new(Variable.RequestUri);

    public SingleCollection RequestUriRaw { get; } = new(Variable.RequestUriRaw);

    public SingleCollection ResponseBody { get; } = new(Variable.ResponseBody);

    public SingleCollection ResponseContentLength { get; } = new(Variable.ResponseContentLength);

    public SingleCollection ResponseProtocol { get; } = new(Variable.ResponseProtocol);

    public SingleCollection ResponseStatus { get; } = new(Variable.ResponseStatus);

    public SingleCollection ServerAddr { get; } = new(Variable.ServerAddr);

    public SingleCollection ServerName { get; } = new(Variable.ServerName);

    public SingleCollection ServerPort { get; } = new(Variable.ServerPort);

    public SingleCollection HighestSeverity { get; } = new(Variable.HighestSeverity);

    public SingleCollection StatusLine { get; } = new(Variable.StatusLine);

    public SingleCollection Duration { get; } = new(Variable.Duration);

    public SingleCollection ResBodyProcessor { get; } = new(Variable.ResBodyProcessor);

    public SingleCollection ResBodyError { get; } = new(Variable.ResBodyError);

    public SingleCollection ResBodyErrorMsg { get; } = new(Variable.ResBodyErrorMsg);

    public SingleCollection ResBodyProcessorError { get; } = new(Variable.ResBodyProcessorError);

    public SingleCollection ResBodyProcessorErrorMsg { get; } = new(Variable.ResBodyProcessorErrorMsg);

    public SingleCollection MultipartStrictError { get; } = new(Variable.MultipartStrictError);

    public SingleCollection MultipartDuplicatePartHeader { get; } = new(Variable.MultipartDuplicatePartHeader);

    public SingleCollection MultipartInvalidQuoting { get; } = new(Variable.MultipartInvalidQuoting);

    public SingleCollection Time { get; } = new(Variable.Time);

    public SingleCollection TimeDay { get; } = new(Variable.TimeDay);

    public SingleCollection TimeEpoch { get; } = new(Variable.TimeEpoch);

    public SingleCollection TimeHour { get; } = new(Variable.TimeHour);

    public SingleCollection TimeMin { get; } = new(Variable.TimeMin);

    public SingleCollection TimeMon { get; } = new(Variable.TimeMon);

    public SingleCollection TimeSec { get; } = new(Variable.TimeSec);

    public SingleCollection TimeWday { get; } = new(Variable.TimeWday);

    public SingleCollection TimeYear { get; } = new(Variable.TimeYear);

    public IWafCollection? Get(Variable variable) => _byVariable[(int)variable];

    private void Register(IWafCollection collection)
    {
        if (collection.Variable != Variable.Unknown)
        {
            _byVariable[(int)collection.Variable] = collection;
        }
    }
}
