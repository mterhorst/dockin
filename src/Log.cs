namespace Dockin
{
    public static partial class Log
    {
        [LoggerMessage(2001, LogLevel.Information, "Found selected app: {app}.")]
        public static partial void LogFoundSelectedApp(ILogger logger, App app);

        [LoggerMessage(2002, LogLevel.Information, "Proxy uri: {uri}.")]
        public static partial void LogProxyUri(ILogger logger, Uri uri);
    }
}
