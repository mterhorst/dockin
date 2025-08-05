namespace Dockin
{
    public static class ConfigHelper
    {
        public static EntraId GetEntraId(this IConfiguration configuration)
        {
            return configuration.GetSection("EntraID").Get<EntraId>() ?? throw new KeyNotFoundException("EntraID not found.");
        }
        public static App GetApp(this IConfiguration configuration)
        {
            return configuration.GetSection("App").Get<App>() ?? throw new KeyNotFoundException("App not found.");
        }
    }
}
