using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.DependencyInjection; // Needed if you use DI

var host = new HostBuilder()
    .ConfigureFunctionsWorkerDefaults()
    // If you use HttpClientFactory or other services via Dependency Injection, configure them here
    // .ConfigureServices(services => {
    //     services.AddHttpClient();
    //     // Add other services
    // })
    .Build();

host.Run();