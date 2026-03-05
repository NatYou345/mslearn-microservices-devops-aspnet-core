using Azure.Messaging.ServiceBus;
using Microsoft.Extensions.Logging;
using System;

namespace Microsoft.eShopOnContainers.BuildingBlocks.EventBusServiceBus
{
    public class DefaultServiceBusPersisterConnection : IServiceBusPersisterConnection
    {
        private readonly ILogger<DefaultServiceBusPersisterConnection> _logger;
        private readonly string _connectionString;
        private ServiceBusClient _client;

        bool _disposed;

        public DefaultServiceBusPersisterConnection(string connectionString,
            ILogger<DefaultServiceBusPersisterConnection> logger)
        {
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));
            _connectionString = connectionString ?? throw new ArgumentNullException(nameof(connectionString));
            _client = new ServiceBusClient(_connectionString);
        }

        public string ConnectionString => _connectionString;

        public ServiceBusClient ServiceBusClient => _client;

        public ServiceBusSender CreateSender(string topicName)
        {
            return _client.CreateSender(topicName);
        }

        public ServiceBusProcessor CreateProcessor(string topicName, string subscriptionName, ServiceBusProcessorOptions options = null)
        {
            var opt = options ?? new ServiceBusProcessorOptions { AutoCompleteMessages = false, MaxConcurrentCalls = 1 };
            return _client.CreateProcessor(topicName, subscriptionName, opt);
        }

        public void Dispose()
        {
            if (_disposed) return;

            _client?.DisposeAsync().GetAwaiter().GetResult();
            _disposed = true;
        }
    }
}
