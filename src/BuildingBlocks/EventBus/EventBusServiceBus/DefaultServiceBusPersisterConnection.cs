using Azure.Messaging.ServiceBus;
using Microsoft.Extensions.Logging;
using System;

namespace Microsoft.eShopOnContainers.BuildingBlocks.EventBusServiceBus
{
    public class DefaultServiceBusPersisterConnection :IServiceBusPersisterConnection
    {
        private readonly ILogger<DefaultServiceBusPersisterConnection> _logger;
        private readonly string _serviceBusConnectionString;
        private ServiceBusClient _serviceBusClient;

        bool _disposed;

        public DefaultServiceBusPersisterConnection(string serviceBusConnectionString,
            ILogger<DefaultServiceBusPersisterConnection> logger)
        {
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));
            _serviceBusConnectionString = serviceBusConnectionString ?? throw new ArgumentNullException(nameof(serviceBusConnectionString));
            _serviceBusClient = new ServiceBusClient(_serviceBusConnectionString);
        }

        public string ServiceBusConnectionString => _serviceBusConnectionString;

        public ServiceBusSender CreateSender(string topicName)
        {
            return _serviceBusClient.CreateSender(topicName);
        }

        public void Dispose()
        {
            if (_disposed) return;

            _disposed = true;
        }
    }
}
