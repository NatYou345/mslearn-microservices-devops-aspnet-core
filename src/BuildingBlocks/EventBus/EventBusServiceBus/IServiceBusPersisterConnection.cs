namespace Microsoft.eShopOnContainers.BuildingBlocks.EventBusServiceBus
{
    using Azure.Messaging.ServiceBus;
    using System;

    public interface IServiceBusPersisterConnection : IDisposable
    {
        string ConnectionString { get; }

        ServiceBusClient ServiceBusClient { get; }

        ServiceBusSender CreateSender(string topicName);

        ServiceBusProcessor CreateProcessor(string topicName, string subscriptionName, ServiceBusProcessorOptions options = null);
    }
}