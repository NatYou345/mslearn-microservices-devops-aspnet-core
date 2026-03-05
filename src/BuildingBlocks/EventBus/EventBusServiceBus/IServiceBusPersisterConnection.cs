namespace Microsoft.eShopOnContainers.BuildingBlocks.EventBusServiceBus
{
    using Azure.Messaging.ServiceBus;
    using System;

    public interface IServiceBusPersisterConnection : IDisposable
    {
        string ServiceBusConnectionString { get; }

        ServiceBusSender CreateSender(string topicName);
    }
}