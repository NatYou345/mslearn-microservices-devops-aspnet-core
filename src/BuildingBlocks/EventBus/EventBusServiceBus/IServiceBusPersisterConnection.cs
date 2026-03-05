namespace Microsoft.eShopOnContainers.BuildingBlocks.EventBusServiceBus
{

    using System;

    public interface IServiceBusPersisterConnection : IDisposable
    {
        string ServiceBusConnectionString { get; }

        IServiceBusSender CreateSender(string topicName);

    }

    public interface IServiceBusSender
    {
        void Send(string body, string subject);
    }
}
