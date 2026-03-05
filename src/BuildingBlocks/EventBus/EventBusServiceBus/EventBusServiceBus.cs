namespace Microsoft.eShopOnContainers.BuildingBlocks.EventBusServiceBus
{
    using Autofac;
    using Azure.Messaging.ServiceBus;
    using Microsoft.eShopOnContainers.BuildingBlocks.EventBus;
    using Microsoft.eShopOnContainers.BuildingBlocks.EventBus.Abstractions;
    using Microsoft.eShopOnContainers.BuildingBlocks.EventBus.Events;
    using Microsoft.Extensions.Logging;
    using Newtonsoft.Json;
    using Newtonsoft.Json.Linq;
    using System;
    using System.Text;
    using System.Threading.Tasks;

    public class EventBusServiceBus : IEventBus
    {
        private readonly IServiceBusPersisterConnection _serviceBusPersisterConnection;
        private readonly ILogger<EventBusServiceBus> _logger;
        private readonly IEventBusSubscriptionsManager _subsManager;
        private readonly ServiceBusProcessor _subscriptionProcessor;
        private readonly ILifetimeScope _autofac;
        private readonly string AUTOFAC_SCOPE_NAME = "eshop_event_bus";
        private const string INTEGRATION_EVENT_SUFFIX = "IntegrationEvent";

        public EventBusServiceBus(IServiceBusPersisterConnection serviceBusPersisterConnection,
            ILogger<EventBusServiceBus> logger, IEventBusSubscriptionsManager subsManager, string subscriptionClientName,
            ILifetimeScope autofac)
        {
            _serviceBusPersisterConnection = serviceBusPersisterConnection;
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));
            _subsManager = subsManager ?? new InMemoryEventBusSubscriptionsManager();

            _subscriptionProcessor = serviceBusPersisterConnection.CreateProcessor(subscriptionClientName.Split(':')[0],
                subscriptionClientName.Split(':')[1]);
            _autofac = autofac;

            RemoveDefaultRule();
            RegisterSubscriptionClientMessageHandler();
        }

        public void Publish(IntegrationEvent @event)
        {
            var eventName = @event.GetType().Name.Replace(INTEGRATION_EVENT_SUFFIX, "");
            var jsonMessage = JsonConvert.SerializeObject(@event);
            var body = new BinaryData(jsonMessage);

            var sender = _serviceBusPersisterConnection.CreateSender(eventName);

            var message = new ServiceBusMessage(body)
            {
                MessageId = Guid.NewGuid().ToString(),
                Subject = eventName
            };

            sender.SendMessageAsync(message).GetAwaiter().GetResult();
        }

        public void SubscribeDynamic<TH>(string eventName)
            where TH : IDynamicIntegrationEventHandler
        {
            _logger.LogInformation("Subscribing to dynamic event {EventName} with {EventHandler}", eventName, typeof(TH).Name);

            _subsManager.AddDynamicSubscription<TH>(eventName);
        }

        public void Subscribe<T, TH>()
            where T : IntegrationEvent
            where TH : IIntegrationEventHandler<T>
        {
            var eventName = typeof(T).Name.Replace(INTEGRATION_EVENT_SUFFIX, "");

            _logger.LogInformation("Registering subscription for event {EventName} with handler {EventHandler}", eventName, typeof(TH).Name);

            // Register handler mapping in the in-memory subscription manager.
            // Topic/subscription creation and filters are expected to be provisioned externally or via management tooling.
            _subsManager.AddSubscription<T, TH>();
        }

        public void Unsubscribe<T, TH>()
            where T : IntegrationEvent
            where TH : IIntegrationEventHandler<T>
        {
            var eventName = typeof(T).Name.Replace(INTEGRATION_EVENT_SUFFIX, "");

            _logger.LogInformation("Removing subscription for event {EventName}", eventName);
            _subsManager.RemoveSubscription<T, TH>();
        }

        public void UnsubscribeDynamic<TH>(string eventName)
            where TH : IDynamicIntegrationEventHandler
        {
            _logger.LogInformation("Unsubscribing from dynamic event {EventName}", eventName);

            _subsManager.RemoveDynamicSubscription<TH>(eventName);
        }

        public void Dispose()
        {
            _subsManager.Clear();
        }

        // The subscription processor is configured in the constructor via RegisterSubscriptionClientMessageHandler

        private void RegisterSubscriptionClientMessageHandler()
        {
            _subscriptionProcessor.ProcessMessageAsync += async args =>
            {
                var message = args.Message;
                var eventName = $"{message.Subject}{INTEGRATION_EVENT_SUFFIX}";
                var messageData = message.Body.ToString();

                if (await ProcessEvent(eventName, messageData))
                {
                    await args.CompleteMessageAsync(message);
                }
            };

            _subscriptionProcessor.ProcessErrorAsync += ExceptionReceivedHandler;

            _subscriptionProcessor.StartProcessingAsync().GetAwaiter().GetResult();
        }

        private Task ExceptionReceivedHandler(ProcessErrorEventArgs exceptionReceivedEventArgs)
        {
            var ex = exceptionReceivedEventArgs.Exception;
            _logger.LogError(ex, "ERROR handling message: {ExceptionMessage}", ex.Message);
            return Task.CompletedTask;
        }

        private async Task<bool> ProcessEvent(string eventName, string message)
        {
            var processed = false;
            if (_subsManager.HasSubscriptionsForEvent(eventName))
            {
                using (var scope = _autofac.BeginLifetimeScope(AUTOFAC_SCOPE_NAME))
                {
                    var subscriptions = _subsManager.GetHandlersForEvent(eventName);
                    foreach (var subscription in subscriptions)
                    {
                        if (subscription.IsDynamic)
                        {
                            var handler = scope.ResolveOptional(subscription.HandlerType) as IDynamicIntegrationEventHandler;
                            if (handler == null) continue;
                            dynamic eventData = JObject.Parse(message);
                            await handler.Handle(eventData);
                        }
                        else
                        {
                            var handler = scope.ResolveOptional(subscription.HandlerType);
                            if (handler == null) continue;
                            var eventType = _subsManager.GetEventTypeByName(eventName);
                            var integrationEvent = JsonConvert.DeserializeObject(message, eventType);
                            var concreteType = typeof(IIntegrationEventHandler<>).MakeGenericType(eventType);
                            await (Task)concreteType.GetMethod("Handle").Invoke(handler, new object[] { integrationEvent });
                        }
                    }
                }
                processed = true;
            }
            return processed;
        }

        private void RemoveDefaultRule()
        {
            // No-op for Azure.Messaging.ServiceBus since rule management is done via the Service Bus management client or portal
        }
    }
}
