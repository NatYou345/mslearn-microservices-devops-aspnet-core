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
        private ServiceBusProcessor _processor;
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

            // Create processor for subscription using Azure.Messaging.ServiceBus
            _processor = new ServiceBusClient(serviceBusPersisterConnection.ServiceBusConnectionString)
                .CreateProcessor(subscriptionClientName, new ServiceBusProcessorOptions { MaxConcurrentCalls = 10, AutoCompleteMessages = false });
            _autofac = autofac;

            RemoveDefaultRule();
            RegisterSubscriptionClientMessageHandler();
        }

        public void Publish(IntegrationEvent @event)
        {
            var eventName = @event.GetType().Name.Replace(INTEGRATION_EVENT_SUFFIX, "");
            var jsonMessage = JsonConvert.SerializeObject(@event);

            var sender = _serviceBusPersisterConnection.CreateSender(eventName);
            var message = new ServiceBusMessage(jsonMessage)
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

            var containsKey = _subsManager.HasSubscriptionsForEvent<T>();
            if (!containsKey)
            {
                    try
                    {
                        // Azure.Messaging.ServiceBus does not support rule management client in the same way; skip creating filter rules here.
                        _logger.LogInformation("Subscribe rule management is not implemented for Azure.Messaging.ServiceBus in this migration.");
                    }
                    catch (Exception)
                    {
                        _logger.LogWarning("The messaging entity {eventName} may already exist.", eventName);
                    }
            }

            _logger.LogInformation("Subscribing to event {EventName} with {EventHandler}", eventName, typeof(TH).Name);

            _subsManager.AddSubscription<T, TH>();
        }

        public void Unsubscribe<T, TH>()
            where T : IntegrationEvent
            where TH : IIntegrationEventHandler<T>
        {
            var eventName = typeof(T).Name.Replace(INTEGRATION_EVENT_SUFFIX, "");

            // Rule removal is not supported in the same way for Azure.Messaging.ServiceBus; log for manual follow-up
            _logger.LogInformation("Unsubscribe rule removal is not implemented for Azure.Messaging.ServiceBus migration for {eventName}", eventName);

            _logger.LogInformation("Unsubscribing from event {EventName}", eventName);

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

        private void RegisterSubscriptionClientMessageHandler()
        {
            _processor.ProcessMessageAsync += async args =>
            {
                var message = args.Message;
                var eventName = $"{message.Subject}{INTEGRATION_EVENT_SUFFIX}";
                var messageData = Encoding.UTF8.GetString(message.Body.ToArray());

                if (await ProcessEvent(eventName, messageData))
                {
                    await args.CompleteMessageAsync(message);
                }
            };

            _processor.ProcessErrorAsync += ExceptionReceivedHandlerAsync;
            _processor.StartProcessingAsync().GetAwaiter().GetResult();
        }

        private Task ExceptionReceivedHandlerAsync(ProcessErrorEventArgs args)
        {
            var ex = args.Exception;
            var context = new { args.ErrorSource, args.EntityPath, args.FullyQualifiedNamespace };
            _logger.LogError(ex, "ERROR handling message: {ExceptionMessage} - Context: {@ExceptionContext}", ex.Message, context);
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
            // Removal of default rule is not applicable with Azure.Messaging.ServiceBus in this migration.
            _logger.LogInformation("RemoveDefaultRule is a no-op for Azure.Messaging.ServiceBus migration.");
        }
    }
}
