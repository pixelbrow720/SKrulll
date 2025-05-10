"""
Messaging system for the CyberOps Orchestrator.

This module provides a unified interface for working with message broker systems
like RabbitMQ and Kafka, allowing different components to communicate asynchronously.
"""
import json
import logging
import os
import threading
from typing import Any, Dict, List, Optional, Union, Callable

logger = logging.getLogger(__name__)

class MessageBroker:
    """
    Message broker interface that supports different backend implementations.
    """
    
    def __init__(self, broker_type: str = None, config: Dict[str, Any] = None):
        """
        Initialize the message broker.
        
        Args:
            broker_type: Type of message broker ('rabbitmq' or 'kafka')
            config: Configuration dictionary for the broker
        """
        self.broker_type = broker_type or os.environ.get("MESSAGING_TYPE", "rabbitmq")
        self.config = config or {}
        self.connection = None
        self.channel = None
        self.consumer_tags = []
        self.kafka_consumers = {}  # Store Kafka consumers for unsubscribe
        
        # Initialize the appropriate broker backend
        try:
            if self.broker_type.lower() == "rabbitmq":
                self._init_rabbitmq()
            elif self.broker_type.lower() == "kafka":
                self._init_kafka()
            else:
                logger.error(f"Unsupported message broker type: {self.broker_type}")
                raise ValueError(f"Unsupported message broker type: {self.broker_type}")
        except ImportError as e:
            logger.warning(f"Could not initialize {self.broker_type}: {str(e)}")
            logger.warning("Messaging functionality will be disabled")
        except Exception as e:
            logger.error(f"Error initializing message broker: {str(e)}")
            logger.warning("Messaging functionality will be disabled")
    
    def _init_rabbitmq(self):
        """Initialize RabbitMQ connection."""
        try:
            import pika
            
            # Get RabbitMQ configuration
            host = self.config.get("host", os.environ.get("RABBITMQ_HOST", "localhost"))
            port = int(self.config.get("port", os.environ.get("RABBITMQ_PORT", 5672)))
            vhost = self.config.get("virtual_host", os.environ.get("RABBITMQ_VHOST", "/"))
            username = self.config.get("username", os.environ.get("RABBITMQ_USERNAME", "guest"))
            password = self.config.get("password", os.environ.get("RABBITMQ_PASSWORD", "guest"))
            
            # Create connection parameters
            credentials = pika.PlainCredentials(username, password)
            parameters = pika.ConnectionParameters(
                host=host,
                port=port,
                virtual_host=vhost,
                credentials=credentials
            )
            
            logger.debug(f"Connecting to RabbitMQ at {host}:{port}{vhost}")
            
            # Establish connection and channel
            self.connection = pika.BlockingConnection(parameters)
            self.channel = self.connection.channel()
            
            logger.info("Connected to RabbitMQ message broker")
        except ImportError:
            logger.warning("pika package not installed, RabbitMQ functionality disabled")
            raise
        except Exception as e:
            logger.error(f"Failed to connect to RabbitMQ: {str(e)}")
            raise
    
    def _init_kafka(self):
        """Initialize Kafka connection."""
        try:
            from kafka import KafkaProducer, KafkaConsumer
            
            # Get Kafka configuration
            bootstrap_servers = self.config.get(
                "bootstrap_servers", 
                os.environ.get("KAFKA_BOOTSTRAP_SERVERS", "localhost:9092")
            )
            client_id = self.config.get(
                "client_id", 
                os.environ.get("KAFKA_CLIENT_ID", "cyberops")
            )
            
            logger.debug(f"Connecting to Kafka at {bootstrap_servers}")
            
            # Initialize Kafka producer
            self.producer = KafkaProducer(
                bootstrap_servers=bootstrap_servers.split(','),
                client_id=client_id,
                value_serializer=lambda v: json.dumps(v).encode('utf-8')
            )
            
            logger.info("Connected to Kafka message broker")
        except ImportError:
            logger.warning("kafka-python package not installed, Kafka functionality disabled")
            raise
        except Exception as e:
            logger.error(f"Failed to connect to Kafka: {str(e)}")
            raise
    
    def check_status(self) -> bool:
        """
        Check if the message broker connection is active.
        
        Returns:
            True if connected, False otherwise
        """
        if self.broker_type.lower() == "rabbitmq":
            return self.connection is not None and self.connection.is_open
        elif self.broker_type.lower() == "kafka":
            return hasattr(self, 'producer') and self.producer is not None
        return False
    
    def publish(self, topic: str, message: Union[str, Dict, List], headers: Dict = None) -> bool:
        """
        Publish a message to a topic.
        
        Args:
            topic: Topic or exchange to publish to
            message: Message content (will be serialized to JSON if not a string)
            headers: Optional message headers
            
        Returns:
            True if successful, False otherwise
        """
        try:
            # Convert message to string if it's not already
            if not isinstance(message, str):
                message_str = json.dumps(message)
            else:
                message_str = message
                
            if self.broker_type.lower() == "rabbitmq":
                # Declare the exchange if it doesn't exist
                self.channel.exchange_declare(
                    exchange=topic,
                    exchange_type='topic',
                    durable=True
                )
                
                # Publish the message
                self.channel.basic_publish(
                    exchange=topic,
                    routing_key='',
                    body=message_str.encode('utf-8'),
                    properties=self.channel.connection.connection)
                
                logger.debug(f"Published message to RabbitMQ exchange '{topic}'")
                return True
                
            elif self.broker_type.lower() == "kafka":
                # Send the message to Kafka
                future = self.producer.send(topic, message)
                self.producer.flush()
                
                # Wait for the result
                record_metadata = future.get(timeout=10)
                logger.debug(f"Published message to Kafka topic '{topic}' at "
                            f"partition {record_metadata.partition}, "
                            f"offset {record_metadata.offset}")
                return True
                
            return False
            
        except Exception as e:
            logger.error(f"Error publishing message to '{topic}': {str(e)}", exc_info=True)
            return False
    
    def subscribe(self, topic: str, callback: Callable[[str, Any], None]) -> str:
        """
        Subscribe to a topic and register a callback for messages.
        
        Args:
            topic: Topic or exchange to subscribe to
            callback: Function to call when a message is received
            
        Returns:
            Consumer tag or identifier for the subscription
        """
        if self.broker_type.lower() == "rabbitmq":
            try:
                import pika
                
                # Declare the exchange if it doesn't exist
                self.channel.exchange_declare(
                    exchange=topic,
                    exchange_type='topic',
                    durable=True
                )
                
                # Create a queue and bind it to the exchange
                result = self.channel.queue_declare(queue='', exclusive=True)
                queue_name = result.method.queue
                self.channel.queue_bind(
                    exchange=topic,
                    queue=queue_name,
                    routing_key='#'
                )
                
                # Define the callback wrapper
                def message_callback(ch, method, properties, body):
                    try:
                        message_str = body.decode('utf-8')
                        callback(topic, message_str)
                    except Exception as e:
                        logger.error(f"Error processing message: {str(e)}", exc_info=True)
                
                # Start consuming
                consumer_tag = self.channel.basic_consume(
                    queue=queue_name,
                    on_message_callback=message_callback,
                    auto_ack=True
                )
                
                self.consumer_tags.append(consumer_tag)
                logger.debug(f"Subscribed to RabbitMQ exchange '{topic}' with consumer tag {consumer_tag}")
                return consumer_tag
                
            except Exception as e:
                logger.error(f"Error subscribing to '{topic}': {str(e)}", exc_info=True)
                return ""
                
        elif self.broker_type.lower() == "kafka":
            try:
                from kafka import KafkaConsumer
                import threading
                
                # Create a consumer for the topic
                consumer = KafkaConsumer(
                    topic,
                    bootstrap_servers=self.config.get("bootstrap_servers", "localhost:9092").split(','),
                    group_id=self.config.get("client_id", "cyberops"),
                    value_deserializer=lambda x: x.decode('utf-8')
                )
                
                # Generate a unique consumer ID
                consumer_id = str(id(consumer))
                
                # Store the consumer for later unsubscribe
                self.kafka_consumers[consumer_id] = {
                    'consumer': consumer,
                    'thread': None,
                    'running': True
                }
                
                # Start a thread for consuming messages
                def consume_messages():
                    try:
                        while self.kafka_consumers[consumer_id]['running']:
                            # Use poll with a timeout to allow for clean shutdown
                            messages = consumer.poll(timeout_ms=1000)
                            for tp, records in messages.items():
                                for record in records:
                                    try:
                                        callback(topic, record.value)
                                    except Exception as e:
                                        logger.error(f"Error processing message: {str(e)}", exc_info=True)
                    except Exception as e:
                        if self.kafka_consumers[consumer_id]['running']:
                            logger.error(f"Error in Kafka consumer thread: {str(e)}", exc_info=True)
                    finally:
                        try:
                            consumer.close()
                            logger.debug(f"Kafka consumer {consumer_id} closed")
                        except Exception as e:
                            logger.error(f"Error closing Kafka consumer: {str(e)}")
                
                consumer_thread = threading.Thread(target=consume_messages, daemon=True)
                consumer_thread.start()
                
                # Store the thread
                self.kafka_consumers[consumer_id]['thread'] = consumer_thread
                
                logger.debug(f"Subscribed to Kafka topic '{topic}' with consumer id {consumer_id}")
                return consumer_id
                
            except Exception as e:
                logger.error(f"Error subscribing to '{topic}': {str(e)}", exc_info=True)
                return ""
                
        return ""
    
    def unsubscribe(self, subscription_id: str) -> bool:
        """
        Unsubscribe from a topic.
        
        Args:
            subscription_id: Consumer tag or identifier from subscribe()
            
        Returns:
            True if successful, False otherwise
        """
        if not subscription_id:
            return False
            
        if self.broker_type.lower() == "rabbitmq":
            try:
                self.channel.basic_cancel(subscription_id)
                self.consumer_tags.remove(subscription_id)
                logger.debug(f"Unsubscribed from RabbitMQ with consumer tag {subscription_id}")
                return True
            except Exception as e:
                logger.error(f"Error unsubscribing: {str(e)}", exc_info=True)
                return False
                
        elif self.broker_type.lower() == "kafka":
            try:
                # Check if we have this consumer
                if subscription_id in self.kafka_consumers:
                    # Signal the consumer thread to stop
                    self.kafka_consumers[subscription_id]['running'] = False
                    
                    # Wait for the thread to finish (with timeout)
                    thread = self.kafka_consumers[subscription_id]['thread']
                    if thread and thread.is_alive():
                        thread.join(timeout=5.0)
                    
                    # Clean up
                    del self.kafka_consumers[subscription_id]
                    logger.debug(f"Unsubscribed from Kafka with consumer id {subscription_id}")
                    return True
                else:
                    logger.warning(f"Consumer ID {subscription_id} not found")
                    return False
            except Exception as e:
                logger.error(f"Error unsubscribing from Kafka: {str(e)}", exc_info=True)
                return False
                
        return False
    
    def close(self):
        """Close the message broker connection."""
        try:
            if self.broker_type.lower() == "rabbitmq" and self.connection:
                # Cancel all consumers
                for tag in self.consumer_tags:
                    try:
                        self.channel.basic_cancel(tag)
                    except Exception:
                        pass
                        
                self.channel.close()
                self.connection.close()
                logger.info("Closed RabbitMQ connection")
                
            elif self.broker_type.lower() == "kafka":
                # Close all Kafka consumers
                for consumer_id, consumer_data in list(self.kafka_consumers.items()):
                    try:
                        consumer_data['running'] = False
                        if consumer_data['thread'] and consumer_data['thread'].is_alive():
                            consumer_data['thread'].join(timeout=2.0)
                    except Exception as e:
                        logger.error(f"Error closing Kafka consumer {consumer_id}: {str(e)}")
                
                # Close the producer
                if hasattr(self, 'producer') and self.producer:
                    self.producer.close()
                
                logger.info("Closed Kafka connection")
                
        except Exception as e:
            logger.error(f"Error closing message broker connection: {str(e)}", exc_info=True)
