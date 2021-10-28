/*
 * AWS IoT Device SDK for Embedded C 202103.00
 * Copyright (C) 2020 Amazon.com, Inc. or its affiliates.  All Rights Reserved.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy of
 * this software and associated documentation files (the "Software"), to deal in
 * the Software without restriction, including without limitation the rights to
 * use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
 * the Software, and to permit persons to whom the Software is furnished to do so,
 * subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
 * FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
 * COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
 * IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */

/*
 * Example showing the use of MQTT APIs to establish an MQTT session
 * and continuously publish to a topic. This is based off of the AWS demo 
 * provided with the SDK.
 *
 * A mutually authenticated TLS connection is used to connect to the AWS IoT
 * MQTT message broker in this example. Define ROOT_CA_CERT_PATH for server
 * authentication in the client. Client authentication happens according to:
 * 1. Define CLIENT_CERT_PATH and CLIENT_PRIVATE_KEY_PATH in demo_config.h
 *    for client authentication to be done based on the client certificate
 *    and client private key. More details about this client authentication
 *    can be found in the link below.
 *    https://docs.aws.amazon.com/iot/latest/developerguide/client-authentication.html
 *
 * The example is single threaded and uses statically allocated memory;
 * it uses QOS0 without any retransmission or Subscribe operations.
 */

/* Standard includes. */
#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

/* POSIX includes. */
#include <unistd.h>

/* Include Demo Config as the first non-system header. */
#include "mqtt_operations_config.h"

/* MQTT API headers. */
#include "core_mqtt.h"

/* OpenSSL sockets transport implementation. */
#include "tls_freertos.h"

/*Include backoff algorithm header for retry logic.*/
#include "backoff_algorithm.h"

/* Clock for timer. */
#include "clock.h"

/* Interface header */
#include "telemetry_operations.h"

/*-----------------------------------------------------------*/

/**
 * @brief The network buffer must remain valid for the lifetime of the MQTT context.
 */
static uint8_t buffer[ NETWORK_BUFFER_SIZE ];

/*-----------------------------------------------------------*/

/**
 * @brief Initializes the MQTT library.
 *
 * @param[in] pMqttContext MQTT context pointer.
 * @param[in] pNetworkContext The network context pointer.
 *
 * @return EXIT_SUCCESS if the MQTT library is initialized;
 * EXIT_FAILURE otherwise.
 */
static int initializeMqtt( MQTTContext_t * pMqttContext,
                           NetworkContext_t * pNetworkContext );

/**
 * @brief Connect to MQTT broker with reconnection retries.
 *
 * If connection fails, retry is attempted after a timeout.
 * Timeout value will exponentially increase until maximum
 * timeout value is reached or the number of attempts are exhausted.
 *
 * @param[out] pNetworkContext The output parameter to return the created network context.
 *
 * @return EXIT_FAILURE on failure; EXIT_SUCCESS on successful connection.
 */
static int connectToServerWithBackoffRetries( NetworkContext_t * pNetworkContext );

/**
 * @brief A function that connects to MQTT broker,
 * and publishes to a topic continuously.
 *
 * @param[in] pMqttContext MQTT context pointer.
 *
 * @return EXIT_FAILURE on failure; EXIT_SUCCESS on success.
 */
static int publishLoop(MQTTContext_t * pMqttContext);

/**
 * @brief Disconnect from MQTT broker by closing the network connection.
 *
 * @param[out] pNetworkContext The output parameter to return the updated network context.
 *
 * @return EXIT_FAILURE on failure; EXIT_SUCCESS on successful disconnect.
 */
static int disconnectFromServer( NetworkContext_t * pNetworkContext );

/**
 * @brief The random number generator to use for exponential backoff with
 * jitter retry logic.
 *
 * @return The generated random number.
 */
static uint32_t generateRandomNumber();

/**
 * @brief The application callback function for getting the incoming publish
 * and incoming acks reported from MQTT library.
 *
 * @param[in] pMqttContext MQTT context pointer.
 * @param[in] pPacketInfo Packet Info pointer for the incoming packet.
 * @param[in] pDeserializedInfo Deserialized information from the incoming packet.
 */
static void eventCallback( MQTTContext_t * pMqttContext,
                           MQTTPacketInfo_t * pPacketInfo,
                           MQTTDeserializedInfo_t * pDeserializedInfo );

/**
 * @brief Sends an MQTT CONNECT packet over the already connected TCP socket.
 *
 * @param[in] pMqttContext MQTT context pointer.
 * @param[in] createCleanSession Creates a new MQTT session if true.
 * If false, tries to establish the existing session if there was session
 * already present in broker.
 * @param[out] pSessionPresent Session was already present in the broker or not.
 * Session present response is obtained from the CONNACK from broker.
 *
 * @return EXIT_SUCCESS if an MQTT session is established;
 * EXIT_FAILURE otherwise.
 */
static int establishMqttSession( MQTTContext_t * pMqttContext,
                                 bool createCleanSession,
                                 bool * pSessionPresent );

/**
 * @brief Close an MQTT session by sending MQTT DISCONNECT.
 *
 * @param[in] pMqttContext MQTT context pointer.
 *
 * @return EXIT_SUCCESS if DISCONNECT was successfully sent;
 * EXIT_FAILURE otherwise.
 */
static int disconnectMqttSession( MQTTContext_t * pMqttContext );

/**
 * @brief Sends an MQTT PUBLISH to #MQTT_EXAMPLE_TOPIC defined at
 * the top of the file.
 *
 * @param[in] pMqttContext MQTT context pointer.
 *
 * @return EXIT_SUCCESS if PUBLISH was successfully sent;
 * EXIT_FAILURE otherwise.
 */
static int publishToTopicQoS0( MQTTContext_t * pMqttContext );

/*-----------------------------------------------------------*/

static uint32_t generateRandomNumber()
{
    return( rand() );
}

/*-----------------------------------------------------------*/

static void eventCallback( MQTTContext_t * pMqttContext,
                           MQTTPacketInfo_t * pPacketInfo,
                           MQTTDeserializedInfo_t * pDeserializedInfo )
{
    assert( pMqttContext != NULL );
    assert( pPacketInfo != NULL );
    assert( pDeserializedInfo != NULL );

    /* Event callback is not used since we are just publishing 
     * with QoS0 and not listening to any topics */
}

/*-----------------------------------------------------------*/

static int establishMqttSession( MQTTContext_t * pMqttContext,
                                 bool createCleanSession,
                                 bool * pSessionPresent )
{
    int returnStatus = EXIT_SUCCESS;
    MQTTStatus_t mqttStatus;
    MQTTConnectInfo_t connectInfo = { 0 };

    assert( pMqttContext != NULL );
    assert( pSessionPresent != NULL );

    /* Establish MQTT session by sending a CONNECT packet. */

    /* If #createCleanSession is true, start with a clean session
     * i.e. direct the MQTT broker to discard any previous session data.
     * If #createCleanSession is false, directs the broker to attempt to
     * reestablish a session which was already present. */
    connectInfo.cleanSession = createCleanSession;

    /* The client identifier is used to uniquely identify this MQTT client to
     * the MQTT broker. In a production device the identifier can be something
     * unique, such as a device serial number. */
    connectInfo.pClientIdentifier = CLIENT_IDENTIFIER;
    connectInfo.clientIdentifierLength = CLIENT_IDENTIFIER_LENGTH;

    /* The maximum time interval in seconds which is allowed to elapse
     * between two Control Packets.
     * It is the responsibility of the Client to ensure that the interval between
     * Control Packets being sent does not exceed the this Keep Alive value. In the
     * absence of sending any other Control Packets, the Client MUST send a
     * PINGREQ Packet. */
    connectInfo.keepAliveSeconds = MQTT_KEEP_ALIVE_INTERVAL_SECONDS;

    /* The username field is populated with voluntary metrics to AWS IoT.
     * The metrics collected by AWS IoT are the operating system, the operating
     * system's version, the hardware platform, and the MQTT Client library
     * information. These metrics help AWS IoT improve security and provide
     * better technical support. */
    connectInfo.pUserName = METRICS_STRING;
    connectInfo.userNameLength = METRICS_STRING_LENGTH;
    /* Password for authentication is not used. */
    connectInfo.pPassword = NULL;
    connectInfo.passwordLength = 0U;

    /* Send MQTT CONNECT packet to broker. */
    mqttStatus = MQTT_Connect( pMqttContext, &connectInfo, NULL, CONNACK_RECV_TIMEOUT_MS, pSessionPresent );

    if( mqttStatus != MQTTSuccess )
    {
        returnStatus = EXIT_FAILURE;
        LogError( ( "Connection with MQTT broker failed with status %s.",
                    MQTT_Status_strerror( mqttStatus ) ) );
    }
    else
    {
        LogInfo( ( "MQTT connection successfully established with broker.\n\n" ) );
    }

    return returnStatus;
}

/*-----------------------------------------------------------*/

static int disconnectMqttSession( MQTTContext_t * pMqttContext )
{
    MQTTStatus_t mqttStatus = MQTTSuccess;
    int returnStatus = EXIT_SUCCESS;

    assert( pMqttContext != NULL );

    /* Send DISCONNECT. */
    mqttStatus = MQTT_Disconnect( pMqttContext );

    if( mqttStatus != MQTTSuccess )
    {
        LogError( ( "Sending MQTT DISCONNECT failed with status=%s.",
                    MQTT_Status_strerror( mqttStatus ) ) );
        returnStatus = EXIT_FAILURE;
    }

    return returnStatus;
}

/*-----------------------------------------------------------*/

static int publishToTopicQoS0(MQTTContext_t * pMqttContext) {
    int returnStatus = EXIT_SUCCESS;
    MQTTStatus_t mqttStatus = MQTTSuccess;

    assert( pMqttContext != NULL );

    // Create the MQTT Publish message
    MQTTPublishInfo_t publishPacket = {0};
    publishPacket.qos = MQTTQoS0;
    publishPacket.pTopicName = MQTT_EXAMPLE_TOPIC;
    publishPacket.topicNameLength = MQTT_EXAMPLE_TOPIC_LENGTH;
    publishPacket.pPayload = MQTT_EXAMPLE_MESSAGE;
    publishPacket.payloadLength = MQTT_EXAMPLE_MESSAGE_LENGTH;
    uint16_t packetId = MQTT_GetPacketId(pMqttContext);
    
    mqttStatus = MQTT_Publish(pMqttContext, &publishPacket, packetId);

    if (mqttStatus == MQTTSuccess) {
        LogInfo(("PUBLISH sent for topic %.*s to broker with packet ID %u.\n\n",
                        MQTT_EXAMPLE_TOPIC_LENGTH,
                        MQTT_EXAMPLE_TOPIC,
                        packetId));
    } else {
        LogError(("Failed to send PUBLISH packet to broker with error = %s.",
                        MQTT_Status_strerror(mqttStatus)));
        returnStatus = EXIT_FAILURE;
    }

    return returnStatus;
}

/*-----------------------------------------------------------*/

static int initializeMqtt( MQTTContext_t * pMqttContext,
                           NetworkContext_t * pNetworkContext )
{
    int returnStatus = EXIT_SUCCESS;
    MQTTStatus_t mqttStatus;
    MQTTFixedBuffer_t networkBuffer;
    TransportInterface_t transport;

    assert( pMqttContext != NULL );
    assert( pNetworkContext != NULL );

    /* Fill in TransportInterface send and receive function pointers.
     * For this demo, TCP sockets are used to send and receive data
     * from network. Network context is SSL context for OpenSSL.*/
    transport.pNetworkContext = pNetworkContext;
    transport.send = TLS_FreeRTOS_send;
    transport.recv = TLS_FreeRTOS_recv;

    /* Fill the values for network buffer. */
    networkBuffer.pBuffer = buffer;
    networkBuffer.size = NETWORK_BUFFER_SIZE;

    /* Initialize MQTT library. */
    mqttStatus = MQTT_Init( pMqttContext,
                            &transport,
                            Clock_GetTimeMs,
                            eventCallback,
                            &networkBuffer );

    if( mqttStatus != MQTTSuccess )
    {
        returnStatus = EXIT_FAILURE;
        LogError( ( "MQTT init failed: Status = %s.", MQTT_Status_strerror( mqttStatus ) ) );
    }

    return returnStatus;
}

/*-----------------------------------------------------------*/

static int connectToServerWithBackoffRetries( NetworkContext_t * pNetworkContext )
{
    int returnStatus = EXIT_SUCCESS;
    BackoffAlgorithmStatus_t backoffAlgStatus = BackoffAlgorithmSuccess;
    TlsTransportStatus_t opensslStatus = TLS_TRANSPORT_SUCCESS;
    BackoffAlgorithmContext_t reconnectParams;
    ServerInfo_t serverInfo;
    NetworkCredentials_t *opensslCredentials = (NetworkCredentials_t*) malloc (sizeof (NetworkCredentials_t));
    opensslCredentials->disableSni = 0;
    uint16_t nextRetryBackOff;

    /* Initialize information to connect to the MQTT broker. */
    serverInfo.pHostName = AWS_IOT_ENDPOINT;
    serverInfo.hostNameLength = AWS_IOT_ENDPOINT_LENGTH;
    serverInfo.port = AWS_MQTT_PORT;

    /* Initialize credentials for establishing TLS session. */
    opensslCredentials->pRootCa = ( const unsigned char * ) root_cert_auth_pem_start;
    opensslCredentials->rootCaSize = root_cert_auth_pem_end - root_cert_auth_pem_start;

    /* If #CLIENT_USERNAME is defined, username/password is used for authenticating
     * the client. */
    #ifndef CLIENT_USERNAME
        opensslCredentials->pClientCert = ( const unsigned char * ) client_cert_pem_start;
        opensslCredentials->clientCertSize = client_cert_pem_end - client_cert_pem_start;
        opensslCredentials->pPrivateKey = ( const unsigned char * ) client_key_pem_start;
        opensslCredentials->privateKeySize = client_key_pem_end - client_key_pem_start;
    #endif

    /* AWS IoT requires devices to send the Server Name Indication (SNI)
     * extension to the Transport Layer Security (TLS) protocol and provide
     * the complete endpoint address in the host_name field. Details about
     * SNI for AWS IoT can be found in the link below.
     * https://docs.aws.amazon.com/iot/latest/developerguide/transport-security.html */

    if( AWS_MQTT_PORT == 443 )
    {
        /* Pass the ALPN protocol name depending on the port being used.
         * Please see more details about the ALPN protocol for the AWS IoT MQTT
         * endpoint in the link below.
         * https://aws.amazon.com/blogs/iot/mqtt-with-tls-client-authentication-on-port-443-why-it-is-useful-and-how-it-works/
         */

        static const char * pcAlpnProtocols[] = { NULL, NULL };
        pcAlpnProtocols[0] = AWS_IOT_MQTT_ALPN;
        opensslCredentials->pAlpnProtos = pcAlpnProtocols;
    } else {
        opensslCredentials->pAlpnProtos = NULL;
    }

    /* Initialize reconnect attempts and interval */
    BackoffAlgorithm_InitializeParams( &reconnectParams,
                                       CONNECTION_RETRY_BACKOFF_BASE_MS,
                                       CONNECTION_RETRY_MAX_BACKOFF_DELAY_MS,
                                       CONNECTION_RETRY_MAX_ATTEMPTS );

    /* Attempt to connect to MQTT broker. If connection fails, retry after
     * a timeout. Timeout value will exponentially increase until maximum
     * attempts are reached.
     */
    do
    {
        /* Establish a TLS session with the MQTT broker. This example connects
         * to the MQTT broker as specified in AWS_IOT_ENDPOINT and AWS_MQTT_PORT
         * at the demo config header. */
        LogInfo( ( "Establishing a TLS session to %.*s:%d.",
                   AWS_IOT_ENDPOINT_LENGTH,
                   AWS_IOT_ENDPOINT,
                   AWS_MQTT_PORT ) );
        opensslStatus = TLS_FreeRTOS_Connect ( pNetworkContext,
                                            serverInfo.pHostName,
                                            serverInfo.port,
                                            opensslCredentials,
                                            TRANSPORT_SEND_RECV_TIMEOUT_MS,
                                            TRANSPORT_SEND_RECV_TIMEOUT_MS );

        if( opensslStatus != TLS_TRANSPORT_SUCCESS )
        {
            /* Generate a random number and get back-off value (in milliseconds) for the next connection retry. */
            backoffAlgStatus = BackoffAlgorithm_GetNextBackoff( &reconnectParams, generateRandomNumber(), &nextRetryBackOff );

            if( backoffAlgStatus == BackoffAlgorithmRetriesExhausted )
            {
                LogError( ( "Connection to the broker failed, all attempts exhausted." ) );
                returnStatus = EXIT_FAILURE;
            }
            else if( backoffAlgStatus == BackoffAlgorithmSuccess )
            {
                LogWarn( ( "Connection to the broker failed. Retrying connection "
                           "after %hu ms backoff.",
                           ( unsigned short ) nextRetryBackOff ) );
                Clock_SleepMs( nextRetryBackOff );
            }
        }
    } while( ( opensslStatus != TLS_TRANSPORT_SUCCESS ) && ( backoffAlgStatus == BackoffAlgorithmSuccess ) );

    return returnStatus;
}

/*-----------------------------------------------------------*/

static int disconnectFromServer(NetworkContext_t * pNetworkContext) 
{
    ( void ) TLS_FreeRTOS_Disconnect( pNetworkContext );

    return EXIT_SUCCESS;
}

/*-----------------------------------------------------------*/

static int publishLoop(MQTTContext_t * pMqttContext) {
    int returnStatus = EXIT_SUCCESS;
    bool createCleanSession = true;
    bool brokerSessionPresent;

    assert(pMqttContext != NULL);

    /* Establish a clean MQTT session on top of TCP+TLS connection. */
    LogInfo(("Creating an MQTT connection to %.*s.",
               AWS_IOT_ENDPOINT_LENGTH,
               AWS_IOT_ENDPOINT));

    /* Sends an MQTT CONNECT packet using the established TLS session,
     * then waits for connection acknowledgment (CONNACK) packet. */
    returnStatus = establishMqttSession(pMqttContext, createCleanSession, &brokerSessionPresent);

    if (returnStatus == EXIT_SUCCESS) {
        
        /* There should not be any existing broker session since 
         * we are establishing a clean MQTT session */
        assert(brokerSessionPresent == false);

        // Publish messages continuously with QoS0
        for (;;) {
            LogInfo(("Sending Publish to the MQTT topic %.*s.",
                       MQTT_EXAMPLE_TOPIC_LENGTH,
                       MQTT_EXAMPLE_TOPIC));
            returnStatus = publishToTopicQoS0(pMqttContext);
            
            LogInfo(("Delay before the next publish.\n\n"));
            sleep(DELAY_BETWEEN_PUBLISHES_SECONDS);
        }

        /* This should not happen, but cleanup the MQTT Session if
         * there is a publish error */
        LogInfo(("Disconnecting the MQTT connection with %.*s.",
                   AWS_IOT_ENDPOINT_LENGTH,
                   AWS_IOT_ENDPOINT));
        returnStatus = disconnectMqttSession(pMqttContext);
    }
    
    return returnStatus;
}

/*-----------------------------------------------------------*/

int enableMQTTTelemetry() {
    
    // Initialize the context
    int returnStatus = EXIT_SUCCESS;
    MQTTContext_t mqttContext = {0};
    NetworkContext_t networkContext = {0};
    struct timespec tp;

    // Initialize the random number generator
    (void) clock_gettime(CLOCK_REALTIME, &tp);
    srand(tp.tv_nsec);

    // Intialize MQTT library
    returnStatus = initializeMqtt(&mqttContext, &networkContext);

    // Connect to MQTT server
    if (returnStatus == EXIT_SUCCESS) {

        /* Attempt to connect to the MQTT broker. If connection fails, retry after
         * a timeout. Timeout value will be exponentially increased till the maximum
         * attempts are reached or maximum timeout value is reached. The function
         * returns EXIT_FAILURE if the TCP connection cannot be established to
         * broker after configured number of attempts. */
        returnStatus = connectToServerWithBackoffRetries(&networkContext);

        // Start the publish loop
        if (returnStatus == EXIT_SUCCESS) {
            returnStatus = publishLoop(&mqttContext);
            LogInfo(("Publish loop terminated. Disconnecting from MQTT Server"));
            returnStatus = disconnectFromServer(&networkContext);
        } else {
            LogError(("Failed to connect to MQTT broker."));
        }
    }

    return returnStatus;
}
