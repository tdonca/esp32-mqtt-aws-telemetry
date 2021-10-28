## Summary
This repo answers the following question: _"How do I connect an ESP32 device to AWS and use it to upload sensor data?"_

This example is based off the MQTT Demo provided by Espressif in their port of the AWS IoT SDK: [ESP IoT SDK Demo](https://github.com/espressif/esp-aws-iot/tree/release/beta/examples/mqtt/tls_mutual_auth)

That demo is then based off the original MQTT Demo provided by AWS in ther IoT SDK: [AWS IoT SDK for Embedded C Demo](https://github.com/aws/aws-iot-device-sdk-embedded-C/tree/main/demos/mqtt/mqtt_demo_mutual_auth)

This example uses TLS mutual authentication to connect to AWS using device-specific certificates and private keys. It also uses MQTT as the communication protocol to send data to the AWS IoT Core server. The example connects to WiFi, then connects to the configured AWS IoT Core MQTT broker and uses QoS0 communication to continuously publish messages on a specified topic. 


## Setup

### Pre-requisites

1. Install ESP-IDF: [ESP-IDF Setup Guide](https://docs.espressif.com/projects/esp-idf/en/latest/esp32/get-started/index.html)
2. Install AWS IoT SDK port for ESP: [AWS IoT SDK Port](https://github.com/espressif/esp-aws-iot/tree/release/beta)
    - Use the beta branch. For more details see: https://www.espressif.com/en/news/LTSrelease
3. Setup your device on AWS Console and download the certificates: [AWS IoT Device Setup Guide](https://docs.aws.amazon.com/iot/latest/developerguide/create-iot-resources.html)

### Application Setup

1. Verify the `IDF_DIR` environment variable points to your ESP-IDF installation directory
    - The project-level [CMakeLists.txt](CMakeLists.txt) requires this 
2. Verify the `ESP_AWS_IOT_SDK_DIR` environment variable points to your AWS IoT SDK installation directory
    - The source code sub-directory [CMakeLists.txt](main/CMakeLists.txt) requires this
3. Place your device certificate files in the [main/certs](main/certs) directory and rename them according to the project configuration
    - The project-level [CMakeLists.txt](CMakeLists.txt) specifies the required file names
4. Configure the application network details using the IDF `idf.py menuconfig` tool
    - WiFi SSID: `Example Connection Configuration` > `WiFi SSID`
    - WiFi password: `Example Connection Configuration` > `WiFi Password`
    - MQTT server hostname: `Example Configuration` > `MQTT Broker Endpoint`
    - MQTT client ID: `Example Configuration` > `MQTT Client Identifier`
5. Build and flash the application
    - `$> idf.py -p [serial port, ex: "/dev/ttyUSB0"] flash`
6. Monitor the application logs
    - `$> idf.py -p [serial port, ex: "/dev/ttyUSB0"] monitor`



## Security Considerations

- The WiFi SSID/password get saved in the generated IDF config files (`sdkconfig` and `sdkconfig.old`). Be careful not to upload your credentials online. The [.gitignore](.gitignore) tries to prevent this.
- The WiFi SSID/password get saved in plaintext locally and on the device. I recommend you setup a guest WiFi network with dummy credentials on your router to isolate your IoT devices. 
- The application requires your IoT device's private key. Be careful not to upload this online. The [main/certs/.gitignore](main/certs/.gitignore) tries to prevent this.


## Console Output

After flashing the example to the ESP32, it should connect to AWS IoT Core and start publishing to `[your clientId]/example/topic`.

```
I (5609) MQTT_DEMO: Establishing a TLS session to xxx.iot.xxx.amazonaws.com:8883.
I (8959) tls_freertos: (Network connection 0x3ffba984) Connection to xxx.iot.xxx.amazonaws.com:8883 established.
I (8959) MQTT_DEMO: Creating an MQTT connection to xxx.iot.xxx.amazonaws.com.
I (9259) MQTT_DEMO: MQTT connection successfully established with broker.


I (9269) MQTT_DEMO: Sending Publish to the MQTT topic testClient/example/topic.
I (9279) MQTT_DEMO: PUBLISH sent for topic testClient/example/topic to broker with packet ID 1.


I (9279) MQTT_DEMO: Delay before the next publish.


I (10289) MQTT_DEMO: Sending Publish to the MQTT topic testClient/example/topic.
I (10289) MQTT_DEMO: PUBLISH sent for topic testClient/example/topic to broker with packet ID 2.
...
```
You can view the MQTT messages received by the AWS server using the AWS Console: [AWS MQTT Monitor Guide](https://docs.aws.amazon.com/iot/latest/developerguide/view-mqtt-messages.html)
