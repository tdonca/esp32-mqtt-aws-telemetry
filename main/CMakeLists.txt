# Include MQTT library's source and header path variables from the AWS IoT SDK
include( $ENV{ESP_AWS_IOT_SDK_DIR}/aws-iot-device-sdk-embedded-C/libraries/standard/coreMQTT/mqttFilePaths.cmake )

# Include backoffAlgorithm library file path configuration from the AWS IoT SDK
include( $ENV{ESP_AWS_IOT_SDK_DIR}/aws-iot-device-sdk-embedded-C/libraries/standard/backoffAlgorithm/backoffAlgorithmFilePaths.cmake )

# Include ESP specific ports of some AWS IoT SDK components
include( $ENV{ESP_AWS_IOT_SDK_DIR}/port/portFilePaths.cmake )

set(COMPONENT_SRCS
	"app_main.c"
	"mqtt_operations.c"
	"${MQTT_SOURCES}"
	"${MQTT_SERIALIZER_SOURCES}"
	"${BACKOFF_ALGORITHM_SOURCES}"
	"${PORT_SOURCES}"
	)

set(COMPONENT_ADD_INCLUDEDIRS
	"."
	"${MQTT_INCLUDE_PUBLIC_DIRS}"
	"${BACKOFF_ALGORITHM_INCLUDE_PUBLIC_DIRS}"
	"${CMAKE_CURRENT_LIST_DIR}"
	"${LOGGING_INCLUDE_DIRS}"
	"${PORT_INCLUDE_PUBLIC_DIRS}"
	)

idf_component_register(SRCS "${COMPONENT_SRCS}"
					   INCLUDE_DIRS ${COMPONENT_ADD_INCLUDEDIRS}
					  )
