CMAKE_MINIMUM_REQUIRED(VERSION 2.6)

# API library
ADD_SUBDIRECTORY(lib)

# API library
ADD_SUBDIRECTORY(bluetooth-media-control)

# Bluetooth FW Agent
ADD_SUBDIRECTORY(bluetooth-frwk-agent)

# Phonebook FW Agent
ADD_SUBDIRECTORY(bluetooth-pb-agent)

# Message FW Agent
ADD_SUBDIRECTORY(bluetooth-map-agent)
