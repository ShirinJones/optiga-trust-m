# Secure Element Integration for IoT Device Security using OPTIGA™ Trust M and ESP32
This project demonstrates the integration of the Infineon OPTIGA™ Trust M hardware security module (HSM) with the Espressif ESP32 microcontroller to enable hardware-backed TLS authentication for IoT devices.
The implementation offloads critical cryptographic operations such as ECDSA signing and ECDH key exchange from the ESP32 to the tamper-resistant OPTIGA Trust M, ensuring that private keys never leave the secure element. This significantly strengthens device identity protection and mitigates vulnerabilities common in software-only security solutions.

## Key Features
- Hardware-backed TLS 1.2 client authentication with MQTT over TLS (MQTTS).
- mbedTLS ALT integration: redirects cryptographic calls (ecdsa_sign, ecdh_gen_public, ecdh_compute_shared) to the OPTIGA Trust M.
- FreeRTOS PAL layer for events, timers, and I²C communication between ESP32 and OPTIGA.
- Certificate Signing Request (CSR) generation within the OPTIGA environment, keeping private keys isolated.
- Performance gains: Reduced handshake time and energy consumption through hardware-accelerated ECC operations.
- Enhanced security: Resistance against key extraction, side-channel attacks, and cloning of device identity.

## Applications
- Secure IoT device authentication in industrial, medical, and critical infrastructure systems.
- Hardware-rooted identity for MQTT-based communication frameworks.
- Reference design for integrating HSMs with resource-constrained microcontrollers.

## Technology Stack
- ESP-IDF (FreeRTOS) for ESP32
- mbedTLS (with ALT hooks)
- Infineon OPTIGA™ Trust M Host Library
- ESP-MQTT client

## Repository Structure
```text
├── main/      
│      ├── main.c                          # Application entry point, demos (ECDH, ECDSA, CSR)      
│      ├── mqtt_optiga_demo.c              # Secure MQTT client implementation      
│      ├── optiga_ecdh_alt.c               # mbedTLS ALT implementation for ECDH      
│      ├── optiga_ecdsa_alt.c              # mbedTLS ALT implementation for ECDSA      
│      ├── optiga_cert.c/h                 # CSR generation logic      
│      └── optiga_demo_shared.h            # Shared definitions      
├── extras/                          
│      └── pal/esp32_freertos/             # Platform Abstraction Layer (ESP32 + FreeRTOS)        
├── src/                                   # OPTIGA Trust M library sources
├── include/                               # Header files
└── CMakeLists.txt                         # Build configuration with ALT flags
```

## Prerequisites
Before building and flashing this project, you must configure the following settings specific to your environment:
- Wi-Fi Credentials: The project must be configured with your local Wi-Fi SSID and password to connect to the network.
- MQTT Broker Details: You must specify the URI (e.g., mqtts://your.broker.ip:8883) of your MQTT broker that supports TLS client authentication.
- Certificate Authority (CA) Certificate: This is critical. The demo uses a hard-coded Certificate Authority (CA) certificate for testing.
    - You MUST replace the ca_pem variable in main.c with the PEM-format certificate of your own Root CA or the CA that signed your MQTT broker's certificate.
    - Without this change, the TLS handshake will fail because the ESP32 will not trust your broker's certificate.

## Hardware Setup
Connect OPTIGA Trust M to ESP32:
```text
VCC -> 3.3V
GND -> GND
SDA -> GPIO21
SCL -> GPIO22
RST -> GPIO19
```

## Software Setup & Configuration
- Clone the repository.
- Configure your settings: The easiest way is to use the idf.py menuconfig tool:

```text
idf.py menuconfig
```

- Navigate to Example Configuration to set your:
    - Wi-Fi SSID
    - Wi-Fi Password
    - MQTT Broker URI
- Replace the Demo CA Certificate: As mentioned in the prerequisites, you must replace the hard-coded ca_pem string in main.c with your own CA certificate.
- Build, flash, and monitor the project:
  
```text
idf.py build flash monitor
```

## ⚠️ Important Note on Certificate Signing Request (CSR) Functionality
Warning: The CSR generation feature (optiga_cert.c) is included as a demonstration of the concept but may require further debugging and customization for your specific PKI infrastructure.

The current implementation successfully demonstrates the entire flow: generating a key pair on the OPTIGA, constructing a CSR, and signing it with the secure element's private key. However, the parsing of the public key format returned by the OPTIGA library can be fragile and may not be compatible with all Certificate Authorities without adjustments.

For production use, it is highly recommended to:
- Test the generated CSR with your specific CA (e.g., OpenSSL, a commercial CA).
- Carefully review and potentially adapt the public key extraction logic in optiga_get_public_key() and generate_csr_with_optiga() to match the expected format of your PKI system.
- Consider pre-provisioning devices with certificates during manufacturing instead of generating CSRs on-device for a more robust lifecycle management strategy.

For immediate testing of the TLS client authentication, you can generate a client certificate offline using your CA and load it onto the ESP32 via the filesystem, bypassing the on-device CSR generation for now.

## 📜 License
This project is licensed under the Apache License 2.0 - see the LICENSE file for details.

## 🔗 References
- [Infineon OPTIGA Trust M](https://infineon.github.io/arduino-optiga-trust-m/index.html)
- [Espressif ESP32](https://docs.espressif.com/projects/esp-idf/en/stable/esp32/api-reference/index.html)
- [mbed TLS](https://github.com/Infineon/optiga-trust-m/tree/main/external)
- [Optiga Trust M Github](https://github.com/Infineon/optiga-trust-m/tree/main)

