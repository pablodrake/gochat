# GoChat

GoChat is a secure, encrypted, anonymous, and decentralized chat application built using Go and the Tor network. This project was developed as a learning exercise with the intention of using minimal external libraries and implementing core functionality from scratch where possible.

## Features

- **Secure Communication**: All messages are encrypted end-to-end using hybrid encryption.
- **Anonymity**: Utilizes the Tor network to ensure user anonymity.
- **Decentralized**: No central server, promoting resilience and privacy.
- **Minimal Dependencies**: Built primarily with Go standard library, with minimal use of external packages.
- **Educational**: Designed as a learning project to understand networking, cryptography, and Go programming.

## Project Goals

1. **Learning**: To gain hands-on experience with Go programming, networking, and cryptography.
2. **Minimal Dependencies**: To implement as much functionality as possible without relying on external libraries.
3. **Security**: To create a secure communication platform using industry-standard encryption techniques.
4. **Anonymity**: To leverage the Tor network for enhanced privacy and anonymity.
5. **Decentralization**: To explore peer-to-peer communication architectures.

## Technical Details

- **Language**: Go
- **Network**: Tor (for anonymity and NAT traversal)
- **Encryption**: AES for message encryption, RSA for key exchange
- **Architecture**: Peer-to-peer
- **External Libraries**: 
  - [bine](https://github.com/cretz/bine): Used for interfacing with the Tor network on the server side

## Disclaimer

This project is a learning exercise and should not be considered production-ready. While efforts have been made to implement security best practices, the code has not undergone professional security audits.

## Getting Started

To run GoChat, follow these simple steps:

1. Clone the repository:
   ```
   git clone https://github.com/yourusername/gochat.git
   cd gochat
   ```

2. Run the application:
   ```
   go run .
   ```

Note: Ensure you have Go installed on your system and that you're using a compatible version.

## Contributing

As this is a learning project, contributions, suggestions, and discussions are welcome. Please open an issue or pull request if you have ideas for improvements or have found bugs.

## Acknowledgements

- The Tor Project for providing the anonymous network infrastructure.
- The Go community for their excellent documentation and resources.
- The [bine](https://github.com/cretz/bine) library for simplifying Tor integration.

Remember: This project prioritizes learning and exploration over production readiness. Use at your own risk and have fun exploring the world of secure, decentralized communication!
