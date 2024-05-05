# Secure E2EE Chat Web Application

## Overview
This chat application is designed with a focus on privacy and security, offering end-to-end encryption (E2EE) to ensure that messages are accessible only to intended recipients. It features:

- **End-to-End Encryption:** Uses AES-GCM to encrypt messages, ensuring only authorized users can decrypt them.
- **Multi-Factor Authentication:** Combines passwords with One-Time Passwords (OTP) for improved account security.
- **Secure Key Exchange:** Implements the Elliptic Curve Diffie-Hellman (ECDH) protocol for secure key exchange.
- **Transport Layer Security (TLS):** Encrypts communication between user devices and servers.
- **Website Authentication:** Uses a valid digital certificate to authenticate the web application.

## Features
- **Authentication:**
  - Login process includes user credential validation and TOTP verification.
  - Multiple secrets for authentication, including passwords, security questions, and OTPs.
  - Rate limiting with captchas and IP tracking to prevent brute-force attacks.
  - Account registration binds OTP for improved security.
  - Session timeout after 20 minutes of inactivity.

- **Encryption:**
  - ECDH exchange allows secure shared secret establishment.
  - AES-GCM encryption ensures message confidentiality.
  - Refresh mechanism updates symmetric keys for better security.
  - Stores previous keys to allow decryption of older messages.

- **Countermeasures:**
  - SQL Injection protection using prepared statements.
  - Cross-Site Scripting (XSS) mitigated through secure cookie handling.
  - Cross-Site Request Forgery (CSRF) mitigated with SameSite cookies.

- **TLS:**
  - Configured using Nginx for secure HTTPS communication.
  - Domain certificate obtained for authenticating the web application.

## Libraries Used
- **bcrypt:** Secure password hashing.
- **Crypto:** Key derivation and encryption.
- **base64:** Encoding.
- **pyqrcode:** Generate QR code for Google Authenticator.
- **onetimepass:** Validate TOTP.
- **re:** Regular expression handling for input validation.

## Getting Started
1. **Dependencies:** Ensure that you have all the required libraries installed.
2. **Configuration:** Set up the necessary environment variables, including database credentials and secret keys.
3. **Database:** Run the provided SQL scripts to set up the database schema.
4. **Server:** Start the server and ensure the TLS configuration is correctly set up.
5. **Client:** Access the application through the web browser to begin secure messaging.

## Conclusion
This application offers robust security features to ensure private communication between users, using advanced encryption methods, secure authentication, and strong countermeasures against common threats.

## References
1. Lodderstedt, E. T., “RFC 6819 - OAuth 2.0 Threat Model and Security Considerations,” datatracker.ietf.org, Jan. 2013.
2. Van Oorschot, P. C., Computer Security and the Internet: Tools and Jewels. Cham: Springer, 2020.
