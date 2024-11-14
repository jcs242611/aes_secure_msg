# Cryptographic Secure Messaging System using AES

- Confidentiality: Only the intended recipient should access the message content.
- Integrity: Messages should be protected against tampering, ensuring the content is exactly what was sent.
- Message Freshness and Replay Attack Prevention: Using a unique Initialization Vector (IV) with a fixed length of 16 bytes for each message.
- Username Privacy: Encrypting usernames with a fixed length (16 bytes maximum) to ensure privacy.
