# Security Stacks 

##    Integrity           : sha256 HASH
##    authentication      : RSA-PSS digital signature, transmitter public key
##    Confidentiality     : AES-GCM symmetrical encryption for messages, RSA-OAEP for AES key
##    Non-Repudiation     : RSA digital signature

# Flow Transmitter

1. Transmitter and receiver generate public and private key using RSA keys
2. Transmitter's payload is received
3. Digital signature is using transmitters public key using RSS
4. AES key is decrypted using Receivers private key
5. Message is decrypted using decrypted AES key
6. Hash is checked for message integrity

# Flow Receiver

1. Transmitter and receiver generate public and private key using RSA keys 
2. Transmitter's payload is received 
3. Digital signature is using transmitters public key using RSS
4. AES key is decrypted using Receivers private key
5. Message is decrypted using decrypted AES key
6. Hash is checked for message integrity
