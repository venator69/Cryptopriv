# Security Stacks 

###    Integrity           : sha256 HASH
###    authentication      : RSA-PSS digital signature, transmitter public key
###    Confidentiality     : AES-GCM symmetrical encryption for messages, RSA-OAEP for AES key
###    Non-Repudiation     : RSA digital signature

# Requirements :
### Python 3.x installed in 2 devices
### Cryptography library installed using "pip install cryptography"

# Steps:
1. Bob runs Receiver.py first: python3 Receiver.py
2. Bob notes down his Tailscale IP and then gives it to Alice.
3. Alice changes the SERVER_IP value in Transmitter.py to Bob’s Tailscale IP.
4. Alice runs Transmitter.py: python Transmitter.py
5. Alice enters the message she wants to send when prompted, then presses Enter.
6. The output on both terminals shows the encryption result on Alice’s side, and the decryption and verification results on Bob’s side.


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
