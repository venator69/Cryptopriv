# Security Stacks 

##    Integrity           : sha256 HASH
##    authentication      : RSA-PSS digital signature, transmitter public key
##    Confidentiality     : AES-GCM symmetrical encryption for messages, RSA-OAEP for AES key
##    Non-Repudiation     : RSA digital signature

# Flow Transmitter

##    Transmitter and receiver generate public and private key using RSA keys -> 
##    -> Transmitter's payload is received -> 
##    -> Digital signature is using transmitters public key using RSS-> 
##    -> AES key is decrypted using Receivers private key ->
##    -> Message is decrypted using decrypted AES key -> 
##    -> Hash is checked for message integrity

# Flow Receiver

## Transmitter and receiver generate public and private key using RSA keys -> 
##   -> Transmitter's payload is received -> 
##   -> Digital signature is using transmitters public key using RSS-> 
##   -> AES key is decrypted using Receivers private key ->
##   -> Message is decrypted using decrypted AES key -> 
##   -> Hash is checked for message integrity
