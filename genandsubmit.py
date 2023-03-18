from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend

class DAGPKI:
    def __init__(self, fog_node_public_key):
        self.fog_node_public_key = fog_node_public_key
        self.generate_key_pair
        
    def generate_key_pair(self):
        # Generate a new public/private key pair
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        public_key = private_key.public_key()

        # Serialize the keys to PEM format
        private_key_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        public_key_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        return private_key_pem, public_key_pem
    
    def generate_self_signed_certificate(self, device_id, fog_node, valid_period_days):
        # Generate a public/private key pair for the device
        private_key, public_key = self.generate_key_pair()

        # Sign the device information with the private key
        message = device_id + public_key + fog_node + str(valid_period_days).encode('utf-8')
        signature = private_key.sign(
            message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )

        # Generate the self-signed certificate
        certificate = {
            "device_id": device_id,
            "public_key": public_key,
            "fog_node": fog_node,
            "valid_period_days": valid_period_days,
            "signature": signature
        }
        
        return certificate
    
    def submit_certificate(self, device_certificate):
        # Encrypt the device certificate with the fog node's public key
        encrypted_certificate = self.fog_node_public_key.encrypt(
            device_certificate,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        # Submit the encrypted certificate to the fog node
        decrypted_certificate = self.decrypt_certificate(encrypted_certificate)
        
        return decrypted_certificate
    
    def decrypt_certificate(self, encrypted_certificate):
        # Decrypt the encrypted certificate using the fog node's private key
        decrypted_certificate = self.private_key.decrypt(
            encrypted_certificate,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        
        return decrypted_certificate

Test = DAGPKI()
