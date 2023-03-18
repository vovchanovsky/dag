class FogNode:
    def __init__(self, private_key):
        self.private_key = private_key
        self.devices = {}

    def register_device(self, device_id, public_key):
        self.devices[device_id] = public_key

    def submit_certificate(self, device_id, encrypted_certificate):
        public_key = self.devices.get(device_id)
        if public_key is None:
            raise ValueError(f"Device {device_id} is not registered.")

        certificate = self.decrypt_certificate(encrypted_certificate)
        self.verify_certificate(certificate, public_key)

        # If the certificate is valid, extract the identity attributes and store them
        identity_attributes = self.extract_identity_attributes(certificate)
        self.devices[device_id] = identity_attributes

    def decrypt_certificate(self, encrypted_certificate):
        return rsa.decrypt(encrypted_certificate, self.private_key)

    def verify_certificate(self, certificate, public_key):
        # Calculate the hash of the certificate contents
        hash_value = hashlib.sha256(certificate).digest()

        # Verify the signature using the public key of the device
        rsa.verify(hash_value, certificate, public_key)

    def extract_identity_attributes(self, certificate):
        # For simplicity, assume that the certificate is a JSON object
        certificate_json = json.loads(certificate)
        return certificate_json.get("attributes", {})
