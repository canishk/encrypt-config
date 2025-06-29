import os
import yaml
from cryptography.fernet import Fernet

class ConfigReader:
    def __init__(self, config_path='config.yml', key_path='config_key.key'):
        self.original_config_path = config_path
        self.encrypted_config_path = config_path.split('.')[0] + '_encrypted.yml'
        self.key_path = key_path
        self.fernet = self._load_or_generate_key()

         # Auto-encrypt if needed
        if not os.path.exists(self.encrypted_config_path):
            print("[🔐] Encrypted config not found. Encrypting plain config...")
            self.encrypt_config_file(
                input_path=self.original_config_path,
                output_path=self.encrypted_config_path
            )

        self.config = self._load_and_decrypt_config()
    
    def _load_or_generate_key(self):
        if not os.path.exists(self.key_path):
            print(f"[🔑] Key not found. Generating new key at: {self.key_path}")
            key = Fernet.generate_key()
            with open(self.key_path, 'wb') as f:
                f.write(key)
        else:
            with open(self.key_path, 'rb') as f:
                key = f.read()
        return Fernet(key)
    
    def encrypt_value(self, plain_text):
        encrypted = self.fernet.encrypt(plain_text.encode()).decode()
        return f"ENC({encrypted})"

    def _decrypt(self, value):
        if isinstance(value, str) and value.startswith("ENC(") and value.endswith(")"):
            encrypted_value = value[4:-1]
            try:
                return self.fernet.decrypt(encrypted_value.encode()).decode()
            except Exception as e:
                raise ValueError(f"Failed to decrypt value: {value}") from e
        return value
    
    def _decrypt_values(self, data):
        if isinstance(data, dict):
            return {k: self._decrypt_values(v) for k, v in data.items()}
        elif isinstance(data, list):
            return [self._decrypt_values(i) for i in data]
        else:
            return self._decrypt(data)

    def get(self, *keys, default=None):
        ref = self.config
        for key in keys:
            if isinstance(ref, dict) and key in ref:
                ref = ref[key]
            else:
                return default
        return ref
    
    def _encrypt_values(self, data, keys_to_encrypt=None, current_path=None):
        if current_path is None:
            current_path = []

        if isinstance(data, dict):
            result = {}
            for k, v in data.items():
                full_path = current_path + [k]
                if keys_to_encrypt is None or full_path[0] in keys_to_encrypt:
                    result[k] = self._encrypt_values(v, keys_to_encrypt, full_path)
                else:
                    result[k] = v
            return result
        elif isinstance(data, list):
            return [self._encrypt_values(i, keys_to_encrypt, current_path) for i in data]
        else:
            if isinstance(data, str) and not data.startswith("ENC("):
                return self.encrypt_value(data)
            return data

    def show_config(self):
        return self.config
    
    def _load_and_decrypt_config(self):
        with open(self.encrypted_config_path, 'r') as f:
            encrypted_data = yaml.safe_load(f)
        return self._decrypt_values(encrypted_data)
    
    def encrypt_config_file(self, input_path='config.yml', output_path='config.encrypted.yml', keys_to_encrypt=None):
        """
        Encrypt selected or all values in the config file and save to a new file.

        :param input_path: Path of the plain config
        :param output_path: Encrypted output config
        :param keys_to_encrypt: Top-level keys to encrypt (all if None)
        """
        with open(input_path, 'r') as f:
            raw_config = yaml.safe_load(f)

        encrypted_config = self._encrypt_values(raw_config, keys_to_encrypt)
        with open(output_path, 'w') as f:
            yaml.safe_dump(encrypted_config, f, default_flow_style=False)
        
        print(f"[✅] Encrypted config written to {output_path}")
    
# Example usage:
if __name__ == "__main__":
    conf = ConfigReader(config_path='config/config_dev.yml', key_path='config/config_key.key')
    # print(conf.show_config())
    print(conf.get('account')) # Example to get a specific value
    print(conf.get('dev_email')) # Example to get a nested value
    
    