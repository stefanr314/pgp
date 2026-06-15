from datetime import datetime


class RowKey:
    def __init__(self, user_id: int, enc_private_key: int, public_key: int):
        self.timestamp: datetime = datetime.now()
        #fields: timestamp, keyid = pub mod 2^64, userid, private key encrypted, public key
        self.user_id: int = user_id
        self.public_key: int = public_key
        self.key_id: int = public_key % pow(2, 64)
        self.enc_private_key: int = enc_private_key
        pass



