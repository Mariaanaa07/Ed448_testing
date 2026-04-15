import pytest
from cryptography.hazmat.primitives.asymmetric import ed448
from cryptography.exceptions import InvalidSignature


PRIV_KEY_HEX = "c4eab05d357007c632f3dbb48489924d552b08fe0c353a0d4a1f00acda2c463afbea67c5e8d2877c5e3bc397a659949ef8021e954e0a12274e"
PUB_KEY_HEX = "43ba28f430cdff456ae531545f7ecd0ac834a55d9358c0372bfa0c6c6798c0866aea01eb00742802b8438ea4cb82169c235160627b4c3a9480"
MESSAGE_HEX = "03"
EXPECTED_SIG_HEX = "26b8f91727bd62897af15e41eb43c377efb9c610d48f2335cb0bd0087810f4352541b143c4b981b7e18f62de8ccdf633fc1bf037ab7cd779805e0dbcc0aae1cbcee1afb2e027df36bc04dcecbf154336c19f0af7e0a6472905e799f1953d2a0ff3348ab21aa4adafd1d234441cf807c03a00"


class TestEd448Implementation:

    def test_key_derivation(self):
        """Перевірка генерації публічного ключа з приватного"""
        priv_bytes = bytes.fromhex(PRIV_KEY_HEX)
        private_key = ed448.Ed448PrivateKey.from_private_bytes(priv_bytes)
        public_key = private_key.public_key()
        assert public_key.public_bytes_raw().hex() == PUB_KEY_HEX

    def test_signature_creation(self):
        """Перевірка створення підпису за тестовим вектором"""
        priv_bytes = bytes.fromhex(PRIV_KEY_HEX)
        msg_bytes = bytes.fromhex(MESSAGE_HEX)
        private_key = ed448.Ed448PrivateKey.from_private_bytes(priv_bytes)
        signature = private_key.sign(msg_bytes)
        assert signature.hex() == EXPECTED_SIG_HEX

    def test_verification_success(self):
        """Перевірка успішної верифікації валідного підпису"""
        pub_bytes = bytes.fromhex(PUB_KEY_HEX)
        msg_bytes = bytes.fromhex(MESSAGE_HEX)
        sig_bytes = bytes.fromhex(EXPECTED_SIG_HEX)
        public_key = ed448.Ed448PublicKey.from_public_bytes(pub_bytes)
        try:
            public_key.verify(sig_bytes, msg_bytes)
        except InvalidSignature:
            pytest.fail("Верифікація не виконана для валідного підпису")

    def test_verification_failure(self):
        """Перевірка відхилення невалідного підпису"""
        pub_bytes = bytes.fromhex(PUB_KEY_HEX)
        public_key = ed448.Ed448PublicKey.from_public_bytes(pub_bytes)
        wrong_msg = b"Wrong message"
        sig_bytes = bytes.fromhex(EXPECTED_SIG_HEX)
        with pytest.raises(InvalidSignature):
            public_key.verify(sig_bytes, wrong_msg)