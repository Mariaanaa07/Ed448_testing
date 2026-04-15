import time
from cryptography.hazmat.primitives.asymmetric import ed448 as crypto_lib
from Crypto.Signature import eddsa


def test_compare_performance():
    priv_hex = "c4eab05d357007c632f3dbb48489924d552b08fe0c353a0d4a1f00acda2c463afbea67c5e8d2877c5e3bc397a659949ef8021e954e0a12274e"
    priv_bytes = bytes.fromhex(priv_hex)
    msg = b"Performance comparison for Ed448"
    iterations = 200

    print(f"\n Порівняння тестування продуктивності бібліотек cryptography та pycryptodome ({iterations} ітерацій):")

    key_1 = crypto_lib.Ed448PrivateKey.from_private_bytes(priv_bytes)
    start_1 = time.perf_counter()
    for _ in range(iterations):
        key_1.sign(msg)
    time_1 = time.perf_counter() - start_1
    print(f"Швидкість Cryptography: {time_1:.4f} сек")

    key_2 = eddsa.import_private_key(priv_bytes)
    signer = eddsa.new(key_2, 'rfc8032')

    start_2 = time.perf_counter()
    for _ in range(iterations):
        signer.sign(msg)
    time_2 = time.perf_counter() - start_2
    print(f"Швидкість PyCryptodome: {time_2:.4f} сек")

    winner = "Cryptography" if time_1 < time_2 else "PyCryptodome"
    diff = max(time_1, time_2) / min(time_1, time_2)
    print(f"Результат: {winner} швидше у {diff:.2f} разів")