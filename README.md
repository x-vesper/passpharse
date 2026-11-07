# passpharse

Enkrip dan dekrip teks pake password, tanpa simpan password di file.
Algoritma: **Argon2id + AES-256-GCM** (authenticated encryption).

Cara jalan (tanpa binary, pake Go yang terpasang):

```bash
cd /home/zakaria/projects/passpharse
```

## Enkrip

```bash
# Ketik di terminal, output ke terminal
go run . encrypt

# Dari file, output ke file
go run . encrypt -in teks.txt -out terenkrip.b64

# Dari terminal (pipe), output ke file
echo "rahasia ku" | go run . encrypt -out terenkrip.b64

# Pakai password langsung (hati-hati: keliatan di history)
echo "rahasia ku" | go run . encrypt -pass "passwordku"
```

Kalau `-pass` diisi, password dianggap final (tanpa konfirmasi).
Kalau `-pass` dikosongin, program nanya password di terminal (disarankan).

## Dekrip

```bash
# Dari terminal (pipe), output ke terminal
echo "<base64>" | go run . decrypt -pass "passwordku"

# Dari file, output ke file
go run . decrypt -in terenkrip.b64 -out teks.txt

# Dari file, output ke terminal
go run . decrypt -in terenkrip.b64 -pass "passwordku"
```

## Flag

| Flag | Arti |
|---|---|
| `-in FILE` | Baca input dari file. Omit = dari stdin. |
| `-out FILE` | Tulis output ke file. Omit = ke stdout. |
| `-pass PASS` | Password. Omit = prompt di terminal. |

## Catatan

- Output berupa base64: `salt || nonce || ciphertext`.
- Salt & nonce disimpan di output, jadi decrypt otomatis.
- Yang perlu dijaga: **password-nya saja**. Bisa kirim base64 ke mana aja.
- Password salah atau data diubah → error `decryption failed: bad password or corrupted data`.