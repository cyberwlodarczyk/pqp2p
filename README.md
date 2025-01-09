# Post-Quantum P2P

### COMMANDS 
```bash
# generowanie klucza prywatnego
openssl genpkey -algorithm dilithium5 -out private_key.pem -provider oqsprovider -provider default
# wyciąganie klucza publicznego z klucza prywatnego
openssl pkey -provider oqsprovider -provider default -in private_key.pem -pubout -out public_key.pem
# weryfikacja podpisu pliku
openssl pkeyutl -verify -pubin -inkey .dev/bob/public_key.pem -in .dev/alice/received_file -sigfile .dev/alice received_signature.sig -provider oqsprovider -provider default
```

### FILE.IO
```bash
# wysyłanie pliku:
curl -F "file=@nazwa_pliku" https://file.io
#pobranie pliku:
curl -o nazwa_pliku https://file.io/abc123
```


