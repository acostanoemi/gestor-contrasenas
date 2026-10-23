# gestor-contraseñas

Gestor de contraseñas (password manager) por línea de comandos, local y **zero-knowledge**. Guarda tus contraseñas cifradas en un único archivo protegido por una master password. Todo se cifra y descifra en tu máquina; la master password nunca se guarda.

## Cómo funciona la criptografía

- De tu **master password** se deriva una clave de cifrado con **Scrypt**, un algoritmo lento a propósito (encarece el fuerza bruta). Usa la password más una "sal" aleatoria que se guarda en el archivo.
- Con esa clave se cifra el vault usando **Fernet** (cifrado + verificación de integridad: si tocan el archivo, se detecta).
- El archivo solo contiene la sal y el bloque cifrado. Sin la master password, es ilegible.

La master password **nunca** se guarda en ningún lado, ni siquiera cifrada.

## ⚠️ No hay recuperación

Si olvidás la master password, se perdió el vault. No hay "recuperar contraseña". Eso es la prueba de que está bien cifrado: ni vos ni nadie puede abrirlo sin ella. Anotá tu master password en un lugar seguro y offline.

## Requisitos

- Python 3
- La librería `cryptography`:

```bash
sudo apt install python3-cryptography
```

- Para el comando `copy` (portapapeles): `sudo apt install xclip`
- El comando `check` necesita conexión a internet (consulta HaveIBeenPwned).

## Uso

```bash
python3 gestor.py init                # crear el vault (pide master password)
python3 gestor.py add github          # agregar una entrada
python3 gestor.py get github          # ver una entrada
python3 gestor.py copy github         # copiar la contraseña (se borra a los 20s)
python3 gestor.py list                # listar los nombres guardados
python3 gestor.py delete github       # borrar una entrada
python3 gestor.py gen --largo 24      # generar una contraseña fuerte
python3 gestor.py check               # revisar TODO el vault contra filtraciones
```

Al agregar una entrada, si dejás la contraseña vacía, genera una fuerte automáticamente.

### Copiar al portapapeles

`copy` pone la contraseña en el portapapeles y la **borra sola a los 20 segundos** (el portapapeles lo puede leer cualquier programa). Necesita `xclip` (o `xsel`/`wl-copy`).

### Revisar filtraciones

`check` recorre todas las contraseñas del vault y chequea cada una contra la base de **HaveIBeenPwned** usando k-anonymity: nunca manda una contraseña, solo los primeros 5 caracteres de su hash. Te dice cuáles están filtradas para que las cambies.

## Seguridad

- El vault se guarda con permisos `600` (solo el dueño puede leerlo).
- Las contraseñas no se escriben en pantalla al tipearlas.
- El generador usa el módulo `secrets` (aleatoriedad criptográficamente segura).

## Roadmap

- [x] v1: vault cifrado, agregar/ver/listar/borrar, generador de contraseñas
- [x] v2: copiar al portapapeles con limpieza automática
- [x] v3: comando `check` (revisar todo el vault contra HaveIBeenPwned)
- [ ] v4: exportar/importar el vault (backup cifrado)
- [ ] v5: código de recuperación al crear el vault
