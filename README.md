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

## Uso

```bash
python3 gestor.py init                # crear el vault (pide master password)
python3 gestor.py add github          # agregar una entrada
python3 gestor.py get github          # ver una entrada
python3 gestor.py list                # listar los nombres guardados
python3 gestor.py delete github       # borrar una entrada
python3 gestor.py gen --largo 24      # generar una contraseña fuerte
```

Al agregar una entrada, si dejás la contraseña vacía, genera una fuerte automáticamente.

## Seguridad

- El vault se guarda con permisos `600` (solo el dueño puede leerlo).
- Las contraseñas no se escriben en pantalla al tipearlas.
- El generador usa el módulo `secrets` (aleatoriedad criptográficamente segura).

## Roadmap

- [x] v1: vault cifrado, agregar/ver/listar/borrar, generador de contraseñas
- [ ] v2: copiar la contraseña al portapapeles y limpiarlo a los 20 segundos
- [ ] v3: exportar/importar el vault (backup cifrado)
- [ ] v4: código de recuperación generado al crear el vault
