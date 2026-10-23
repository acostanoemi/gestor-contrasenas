#!/usr/bin/env python3
"""
Gestor de contraseñas (password manager) - v1  [CLI, local, zero-knowledge]

Guarda tus contraseñas cifradas en un unico archivo (vault.dat) protegido por
una master password. Todo se cifra y descifra en tu maquina; la master
password nunca se guarda en ningun lado.

Como funciona la cripto:
  - De la master password se DERIVA una clave con Scrypt (lento a proposito:
    encarece el fuerza bruta). Scrypt usa la password + una "sal" aleatoria.
  - Con esa clave se cifra el vault con Fernet (cifrado + verificacion de
    integridad: si tocan el archivo, se detecta).
  - El archivo solo guarda: la sal + el bloque cifrado. Sin la master
    password, es ilegible.

IMPORTANTE: si olvidás la master password, se perdió el vault. No hay
recuperacion: esa es justamente la prueba de que esta bien cifrado.

Requisitos: python3 y la libreria 'cryptography'
    sudo apt install python3-cryptography

Uso:
    python3 gestor.py init                    # crear el vault
    python3 gestor.py add github              # agregar una entrada
    python3 gestor.py get github              # ver una entrada
    python3 gestor.py list                    # listar los nombres guardados
    python3 gestor.py delete github           # borrar una entrada
    python3 gestor.py gen                      # generar una contraseña fuerte
"""

import os
import sys
import json
import base64
import secrets
import string
import getpass
import argparse

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

ARCHIVO_VAULT = "vault.dat"
LARGO_SAL = 16


# ---------- Cripto ----------

def derivar_clave(master, sal):
    """
    De la master password + la sal, deriva la clave de cifrado con Scrypt.
    Scrypt es lento y usa memoria a proposito: hace carisimo probar millones
    de passwords por fuerza bruta.
    """
    kdf = Scrypt(salt=sal, length=32, n=2**14, r=8, p=1)
    clave = kdf.derive(master.encode())
    # Fernet necesita la clave en base64 url-safe
    return base64.urlsafe_b64encode(clave)


def cargar_vault(master):
    """Abre y descifra el vault. Devuelve el dict de entradas, o None si la
    master password es incorrecta."""
    with open(ARCHIVO_VAULT, "rb") as f:
        datos = f.read()
    sal, cifrado = datos[:LARGO_SAL], datos[LARGO_SAL:]
    fernet = Fernet(derivar_clave(master, sal))
    try:
        claro = fernet.decrypt(cifrado)
    except InvalidToken:
        return None          # master password incorrecta (o archivo corrupto)
    return json.loads(claro.decode())


def guardar_vault(master, entradas, sal=None):
    """Cifra las entradas y las escribe al archivo. Reusa la sal si ya existe."""
    if sal is None:
        sal = secrets.token_bytes(LARGO_SAL)
    fernet = Fernet(derivar_clave(master, sal))
    cifrado = fernet.encrypt(json.dumps(entradas).encode())
    with open(ARCHIVO_VAULT, "wb") as f:
        f.write(sal + cifrado)
    # Permisos: solo el dueño puede leer/escribir el archivo
    os.chmod(ARCHIVO_VAULT, 0o600)


def leer_sal():
    """Lee la sal del archivo existente (los primeros bytes)."""
    with open(ARCHIVO_VAULT, "rb") as f:
        return f.read(LARGO_SAL)


# ---------- Generador de contraseñas ----------

def generar_password(largo=20, con_simbolos=True):
    """Genera una contraseña aleatoria fuerte usando 'secrets' (seguro)."""
    alfabeto = string.ascii_letters + string.digits
    if con_simbolos:
        alfabeto += "!@#$%^&*()-_=+[]"
    return "".join(secrets.choice(alfabeto) for _ in range(largo))


# ---------- Helpers de interaccion ----------

def pedir_master(confirmar=False):
    """Pide la master password sin mostrarla en pantalla."""
    m = getpass.getpass("Master password: ")
    if confirmar:
        m2 = getpass.getpass("Repetir master password: ")
        if m != m2:
            print("No coinciden.")
            sys.exit(1)
    return m


def abrir_o_salir():
    """Pide la master, abre el vault y devuelve (master, sal, entradas).
    Sale si la password es incorrecta."""
    if not os.path.exists(ARCHIVO_VAULT):
        print("No hay vault todavia. Creá uno con: python3 gestor.py init")
        sys.exit(1)
    master = pedir_master()
    entradas = cargar_vault(master)
    if entradas is None:
        print("Master password incorrecta.")
        sys.exit(1)
    return master, leer_sal(), entradas


# ---------- Comandos ----------

def cmd_init(args):
    if os.path.exists(ARCHIVO_VAULT):
        print(f"Ya existe un vault ({ARCHIVO_VAULT}). Borralo a mano si querés uno nuevo.")
        return
    print("Creá tu master password. OJO: si la olvidás, se pierde todo el vault.")
    master = pedir_master(confirmar=True)
    guardar_vault(master, {})
    print(f"Vault creado en {ARCHIVO_VAULT}.")


def cmd_add(args):
    master, sal, entradas = abrir_o_salir()
    nombre = args.nombre
    if nombre in entradas and input(f"'{nombre}' ya existe. ¿Sobrescribir? (si/no): ").strip().lower() != "si":
        print("Cancelado.")
        return
    usuario = input("  Usuario: ")
    print("  Contraseña: (dejá vacio para generar una fuerte)")
    passw = getpass.getpass("  > ")
    if not passw:
        passw = generar_password()
        print(f"  Generada: {passw}")
    nota = input("  Nota (opcional): ")
    entradas[nombre] = {"usuario": usuario, "password": passw, "nota": nota}
    guardar_vault(master, entradas, sal)
    print(f"Guardado '{nombre}'.")


def cmd_get(args):
    _, _, entradas = abrir_o_salir()
    e = entradas.get(args.nombre)
    if not e:
        print(f"No existe '{args.nombre}'. Mirá la lista con: python3 gestor.py list")
        return
    print(f"\n  {args.nombre}")
    print(f"    Usuario:    {e['usuario']}")
    print(f"    Contraseña: {e['password']}")
    if e.get("nota"):
        print(f"    Nota:       {e['nota']}")


def cmd_list(args):
    _, _, entradas = abrir_o_salir()
    if not entradas:
        print("El vault esta vacio.")
        return
    print(f"\n{len(entradas)} entrada(s):")
    for nombre in sorted(entradas):
        print(f"  - {nombre}")


def cmd_delete(args):
    master, sal, entradas = abrir_o_salir()
    if args.nombre not in entradas:
        print(f"No existe '{args.nombre}'.")
        return
    if input(f"¿Borrar '{args.nombre}'? (si/no): ").strip().lower() == "si":
        del entradas[args.nombre]
        guardar_vault(master, entradas, sal)
        print(f"Borrado '{args.nombre}'.")
    else:
        print("Cancelado.")


def cmd_gen(args):
    print(generar_password(args.largo, not args.sin_simbolos))


def main():
    p = argparse.ArgumentParser(description="Gestor de contraseñas cifrado (CLI, local).")
    sub = p.add_subparsers(dest="comando", required=True)

    sub.add_parser("init", help="crear el vault")

    pa = sub.add_parser("add", help="agregar una entrada")
    pa.add_argument("nombre", help="nombre de la entrada, ej: github")

    pg = sub.add_parser("get", help="ver una entrada")
    pg.add_argument("nombre")

    sub.add_parser("list", help="listar los nombres guardados")

    pd = sub.add_parser("delete", help="borrar una entrada")
    pd.add_argument("nombre")

    pgen = sub.add_parser("gen", help="generar una contraseña fuerte")
    pgen.add_argument("--largo", type=int, default=20, help="largo (default: 20)")
    pgen.add_argument("--sin-simbolos", action="store_true", help="solo letras y numeros")

    args = p.parse_args()
    comandos = {
        "init": cmd_init, "add": cmd_add, "get": cmd_get,
        "list": cmd_list, "delete": cmd_delete, "gen": cmd_gen,
    }
    comandos[args.comando](args)


if __name__ == "__main__":
    main()
