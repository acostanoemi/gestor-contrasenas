"""
Tests del gestor de contraseñas.

Cada funcion que empieza con 'test_' es una prueba. Adentro usamos 'assert'
(afirmá que esto es verdad). Se corren todas con:  pytest -v

'tmp_path' es una carpeta temporal que pytest crea y borra sola para cada
test: la usamos para no tocar tu vault real.
"""
import string
import gestor


# ---------- Generador de contraseñas ----------

def test_generar_password_respeta_el_largo():
    assert len(gestor.generar_password(16)) == 16
    assert len(gestor.generar_password(32)) == 32


def test_generar_password_sin_simbolos_solo_letras_y_numeros():
    p = gestor.generar_password(40, con_simbolos=False)
    permitido = string.ascii_letters + string.digits
    assert all(c in permitido for c in p)


def test_dos_passwords_generadas_son_distintas():
    # Siendo aleatorias, dos seguidas no deberían coincidir.
    assert gestor.generar_password(20) != gestor.generar_password(20)


# ---------- Derivación de clave (Scrypt) ----------

def test_derivar_clave_es_determinista():
    # Misma master + misma sal => misma clave (si no, no podrías descifrar).
    sal = b"0123456789abcdef"
    assert gestor.derivar_clave("hola", sal) == gestor.derivar_clave("hola", sal)


def test_derivar_clave_cambia_si_cambia_la_password():
    sal = b"0123456789abcdef"
    assert gestor.derivar_clave("hola", sal) != gestor.derivar_clave("chau", sal)


# ---------- Vault: cifrar y descifrar ----------

def test_vault_guardar_y_recuperar(tmp_path):
    gestor.ARCHIVO_VAULT = str(tmp_path / "vault.dat")
    datos = {"github": {"usuario": "noe", "password": "secreta", "nota": ""}}
    gestor.guardar_vault("master123", datos)
    assert gestor.cargar_vault("master123") == datos


def test_vault_con_password_incorrecta_no_abre(tmp_path):
    gestor.ARCHIVO_VAULT = str(tmp_path / "vault.dat")
    gestor.guardar_vault("correcta", {"a": {"usuario": "x", "password": "y", "nota": ""}})
    # Con la clave equivocada, cargar_vault debe devolver None (no abrir).
    assert gestor.cargar_vault("incorrecta") is None


def test_vault_no_guarda_la_password_en_texto_plano(tmp_path):
    ruta = tmp_path / "vault.dat"
    gestor.ARCHIVO_VAULT = str(ruta)
    gestor.guardar_vault("master123", {"x": {"usuario": "u", "password": "SUPERSECRETA", "nota": ""}})
    crudo = ruta.read_bytes()
    assert b"SUPERSECRETA" not in crudo   # debe estar cifrado, no legible
