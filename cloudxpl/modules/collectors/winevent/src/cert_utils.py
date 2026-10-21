"""
Utilitários para certificados: resolver chave privada com senha (descriptografar para arquivo temporário).
A senha da chave é opcional: só é necessária quando o .key/.pem está criptografado.
"""
import os
import tempfile
from typing import Optional, Tuple


def resolve_client_key_path(
    key_pem_path: str,
    password: Optional[str] = None,
) -> Tuple[str, Optional[str]]:
    """
    Retorna (path_para_usar, path_temp_a_remover).
    Se password for informado e a chave estiver criptografada, descriptografa e grava em arquivo
    temporário (restrito ao usuário); path_temp_a_remover será esse path para o caller apagar depois.
    Se password for None ou chave não criptografada, retorna (key_pem_path, None).
    """
    if not key_pem_path or not os.path.isfile(key_pem_path):
        return (key_pem_path, None)
    if not password:
        return (key_pem_path, None)
    try:
        from cryptography.hazmat.primitives.serialization import (
            load_pem_private_key,
            Encoding,
            PrivateFormat,
            NoEncryption,
        )
    except ImportError:
        raise RuntimeError(
            "Chave criptografada exige 'cryptography'. Instale: pip install cryptography"
        )
    with open(key_pem_path, "rb") as f:
        key_data = f.read()
    try:
        key = load_pem_private_key(key_data, password=None)
    except Exception:
        pass
    else:
        return (key_pem_path, None)
    key = load_pem_private_key(key_data, password=password.encode("utf-8"))
    decrypted = key.private_bytes(
        Encoding.PEM, PrivateFormat.TraditionalOpenSSL, NoEncryption()
    )
    fd, temp_path = tempfile.mkstemp(suffix=".pem", prefix="wincollect_key_")
    try:
        os.write(fd, decrypted)
        os.close(fd)
        os.chmod(temp_path, 0o600)
    except Exception:
        os.close(fd)
        try:
            os.unlink(temp_path)
        except Exception:
            pass
        raise
    return (temp_path, temp_path)
