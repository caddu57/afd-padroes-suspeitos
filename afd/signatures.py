"""Base de assinaturas simbolicas (didatica, para arquivos de teste simulados).

strong=True  -> um unico achado ja torna o arquivo suspeito (ex.: EICAR).
strong=False -> indicio fraco; so conta como suspeito com >= WEAK_THRESHOLD
                indicios fracos distintos (reduz falsos positivos).
"""
from dataclasses import dataclass
from typing import List

WEAK_THRESHOLD = 2


@dataclass(frozen=True)
class Signature:
    name: str
    pattern: bytes
    nocase: bool = False
    strong: bool = False
    description: str = ""


SIGNATURES: List[Signature] = [
    # Arquivo de teste padrao da industria (inofensivo)
    Signature("EICAR-Test-File", b"EICAR-STANDARD-ANTIVIRUS-TEST-FILE",
              strong=True, description="Assinatura do arquivo de teste EICAR"),

    # Scripts .bat / PowerShell
    Signature("BAT-PowerShell-Encoded", b"powershell -enc", nocase=True,
              description="PowerShell com comando codificado"),
    Signature("BAT-PowerShell-NoProfile", b"powershell -nop", nocase=True,
              description="PowerShell sem perfil"),
    Signature("BAT-Certutil-Download", b"certutil -urlcache", nocase=True,
              description="Download via certutil"),
    Signature("BAT-Bitsadmin-Transfer", b"bitsadmin /transfer", nocase=True,
              description="Download via bitsadmin"),
    Signature("BAT-Registry-Run", b"currentversion\\run", nocase=True,
              description="Persistencia via chave Run do registro"),

    # Scripts .vbs
    Signature("VBS-WScript-Shell", b"wscript.shell", nocase=True,
              description="Objeto WScript.Shell"),
    Signature("VBS-XMLHTTP", b"msxml2.xmlhttp", nocase=True,
              description="Requisicao HTTP em VBScript"),
    Signature("VBS-ADODB-Stream", b"adodb.stream", nocase=True,
              description="Gravacao de binario em disco via ADODB.Stream"),

    # Binarios (strings de API frequentemente usadas em injecao de codigo)
    Signature("BIN-WriteProcessMemory", b"WriteProcessMemory",
              description="API de injecao de codigo"),
    Signature("BIN-CreateRemoteThread", b"CreateRemoteThread",
              description="API de injecao de codigo"),
]
