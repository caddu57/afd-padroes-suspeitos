from afd import DFA, Scanner

# O EICAR e montado em partes para o proprio arquivo de teste nao disparar antivirus.
EICAR = (b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$" + b"EICAR-STANDARD-" + b"ANTIVIRUS-TEST-FILE!$H+H*")


def test_classico_aho_corasick():
    dfa = DFA({"he": b"he", "she": b"she", "his": b"his", "hers": b"hers"})
    nomes = sorted(n for n, _ in dfa.scan_bytes(b"ushers"))
    assert nomes == ["he", "hers", "she"]  # 'he' tambem e sufixo de 'she'


def test_sobreposicao():
    dfa = DFA({"aa": b"aa"})
    assert len(dfa.scan_bytes(b"aaaa")) == 3


def test_offset():
    dfa = DFA({"abc": b"abc"})
    assert dfa.scan_bytes(b"xxabc") == [("abc", 4)]


def test_ignore_case():
    dfa = DFA({"p": b"PowerShell"}, ignore_case=True)
    assert dfa.scan_bytes(b"POWERSHELL") and dfa.scan_bytes(b"powershell")


def test_padrao_atravessa_chunks():
    dfa = DFA({"abc": b"abc"})
    assert dfa.scan_chunks([b"xa", b"bc"]) == [("abc", 3)]


def test_afd_total():
    dfa = DFA({"ab": b"ab"})
    assert all(t != -1 for row in dfa.delta for t in row)


def test_eicar_suspeito():
    assert Scanner().scan_bytes(EICAR).suspicious


def test_arquivo_limpo():
    assert not Scanner().scan_bytes(b"echo ola mundo\r\npause\r\n").suspicious


def test_um_indicio_fraco_nao_basta():
    assert not Scanner().scan_bytes(b"set sh = CreateObject(\"WScript.Shell\")").suspicious


def test_dois_indicios_fracos_sao_suspeitos():
    data = b"WScript.Shell ... MSXML2.XMLHTTP"
    assert Scanner().scan_bytes(data).suspicious


def test_scan_file(tmp_path):
    p = tmp_path / "teste.bin"
    p.write_bytes(b"lixo" * 100000 + EICAR)
    assert Scanner().scan_file(str(p)).suspicious


def test_dot():
    assert "digraph AFD" in DFA({"ab": b"ab"}).to_dot()
