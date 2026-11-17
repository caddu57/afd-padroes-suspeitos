# AFD – Identificação de padrões suspeitos em arquivos

Ferramenta em linha de comando que usa um **Autômato Finito Determinístico** para
dizer se um arquivo é suspeito. Projeto da disciplina de Teoria da Computação.

## Uso

```bash
python -m afd arquivo.bat            # LIMPO (exit 0) / SUSPEITO (exit 1)
python -m afd arquivo.vbs -v         # lista os padrões encontrados
python -m afd --dot afd.dot --fail   # exporta o AFD p/ Graphviz
dot -Tpng afd.dot -o afd.png
pytest                               # roda os testes
```

## Como funciona

1. `signatures.py` define os padrões (bytes). Padrão **forte** (ex.: EICAR) basta
   sozinho; padrões **fracos** só marcam suspeito se ≥ 2 distintos aparecerem
   (reduz falsos positivos).
2. `dfa.py` constrói a trie de todos os padrões e, por BFS, completa a função de
   transição δ(q, a) para todo estado e símbolo (transições de retorno por
   sufixo). Resultado: AFD **total**, 1 transição por byte, tempo O(n).
   M = (Q, Σ={0..255}, δ, q0=0, F={q | out[q] ≠ ∅}).
3. `scanner.py` usa dois AFDs (case-sensitive e case-insensitive), lê o arquivo
   em blocos de 64 KB (o estado é mantido entre blocos) e dá o veredito.

## Estrutura

```
afd/            dfa.py  signatures.py  scanner.py  cli.py
tests/          test_afd.py
```

## Segurança

Não manipule malware real. Use o arquivo EICAR (inofensivo) e scripts simulados.
O antivírus pode apagar arquivos EICAR do disco; nos testes ele é montado em
memória.
