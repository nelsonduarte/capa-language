# Índice de registry assinado, design (slice 27, 2026-05-31)

## Problema

O índice de registry (`capa/pkg/_registry.py`) é a **raiz de confiança**
de todo o fluxo `capa add <name>`: fornece a URL git **e** a `verify_key`
(fingerprint GPG) que ancora toda a verificação de assinatura a jusante
(`_verify_signed_pin` em `_install.py`). Auditoria slice 27: o índice em
si não estava assinado nem protegido, fetchado com `http://` permitido,
`CAPA_REGISTRY_URL` env-overridável, e cache em disco confiado por mtime
sem verificação de integridade. Um atacante que faça MITM do índice (ou
escreva o cache, ou ponha a env var) troca URL git + verify_key numa
entrada coerente, e a camada GPG depois "passa" contra a chave do próprio
atacante.

A parte https já foi fechada (`_ALLOWED_INDEX_SCHEMES`). Este doc cobre a
assinatura do índice, que fecha o vetor por completo: mesmo um cache
envenenado ou um mirror comprometido é rejeitado se a assinatura não
verificar contra a chave-raiz embutida no toolchain.

## Modelo de confiança

- **Chave-raiz**: uma fingerprint GPG embutida no código do toolchain
  (`_REGISTRY_ROOT_KEY`). É a única âncora que o atacante não controla,
  vem com o binário do compilador, não com o índice. Rotação =
  release do toolchain (mesma cadência que qualquer constante de
  segurança embutida).
- **Assinatura detached**: o índice é `index.json`; a assinatura é
  `index.json.asc` (armadura ASCII GPG detached), servida ao lado, no
  mesmo diretório/URL. Detached (não embebida) porque: (a) o JSON
  permanece JSON puro, parseável por qualquer tooling sem strip de
  assinatura; (b) reutiliza exatamente o mecanismo `git verify-tag
  --raw` → `VALIDSIG <fpr>` que `_verify_signed_pin` já usa, via
  `gpg --verify`.
- **Verificação**: sobre os **bytes brutos** do índice (antes do parse
  JSON), contra a chave-raiz, exigindo `VALIDSIG` com a fingerprint
  igual a `_REGISTRY_ROOT_KEY`. Mesma lógica de comparação de
  fingerprint completa (40 hex maiúsculas) de `_verify_signed_pin`.

## Estado: ENFORCED (2026-06-01)

A transição completou-se. O `capa-registry` shippa `index.json.asc`
(assinado pela chave-raiz `6C1D222D491FB88031E041A536CFB426101AA24B`),
live em `raw.githubusercontent.com/.../index.json.asc`, e
`_REGISTRY_ROOT_KEY` está preenchida com essa fingerprint. A tabela de
decisão final:

- **Assinatura presente + verifica contra a raiz** → aceitar.
- **Assinatura presente + inválida / chave errada / corrompida** →
  **fail-closed** (`RegistryError`). Uma assinatura má é sinal de
  ataque, nunca aceitável. O opt-out NÃO se aplica aqui.
- **Assinatura ausente**:
  - sem opt-out → **fail-closed** (`RegistryError`). Fecha o
    *downgrade attack*: um atacante que troca o índice também consegue
    remover o `.asc`, logo a ausência é recusada quando o toolchain
    conhece a chave.
  - com `CAPA_REGISTRY_ALLOW_UNSIGNED=1` → **fail-open com aviso**.
    Escape hatch explícito para mirrors air-gapped / self-hosted que
    legitimamente servem um índice não-assinado. Cobre apenas
    assinatura ausente, nunca inválida.
- **gpg ausente do PATH** → **fail-open com aviso**. Limitação de
  ambiente do utilizador, não um vetor controlável pelo atacante de
  rede; degrada em vez de bloquear.
- **chave-raiz vazia** (`_REGISTRY_ROOT_KEY == ""`, só builds pre-1.0)
  → fail-open com aviso.

`file://` segue as mesmas regras. Verificado end-to-end: fetch real do
índice live + assinatura verifica contra a chave-raiz; índice
adulterado / não-assinado / mal-assinado recusado; opt-out resgata só
ausência, nunca assinatura inválida.

## Pontos de aplicação

- `_load_index(url, cache_path)` já é o único caminho de fetch. A
  verificação encaixa logo após obter os bytes brutos do índice
  (rede ou cache) e **antes** do parse/uso. Verificar os bytes
  cacheados também fecha o vetor do cache envenenado: um
  `~/.capa/registry-index.json` escrito por outro processo só é aceite
  se a assinatura cacheada ao lado verificar.
- A assinatura cacheada: guardar `index.json.asc` ao lado do
  `registry-index.json` no cache, escrita junto com ele em
  `_write_cache`. Na leitura do cache, verificar os bytes contra a
  assinatura cacheada.

## Fluxo de publicação (repo capa-registry, separado)

1. Editar `index.json`.
2. `gpg --armor --detach-sign --local-user <ROOT_KEY> index.json`
   → produz `index.json.asc`.
3. Commitar ambos. O `raw.githubusercontent.com/.../index.json` e
   `.../index.json.asc` ficam servidos lado a lado.
4. A fingerprint da chave-raiz é publicada no README do registry E
   embutida em `_REGISTRY_ROOT_KEY` no toolchain (out-of-band: o
   utilizador confia no binário do compilador, não no índice).

## Dependências

Nenhuma nova. Reutiliza `gpg` no PATH (já requerido por
`_verify_signed_pin`). `cryptography` está disponível mas não é
necessária, manter consistência com a abordagem shell-out-to-gpg do
resto do package manager, e o princípio "core compiler dependency-free".

## Testabilidade

`gpg` está skipped em alguns Windows boxes (path mangling MSYS). Os
testes desta feature:
- Geram um keypair efémero num `GNUPGHOME` temporário, assinam um índice
  de teste, verificam aceitação; corrompem a assinatura, verificam
  rejeição. `@skipUnless(gpg disponível)`.
- O caminho fail-open-com-aviso (assinatura ausente) é testável sem gpg:
  só verifica que um índice sem `.asc` produz aviso + sucesso.
- O caminho fail-closed (assinatura presente mas inválida) com uma `.asc`
  lixo é testável sem gpg real se a verificação distinguir "gpg disse
  inválido" de "gpg indisponível", mas a comparação de fingerprint
  precisa de gpg, então marca-se skipUnless para o caminho positivo.

## Não-objetivos

- Não substituir GPG por Sigstore/cosign para o índice (o resto do PM
  usa GPG; manter consistência).
- Não implementar rotação de chave-raiz automática (rotação = release).
- Não assinar entradas individuais do índice (a assinatura do documento
  inteiro cobre todas as entradas; granularidade por-entrada é
  over-engineering para um índice único).
