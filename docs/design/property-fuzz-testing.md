# Camada de testes property-based / fuzz — âmbito

> Estado: proposta de âmbito (2026-05-30). Ainda não implementada.
> Motivada pela campanha de auditoria slices 16-26.

## Porquê

A campanha de auditoria (slices 16-26) encontrou ~21 bugs reais, quatro
dos quais contradiziam diretamente a afirmação principal do Capa
("SBOMs verificáveis por máquina, por construção"). O ponto crítico:
**o teste de paridade tem um ponto cego estrutural.** A paridade só
deteta *divergência entre backends* — não apanha:

- **"Ambos os backends concordam na resposta errada"** (a tradução
  AST→CIR perde semântica que ambos os backends honram fielmente —
  slice 24).
- **Afirmações sobre o que o código *faria*** sob raciocínio de mundo
  fechado (correção do manifesto — slices 18, 21).
- **Sub-divulgação nos exportadores** (o manifesto está certo mas o
  SBOM omite — slice 23).
- **A afirmação do manifesto vs. o comportamento real em runtime**
  (atenuação entre funções no Wasm — slice 25).

Três destes (21, 23, 24) eram invisíveis à paridade *por desenho*.
Nenhuma camada de teste apanharia automaticamente o próximo da mesma
classe. Esta camada fecha esse ponto cego.

## Princípio organizador

Precisamos de **oráculos para além da paridade entre backends**. Quatro
categorias, por tipo de oráculo:

| Cat | Oráculo | Classe de bug que apanha | Custo |
|-----|---------|--------------------------|-------|
| A — Diferencial | os 3 backends concordam entre si | divergência silenciosa (a rede atual, mas com programas gerados) | médio (precisa de gerador) |
| B — Metamórfico / round-trip | propriedade independente do backend | "ambos os backends errados", bugs de parser/formatter/posições | baixo |
| C — Invariante de capability | o runtime instrumentado é a verdade | **incorreção do manifesto — o núcleo regulatório** | alto |
| D — Crash-fuzz | "nunca crasha/pendura, sempre diagnostica ou aceita" | robustez do front-end | muito baixo |

## Fases (ordenadas por ROI)

### Fase 1 — Crash-fuzz do front-end (`tests/test_fuzz.py`)
**O mais barato, robustez imediata. ~1 slice.**

Estratégias `hypothesis`:
- `binary()` e `text()` aleatórios → `Lexer().lex()`.
- Tokens estruturalmente válidos mas aleatoriamente ordenados → `Parser`.
- Corpus de `examples/` + `tests/programs/` mutado byte-a-byte (bit-flips,
  truncagem, duplicação de linhas) → pipeline `lex→parse→analyze`.

**Invariante:** para qualquer input, o pipeline ou (a) produz um
`LexerError`/`ParserError`/erro de análise limpo e posicionado, ou (b)
produz um AST/manifesto válido. **Nunca** uma exceção Python não-capturada,
um hang, ou um trap no wasmtime. (O slice 26 já encontrou um caso destes
manualmente: `${` não-terminado; um fuzzer tê-lo-ia apanhado.)

Sem gerador de programas necessário — é o ponto de partida.

### Fase 2 — Propriedades metamórficas / round-trip (`tests/test_property.py`)
**Apanha "ambos os backends errados". ~1 slice.**

Sobre o corpus existente + variantes levemente mutadas (preservando
validade):
- **Idempotência do formatter:** `fmt(fmt(x)) == fmt(x)`.
- **Round-trip parse/unparse:** `parse(fmt(x))` é AST-equivalente a
  `parse(x)` (módulo posições).
- **Invariante de posições:** para cada token, `source[tok.start:tok.end]
  == tok.text`. (Apanharia bugs de `Pos` que corrompem o campo `pos` do
  manifesto que os reguladores leem.)
- **Mutações que preservam a semântica:** `x + 0 ≡ x`, `if true then A
  else B ≡ A`, renomear um local não muda o output. Dão um oráculo
  *independente dos backends* — se o output mudar, é bug, sem precisar de
  comparar Python vs Wasm.

### Fase 3 — Invariante de soundness de capabilities (`tests/test_property_attenuation.py`, `tests/test_property_manifest.py`)
**A joia regulatória. Apanharia os slices 18, 21, 25 automaticamente. ~2 slices.**

A propriedade central, enunciada precisamente:

> Para qualquer programa gerado P e função f em P: se o manifesto de f
> declara `C ∈ provably_excluded_capabilities`, então executar P nunca
> exerce a capability `C` dentro de f (nem transitivamente via impls de
> user-cap que f alcança).

Mecânica:
1. Instrumentar as classes de capability do runtime
   (`capa/runtime/_capabilities.py`) para registar cada operação
   privilegiada efetivamente executada, atribuída à função chamadora.
2. Gerar programas (gerador nível-gramática — ver Fase 4 para o
   nível-tipo) que passam capabilities por várias funções, atenuam,
   guardam em structs/closures.
3. Executar; afirmar: conjunto-usado(f) ⊆ declared(f), e
   conjunto-usado(f) ∩ provably_excluded(f) = ∅.

Propriedades adjacentes:
- **Monotonia da atenuação:** `restrict(restrict(c, a), b)` nunca tem
  mais autoridade que `restrict(c, a)`. (Verificável diretamente sobre
  os objetos de capability, sem gerar programas.)
- **Identidade do manifesto entre backends:** o manifesto é
  independente do alvo; afirmar byte-idêntico qualquer que seja o
  backend.
- **Conservação no exportador:** todo `transitively_reachable_capability`
  no manifesto aparece como aresta + propriedade no CycloneDX **e** no
  SPDX. (Apanharia o slice 23.)

### Fase 4 — Gerador dirigido-por-tipos + execução diferencial completa (`tests/test_property_wasm_parity.py`)
**O mais difícil; desbloqueia A e C totalmente. ~2-3 slices.**

A peça dura é um **gerador de Capa source bem-tipado** — uma estratégia
`hypothesis` que emite programas que passam o analyzer. Duas camadas:
- **Nível-gramática** (Fase 1/3): emite source sintaticamente válido.
  Mais barato; desbloqueia crash-fuzz e round-trip.
- **Nível-tipo** (esta fase): emite source bem-tipado e analisável —
  essencialmente um gerador de termos restrito por um contexto de tipos.
  Desbloqueia os invariantes de soundness (C) sem desperdiçar 99% dos
  casos em rejeições do analyzer, e a execução diferencial completa
  (gerar → correr nos 3 backends → afirmar stdout idêntico).

Construir incrementalmente: começar com um sub-conjunto (Int/Bool/String,
funções, if/match, uma capability) e alargar tipos um a um.

## Onde isto encaixa

- `hypothesis 6.152.7` já é dependência presente — sem novo requisito.
- Os 5 ficheiros-alvo já existem como placeholders vazios (não no git);
  esta proposta preenche-os por fase.
- Reutilizar os helpers de execução de `tests/test_ir_wasm_parity.py`
  (`_run_python` / `_run_wasm` / `_run_wasm_component` / `_capture_stdout`).
- Reutilizar a API pública: `Lexer`, `Parser`, `analyze`, `transpile`,
  `lower`, `compile_wasm`.

## Não-objetivos

- Não substitui o corpus de paridade escrito à mão — complementa-o
  (regressões nomeadas continuam a ser o registo legível).
- Fase 4 (gerador nível-tipo) é genuinamente várias semanas; não a
  bloquear nas Fases 1-3, que entregam a maior parte do valor de
  robustez e a propriedade de soundness mais cedo.
- Não é um substituto da auditoria humana para *desenho* — apanha
  regressões de *implementação* da classe que a campanha encontrou
  repetidamente, libertando a auditoria humana para questões de desenho.

## Ordem recomendada

1. **Fase 1** (crash-fuzz) — 1 slice, ROI imediato, sem gerador.
2. **Fase 3 propriedades diretas** (monotonia da atenuação, identidade
   do manifesto, conservação no exportador) — meio slice, verificáveis
   sobre o corpus existente sem gerador.
3. **Fase 2** (round-trip/metamórfico) — 1 slice.
4. **Fase 3 invariante de soundness** com gerador nível-gramática —
   2 slices (instrumentação + gerador).
5. **Fase 4** (gerador nível-tipo + diferencial completo) — 2-3 slices,
   incremental por tipo.

Total ~7-8 slices para cobertura completa; as Fases 1-3 (≈3.5 slices)
entregam o ponto cego principal fechado.
