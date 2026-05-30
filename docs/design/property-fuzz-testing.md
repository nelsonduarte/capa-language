# Camada de testes property-based / fuzz — âmbito

> Estado: proposta de âmbito (2026-05-30, revista). Motivada pela
> campanha de auditoria slices 16-26.

## Ponto de partida: o que JÁ existe

Correção a uma suposição inicial errada — a infraestrutura não está
em branco. Já existem, com `hypothesis 6.152.7` (dependência presente):

- **`tests/test_properties.py`** — `TestLexerProperties`,
  `TestParserProperties`, `TestFormatterProperties`,
  `TestAnalyzerProperties`, `TestRoundTripProperties`,
  `TestPipelineProperties`.
- **`tests/test_evaluation_fuzz.py`** — `TestProgramGenerator`,
  `TestDifferentialFuzz`, `TestParserFuzz`, `TestManifestFuzz`,
  `TestAttenuationFuzz`, `TestEndToEndFuzz`.

Ou seja: já existe um gerador de programas, fuzz diferencial entre
backends, fuzz do manifesto, e fuzz de atenuação — exatamente as
*categorias* que deveriam ter apanhado os slices 18/21/23/25.

## A pergunta certa

**Se esta infraestrutura existe, porque é que a campanha encontrou ~21
bugs — quatro deles a contradizer a afirmação principal?**

A resposta não é "falta a categoria de teste". É **profundidade**: o
gerador existente não produz as *formas de programa* que dispararam os
bugs. Os bugs da campanha viviam em formas específicas que o gerador
provavelmente não emite:

- **slice 21** (reachability por-impl): precisa de `impl UserCap for
  Struct` onde o struct embrulha uma built-in cap, *passada* a uma
  função que declara só a user-cap. Gerador de termos simples não
  inventa esta cadeia.
- **slice 25** (atenuação entre funções): precisa de `let n =
  cap.restrict_to(x); helper(n)` — a atenuação e a operação privilegiada
  em *funções diferentes*. Fuzz de atenuação intra-função não toca nisto.
- **slice 24** (lambda block-body): precisa de uma lambda com corpo em
  bloco terminando em expressão implícita, com tipo de retorno não-Unit.
- **slice 23** (sub-divulgação no exportador): o oráculo tem de ser o
  *CycloneDX/SPDX*, não a paridade entre backends.

Portanto o âmbito não é "construir do zero" — é **aprofundar o gerador e
adicionar os oráculos em falta**.

## Trabalho, por lacuna concreta (ordenado por ROI)

### Lacuna 1 — Gerador: formas inter-função e cap-embrulhada
**A de maior valor. ~1-2 slices.**

Estender `TestProgramGenerator` para emitir:
- programas multi-função onde caps/valores atravessam fronteiras de
  função (passar cap a helper, devolver de factory);
- `impl UserCap for Struct` com a struct a embrulhar uma built-in cap;
- cadeias `restrict_to(...)` separadas por chamadas de função;
- lambdas com corpo em bloco (expressão tail implícita vs `return`).

Cada uma corresponde diretamente a um bug que escapou. Se o gerador as
tivesse emitido, o fuzz diferencial + de atenuação já existente
tê-las-ia apanhado.

### Lacuna 2 — Oráculo de soundness: runtime instrumentado
**O núcleo regulatório. ~1-2 slices.**

`TestAttenuationFuzz` / `TestManifestFuzz` precisam do oráculo certo:
instrumentar `capa/runtime/_capabilities.py` para registar cada
operação privilegiada realmente executada, atribuída à função
chamadora. Depois a propriedade:

> Para qualquer programa gerado P e função f: se o manifesto de f diz
> `C ∈ provably_excluded_capabilities`, executar P nunca exerce `C`
> dentro de f (nem transitivamente via impls de user-cap alcançadas).

Sem esta instrumentação, o fuzz de atenuação só consegue verificar
"deny vs allow" em casos que o gerador conhece — não a invariante
universal. Combinada com a Lacuna 1, esta teria apanhado o slice 25
automaticamente.

### Lacuna 3 — Oráculo de exportador
**~0.5 slice.**

Propriedade independente de backend: todo
`transitively_reachable_capability` no manifesto aparece como aresta
**e** propriedade no CycloneDX **e** no SPDX; todo
`provably_excluded_capability` aparece como a anotação negativa
correspondente. (Apanharia o slice 23.) Verificável sobre o corpus
existente + programas gerados, sem novo oráculo de runtime.

### Lacuna 4 — Oráculos metamórficos (independentes de backend)
**~1 slice. Apanha "ambos os backends errados".**

Sobre o corpus + variantes geradas:
- idempotência do formatter: `fmt(fmt(x)) == fmt(x)` (pode já estar em
  `TestFormatterProperties` — verificar antes de duplicar);
- invariante de posições: `source[tok.start:tok.end] == tok.text` para
  cada token (protege o campo `pos` do manifesto que os reguladores
  leem);
- mutações que preservam semântica: `x + 0 ≡ x`, renomear local não
  muda output — oráculo sem precisar de comparar backends.

### Lacuna 5 — Robustez do gerador nível-tipo
**O peão pesado; várias semanas. Incremental.**

O gerador atual emite *algum* subconjunto bem-tipado. Alargá-lo tipo a
tipo (genéricos, sum types com payloads mistos, closures que capturam
caps, structs aninhadas) aumenta a fração do espaço de programas
coberto. Não bloquear as Lacunas 1-4 nisto.

## Onde encaixa

- `hypothesis` já é dependência (`pyproject.toml [test]`).
- Reutilizar helpers de `tests/test_ir_wasm_parity.py` (`_run_python`,
  `_run_wasm`, `_run_wasm_component`, `_capture_stdout`).
- Reutilizar API pública: `Lexer`, `Parser`, `analyze`, `transpile`,
  `format_source`, `is_formatted`, e `capa.ir.lower` / `compile_wasm`.
- Estender os ficheiros existentes, não criar paralelos.

## Não-objetivos

- Não substitui o corpus de paridade escrito à mão nem a auditoria
  humana de *desenho* — apanha regressões de *implementação* da classe
  que a campanha encontrou repetidamente.
- Lacuna 5 (gerador nível-tipo completo) é multi-semana; as Lacunas
  1-4 (~4 slices) fecham o ponto cego que a campanha expôs.

## Ordem recomendada

1. **Lacuna 1** (gerador: formas inter-função + cap-embrulhada) —
   maior alavancagem; sozinha torna os fuzzers existentes capazes de
   reencontrar slices 21/24/25.
2. **Lacuna 2** (oráculo de runtime instrumentado) — fecha a invariante
   de soundness universal.
3. **Lacuna 3** (oráculo de exportador) — barato, fecha slice 23.
4. **Lacuna 4** (metamórficos) — fecha "ambos errados".
5. **Lacuna 5** (gerador nível-tipo) — incremental, contínuo.

Antes de cada lacuna: **ler a classe existente correspondente** e
estendê-la, em vez de assumir que está vazia (lição desta própria
revisão de âmbito).
