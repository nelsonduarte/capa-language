# Plano técnico detalhado das fases

> Estado: design técnico (2026-06-01). Companion de
> `roadmap-security-performance.md`. Cada fase ancora em pontos de
> integração REAIS do código (file:line verificados), na sequência
> recomendada: P1 → S1 → P3 → S2 → P2 → S4 → S3.

---

## P1 — Wasm AOT (`capa build --release`) — FEITO (2026-06-01)

**Estado:** implementado. `capa build --release` + `capa run-aot`,
container `capa/runtime/_aot.py`, `WasmHost.run_main_aot`, 12 testes
em `tests/test_aot.py`. Notas de implementação face ao desenho abaixo:
(1) os param-names do main TÊM de ser capturados no header do
container — o `.cwasm` serializado perde a name section (confirmado:
`'net'` não aparece nos bytes serializados); (2) `load_aot` recebe o
engine do host porque o wasmtime recusa cross-Engine instantiation;
(3) ganho de module-load ~1.3x num módulo trivial (escala com o
tamanho), wall-clock dominado pelo arranque do Python — a P1.2(b)
launcher Rust removeria esse piso, deferida.

**Objetivo:** binário standalone de performance near-native, sem
escrever backend novo. Reaproveita 100% do pipeline Wasm auditado.

### Estado atual (verificado)
- `compile_wasm(module, types, ...) -> bytes`
  (`capa/ir/__init__.py:274`) já produz um `.wasm` binário: gera WAT
  via `compile_wat`, depois faz shell para `wasm-tools parse -`.
- `--output` escreve o blob para disco
  (`capa/cli.py:1049`, `Path(args.output).write_bytes(blob)`).
- `--run` instancia via `WasmHost.run_main`
  (`capa/cli.py:1088`; host em `capa/runtime/_wasm_host.py:54`), que
  usa o package Python `wasmtime` (`wasmtime.Engine/Store/Linker`).
- `_wasm_tooling_available()` (`capa/cli.py:71`) já testa
  `wasm-tools` no PATH + `wasmtime` importável.

### O gap
`--run` instancia e corre no *interpretador/JIT do wasmtime via Python*
em cada execução. Não há artefacto AOT pré-compilado; cada run paga
parse + compile do módulo. Falta um caminho "compila uma vez, corre
muitas, a velocidade Cranelift".

### Desenho

**P1.1 — `capa build --release <file> -o <out>` (novo dispatcher).**
Novo `_dispatch_build` em `capa/cli.py`, ao lado de `_dispatch_init`
etc. (o padrão de dispatch já existe em `main()`,
`capa/cli.py:468+`). Passos:
1. `compile_wasm(...)` → blob (já existe).
2. `wasmtime.Module(engine, blob).serialize()` → bytes AOT
   (Cranelift-compiled, `.cwasm`). O package `wasmtime` Python expõe
   `Module.serialize()` / `Module.deserialize()`; é a API AOT do
   wasmtime sem precisar do CLI `wasmtime` separado.
3. Escrever o `.cwasm` + um pequeno *launcher* (ver P1.2).

**P1.2 — Launcher / runtime embarcado.** O `.cwasm` precisa do
`WasmHost` (as host bridges das capabilities) para correr. Duas
opções, por ordem de esforço:
- **(a) Launcher Python fino** (~1 slice): um script/entry-point que
  faz `Module.deserialize()` + `WasmHost(...).run_main_precompiled()`.
  `run_main` (`_wasm_host.py:2048`) já faz quase tudo; adicionar um
  `run_main_precompiled(cwasm_bytes)` que usa `Module.deserialize`
  em vez de `wasmtime.Module(engine, blob)`. Distribuível via
  PyInstaller (já no projeto, ver memória de packaging).
- **(b) Launcher Rust standalone** (~3-4 slices, defer): embute o
  wasmtime crate + reimplementa as host bridges em Rust. Performance
  máxima, zero dependência Python, mas duplica ~1600 LOC de bridges
  (`_wasm_host.py`). Só fazer se (a) provar insuficiente.

**Recomendação:** P1.2(a) primeiro. Mede-se o ganho real
(deserialize evita o re-compile; Cranelift já estava lá no JIT, mas o
AOT remove o custo de arranque). Se o arranque Python dominar para
CLIs curtos, P1.2(b).

### Verificação
- Novo `capa build --release` produz `.cwasm` que corre com output
  idêntico ao `--run` (reusar o harness de paridade
  `tests/test_ir_wasm_parity.py`).
- Benchmark: medir `--run` (JIT) vs `.cwasm` (AOT) em 3 programas
  (CPU-bound, alloc-heavy, IO-heavy). Documentar os números — a tese
  precisa de um número real, não "near-native" hand-wave.

### Riscos
- `Module.serialize()` é específico da versão do wasmtime; o `.cwasm`
  não é portável entre versões. Documentar + versionar o header.
- As host bridges não mudam, mas o launcher tem de as registar na
  mesma ordem (a slice 25.8 mostrou como `_TracingWasmHost` ficou
  stale ao copiar parcialmente o `__init__` — o launcher deve chamar
  o setup real, não re-implementá-lo).

---

## S1 — Linear handles / must-call types

**Objetivo:** tipos de utilizador que TÊM de ser consumidos (ficheiro
fechado, transação resolvida). Fecha resource leaks; fundação para S3.

### Estado atual (verificado)
A maquinaria de linearidade JÁ existe, mas só para capabilities:
- `consume` num param: `Param.consuming: bool`
  (`capa/capa_ast/_items.py:126`).
- Marcação de consumo: `_mark_consumed_args`
  (`capa/analyzer/_discipline.py:27-73`) → `self._consumed.add(path)`.
- Enforcement no-use-after-consume: `_check_ident`
  (`capa/analyzer/_expressions.py:456-461`).
- O `self._consumed: set[str]` é reset por-função
  (`capa/analyzer/__init__.py:297`), com fork/merge em branches
  (snapshot antes, união conservadora depois) — exatamente a
  semântica que linear handles precisam.
- `Symbol.consuming_params: list[bool]`
  (`capa/analyzer/_declarations.py:227`) propaga para call sites.

### O gap
A linearidade atual é uma *propriedade da capability* (uma cap pode
ser consumida), não uma *obrigação do tipo* (este tipo TEM de ser
consumido antes de a função retornar). Falta:
1. Marcar um tipo como linear/must-use.
2. Verificar que um valor linear NÃO é descartado (o oposto de
   use-after-consume: é *non-use* que é o erro).

### Desenho

**S1.1 — Sintaxe + AST.** Um qualificador `linear` num `type`:
```
linear type FileHandle { fd: Int }
```
Adicionar `is_linear: bool` ao `TypeStruct` AST
(`capa/capa_ast/_items.py`, ao lado de `is_pub`). O parser de items
(`capa/parser/_items.py`) reconhece o keyword antes de `type`.

**S1.2 — Modelo de analyzer.** Marcar o `Symbol` do tipo com
`is_linear`. Quando um valor de tipo linear é criado (struct literal,
ou retorno de uma função que produz um), entra num conjunto novo
`self._live_linear: dict[name, Pos]` (paralelo ao `self._consumed`,
mesma mecânica de fork/merge em branches —
`capa/analyzer/__init__.py:297` mostra o padrão).

**S1.3 — Enforcement (a inovação face ao consume existente).** O
consume existente erra em *use após consumir*. Linear handles erram
em *não-consumir antes de sair de scope*:
- No fim de cada função / bloco, `self._live_linear` tem de estar
  vazio (todo o valor linear foi consumido — passado a um
  `consume`-param, ou explicitamente libertado via um método marcado
  `consumes self`).
- Erro novo via `self._err(...)`
  (`capa/analyzer/__init__.py:361`, mesma convenção):
  `f"linear value {name!r} of type {ty!r} is dropped without being
  consumed; it must be passed to a consuming function (e.g. close())
  before it goes out of scope"`.
- Reaproveitar fork/merge: um valor consumido num ramo de `if` mas
  não no outro é um erro (a união conservadora já existe para o
  caso simétrico).

**S1.4 — Surface no SBOM.** Novo campo no function record
(`capa/manifest/_funrec.py:333-348`, onde estão as 12 chaves):
`"linear_obligations": [...]` — "esta função recebe/produz handles
lineares que tem de libertar; estes são". Param-level: adicionar
`"is_linear"` ao param record (`_funrec.py:212-217`, ao lado de
`is_capability`).

### Verificação
- Property-test: gerar programas com handles lineares
  consumidos/não-consumidos; o analyzer aceita os primeiros, recusa
  os segundos (estender `tests/test_properties.py`, que já tem
  geradores de programas com caps).
- Reproduzir o bug-class concreto: um ficheiro aberto e nunca
  fechado → erro de compilação.

### Riscos
- Interação com closures: um valor linear capturado numa closure que
  pode ser chamada N vezes não pode ser consumido lá (o
  `_discipline.py:65-71` já tem o erro análogo para caps consumidas
  em closures — reaproveitar o raciocínio).
- Retorno de valores lineares: uma função pode *devolver* um handle
  linear (transferindo a obrigação ao chamador). O `_live_linear` tem
  de tratar `return x` como "consome x" (transfere, não dropa).

---

## S2 — Information Flow Control (a aposta de unicidade)

**Objetivo:** provar para onde os dados podem fluir, não só que efeitos
uma função exerce. `usado ∩ provably_excluded = ∅` é sobre autoridade;
IFC é sobre `secret nunca alcança sink public sem declassify`.

### Estado atual (verificado)
- Não existe nada de IFC. Mas a infraestrutura de *propagação de
  factos por expressão* existe: o analyzer já caminha cada expressão
  (`_check_ident`, `_check_expr` em `capa/analyzer/_expressions.py`) e
  já tem `result.bindings.get(id(ident))` ligando cada uso ao seu
  símbolo (usado pelo manifesto e LSP).
- O `_resolve_type` (`capa/analyzer/_declarations.py:385`) é onde
  qualificadores de tipo viram factos.
- A convenção de erro `_err` (`capa/analyzer/__init__.py:361`) e o
  fork/merge de branches (`self._consumed`) são os mesmos padrões que
  o IFC precisa para propagar labels.

### Desenho (explicit IFC, lattice pequena, declassify auditável)

**S2.1 — Lattice mínima.** Dois níveis para v1: `@public` (default,
implícito) e `@secret`. Ordem: `public ⊑ secret` (secret é mais
restrito). NÃO labels de princípios arbitrárias (lição da Pony:
poder a mais mata ergonomia). v2 pode acrescentar níveis
intermédios.

**S2.2 — Sintaxe + AST.** Label num tipo ou param:
```
fun handler(token: @secret String, net: Net) -> Result<Unit, IoError>
```
Adicionar `label: Optional[SecurityLabel]` ao `TypeExpr`/`Param`
(`capa/capa_ast/_types.py`, `_items.py`). Parser de tipos
(`capa/parser/_types.py`) reconhece `@secret`/`@public` antes do tipo.

**S2.3 — Propagação de labels (o núcleo).** Estender o walk de
expressões (`capa/analyzer/_expressions.py`) para computar o label de
cada expressão:
- Literal → `public`.
- Ident → label do seu símbolo (de `result.bindings`).
- Operação binária / chamada → join (lattice ⊔) dos labels dos
  operandos/args. `secret + public = secret`.
- Field access numa struct → label do campo (structs podem ter campos
  labelados).
- Manter um `self._expr_label: dict[id(expr), Label]` paralelo aos
  `bindings` existentes.

**S2.4 — Sinks e enforcement.** Definir os *sinks public*: parâmetros
de métodos de capability que saem do programa —
`stdio.println(x)`, `net.post(url, body)`, `net.get(url)`,
`fs.write(path, content)`. Quando um argumento `@secret` chega a um
sink que exige `@public`:
```
self._err(
    f"information-flow violation: secret value reaches {sink!r} "
    f"(a public sink); route it through declassify(..., reason=...) "
    f"if this disclosure is intended",
    pos,
)
```
A lista de sinks vive ao lado de `CAPABILITY_NAMES` / da definição de
métodos de cap (já há um sítio canónico — o builtins/typesys).

**S2.5 — Declassify (a inovação regulatória).** Um builtin
`declassify(value: @secret T, reason: String) -> @public T` — o ÚNICO
ponto onde secret→public é permitido. Cada chamada:
- É verificada (tem de ter um `reason` literal não-vazio).
- Aparece no SBOM: novo campo no function record
  (`capa/manifest/_funrec.py:333`):
  `"declassification_sites": [{"pos": ..., "reason": ...}]`. Isto é o
  diferenciador — o SBOM passa a dizer "esta função desclassifica
  dados secretos nestes N pontos, por estas razões", algo que
  NENHUMA ferramenta mainstream produz.

**S2.6 — Roll-out warn-then-enforce** (lição da slice 27): primeiro o
analyzer *avisa* sobre fluxos secret→sink não-declassificados (não
quebra programas existentes, que não têm labels); quando o ecossistema
adotar labels, fail-closed. Um flag/atributo opt-in
(`@strict_ifc`) por módulo durante a transição.

### Verificação
- Property-test da invariante de noninterferência: gerar programas
  com dados `@secret` e sinks; o analyzer recusa fluxo direto, aceita
  fluxo via `declassify`. Estender `tests/test_properties.py`.
- O caso headline dos CVE studies: um agente LLM que lê um segredo
  (`env.get("API_KEY")` labelado `@secret`) e tenta `net.post`-á-lo →
  erro de compilação a menos que declassificado.
- Mutation-check (como nas slices 23/27): remover a verificação de
  sink faz o teste falhar.

### Riscos (este é o arco mais difícil, ~8-12 slices)
- **Label inference vs explicit**: começar explicit. Inferência
  (computar labels sem anotação) é um arco próprio; defer a v2.
- **Implicit flows**: `if secret > 0 { public_log("hit") }` vaza um
  bit via control flow. v1 pode cobrir só *explicit flows* (dados que
  fluem por atribuição/chamada) e documentar honestamente que
  implicit flows não são cobertos — é a fronteira clássica IFC, e
  over-claiming aqui seria o tipo de bug que a campanha de auditoria
  encontrou. Honestidade: o SBOM diz "explicit-flow IFC", não "IFC".
- **Interação com capabilities**: um valor `@secret` passado a uma
  capability já declarada — os dois sistemas são ortogonais (um sobre
  autoridade, outro sobre fluxo) mas o SBOM tem de os apresentar
  coerentemente.
- **Containers**: `List<@secret String>` — o label propaga pelo
  container. v1 pode exigir o label no elemento e propagar
  conservadoramente (todo o container vira secret se um elemento for).

---

## P2 — GC real via Wasm GC proposal

**Objetivo:** substituir o bump allocator que vaza em processos de
longa duração.

### Estado atual (verificado)
- Bump allocator `$alloc(size) -> i32`
  (`capa/ir/_emit_wasm/_runtime.py:870`): devolve `heap_top`, alinha a
  8, avança; `memory.grow` quando cruza a página; `unreachable` se o
  host recusar. **Sem free, sem GC.**
- Memória linear declarada em
  `capa/ir/_emit_wasm/__init__.py:438`:
  `(memory (export "memory") 1 {cap_pages})`, default 256 pages
  (16 MiB, `MEMORY_CAP_DEFAULT_PAGES`).
- Tudo (structs, listas, strings, closures) aloca via `$alloc` em
  memória linear, manipulado por ponteiros i32.

### O gap
Run curto de CLI: fine (processo morre, OS recupera). Serviço de longa
duração: cada alocação é permanente até `unreachable` no cap. Inviável
para servidores.

### Desenho

**P2.1 — Avaliar o Wasm GC proposal.** O wasmtime já suporta o GC
proposal (structs/arrays geridos pelo runtime, `ref`/`struct.new`/
`array.new`). Reaproveita a estratégia "dobrar no Wasm" do P1.
Trade-off: o modelo de memória muda de "tudo i32 em linear memory"
para "valores geridos são `ref`". Isto é uma reescrita do layout
(`capa/ir/_emit_wasm/_layout.py`, `_structs.py`, `_lists.py`), não
incremental.

**P2.2 — Faseamento.** Demasiado grande para uma slice. Sequência:
1. Manter o bump allocator como default; adicionar um modo GC opt-in
   (`capa build --gc`) que emite o GC proposal para os tipos heap.
2. Migrar tipo a tipo (structs primeiro, depois listas, depois
   strings/closures) — cada um com o harness de paridade a confirmar
   output idêntico. Mesma disciplina das slices 25.2-25.7 (uma cap de
   cada vez).
3. Quando estável e medido, virar default.

**Alternativa mais barata (se o GC proposal provar difícil):**
reference counting no runtime emitido — um refcount i32 no header de
cada objeto, `$retain`/`$release` emitidos nos pontos de
cópia/drop (o `_live_linear` de S1 dá os pontos de drop de borla).
Não apanha ciclos, mas a maioria do código Capa não os cria (sem
mutabilidade partilhada arbitrária). Mais simples que GC tracing, e
S1 fá-lo quase de graça para os tipos lineares.

**Recomendação:** medir primeiro (P1 dá o harness de benchmark). Se o
working-set típico cabe no cap de 16 MiB para os casos de uso reais,
P2 pode esperar. Não fazer GC por purismo — fazer quando um caso de
uso de longa duração o exigir.

### Riscos
- O GC proposal muda o ABI do heap; toca em todos os ficheiros de
  `_emit_wasm/` que assumem ponteiros i32. É o maior risco de
  regressão de todo o plano — daí o faseamento opt-in.
- A Component Model (slice 25.8) interage com GC; verificar paridade
  nos dois hosts.

---

## Fases menores (resumo técnico)

- **P3 (otimizações lowerer):** dedup de closures lifted, constant-fold
  IR (fecha o resíduo slice 26: literal 2^63 não-negado), DCE. Cada
  passe contra o harness de paridade. Baixo risco, contínuo.
- **P4 (TCO):** lowrar chamadas em posição de cauda para `return_call`
  (Wasm tail-call proposal, estável). Detetar tail position no lowerer
  (`capa/ir/_lower_*`), emitir `return_call` em vez de `call`+`return`.
- **S4 (constant-time):** qualificador `@constant_time` numa função; o
  analyzer recusa branch/index dependente de `@secret` (reaproveita os
  labels de S2). Surface: `constant_time_guarantees` no SBOM.
- **S3 (typestate):** estados num handle linear (de S1);
  transições mudam o tipo. `protocol_states` no SBOM. Constrói sobre
  S1.

## Dependências (grafo)
```
P1 (AOT) ──── independente, primeiro
S1 (linear) ─── independente ──→ S3 (typestate), P2-refcount-alt
P3 (opt) ────── independente
S2 (IFC) ────── independente ──→ S4 (constant-time)
P2 (GC) ─────── beneficia de P1 (benchmark) + S1 (drop points)
```

## A regra que governa todas as fases
Cada fase deixa a suite verde + **ou** uma alegação SBOM nova **ou**
um número de performance medido. Warn-then-enforce em tudo o que muda
semântica de programas existentes (S1, S2). Property-test + mutation-
check em tudo o que é alegação de segurança (S1, S2, S4) — a campanha
de auditoria provou que paridade entre backends não chega.
