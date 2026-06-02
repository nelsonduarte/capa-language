# Roadmap: Capa competitiva e única em segurança + performance

> Estado: proposta de plano (2026-06-01). Constrói sobre a secção
> "P3 — research-grade, parked" do TODO.md, sequenciando-a por ROI,
> dependências e tese de posicionamento. Não substitui o plano de
> curto prazo (estabilização v1.0); é o arco que vem depois.

## Tese de posicionamento (ler primeiro)

O Capa **não vai** ganhar:
- à Rust / Zig em performance geral nem em segurança de memória;
- à Koka / Unison / Effekt em sofisticação de effect system
  (inferência de efeitos, handlers, polimorfismo de efeitos);
- a qualquer linguagem mainstream em maturidade de ecossistema.

Tentar competir nessas frentes é perder devagar. A aposta vencedora é
a **interseção que mais ninguém ocupa**:

> **Capabilities + Information Flow Control + um SBOM machine-verificável
> que expressa ambos — com performance suficiente para produção.**

Nenhuma linguagem de produção combina disciplina de autoridade
(capabilities) com controlo de fluxo de informação (IFC) E exporta isso
como um artefacto de conformidade regulatória (CycloneDX/SPDX/VEX) por
construção. A E/Pony têm capabilities mas não SBOM; a Jif/FlowCaml têm
IFC mas são académicas e sem tooling; a Rust tem `unsafe`-counting mas
não prova exclusão de efeitos nem de fluxos. A combinação é o fosso.

Dois eixos, geridos em paralelo mas com sequência interna:

- **Eixo Segurança** — torna a alegação *mais forte e mais única*.
- **Eixo Performance** — torna a linguagem *deployável*, removendo o
  bloqueador de adoção que o próprio TODO identifica.

---

## Eixo Segurança

### S1 — Linear handles / must-call types (FUNDAÇÃO, primeiro)
**ROI: alto. Esforço: ~3-4 slices. Dependências: nenhuma.**

Tipos que *têm de ser consumidos* (um ficheiro aberto tem de ser
fechado; uma transação tem de ser commitada ou abortada). O analyzer
já tem a maquinaria de `consume`/linearidade para capabilities (slice
18 auditou-a); estender a um qualificador `must_use` / `linear` em
tipos de utilizador é incremental, não greenfield.

Porquê primeiro: (a) fecha uma classe de bug concreta (resource leaks)
que o TODO marca "smallest, most defensible"; (b) é o substrato para
typestate (S3) e para a libertação determinística de recursos que o
IFC e o backend nativo vão precisar. Surface no SBOM: um novo campo
`linear_obligations` por função — "esta função recebe um handle que
DEVE libertar".

### S2 — Information Flow Control (A APOSTA DE UNICIDADE)
**ROI: o mais alto do plano. Esforço: grande, ~8-12 slices. Dependências: S1 ajuda mas não bloqueia.**

Esta é a peça que torna o Capa genuinamente único. Capabilities
controlam *que efeitos* uma função pode exercer; IFC controla *para
onde os dados podem fluir*. Juntos respondem à pergunta que nenhuma
ferramenta mainstream responde por construção: "esta função pode ler
o segredo X e enviá-lo pela rede?"

Caso de uso headline (já nos CVE studies do repo): **prompt-injection
e data-exfiltration em agentes LLM**. Capability discipline sozinha
não chega — uma função pode legitimamente ter Net E ler um segredo; o
que é preciso provar é que o segredo nunca *flui* para o Net.

Desenho mínimo viável (não a Jif completa):
- **Labels de dois pontos**: `@secret` / `@public` em tipos e
  parâmetros, com uma rede de fluxo (lattice) simples (2-4 níveis,
  não labels arbitrárias de princípios — manter ergonómico, a lição
  da Pony).
- **Noninterference verificada pelo analyzer**: dados `@secret` não
  podem alcançar um sink `@public` (incluindo `stdio.println`,
  `net.post`) sem passar por um *declassifier* explícito e auditável.
- **Declassificação como ponto auditável**: `declassify(secret, reason:
  "hashed for logging")` — o único sítio onde fluxo secret→public é
  permitido, e cada um aparece no SBOM como
  `declassification_sites`. Isto é a inovação regulatória: o SBOM
  passa a dizer "esta função desclassifica dados secretos nestes N
  pontos, por estas razões".

Fasear: começar por **explicit IFC** (labels declaradas, sem
inferência) — mais fácil de implementar e de auditar do que inferência
de fluxo. Inferência é v2.

Faseamento de roll-out (lição da slice 27): warn-then-enforce. Primeiro
o analyzer *avisa* sobre fluxos não-declassificados; depois fail-closed.

**Estado de implementação (2026-06):** entregue a fundação explícita —
lattice de dois pontos (`@secret`/`@public`), propagação por join,
enforcement secret→sink (`Stdio.println`, `Net.post`, `Fs.write`, ...)
em warn-then-enforce (`@strict_ifc` torna erro), source caps
secret-by-default (`env.get`) com fluxo do label por pattern-destructure,
e `declassify(value, reason: "...")` como a única ponte auditável, com
cada site registado no SBOM (`declassifications` por função +
`declassification_sites` no sumário). Fluxo implícito (pc-label em
branches `if`/`match` com condição secret) entregue como check
**strict-only**: o tier default fica focado nos fluxos de dados
explícitos (alto valor, baixo ruído), e `@strict_ifc` liga
noninterference completa (explícito + implícito como erros). Pendente:
inferência de fluxo (v2) e fluxo implícito em loops (`while`/`for`).

### S3 — Typestate / session types
**ROI: médio-alto. Esforço: ~5-6 slices. Dependências: S1 (linearidade).**

Tipos cujas operações permitidas mudam com o estado (um socket:
`Created → Connected → Closed`; um parser: `Idle → Reading → Done`).
Real para código de protocolo/rede; ponto de dor mesmo na Rust. Liga
ao SBOM: `protocol_states` por handle. Constrói sobre os linear
handles de S1.

### S4 — Constant-time markers para crypto
**ROI: nicho mas mecanicamente verificável. Esforço: ~3 slices. Dependências: nenhuma.**

Um qualificador `@constant_time` numa função: o analyzer (e o emitter
Wasm) recusam branches/indexação dependentes de dados `@secret` dentro
dela. Os CVE studies do repo já incluem CWE-208 (timing); isto
preveni-lo-ia mecanicamente. Liga a S2 (os dados secret são os mesmos
labels). Surface no SBOM: `constant_time_guarantees`.

### S5 — Quantitative / budgeted capabilities (DEFER)
O TODO marca ROI marginal. Manter parked — a maioria do rate-limiting
resolve-se ao nível da aplicação. Só implementar se um caso concreto
de regulador o exigir (ex. "esta função pode fazer no máximo N
chamadas de rede").

---

## Eixo Performance

### P1 — Wasm AOT via Cranelift/wasmtime (A JOGADA ESPERTA, primeiro)
**ROI: alto. Esforço: ~2-3 slices. Dependências: o backend Wasm que já existe.**

O TODO lista "backend LLVM nativo" como o maior bloqueador de adoção —
mas construir um backend LLVM do zero é um arco de muitos meses e
duplica trabalho. A jogada esperta: **o Capa já lowra para Wasm**.
Compilar esse Wasm AOT via `wasmtime compile` (Cranelift) dá
performance near-native (tipicamente 1.5-3x de Python, dentro de
2-5x de C para a maioria do código) **sem escrever um backend novo**.

Entregar: `capa build --release app.capa` → binário standalone via
`wasmtime compile` + um runtime embarcado. Isto torna o Capa
deployável hoje, reaproveitando 100% do investimento Wasm já feito e
auditado (slices 16-25).

### P2 — GC real (substituir o bump allocator)
**ROI: alto para serviços de longa duração. Esforço: ~6-8 slices. Dependências: P1 ajuda a medir.**

O alocador atual (bump + cap de memória) serve runs curtos de CLI mas
vaza em qualquer processo de longa duração. Opções, por ordem de
esforço:
1. **Wasm GC proposal** (host-provided GC) — agora estável em wasmtime;
   reaproveita o backend Wasm. Mais barato, alinhado com P1.
2. Reference counting + cycle collector no runtime emitido.
3. GC tracing próprio — caro, evitar.

Recomendação: apostar no Wasm GC proposal (opção 1), consistente com a
estratégia "dobrar no Wasm" de P1.

### P3 — Otimizações no lowerer (ganhos baratos)
**ROI: médio. Esforço: contínuo. Dependências: nenhuma.**

A campanha de auditoria mostrou o lowerer a fazer trabalho redundante
(slice 24 encontrou monomorphização frágil; o `_attenuation_map` era
recomputado). Passes baratos: dedup de closures lifted, constant-fold
ao nível IR (também fecha o resíduo do slice 26: literal 2^63 não-negado),
eliminação de instruções mortas. Cada um é pequeno e mensurável contra
o harness de paridade.

### P4 — Tail-call optimisation
**ROI: médio. Esforço: ~2 slices. Dependências: nenhuma.**
O TODO já o lista. O Wasm tem tail-calls nativos (proposal estável);
lowrar chamadas em posição de cauda para `return_call` dá recursão
sem stack-overflow. Barato dado o backend Wasm.

---

## Sequência recomendada (entrelaçada)

A regra: cada fase tem de deixar a suite verde + uma alegação de SBOM
nova ou um número de performance medido. Nunca duas frentes de risco
alto ao mesmo tempo.

1. **P1 (Wasm AOT)** — desbloqueia "deployável" cedo, baixo risco,
   reaproveita o que existe. Dá um número de performance real para
   ancorar tudo o resto.
2. **S1 (linear handles)** — fundação de segurança, incremental sobre
   a linearidade existente. Novo campo SBOM.
3. **P3 (otimizações lowerer)** — ganhos baratos enquanto S2 é
   desenhado; fecha resíduos de auditoria.
4. **S2 (IFC)** — a aposta de unicidade, a maior. Fasear
   explicit-first, warn-then-enforce. É aqui que o Capa passa de
   "SBOM de autoridade" para "SBOM de autoridade + fluxo", o fosso
   competitivo.
5. **P2 (GC via Wasm GC)** — quando S2 estabilizar e houver pressão de
   serviços de longa duração.
6. **S4 (constant-time)** — depois de S2 (reaproveita os labels secret).
7. **S3 (typestate)** — depois de S1 (reaproveita linearidade).
8. **P4 (TCO)**, **S5 (budgeted caps)** — oportunistas, quando encaixar.

## O que NÃO fazer (anti-âmbito)

- **Não** construir um backend LLVM do zero. Wasm AOT cobre 90% do
  valor a 10% do custo. LLVM só se houver um caso de performance que o
  Wasm comprovadamente não atinja.
- **Não** perseguir inferência de efeitos estilo Koka. É um arco de
  investigação inteiro e não é o fosso do Capa; o fosso é o SBOM, não
  a elegância do effect system.
- **Não** implementar IFC com labels de princípios arbitrárias (estilo
  Jif). A lição da Pony: poder a mais mata a ergonomia. Lattice
  pequena, declassificação explícita e auditável.
- **Não** alargar a superfície de linguagem (async, macros,
  self-hosting) antes de S2 + P1/P2 estarem sólidos. Cada feature nova
  é mais superfície para a campanha de auditoria cobrir.

## A frase de posicionamento, depois deste arco

> "A única linguagem que prova — por construção, num SBOM que um
> regulador pode verificar por máquina — não só *que efeitos* um
> módulo pode exercer (capabilities) mas *para onde os dados podem
> fluir* (IFC), com binários AOT de performance de produção."

Isso não é "melhor que a Rust" nem "melhor que a Koka". É uma categoria
que mais ninguém ocupa, e é defensável.
