# Camada de testes property-based / fuzz, âmbito

> Estado: proposta de âmbito (2026-05-30, 3ª revisão após inspeção do
> que já existe). Motivada pela campanha de auditoria slices 16-26.

## Realidade: a infraestrutura NÃO está em branco

Duas revisões deste doc partiram de suposições erradas. A verdade,
confirmada por inspeção do código:

**`tests/test_properties.py` (1126 linhas)** já contém:
- Fuzz robustez front-end: `TestLexerProperties`, `TestParserProperties`,
  `TestFormatterProperties`, `TestFormatterFixpoint` (idempotência +
  convergência num passo).
- Pipeline sintaxe-ciente: `TestSyntaxAwarePipeline` com gerador
  `_program()` que emite programas plausíveis e afirma
  lex+parse+analyze+transpile+`ast.parse` ponta-a-ponta.
- **A invariante de soundness, nos dois backends**:
  `TestRuntimeSubsetOfManifest` (Python) e
  `TestWasmRuntimeSubsetOfManifest` (Wasm, via `_TracingWasmHost` que
  regista cada operação de capability executada). Geradores
  `_program_with_caps`, `_program_with_caps_advanced`,
  `_program_with_caps_wasm`, `_program_with_caps_wasm_advanced`.

**`evaluation/fuzz/`**, painel de ataques separado, 9 categorias
(`cat_fs_traversal`, `cat_env_leak`, `cat_net_punch`,
`cat_capability_aliasing`, `cat_capability_in_data`,
`cat_llm_dispatch_escape`, etc.), cada uma gera ataques que
`capa --check` deve rejeitar.

`hypothesis 6.152.7` é dependência declarada (`pyproject.toml [test]`).

## A pergunta afiada

**Se a invariante de soundness já é testada nos dois backends com runtime
instrumentado, porque é que o slice 25 (atenuação entre funções)
escapou?**

Porque a invariante testada é a errada para essa classe de bug.

`TestRuntimeSubsetOfManifest` afirma:

> usado(f) ⊆ declarado(f), "o manifesto é um limite superior honesto"

O slice 25 **não** violava isto. Um programa que faz
`let n = fs.restrict_to("/tmp"); helper(n)` e depois lê
`/etc/passwd` dentro de `helper` continua a usar apenas a capability
`Fs` que `helper` declara, passa a invariante de subset perfeitamente.
O que é violado é uma invariante diferente, que **não existe** no suite:

> Para cada cap atenuada c com restrição R, toda operação privilegiada
> sobre c em runtime satisfaz R, "a atenuação é honrada"

E, na sua forma de manifesto:

> usado(f) ∩ provably_excluded(f) = ∅, "a exclusão é honrada"

Esta é a invariante que torna `provably_excluded_capabilities` um facto
em vez de uma esperança. É a peça que falta.

Segundo motivo, complementar: mesmo que a invariante existisse, os
geradores `_program_with_caps*` provavelmente não emitem a *forma* que
dispara o bug, `restrict_to` numa função, operação privilegiada noutra.
Um gerador que só atenua e usa na mesma função nunca exercita o caminho
inter-função.

## Trabalho real: duas lacunas cirúrgicas

Não é uma camada nova. São duas adições contra infraestrutura existente.

### Lacuna A, Invariante de atenuação/exclusão (~1 slice)
Ao lado de `TestRuntimeSubsetOfManifest` / `TestWasmRuntimeSubsetOfManifest`,
adicionar `TestAttenuationHonoured` (Python) e o gémeo Wasm. Reutiliza o
`_TracingWasmHost` e o `_trace` que já existem; estende o traço para
registar **o argumento** de cada operação privilegiada (o caminho lido,
o host contactado, a chave de env), não só a classe da cap.

Duas afirmações por programa gerado:
1. Toda operação registada sobre uma cap atenuada satisfaz a restrição
   acumulada dessa cap (prefixo/host/chave/deadline).
2. Para cada função f, `usado(f) ∩ manifest.provably_excluded(f) = ∅`.

Isto teria apanhado os slices 18, 21 e 25 automaticamente.

### Lacuna B, Aprofundar os geradores (~1 slice)
Estender `_program_with_caps_advanced` e `_program_with_caps_wasm_advanced`
para emitir as formas que escaparam, cada uma ligada a um bug real:
- atenuar numa função, usar a cap atenuada noutra (slice 25);
- `impl UserCap for Struct` onde a struct embrulha uma built-in cap,
  passada a uma função que declara só a user-cap (slice 21);
- lambda com corpo em bloco terminando em expressão, retorno não-Unit
  (slice 24);
- cap guardada em campo de struct / capturada em closure e usada
  depois.

A Lacuna B sozinha torna os fuzzers *existentes* capazes de reencontrar
21/24; combinada com a Lacuna A, fecha também 25.

## Lacunas menores, AMBAS FEITAS (2026-05-31)

### Lacuna C, Oráculo de exportador, FEITA
Propriedade independente de backend: todo
`transitively_reachable_capability` no manifesto aparece como
propriedade no CycloneDX **e** anotação no SPDX; todo
`provably_excluded` aparece como a entrada negativa correspondente;
todo built-in transitivamente alcançado tem um componente sintetizado
`capa:builtin:...` no CycloneDX. (Apanharia o slice 23.) Não precisa de
runtime, compara manifesto vs. exportadores.

Implementada em `TestExporterConservation` a granularidade **por-função**
(a forma forte): cada função do manifesto é casada com o seu componente
CycloneDX (por bom-ref reconstruído) e o seu pacote SPDX (por nome de
exibição). Geradores: `_program_user_cap_wraps_builtin` (forma slice-21,
reachability transitiva não-trivial) + `_program_with_caps_advanced`.
Verificado por mutação: ao remover a propriedade transitiva do
CycloneDX, dispara `AssertionError`.

### Lacuna D, Invariante de posições, FEITA
`source[tok.start.offset:tok.end.offset] == tok.text` para cada token
não-layout, sobre texto bruto (`_CAPA_ISH_TEXT` / `_SOURCE_TEXT`) e
sobre programas gerados (`_program()`). Protege o campo `pos` do
manifesto que os reguladores leem. Implementada em
`TestLexerProperties` (dois métodos raw-text) + `TestPositionProperties`
(programas). Verificada por mutação: um off-by-one no offset start ou
end dispara; a baseline não.

## Estado final do âmbito

Todas as quatro lacunas (A, B, C, D) estão fechadas. `test_properties.py`
cresceu de 11 para 21 métodos. A frase defensável para a NLnet é agora:
**`usado ∩ provably_excluded = ∅` (atenuação honrada) é property-tested
em ambos os backends, e a conservação manifesto→SBOM é property-tested
por-função**, não só por auditoria manual. A Lacuna 5 (gerador
nível-tipo completo: genéricos, sum types com payloads, closures
cap-capturantes) fica como alargamento contínuo, não pré-requisito.

## Não-objetivos

- Não construir do zero, estender `test_properties.py` e
  `test_evaluation_fuzz.py`.
- Não duplicar a invariante de subset, que já existe e funciona.
- Não substitui a auditoria humana de *desenho*, apanha regressões de
  *implementação* da classe que a campanha encontrou repetidamente.
- O gerador nível-tipo completo (genéricos, sum types com payloads,
  closures cap-capturantes) é alargamento contínuo, não um pré-requisito.

## Ordem recomendada

1. **Lacuna B** (aprofundar geradores): desbloqueia tudo o resto;
   sozinha reativa os fuzzers existentes para 21/24.
2. **Lacuna A** (invariante de atenuação/exclusão): fecha o núcleo
   regulatório; com B, apanha 25.
3. **Lacuna C** (exportador): barata, fecha 23.
4. **Lacuna D** (posições): barata.

Total ~3 slices para fechar o ponto cego que a campanha expôs. Antes de
cada lacuna: **ler a classe/gerador existente e estendê-lo**, lição
das duas revisões erradas deste próprio doc.

## Nota de honestidade para a NLnet

A frase defensável após este trabalho: "a invariante
`usado ⊆ declarado` é verificada por property-testing em ambos os
backends desde [data]; a invariante `usado ∩ provably_excluded = ∅`
(atenuação honrada) é adicionada na Lacuna A". Antes da Lacuna A,
**não** afirmar que a exclusão é property-tested: só a auditoria
manual (slice 25) a verificou até agora, num conjunto fixo de
reprodutores.
