# ADR 0001 — Dashboard estático sem framework

- **Status:** aceito
- **Data:** 2026-11-09
- **Contexto:** decisão de front-end do EnvVault v0.1

## Contexto

O EnvVault é um cofre local de segredos. A interface web é uma superfície
sensível: ela pode revelar valores e disparar comandos com injeção. Cada
dependência de front-end (framework, roteador, biblioteca de UI, toolchain de
build) adiciona código executado no mesmo contexto de origem que a sessão
autenticada.

O dashboard precisa de: login, listas, formulários, modais, abas de ambiente,
console com streaming SSE, e um gerador de senha. Não precisa de SEO, render
no servidor, rotas profundas estáveis nem compartilhamento de componentes entre
times.

## Decisão

Servir uma SPA mínima em HTML/CSS/JS puro, embutida no pacote Python:

- `web/index.html` — shell, login e `<dialog>` de modal
- `web/app.css` — tema escuro com variáveis CSS
- `web/app.js` — módulo ES único, sem build

Regras:

1. Nada de `innerHTML` com dados do usuário; o helper `el()` cria nós e anexa
   texto via `document.createTextNode`.
2. Nenhuma dependência externa ou CDN. Todos os assets são servidos por
   `/static` a partir do próprio pacote.
3. Estado em um objeto `state` simples; navegação por `location.hash`.
4. O console de execução lê `ReadableStream` e parseia frames SSE manualmente.

## Consequências

**Positivas**

- Superfície de ataque e de supply chain mínima: não há `node_modules` no
  runtime, nem script de terceiros na origem autenticada.
- Deploy trivial: o wheel já contém a UI; nada para compilar.
- CSP e auditoria de código viáveis: o app inteiro é legível em três arquivos.
- Sem incompatibilidade de versão de framework ao atualizar Python/FastAPI.

**Negativas**

- Sem componentização reativa; telas são funções que reconstroem o DOM.
- Sem type-checking de front-end; o contrato da API depende de disciplina e dos
  testes de backend.
- Sem testes unitários de UI no repositório (o smoke test com Playwright vive
  fora, porque exige binário de browser).
- Se a UI crescer muito, a manutenção fica mais cara que a de um framework.

## Alternativas consideradas

- **React + Vite:** produtividade e ecossistema, mas adiciona build, centenas de
  dependências transitivas e um bundle servido na origem da sessão.
- **HTMX/Alpine via CDN:** pouco código, mas depende de terceiros em runtime.
- **Server-side templates (Jinja):** simples, porém o console SSE e os modais
  ficam mais verbosos e a interatividade exige mais idas ao servidor.

A decisão é revisitável se a UI passar de ~2.000 linhas de JS ou precisar de
estado compartilhado complexo.
