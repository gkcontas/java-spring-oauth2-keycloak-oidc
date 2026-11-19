# OAuth2 e OpenID Connect com Keycloak

Uma aplicação Spring Boot protegida por um provedor de identidade real, o
Keycloak. Ela não conhece senha de ninguém nem guarda chave privada: confia num
emissor, baixa dele as chaves públicas e decide o acesso a partir do que vem no
token. É o oposto dos projetos que emitem o próprio JWT.

A mesma aplicação faz os dois papéis do protocolo, em cadeias de segurança
separadas:

- **Resource server** (`/api/**`, sem sessão): recebe um access token e valida
  localmente, pela JWKS do Keycloak. Uma segunda rota (`/api/introspected/**`)
  valida o mesmo token perguntando ao Keycloak a cada requisição, para comparar
  as duas formas no mesmo processo.
- **Cliente OIDC no papel de BFF** (`/web/**`, com sessão): login por
  authorization code com PKCE, tokens guardados no servidor, refresh
  automático, logout iniciado pela aplicação e logout por back-channel.

## Tecnologias

- **Java 21** e **Spring Boot 3.5**
- **Spring Security 6.5**: OAuth2 Resource Server, OAuth2 Client e OIDC logout
- **Nimbus JOSE + JWT** para a JWKS com cache, limite de frequência e
  tolerância a queda
- **Keycloak 26** com o realm importado de `keycloak/docs-realm.json`
- **Testcontainers** para subir o Keycloak nos testes de integração
- **Gradle** (Kotlin DSL) com wrapper

## O realm

| Cliente | Tipo | Para quê |
|---|---|---|
| `docs-web` | confidencial, PKCE S256 obrigatório | o BFF desta aplicação |
| `docs-cli` | público, PKCE S256 obrigatório | um cliente nativo (linha de comando) |
| `other-app` | público | outra aplicação do mesmo realm |
| `report-job` | confidencial, client credentials | um processo sem usuário |
| `docs-api` | confidencial, sem fluxo | a própria API, só para introspecção |

Os escopos `documents:read` e `documents:write` colocam `docs-api` na audiência
do token. A usuária `alice` tem os papéis `reader` e `editor` e o papel de
cliente `docs-api/admin`; `bob` tem só `reader`, e é `admin` de `other-app`.
Password grant e implicit estão desligados em todos os clientes.

## Resource server

| Rota | Exige |
|---|---|
| `GET /api/documents/**` | scope `documents:read` |
| `POST /api/documents` | scope `documents:write` **e** role `editor` |
| `DELETE /api/documents/{id}` | scope `documents:write` **e** role de cliente `docs-api:admin` |
| `GET /api/me` | qualquer token válido |
| `GET /api/introspected/documents/**` | scope `documents:read`, por introspecção |

Qualquer outra rota é negada.

- **Validar não é só conferir a assinatura.** O decoder aceita apenas RS256,
  sem ler o algoritmo do cabeçalho, e confere emissor, expiração (com 30 s de
  tolerância de relógio), **audiência** e **tipo**. O Spring Boot só verifica a
  audiência quando ela é configurada; sem isso, um token que o Keycloak emitiu
  para qualquer outro cliente do realm passa. O tipo existe porque o Keycloak
  assina access token, ID token e logout token com a mesma chave e o mesmo
  emissor: só o `typ` distingue um ID token, que prova autenticação para o
  cliente que o pediu, de uma autorização para chamar a API.
- **Scope não é role.** O scope diz o que o *cliente* pode fazer em nome do
  usuário; a role diz o que o *usuário* pode fazer. O Keycloak concede um scope
  opcional a quem pedir, então `bob` consegue um token com `documents:write` e
  mesmo assim não cria documento. Criar exige os dois.
- **Roles do Keycloak precisam de conversor.** O Spring mapeia só o claim
  `scope`. As roles do realm (`realm_access`) viram `ROLE_x`, e as roles de
  cliente (`resource_access`) só contam quando são do próprio `docs-api`, como
  `ROLE_docs-api:admin`. O `admin` que `bob` tem em `other-app` aparece no token
  dele e não vale nada aqui.
- **A audiência sozinha não basta.** O escopo padrão `roles` do Keycloak traz o
  mapper *audience resolve*: quem tem uma role de cliente do `docs-api` recebe
  `docs-api` na audiência de qualquer token, inclusive de outra aplicação que
  nunca pediu documentos. Um token da `alice` emitido para `other-app` passa
  pela audiência; é a exigência de scope que o barra. Por isso o `DELETE` exige
  o scope além da role.
- **Introspecção também precisa conferir a audiência.** O Keycloak responde
  `active: true` para qualquer token válido do realm.

### JWKS: cache, rotação e kid inventado

As chaves públicas ficam em cache por 5 minutos. Um token com `kid`
desconhecido força uma nova busca, e é assim que uma chave rotacionada é
descoberta. Mas essa busca é limitada: no máximo duas por janela de 30 s.
Sem o limite, qualquer um faria a API martelar o Keycloak mandando tokens com
`kid` inventado. Se o Keycloak estiver fora do ar quando o cache vencer, as
chaves antigas continuam valendo por até 1 hora.

O limite tem um efeito colateral: um `kid` desconhecido acima do limite chega
ao Spring como erro ao obter as chaves, que ele responde com `500`. Aqui ele
vira `401` - quem errou foi o token. Uma queda real do Keycloak, sem chave em
cache, continua sendo `500`.

## BFF

O navegador só recebe um cookie de sessão. Access, refresh e ID token ficam na
sessão, no servidor.

| Rota | O que faz |
|---|---|
| `GET /web/me` | identidade do usuário logado, sem nenhum token |
| `GET /web/documents` | chama `/api/documents` com o token do usuário |
| `GET /web/csrf` | token CSRF para o frontend devolver em `X-CSRF-TOKEN` |
| `POST /logout` | encerra a sessão local e a do Keycloak |

- **PKCE também no cliente confidencial.** O Spring só manda `code_challenge`
  quando o cliente é público. O `docs-web` tem segredo e, ainda assim, o
  Keycloak exige PKCE S256 dele; o customizador de requisição é obrigatório.
  PKCE protege contra o código interceptado, coisa que o segredo do cliente
  não resolve no caminho de volta pelo navegador.
- **Margem de renovação.** O Spring renova o access token um pouco antes de
  ele vencer. O padrão é 60 s: com um token de 60 s ou menos, toda chamada é
  precedida por um refresh. Aqui a margem é 30 s.
- **Refresh token com rotação.** Cada refresh devolve um refresh token novo e
  invalida o anterior. Se o refresh falhar porque a sessão acabou no Keycloak,
  o BFF esquece os tokens e responde `401 reauthentication_required`.
- **Logout iniciado pela aplicação.** `POST /logout` encerra a sessão local e
  redireciona para o endpoint de logout do Keycloak com `id_token_hint`, que
  encerra o single sign-on e volta para `/`.
- **Logout por back-channel.** Quando a sessão termina no Keycloak por outro
  caminho - outra aplicação do mesmo SSO, um administrador -, o Keycloak manda
  um logout token assinado para `/logout/connect/back-channel/keycloak` e a
  sessão local correspondente (pelo `sid`) é invalidada. O handler padrão do
  Spring faz isso chamando o próprio `POST /logout` por HTTP, passando pela
  verificação de CSRF; quando essa chamada é recusada, o Keycloak recebe o seu
  `200` e o usuário continua logado aqui. Esta aplicação invalida a sessão
  diretamente.
- **"Sign out" do usuário no Keycloak avisa uma sessão só.** No Keycloak
  26.0.7, encerrar todas as sessões de um usuário pela administração derruba
  todas no Keycloak, mas envia back-channel para apenas uma. Encerrar sessão
  por sessão avisa cada uma. A sessão local que não foi avisada perde o acesso
  quando o token precisar ser renovado.
- **CSRF ligado** na cadeia com sessão, porque o cookie vai sozinho em toda
  requisição do navegador, e desligado na cadeia da API, onde não há cookie.
- Requisição sem login com `X-Requested-With: XMLHttpRequest` recebe `401`; a
  navegação comum é redirecionada para o Keycloak.

## Como executar

Pré-requisitos: Docker, JDK 21 e Python 3 (para os scripts).

```bash
docker compose up -d
./gradlew bootRun
```

O Keycloak sobe na porta 8180 com o realm `docs` já importado (console em
`http://localhost:8180`, `admin`/`admin`); a aplicação sobe na 8080 e as
métricas ficam em `127.0.0.1:8081`. Para o login no navegador, abra
`http://localhost:8080/web/me` e entre como `alice`/`alice` ou `bob`/`bob`.

O script `scripts/kc.py` obtém tokens pelo fluxo real de authorization code
com PKCE, preenchendo o formulário de login do Keycloak - não há password grant
no realm.

### Exemplos

```bash
ALICE=$(scripts/kc.py token alice documents:write)
BOB=$(scripts/kc.py token bob documents:write)
JOB=$(scripts/kc.py service)
```

O que a API extraiu do token:

```bash
curl localhost:8080/api/me -H "Authorization: Bearer $ALICE"
```

Scope e role. `alice` cria; `bob` tem o scope mas não a role, e o processo
`report-job` só lê:

```bash
curl -X POST localhost:8080/api/documents -H "Authorization: Bearer $ALICE" \
  -H 'Content-Type: application/json' -d '{"title":"Plan","content":"Q1"}'
curl -i -X POST localhost:8080/api/documents -H "Authorization: Bearer $BOB" \
  -H 'Content-Type: application/json' -d '{"title":"Plan","content":"Q1"}'
curl localhost:8080/api/documents -H "Authorization: Bearer $JOB"
```

Token emitido para outra aplicação e ID token no lugar de access token:

```bash
curl -i localhost:8080/api/me -H "Authorization: Bearer $(scripts/kc.py token bob '' other-app)"
curl -i localhost:8080/api/me -H "Authorization: Bearer $(scripts/kc.py tokens alice | jq -r .id_token)"
```

A mesma leitura por introspecção:

```bash
curl localhost:8080/api/introspected/documents -H "Authorization: Bearer $JOB"
```

## Testes

```bash
./gradlew test
```

São 52 testes. Os de integração usam um único Keycloak em container, iniciado
por inicializador estático e compartilhado por todas as classes. Os tokens de
usuário saem do fluxo de authorization code de verdade, com o formulário de
login preenchido por HTTP; ajustes no realm (rotação de chave, tempo de vida do
token, encerramento de sessão) são feitos pela API de administração. A porta da
aplicação é fixada antes de o Keycloak subir, para o realm apontar o
back-channel para ela.

Os cenários cobrem a matriz de scope e role, roles de cliente de outra
aplicação, audiência (inclusive o *audience resolve*), ID token como bearer,
payload adulterado, chave própria com o `kid` do Keycloak, `alg: none`, HMAC
assinado com a chave pública, outro emissor, cache da JWKS, enxurrada de `kid`
inventado, rotação de chave, introspecção depois do logout, PKCE (sem
verificador, verificador errado, `plain`, sem challenge, código reutilizado),
password grant desligado, rotação do refresh token, o login do BFF com PKCE,
CSRF no logout, logout iniciado pela aplicação, logout federado por SSO e por
back-channel, e a renovação por margem de relógio.

## Medições

Setup: todas as medições foram feitas numa única sessão, com o jar empacotado
(`bootJar`, JDK 21), o daemon do Gradle parado e o Keycloak 26.0.7 em
container (`start-dev`), tudo no mesmo host (12 núcleos). O cliente é um
script em Python que usa só a biblioteca padrão, com conexão persistente
(`scripts/measure.py`); os números de chamadas ao Keycloak saem de contadores
da aplicação. Antes de cada série, 500 requisições de aquecimento foram
descartadas.

### JWT local contra introspecção

2000 requisições sequenciais com o mesmo token:

| Validação | p50 | p99 | Chamadas ao Keycloak |
|---|---|---|---|
| **JWT local (JWKS em cache)** | **0,94 ms** | **1,73 ms** | **0** |
| Introspecção | 3,95 ms | 10,35 ms | 2000 |

Com 16 clientes simultâneos por 10 s, o caminho com JWT atendeu 5420
requisições por segundo (p99 8,4 ms) e o com introspecção 2468 (p99 18,2 ms),
com o Keycloak recebendo uma chamada por requisição. No caminho com JWT o
limite é o próprio cliente de carga.

### Revogação

Token de 60 s, logout do `bob` logo depois de obtê-lo:

| Validação | Token ainda aceito depois do logout |
|---|---|
| Introspecção | 0 s |
| JWT local | 90,1 s |

O JWT não sabe do logout: vale até expirar, mais a tolerância de relógio de
30 s. É o preço da validação local, e o motivo para manter o access token
curto.

### Keycloak fora do ar

Keycloak parado, 200 requisições com um token emitido antes:

| Validação | Respostas |
|---|---|
| JWT local | 200 × `200` (p50 0,51 ms) |
| Introspecção | 200 × `500` |

A introspecção falha fechada: sem o provedor, ninguém entra.

### Kid inventado e rotação

Limite de frequência de produção (duas buscas por janela de 30 s):

| Cenário | Resultado |
|---|---|
| 137.699 tokens com `kid` aleatório em 65 s | 137.699 × `401`, **6 buscas** à JWKS |
| Chave nova no Keycloak logo depois de 3 s de enxurrada | token legítimo recusado por **21,9 s** (87 × `401`) |

Sem o limite seriam 137.699 chamadas ao Keycloak. O custo aparece na
rotação: se a cota da janela já foi gasta, a chave nova só é buscada quando a
janela abre de novo. Na prática, a chave nova deve ser publicada antes de
começar a assinar com ela.

### Margem de renovação no BFF

Access token de 60 s, 20 chamadas a `/web/documents` logo após o login,
aplicação recém-iniciada nos dois casos:

| Margem de renovação | Refresh grants | p50 |
|---|---|---|
| 60 s (padrão do Spring) | 20 | 22,7 ms |
| **30 s** | **0** | **8,4 ms** |

Com a margem igual ao tempo de vida, o token já nasce "vencendo" e cada
chamada vira duas: um refresh no Keycloak e a chamada à API.

### Logout por back-channel

20 rodadas de login no BFF seguido do encerramento da sessão pela
administração do Keycloak: a sessão local caiu em 41,9 ms de mediana (máximo
122 ms), medidos até a próxima requisição do navegador ser redirecionada para
o login.

## Estrutura

```
com.gkcontas.documents
├── security   decoder JWT, validadores, conversor de roles, introspecção, cadeias da API
├── web        cadeia com sessão, cliente OAuth2, BFF, back-channel logout, sessões locais
├── api        controllers de documentos e /api/me
├── document   documentos em memória
└── config     propriedades do Keycloak, cadeia do Actuator e relógio
```
