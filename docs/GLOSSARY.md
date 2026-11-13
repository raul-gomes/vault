# Glossário

| Termo | Significado |
| --- | --- |
| **Cofre** | O banco `vault.db` com tudo cifrado, mais o daemon que o abre. |
| **Daemon** | Processo local (`127.0.0.1:8787`) que guarda a DEK na memória, decifra e roda os comandos. |
| **Passphrase** | Senha mestra do humano. Deriva a KEK; nunca é guardada. |
| **KEK** | Chave derivada da passphrase (Argon2id). Só serve para embrulhar a DEK. |
| **DEK** | Chave aleatória que cifra segredos e credenciais. Fica embrulhada em `meta` e, desbloqueada, só na memória do daemon. |
| **AAD** | Dado associado do AES-GCM: amarra o ciphertext ao seu lugar e versão. |
| **Desbloquear / bloquear** | Pôr / tirar a DEK da memória. Bloquear também derruba sessões e mata execuções. |
| **Projeto** | Um repo local registrado (slug + pasta). Comandos só rodam dentro da pasta dele. |
| **Ambiente** | Conjunto de segredos de um projeto (`dev`, `prod`…). |
| **Segredo** | Uma variável de ambiente cifrada (`CHAVE=valor`). |
| **Credencial** | Login de serviço (hosting, DNS, e-mail), global ou de um projeto. |
| **Token de agente** | `ev_...` com escopo de projeto, ambientes e comandos. Pode listar nomes e rodar comandos; nunca revela valor. |
| **Sessão** | Login humano no painel ou na CLI (cookie + CSRF). Única que pode revelar/exportar. |
| **Redação** | Troca de valores de segredo por `[REDACTED:CHAVE]` na saída dos comandos. |
| **Reveal / export** | Mostrar um valor / gerar `.env`. Só pela sessão humana, auditados. |
| **Auditoria** | Log append-only encadeado com HMAC (chave derivada da DEK); a última entrada fica fixada em `meta`. `envvault verify` confere (com o cofre desbloqueado). |
