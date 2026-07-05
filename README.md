# N.A.Diesel Diagnósticos e Programação

Sistema responsivo de gestão de oficina, executado com Node.js sem dependências externas.

## Iniciar

Execute `INICIAR-SISTEMA.bat` ou rode `npm start` nesta pasta. Depois, acesse `http://127.0.0.1:3015`.

## Usuários iniciais

| Usuário | Senha inicial | Perfil |
|---|---|---|
| Admin | `admin123` | Administrador |
| Gabriel | `1234` | Técnico |
| Leonardo | `1234` | Técnico |
| Naldo | `1234` | Técnico |

Troque as senhas antes de disponibilizar o sistema em uma rede pública.

No Netlify, configure `INITIAL_ADMIN_PASSWORD`, `INITIAL_GABRIEL_PASSWORD`, `INITIAL_LEONARDO_PASSWORD` e `INITIAL_NALDO_PASSWORD` como variáveis de ambiente antes do primeiro acesso.

Os dados são persistidos em `data/db.json`, criado automaticamente na primeira execução. Faça backup periódico desse arquivo.
