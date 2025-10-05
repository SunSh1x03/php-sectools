# php-sectools

Backend PHP para proxy de APIs e geração de mapas de ataque (visualização de vulnerabilidades).

## Visão geral

Este projeto expõe uma API simples em PHP que permite:

* Ingerir resultados de varreduras de vulnerabilidades e construir grafos contendo hosts, serviços e CVEs.
* Listar grafos e recuperar os nós/arestas armazenados para visualização em um front-end.
* Consultar rapidamente cabeçalhos de segurança de um site.
* Encaminhar solicitações de análise para a API do VirusTotal (quando configurada).

Os dados são persistidos em um banco SQLite dentro do diretório `storage/`.

## Requisitos

* PHP 7.4 ou superior com extensões `pdo_sqlite` e `curl` habilitadas.
* Servidor web capaz de executar PHP (Apache, Nginx + FPM etc.).

## Instalação

1. Faça o deploy do conteúdo deste repositório no diretório público do servidor.
2. Garanta que o diretório `storage/` seja gravável pelo usuário do servidor web.
3. (Opcional) Crie um arquivo `.env` na raiz com as seguintes variáveis:

   ```env
   VT_API_KEY=chave_da_api_do_virustotal
   ALLOWED_ORIGIN=https://frontend.exemplo
   API_TOKEN=token_para_autenticacao
   ```

4. Acesse `api.php` no navegador ou via cURL para ver o payload de ajuda com as rotas disponíveis.

## Segurança

O endpoint `api.php` foi ajustado para reduzir riscos comuns:

* URLs fornecidas aos recursos de checagem de cabeçalhos ou VirusTotal passam por validação rígida. Apenas HTTP/HTTPS são aceitos e hosts que resolvem para redes privadas, loopback ou link-local são recusados. Isso mitiga SSRF.
* As requisições cURL utilizam `CURLOPT_PROTOCOLS`/`CURLOPT_REDIR_PROTOCOLS` e limite de redirecionamentos para evitar escapes de protocolo inesperados.
* O rate limiting básico por IP continua ativo para proteger o serviço contra abuso.

Recomenda-se expor a API apenas atrás de HTTPS e configurar `API_TOKEN` para exigir autenticação Bearer nas rotas de escrita (`POST /api/upload-scan`).

## Teste rápido

Enviar um JSON de exemplo para criar um grafo:

```bash
curl -X POST https://seu-servidor/api/upload-scan \
  -H "Content-Type: application/json" \
  -d @example-scan.json
```

Listar grafos existentes:

```bash
curl https://seu-servidor/api/graphs
```

Consultar cabeçalhos de segurança de um site:

```bash
curl -X POST https://seu-servidor/api/headers/check \
  -H "Content-Type: application/json" \
  -d '{"url":"https://exemplo.com"}'
```

## Licença

Distribuído sob a licença MIT. Consulte o arquivo `LICENSE` para mais detalhes.
