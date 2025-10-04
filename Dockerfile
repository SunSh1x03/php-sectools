# Usando imagem oficial do PHP com servidor embutido
FROM php:8.1-cli

# Copia os arquivos do repositório para o container
WORKDIR /app
COPY . .

# Expõe a porta usada pelo Render
EXPOSE 8080

# Comando para iniciar o servidor PHP embutido
CMD ["php", "-S", "0.0.0.0:8080", "api.php"]
