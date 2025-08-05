# 1. On part d'une base factuelle : l'image officielle de Node.js
#    basée sur Debian Bullseye, qui contient bien 'apt-get'.
FROM node:18-bullseye

# 2. On installe le client Docker en suivant la procédure officielle pour Debian.
#    Ceci est une procédure factuelle et documentée.
USER root
RUN apt-get update && \
    apt-get install -y apt-transport-https ca-certificates curl gnupg lsb-release && \
    mkdir -p /etc/apt/keyrings && \
    curl -fsSL https://download.docker.com/linux/debian/gpg | gpg --dearmor -o /etc/apt/keyrings/docker.gpg && \
    echo \
      "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/debian \
      $(lsb_release -cs) stable" | tee /etc/apt/sources.list.d/docker.list > /dev/null && \
    apt-get update && \
    apt-get install -y docker-ce-cli

# On repasse à un utilisateur non-privilégié pour la sécurité.
USER node
