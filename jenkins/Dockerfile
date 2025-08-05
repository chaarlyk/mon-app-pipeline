# On part de l'image Jenkins Long-Term Support (LTS) officielle
FROM jenkins/jenkins:lts

# On passe en utilisateur root pour pouvoir installer des logiciels
USER root

# On met à jour les paquets et on installe le client Docker
RUN apt-get update && \
    apt-get install -y lsb-release curl gpg && \
    curl -fsSLo /usr/share/keyrings/docker-archive-keyring.asc \
    https://download.docker.com/linux/debian/gpg && \
    echo "deb [arch=$(dpkg --print-architecture) \
    signed-by=/usr/share/keyrings/docker-archive-keyring.asc] \
    https://download.docker.com/linux/debian \
    $(lsb_release -cs) stable" | tee /etc/apt/sources.list.d/docker.list > /dev/null && \
    apt-get update && \
    apt-get install -y docker-ce-cli

# On repasse à l'utilisateur jenkins par défaut pour la sécurité
USER jenkins
