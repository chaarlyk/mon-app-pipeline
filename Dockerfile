# --- STAGE 1 : Build ---
# On utilise une image complète de Node pour installer les dépendances
FROM node:18 AS builder
WORKDIR /app
COPY package*.json ./
RUN npm install

# --- STAGE 2 : Production ---
# On part d'une image alpine, beaucoup plus légère
FROM node:18-alpine
WORKDIR /app

# Créer un utilisateur non-root pour plus de sécurité
RUN addgroup -S appgroup && adduser -S appuser -G appgroup

# Copier les dépendances depuis le stage "builder"
COPY --from=builder /app/node_modules ./node_modules
# Copier le code de l'application
COPY . .

# Changer le propriétaire des fichiers
RUN chown -R appuser:appgroup .

# Passer à l'utilisateur non-root
USER appuser

# Exposer le port et lancer l'application
EXPOSE 3000
CMD [ "node", "server.js" ]