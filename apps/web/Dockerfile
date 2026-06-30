# Development image for the web app (Vite dev server). For production a static
# build would be served behind a CDN/reverse proxy; SECP-001 targets local dev.
FROM node:22-alpine

WORKDIR /app

COPY package.json ./
# Use a plain install (no lockfile committed yet for the initial scaffold).
RUN npm install

COPY . .

EXPOSE 5173
CMD ["npm", "run", "dev"]
