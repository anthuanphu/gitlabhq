# Dockerfile mẫu cho project Node.js
FROM node:20-alpine
WORKDIR /app
COPY dist/ ./dist/
COPY package.json ./
RUN npm ci --production
EXPOSE 3000
CMD ["node", "dist/index.js"]
