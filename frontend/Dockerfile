FROM node:22-slim AS build
WORKDIR /app
COPY package*.json ./
RUN npm ci
COPY . .
RUN npm run build
FROM node:22-slim
WORKDIR /app
ENV NODE_ENV=production
RUN useradd --uid 10001 qyrix
COPY --from=build /app/.next/standalone ./
COPY --from=build /app/.next/static ./.next/static
USER 10001
EXPOSE 3000
CMD ["node", "server.js"]
