FROM node:24-alpine

WORKDIR /app

COPY package*.json ./
RUN npm ci --only=production

COPY prisma ./prisma
COPY prisma/migrations ./prisma/migrations
RUN npx prisma generate

COPY . .

CMD ["sh", "-c", "npx prisma migrate deploy && npm start"]