FROM node:24-alpine

WORKDIR /app

RUN apk add --no-cache g++ make

COPY package*.json ./
RUN npm ci --only=production

COPY prisma ./prisma
COPY prisma/migrations ./prisma/migrations
RUN npx prisma generate

COPY . .

RUN g++ -O2 -o qrgen qrgen.cpp && chmod +x qrgen

CMD ["sh", "-c", "npx prisma migrate deploy && npm start"]