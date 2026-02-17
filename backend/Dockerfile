FROM node:24-alpine

WORKDIR /app

COPY package*.json ./
RUN npm ci --only=production

# Copy Prisma files and generate client
COPY prisma ./prisma
RUN npx prisma generate

COPY . .

CMD ["npm", "start"]