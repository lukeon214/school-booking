import { defineConfig } from "@prisma/config";
import { env } from "@prisma/config/env";

export default defineConfig({
  schema: "./prisma/schema.prisma",

  datasource: {
    url: env("DATABASE_URL"),
  },
});