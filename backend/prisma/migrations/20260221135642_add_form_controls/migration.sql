-- AlterTable
ALTER TABLE "Form" ADD COLUMN     "closeDate" TIMESTAMP(3),
ADD COLUMN     "maxTotalResponses" INTEGER NOT NULL DEFAULT 0;
