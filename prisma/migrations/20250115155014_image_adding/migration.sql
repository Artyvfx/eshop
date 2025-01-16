/*
  Warnings:

  - You are about to alter the column `imageUrl` on the `Product` table. The data in that column could be lost. The data in that column will be cast from `LongBlob` to `VarChar(191)`.

*/
-- AlterTable
ALTER TABLE `Product` MODIFY `imageUrl` VARCHAR(191) NULL;
