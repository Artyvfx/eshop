// src/scripts/createUser.ts

import { PrismaClient } from '@prisma/client'
import * as bcrypt from 'bcrypt'
import * as dotenv from 'dotenv'

dotenv.config()

const prisma = new PrismaClient()

async function createAdminUser() {
    try {
        const hashedPassword = await bcrypt.hash('admin123', 10)

        const user = await prisma.user.upsert({
            where: { username: 'admin' },
            update: {},
            create: {
                username: 'admin',
                password: hashedPassword,
                role: 'admin'
            }
        })

        console.log('Admin user created successfully:', user.username)
    } catch (error) {
        console.error('Error creating admin user:', error)
    } finally {
        await prisma.$disconnect()
    }
}

createAdminUser()