import express from "express";
import cors from "cors";
import helmet from "helmet";
import rateLimit from "express-rate-limit";
import dotenv from "dotenv";
import crypto from "crypto";
import { PrismaClient } from "@prisma/client";

dotenv.config();

const app = express();
const prisma = new PrismaClient();

const PORT = process.env.PORT || 3001;

const FRONTEND_URL =
    process.env.FRONTEND_URL || "*";

app.disable("x-powered-by");

app.set("trust proxy", 1);

app.use(
    helmet({
        crossOriginResourcePolicy: false
    })
);

app.use(
    cors({
        origin:
            FRONTEND_URL === "*"
                ? true
                : FRONTEND_URL,
        methods: [
            "GET",
            "POST",
            "DELETE",
            "OPTIONS"
        ],
        allowedHeaders: [
            "Content-Type",
            "Authorization"
        ]
    })
);

app.use(
    express.json({
        limit: "5mb"
    })
);

/* =========================================================
   RATE LIMITERS
========================================================= */

const faceRegisterLimiter =
    rateLimit({
        windowMs: 15 * 60 * 1000,
        max: 10,
        standardHeaders: true,
        legacyHeaders: false,
        message: {
            success: false,
            message:
                "Too many face registration attempts. Please try again later."
        }
    });

const faceLoginLimiter =
    rateLimit({
        windowMs: 15 * 60 * 1000,
        max: 20,
        standardHeaders: true,
        legacyHeaders: false,
        message: {
            success: false,
            authenticated: false,
            message:
                "Too many face login attempts. Please try again later."
        }
    });

/* =========================================================
   HELPERS
========================================================= */

function normalizeEmail(email) {
    return String(email || "")
        .trim()
        .toLowerCase();
}

function validEmail(email) {
    return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(
        email
    );
}

function validateDescriptor(descriptor) {
    if (!Array.isArray(descriptor)) {
        return false;
    }

    if (descriptor.length !== 128) {
        return false;
    }

    return descriptor.every(
        value =>
            typeof value === "number" &&
            Number.isFinite(value)
    );
}

function faceDistance(a, b) {
    if (
        !Array.isArray(a) ||
        !Array.isArray(b) ||
        a.length !== b.length
    ) {
        return Infinity;
    }

    let sum = 0;

    for (let i = 0; i < a.length; i++) {
        const difference =
            a[i] - b[i];

        sum +=
            difference *
            difference;
    }

    return Math.sqrt(sum);
}

function averageDescriptors(
    descriptors
) {
    if (
        !Array.isArray(descriptors) ||
        descriptors.length === 0
    ) {
        return null;
    }

    const length =
        descriptors[0].length;

    const average =
        new Array(length).fill(0);

    for (
        const descriptor
        of descriptors
    ) {
        for (
            let i = 0;
            i < length;
            i++
        ) {
            average[i] +=
                descriptor[i];
        }
    }

    for (
        let i = 0;
        i < length;
        i++
    ) {
        average[i] /=
            descriptors.length;
    }

    return average;
}

/*
    We never store the raw session token in the database.

    Browser:
        token

    Database:
        SHA-256(token)
*/

function hashToken(token) {
    return crypto
        .createHash("sha256")
        .update(token)
        .digest("hex");
}

function createSessionToken() {
    return crypto
        .randomBytes(32)
        .toString("hex");
}

async function deleteExpiredSessions() {
    try {
        await prisma.session.deleteMany({
            where: {
                expiresAt: {
                    lt: new Date()
                }
            }
        });
    } catch (error) {
        console.error(
            "Expired session cleanup error:",
            error
        );
    }
}

setInterval(
    deleteExpiredSessions,
    60 * 60 * 1000
);

/* =========================================================
   ROOT
========================================================= */

app.get(
    "/",
    (req, res) => {
        return res.json({
            success: true,
            service:
                "Legacy Lens AI Face Security",
            status: "online"
        });
    }
);

/* =========================================================
   HEALTH
========================================================= */

app.get(
    "/api/health",
    async (req, res) => {
        try {
            await prisma.$queryRaw`SELECT 1`;

            return res.json({
                success: true,
                service:
                    "Legacy Lens AI Face Security",
                status: "online",
                database:
                    "connected"
            });

        } catch (error) {
            console.error(
                "Database health error:",
                error
            );

            return res.status(500).json({
                success: false,
                service:
                    "Legacy Lens AI Face Security",
                status: "online",
                database:
                    "disconnected"
            });
        }
    }
);

/* =========================================================
   REGISTER FACE
========================================================= */

app.post(
    "/api/face/register",
    faceRegisterLimiter,
    async (req, res) => {

        try {

            const email =
                normalizeEmail(
                    req.body?.email
                );

            const descriptors =
                req.body?.descriptors;

            if (!email) {
                return res.status(400).json({
                    success: false,
                    message:
                        "Email address is required."
                });
            }

            if (!validEmail(email)) {
                return res.status(400).json({
                    success: false,
                    message:
                        "Please provide a valid email address."
                });
            }

            if (
                !Array.isArray(
                    descriptors
                ) ||
                descriptors.length < 3 ||
                descriptors.length > 10
            ) {
                return res.status(400).json({
                    success: false,
                    message:
                        "Please provide between 3 and 10 face captures."
                });
            }

            for (
                const descriptor
                of descriptors
            ) {

                if (
                    !validateDescriptor(
                        descriptor
                    )
                ) {

                    return res.status(400).json({
                        success: false,
                        message:
                            "Invalid face descriptor received."
                    });
                }
            }

            const faceTemplate =
                averageDescriptors(
                    descriptors
                );

            if (
                !validateDescriptor(
                    faceTemplate
                )
            ) {

                return res.status(400).json({
                    success: false,
                    message:
                        "Unable to create face template."
                });
            }

            /*
                Find existing account.
            */

            const existing =
                await prisma.faceUser.findUnique({
                    where: {
                        email
                    }
                });

            let user;

            if (existing) {

                user =
                    await prisma.faceUser.update({
                        where: {
                            email
                        },
                        data: {
                            faceTemplate
                        }
                    });

            } else {

                user =
                    await prisma.faceUser.create({
                        data: {
                            email,
                            faceTemplate
                        }
                    });
            }

            /*
                Delete old sessions.

                If the user registers a new face,
                old login sessions are invalidated.
            */

            await prisma.session.deleteMany({
                where: {
                    userId:
                        user.id
                }
            });

            console.log(
                `Face registered for ${email}`
            );

            return res.json({
                success: true,
                registered: true,
                message:
                    "Face registered successfully."
            });

        } catch (error) {

            console.error(
                "Face registration error:",
                error
            );

            return res.status(500).json({
                success: false,
                message:
                    "Unable to register your face."
            });
        }
    }
);

/* =========================================================
   FACE STATUS
========================================================= */

app.post(
    "/api/face/status",
    async (req, res) => {

        try {

            const email =
                normalizeEmail(
                    req.body?.email
                );

            if (!email) {
                return res.status(400).json({
                    success: false,
                    message:
                        "Email address is required."
                });
            }

            if (!validEmail(email)) {
                return res.status(400).json({
                    success: false,
                    message:
                        "Please provide a valid email address."
                });
            }

            const user =
                await prisma.faceUser.findUnique({
                    where: {
                        email
                    },
                    select: {
                        id: true
                    }
                });

            return res.json({
                success: true,
                registered:
                    Boolean(user)
            });

        } catch (error) {

            console.error(
                "Face status error:",
                error
            );

            return res.status(500).json({
                success: false,
                message:
                    "Unable to check face status."
            });
        }
    }
);

/* =========================================================
   FACE LOGIN
========================================================= */

app.post(
    "/api/face/login",
    faceLoginLimiter,
    async (req, res) => {

        try {

            const email =
                normalizeEmail(
                    req.body?.email
                );

            const descriptor =
                req.body?.descriptor;

            if (!email) {
                return res.status(400).json({
                    success: false,
                    authenticated:
                        false,
                    message:
                        "Email address is required."
                });
            }

            if (!validEmail(email)) {
                return res.status(400).json({
                    success: false,
                    authenticated:
                        false,
                    message:
                        "Please provide a valid email address."
                });
            }

            if (
                !validateDescriptor(
                    descriptor
                )
            ) {

                return res.status(400).json({
                    success: false,
                    authenticated:
                        false,
                    message:
                        "Invalid face descriptor."
                });
            }

            /*
                Find registered face.
            */

            const user =
                await prisma.faceUser.findUnique({
                    where: {
                        email
                    }
                });

            if (!user) {

                return res.status(404).json({
                    success: false,
                    authenticated:
                        false,
                    registered:
                        false,
                    message:
                        "No face is registered for this account."
                });
            }

            /*
                Prisma Json field already gives
                us the descriptor as an array.
            */

            const registeredDescriptor =
                user.faceTemplate;

            if (
                !validateDescriptor(
                    registeredDescriptor
                )
            ) {

                return res.status(500).json({
                    success: false,
                    authenticated:
                        false,
                    message:
                        "Stored face template is invalid."
                });
            }

            /*
                Compare NEW face against
                REGISTERED face.
            */

            const distance =
                faceDistance(
                    descriptor,
                    registeredDescriptor
                );

            /*
                Lower distance = more similar.

                0.45 = strict matching.
            */

            const MATCH_THRESHOLD =
                0.45;

            const matched =
                distance <=
                MATCH_THRESHOLD;

            console.log(
                "================================"
            );

            console.log(
                "FACE LOGIN ATTEMPT"
            );

            console.log(
                `Email: ${email}`
            );

            console.log(
                `Distance: ${distance}`
            );

            console.log(
                `Threshold: ${MATCH_THRESHOLD}`
            );

            console.log(
                `Matched: ${matched}`
            );

            console.log(
                "================================"
            );

            /*
                DIFFERENT FACE
            */

            if (!matched) {

                return res.status(401).json({
                    success: false,
                    authenticated:
                        false,
                    message:
                        "Face not recognized. Login denied."
                });
            }

            /*
                SAME FACE

                Create persistent session.
            */

            const rawToken =
                createSessionToken();

            const tokenHash =
                hashToken(
                    rawToken
                );

            const expiresAt =
                new Date(
                    Date.now() +
                    24 * 60 * 60 * 1000
                );

            await prisma.session.create({
                data: {
                    tokenHash,
                    userId:
                        user.id,
                    expiresAt
                }
            });

            console.log(
                `Face login successful for ${email}`
            );

            return res.json({
                success: true,
                authenticated:
                    true,
                email,
                token:
                    rawToken,
                expiresAt,
                message:
                    "Face recognized successfully."
            });

        } catch (error) {

            console.error(
                "Face login error:",
                error
            );

            return res.status(500).json({
                success: false,
                authenticated:
                    false,
                message:
                    "Unable to complete face login."
            });
        }
    }
);

/* =========================================================
   VALIDATE SESSION
========================================================= */

app.post(
    "/api/face/session",
    async (req, res) => {

        try {

            const token =
                String(
                    req.body?.token ||
                    ""
                ).trim();

            if (!token) {

                return res.status(401).json({
                    success: false,
                    authenticated:
                        false,
                    message:
                        "Authentication token is required."
                });
            }

            const tokenHash =
                hashToken(token);

            const session =
                await prisma.session.findUnique({
                    where: {
                        tokenHash
                    },
                    include: {
                        user: {
                            select: {
                                email: true
                            }
                        }
                    }
                });

            if (!session) {

                return res.status(401).json({
                    success: false,
                    authenticated:
                        false,
                    message:
                        "Invalid authentication session."
                });
            }

            if (
                new Date() >
                session.expiresAt
            ) {

                await prisma.session.delete({
                    where: {
                        id:
                            session.id
                    }
                });

                return res.status(401).json({
                    success: false,
                    authenticated:
                        false,
                    message:
                        "Authentication session has expired."
                });
            }

            return res.json({
                success: true,
                authenticated:
                    true,
                email:
                    session.user.email,
                expiresAt:
                    session.expiresAt
            });

        } catch (error) {

            console.error(
                "Session validation error:",
                error
            );

            return res.status(500).json({
                success: false,
                authenticated:
                    false,
                message:
                    "Unable to validate authentication session."
            });
        }
    }
);

/* =========================================================
   LOGOUT
========================================================= */

app.post(
    "/api/face/logout",
    async (req, res) => {

        try {

            const token =
                String(
                    req.body?.token ||
                    ""
                ).trim();

            if (!token) {

                return res.json({
                    success: true,
                    message:
                        "Logged out successfully."
                });
            }

            const tokenHash =
                hashToken(token);

            await prisma.session.deleteMany({
                where: {
                    tokenHash
                }
            });

            return res.json({
                success: true,
                message:
                    "Logged out successfully."
            });

        } catch (error) {

            console.error(
                "Logout error:",
                error
            );

            return res.status(500).json({
                success: false,
                message:
                    "Unable to log out."
            });
        }
    }
);

/* =========================================================
   REMOVE FACE
========================================================= */

app.delete(
    "/api/face/remove",
    async (req, res) => {

        try {

            const email =
                normalizeEmail(
                    req.body?.email
                );

            if (!email) {

                return res.status(400).json({
                    success: false,
                    message:
                        "Email address is required."
                });
            }

            if (!validEmail(email)) {

                return res.status(400).json({
                    success: false,
                    message:
                        "Please provide a valid email address."
                });
            }

            const user =
                await prisma.faceUser.findUnique({
                    where: {
                        email
                    }
                });

            if (!user) {

                return res.json({
                    success: true,
                    removed: false,
                    message:
                        "No registered face was found."
                });
            }

            /*
                Sessions are deleted automatically
                because schema.prisma uses
                onDelete: Cascade.
            */

            await prisma.faceUser.delete({
                where: {
                    email
                }
            });

            return res.json({
                success: true,
                removed: true,
                message:
                    "Face data removed successfully."
            });

        } catch (error) {

            console.error(
                "Face removal error:",
                error
            );

            return res.status(500).json({
                success: false,
                message:
                    "Unable to remove face data."
            });
        }
    }
);

/* =========================================================
   404
========================================================= */

app.use(
    (req, res) => {

        return res.status(404).json({
            success: false,
            message:
                "Endpoint not found."
        });
    }
);

/* =========================================================
   GLOBAL ERROR HANDLER
========================================================= */

app.use(
    (
        error,
        req,
        res,
        next
    ) => {

        console.error(
            "Global server error:",
            error
        );

        return res.status(500).json({
            success: false,
            message:
                "Internal server error."
        });
    }
);

/* =========================================================
   START SERVER
========================================================= */

const server =
    app.listen(
        PORT,
        async () => {

            console.log(
                "======================================"
            );

            console.log(
                "Legacy Lens AI Face Security"
            );

            console.log(
                "======================================"
            );

            console.log(
                `Port: ${PORT}`
            );

            console.log(
                `Health: /api/health`
            );

            console.log(
                `Register: /api/face/register`
            );

            console.log(
                `Status: /api/face/status`
            );

            console.log(
                `Login: /api/face/login`
            );

            console.log(
                `Session: /api/face/session`
            );

            console.log(
                `Logout: /api/face/logout`
            );

            console.log(
                `Remove: /api/face/remove`
            );

            try {

                await prisma.$connect();

                console.log(
                    "PostgreSQL: CONNECTED"
                );

            } catch (error) {

                console.error(
                    "PostgreSQL: CONNECTION FAILED"
                );

                console.error(
                    error.message
                );
            }

            console.log(
                "======================================"
            );
        }
    );

server.on(
    "error",
    error => {

        console.error(
            "HTTP server error:",
            error
        );
    }
);

/* =========================================================
   SHUTDOWN
========================================================= */

async function shutdown() {

    console.log(
        "Shutting down..."
    );

    await prisma.$disconnect();

    process.exit(0);
}

process.on(
    "SIGINT",
    shutdown
);

process.on(
    "SIGTERM",
    shutdown
);