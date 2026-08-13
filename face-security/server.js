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

const PORT = Number(process.env.PORT) || 10000;

const FRONTEND_URL =
    process.env.FRONTEND_URL || "*";

app.disable("x-powered-by");
app.set("trust proxy", 1);

/* =========================================================
   SECURITY
========================================================= */

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
        limit: "10mb"
    })
);

/* =========================================================
   RATE LIMITING
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
                "Too many registration attempts. Please wait and try again."
        }
    });

const faceLoginLimiter =
    rateLimit({
        windowMs: 15 * 60 * 1000,
        max: 30,
        standardHeaders: true,
        legacyHeaders: false,
        message: {
            success: false,
            authenticated: false,
            message:
                "Too many login attempts. Please wait and try again."
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

/*
    Face-api.js descriptors normally contain
    exactly 128 numeric values.
*/

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

/*
    Convert every descriptor value to a normal
    JavaScript Number.

    This prevents problems if the browser sends
    Float32Array-like values.
*/

function cleanDescriptor(descriptor) {
    if (!Array.isArray(descriptor)) {
        return null;
    }

    const cleaned =
        descriptor.map(value =>
            Number(value)
        );

    if (!validateDescriptor(cleaned)) {
        return null;
    }

    return cleaned;
}

function cleanDescriptors(descriptors) {
    if (!Array.isArray(descriptors)) {
        return null;
    }

    const cleaned =
        descriptors.map(
            descriptor =>
                cleanDescriptor(
                    descriptor
                )
        );

    if (
        cleaned.some(
            descriptor =>
                descriptor === null
        )
    ) {
        return null;
    }

    return cleaned;
}

/*
    Euclidean distance between two face descriptors.
*/

function faceDistance(a, b) {
    if (
        !validateDescriptor(a) ||
        !validateDescriptor(b)
    ) {
        return Infinity;
    }

    let sum = 0;

    for (
        let i = 0;
        i < 128;
        i++
    ) {
        const difference =
            a[i] - b[i];

        sum +=
            difference *
            difference;
    }

    return Math.sqrt(sum);
}

/*
    Average multiple face descriptors
    into one face template.
*/

function averageDescriptors(
    descriptors
) {
    if (
        !Array.isArray(descriptors) ||
        descriptors.length === 0
    ) {
        return null;
    }

    const cleaned =
        cleanDescriptors(
            descriptors
        );

    if (!cleaned) {
        return null;
    }

    const average =
        new Array(128).fill(0);

    for (
        const descriptor
        of cleaned
    ) {
        for (
            let i = 0;
            i < 128;
            i++
        ) {
            average[i] +=
                descriptor[i];
        }
    }

    for (
        let i = 0;
        i < 128;
        i++
    ) {
        average[i] =
            average[i] /
            cleaned.length;
    }

    return average;
}

/* =========================================================
   SESSION HELPERS
========================================================= */

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
        res.json({
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
            await prisma.$queryRaw`
                SELECT 1
            `;

            res.json({
                success: true,
                service:
                    "Legacy Lens AI Face Security",
                status: "online",
                database:
                    "connected"
            });

        } catch (error) {
            console.error(
                "Health check error:",
                error
            );

            res.status(500).json({
                success: false,
                service:
                    "Legacy Lens AI Face Security",
                status: "online",
                database:
                    "disconnected",
                error:
                    error.message
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

        console.log(
            "======================================"
        );

        console.log(
            "FACE REGISTRATION REQUEST"
        );

        try {

            const email =
                normalizeEmail(
                    req.body?.email
                );

            const descriptors =
                req.body?.descriptors;

            console.log(
                "Email:",
                email
            );

            console.log(
                "Descriptor count:",
                Array.isArray(
                    descriptors
                )
                    ? descriptors.length
                    : "NOT ARRAY"
            );

            /* -----------------------------------------
               EMAIL
            ----------------------------------------- */

            if (!email) {

                return res.status(400).json({
                    success: false,
                    registered: false,
                    message:
                        "Email address is required."
                });
            }

            if (!validEmail(email)) {

                return res.status(400).json({
                    success: false,
                    registered: false,
                    message:
                        "Please provide a valid email address."
                });
            }

            /* -----------------------------------------
               DESCRIPTORS
            ----------------------------------------- */

            if (
                !Array.isArray(
                    descriptors
                )
            ) {

                return res.status(400).json({
                    success: false,
                    registered: false,
                    message:
                        "Face descriptors were not received as an array."
                });
            }

            if (
                descriptors.length < 3
            ) {

                return res.status(400).json({
                    success: false,
                    registered: false,
                    message:
                        `Only ${descriptors.length} face capture(s) were received. At least 3 are required.`
                });
            }

            if (
                descriptors.length > 10
            ) {

                return res.status(400).json({
                    success: false,
                    registered: false,
                    message:
                        "Too many face captures. Maximum is 10."
                });
            }

            /* -----------------------------------------
               CLEAN DESCRIPTORS
            ----------------------------------------- */

            const cleanedDescriptors =
                cleanDescriptors(
                    descriptors
                );

            if (
                !cleanedDescriptors
            ) {

                console.error(
                    "Invalid descriptor detected."
                );

                return res.status(400).json({
                    success: false,
                    registered: false,
                    message:
                        "One or more face descriptors are invalid. Each face descriptor must contain exactly 128 numeric values."
                });
            }

            console.log(
                "All descriptors valid."
            );

            /* -----------------------------------------
               CREATE TEMPLATE
            ----------------------------------------- */

            const faceTemplate =
                averageDescriptors(
                    cleanedDescriptors
                );

            if (
                !faceTemplate ||
                !validateDescriptor(
                    faceTemplate
                )
            ) {

                return res.status(400).json({
                    success: false,
                    registered: false,
                    message:
                        "The server could not create a valid face template."
                });
            }

            console.log(
                "Face template created."
            );

            /* -----------------------------------------
               FIND EXISTING USER
            ----------------------------------------- */

            const existing =
                await prisma.faceUser.findUnique({
                    where: {
                        email
                    }
                });

            let user;

            if (existing) {

                console.log(
                    "Existing account found. Updating face."
                );

                user =
                    await prisma.faceUser.update({
                        where: {
                            email
                        },
                        data: {
                            faceTemplate:
                                faceTemplate
                        }
                    });

            } else {

                console.log(
                    "Creating new face account."
                );

                user =
                    await prisma.faceUser.create({
                        data: {
                            email,
                            faceTemplate:
                                faceTemplate
                        }
                    });
            }

            console.log(
                "Face user saved:",
                user.id
            );

            /* -----------------------------------------
               DELETE OLD SESSIONS
            ----------------------------------------- */

            await prisma.session.deleteMany({
                where: {
                    userId:
                        user.id
                }
            });

            console.log(
                `Face registered successfully for ${email}`
            );

            console.log(
                "======================================"
            );

            return res.json({
                success: true,
                registered: true,
                email,
                message:
                    "Face registered successfully."
            });

        } catch (error) {

            console.error(
                "======================================"
            );

            console.error(
                "FACE REGISTRATION ERROR"
            );

            console.error(
                error
            );

            console.error(
                "Message:",
                error?.message
            );

            console.error(
                "Code:",
                error?.code
            );

            console.error(
                "Meta:",
                error?.meta
            );

            console.error(
                "======================================"
            );

            /*
                IMPORTANT:
                Return the actual Prisma error during
                debugging instead of always hiding it.
            */

            return res.status(500).json({
                success: false,
                registered: false,
                message:
                    "Face registration failed.",
                error:
                    error?.message ||
                    "Unknown server error.",
                code:
                    error?.code || null
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
                    registered: false,
                    message:
                        "Email address is required."
                });
            }

            if (!validEmail(email)) {

                return res.status(400).json({
                    success: false,
                    registered: false,
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
                registered: false,
                message:
                    "Unable to check face status.",
                error:
                    error?.message
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
                cleanDescriptor(
                    req.body?.descriptor
                );

            if (!email) {

                return res.status(400).json({
                    success: false,
                    authenticated: false,
                    message:
                        "Email address is required."
                });
            }

            if (!validEmail(email)) {

                return res.status(400).json({
                    success: false,
                    authenticated: false,
                    message:
                        "Please provide a valid email address."
                });
            }

            if (!descriptor) {

                return res.status(400).json({
                    success: false,
                    authenticated: false,
                    message:
                        "Invalid face descriptor. The camera did not produce a valid 128-value face descriptor."
                });
            }

            const user =
                await prisma.faceUser.findUnique({
                    where: {
                        email
                    }
                });

            if (!user) {

                return res.status(404).json({
                    success: false,
                    authenticated: false,
                    registered: false,
                    message:
                        "No face is registered for this account."
                });
            }

            const registeredDescriptor =
                cleanDescriptor(
                    user.faceTemplate
                );

            if (
                !registeredDescriptor
            ) {

                return res.status(500).json({
                    success: false,
                    authenticated: false,
                    message:
                        "The stored face template is invalid."
                });
            }

            const distance =
                faceDistance(
                    descriptor,
                    registeredDescriptor
                );

            /*
                0.45 is a common starting point
                for face-api.js Euclidean matching.

                Smaller = stricter.
                Larger = more forgiving.
            */

            const MATCH_THRESHOLD =
                0.45;

            const matched =
                distance <=
                MATCH_THRESHOLD;

            console.log(
                "======================================"
            );

            console.log(
                "FACE LOGIN ATTEMPT"
            );

            console.log(
                "Email:",
                email
            );

            console.log(
                "Distance:",
                distance
            );

            console.log(
                "Threshold:",
                MATCH_THRESHOLD
            );

            console.log(
                "Matched:",
                matched
            );

            console.log(
                "======================================"
            );

            if (!matched) {

                return res.status(401).json({
                    success: false,
                    authenticated: false,
                    message:
                        "Face not recognized. Login denied.",
                    distance
                });
            }

            /* -----------------------------------------
               CREATE SESSION
            ----------------------------------------- */

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
                authenticated: true,
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
                authenticated: false,
                message:
                    "Unable to complete face login.",
                error:
                    error?.message,
                code:
                    error?.code || null
            });
        }
    }
);

/* =========================================================
   SESSION
========================================================= */

app.post(
    "/api/face/session",
    async (req, res) => {

        try {

            const token =
                String(
                    req.body?.token || ""
                ).trim();

            if (!token) {

                return res.status(401).json({
                    success: false,
                    authenticated: false,
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
                    authenticated: false,
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
                    authenticated: false,
                    message:
                        "Authentication session has expired."
                });
            }

            return res.json({
                success: true,
                authenticated: true,
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
                authenticated: false,
                message:
                    "Unable to validate authentication session.",
                error:
                    error?.message
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
                    req.body?.token || ""
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
                    "Unable to log out.",
                error:
                    error?.message
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
                    "Unable to remove face data.",
                error:
                    error?.message,
                code:
                    error?.code || null
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
            "GLOBAL ERROR:",
            error
        );

        return res.status(500).json({
            success: false,
            message:
                "Internal server error.",
            error:
                error?.message
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
                "Health: /api/health"
            );

            console.log(
                "Register: /api/face/register"
            );

            console.log(
                "Status: /api/face/status"
            );

            console.log(
                "Login: /api/face/login"
            );

            console.log(
                "Session: /api/face/session"
            );

            console.log(
                "Logout: /api/face/logout"
            );

            console.log(
                "Remove: /api/face/remove"
            );

            try {

                await prisma.$connect();

                console.log(
                    "PostgreSQL: CONNECTED"
                );

            } catch (error) {

                console.error(
                    "POSTGRESQL CONNECTION FAILED"
                );

                console.error(
                    error
                );
            }

            console.log(
                "======================================"
            );
        }
    );

/* =========================================================
   SERVER ERROR
========================================================= */

server.on(
    "error",
    error => {

        console.error(
            "HTTP SERVER ERROR:",
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

    try {

        await prisma.$disconnect();

    } catch (error) {

        console.error(
            "Prisma disconnect error:",
            error
        );
    }

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
