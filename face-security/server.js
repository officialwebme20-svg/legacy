import express from "express";
import cors from "cors";
import helmet from "helmet";
import rateLimit from "express-rate-limit";
import dotenv from "dotenv";
import crypto from "crypto";
import { PrismaClient } from "@prisma/client";

dotenv.config();

/* =========================================================
   CONFIGURATION
========================================================= */

const app = express();

const prisma = new PrismaClient({
    log: ["error", "warn"]
});

const PORT = Number(process.env.PORT) || 10000;

const FRONTEND_URL =
    process.env.FRONTEND_URL ||
    "https://legacy-lens.onrender.com";

/* =========================================================
   STARTUP CONFIG CHECK
========================================================= */

console.log("======================================");
console.log("Legacy Lens AI Face Security");
console.log("======================================");

console.log("Environment:", process.env.NODE_ENV || "production");
console.log("Port:", PORT);
console.log("Frontend URL:", FRONTEND_URL);
console.log(
    "DATABASE_URL:",
    process.env.DATABASE_URL
        ? "SET"
        : "NOT SET"
);

/* =========================================================
   EXPRESS SECURITY
========================================================= */

app.disable("x-powered-by");

app.set("trust proxy", 1);

/* =========================================================
   CORS
========================================================= */

const allowedOrigins = [
    "https://legacy-lens.onrender.com",
    FRONTEND_URL
].filter(Boolean);

app.use(
    cors({
        origin: function (origin, callback) {
            /*
             * Requests without an Origin header can happen from:
             * curl, Render health checks, Postman, server-side tools, etc.
             */
            if (!origin) {
                return callback(null, true);
            }

            if (allowedOrigins.includes(origin)) {
                return callback(null, true);
            }

            console.warn(
                "CORS blocked origin:",
                origin
            );

            return callback(
                new Error(
                    `CORS blocked origin: ${origin}`
                )
            );
        },

        methods: [
            "GET",
            "POST",
            "DELETE",
            "OPTIONS"
        ],

        allowedHeaders: [
            "Content-Type",
            "Authorization"
        ],

        credentials: false,

        optionsSuccessStatus: 204
    })
);

/* =========================================================
   HELMET
========================================================= */

app.use(
    helmet({
        crossOriginResourcePolicy: false
    })
);

/* =========================================================
   BODY PARSER
========================================================= */

app.use(
    express.json({
        limit: "10mb"
    })
);

/* =========================================================
   REQUEST LOGGER
========================================================= */

app.use(
    (req, res, next) => {
        console.log(
            `${new Date().toISOString()} ${req.method} ${req.originalUrl}`
        );

        next();
    }
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
            registered: false,
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
   DATABASE STATE
========================================================= */

let databaseReady = false;

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

/* =========================================================
   DESCRIPTOR VALIDATION
========================================================= */

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

function cleanDescriptor(descriptor) {
    if (!Array.isArray(descriptor)) {
        return null;
    }

    const cleaned = descriptor.map(
        value => Number(value)
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

    const cleaned = descriptors.map(
        descriptor =>
            cleanDescriptor(descriptor)
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

/* =========================================================
   FACE DISTANCE
========================================================= */

function faceDistance(a, b) {
    if (
        !validateDescriptor(a) ||
        !validateDescriptor(b)
    ) {
        return Infinity;
    }

    let sum = 0;

    for (let i = 0; i < 128; i++) {
        const difference =
            a[i] - b[i];

        sum +=
            difference *
            difference;
    }

    return Math.sqrt(sum);
}

/* =========================================================
   AVERAGE DESCRIPTORS
========================================================= */

function averageDescriptors(
    descriptors
) {
    const cleaned =
        cleanDescriptors(
            descriptors
        );

    if (
        !cleaned ||
        cleaned.length === 0
    ) {
        return null;
    }

    const average =
        new Array(128).fill(0);

    for (
        const descriptor
        of cleaned
    ) {
        for (let i = 0; i < 128; i++) {
            average[i] +=
                descriptor[i];
        }
    }

    for (let i = 0; i < 128; i++) {
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

/* =========================================================
   DATABASE CONNECTION
========================================================= */

async function connectDatabase() {
    try {
        if (!process.env.DATABASE_URL) {
            console.error(
                "DATABASE_URL is not configured."
            );

            databaseReady = false;

            return false;
        }

        await prisma.$connect();

        await prisma.$queryRaw`
            SELECT 1
        `;

        databaseReady = true;

        console.log(
            "PostgreSQL: CONNECTED"
        );

        return true;

    } catch (error) {

        databaseReady = false;

        console.error(
            "======================================"
        );

        console.error(
            "POSTGRESQL CONNECTION FAILED"
        );

        console.error(
            "Message:",
            error?.message
        );

        console.error(
            "Code:",
            error?.code || "N/A"
        );

        console.error(
            "======================================"
        );

        return false;
    }
}

/* =========================================================
   DATABASE CHECK MIDDLEWARE
========================================================= */

function requireDatabase(
    req,
    res,
    next
) {
    if (!databaseReady) {
        return res.status(503).json({
            success: false,
            message:
                "Database is not connected.",
            error:
                "The face security server cannot access PostgreSQL."
        });
    }

    next();
}

/* =========================================================
   EXPIRED SESSION CLEANUP
========================================================= */

async function deleteExpiredSessions() {
    if (!databaseReady) {
        return;
    }

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
            error?.message
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
            status: "online",
            database:
                databaseReady
                    ? "connected"
                    : "disconnected"
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

            if (!process.env.DATABASE_URL) {
                return res.status(503).json({
                    success: false,
                    service:
                        "Legacy Lens AI Face Security",
                    status: "online",
                    database:
                        "not_configured",
                    message:
                        "DATABASE_URL is missing from the server environment."
                });
            }

            await prisma.$queryRaw`
                SELECT 1
            `;

            databaseReady = true;

            return res.json({
                success: true,
                service:
                    "Legacy Lens AI Face Security",
                status: "online",
                database:
                    "connected",
                frontend:
                    FRONTEND_URL
            });

        } catch (error) {

            databaseReady = false;

            console.error(
                "Health check database error:",
                error
            );

            return res.status(503).json({
                success: false,
                service:
                    "Legacy Lens AI Face Security",
                status: "online",
                database:
                    "disconnected",
                error:
                    error?.message ||
                    "Database connection failed."
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
    requireDatabase,
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
                "Registration email:",
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
                    "Invalid descriptor received."
                );

                return res.status(400).json({
                    success: false,
                    registered: false,
                    message:
                        "One or more face descriptors are invalid. Each descriptor must contain exactly 128 numeric values."
                });
            }

            console.log(
                "All descriptors are valid."
            );

            /* -----------------------------------------
               CREATE FACE TEMPLATE
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
                    "Existing face account found."
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
                "FACE REGISTRATION SUCCESS"
            );

            console.log(
                "Email:",
                email
            );

            console.log(
                "======================================"
            );

            return res.status(200).json({
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
                "Message:",
                error?.message
            );

            console.error(
                "Code:",
                error?.code || null
            );

            console.error(
                "Meta:",
                error?.meta || null
            );

            console.error(
                error
            );

            console.error(
                "======================================"
            );

            return res.status(500).json({
                success: false,
                registered: false,
                message:
                    "Face registration failed.",
                error:
                    error?.message ||
                    "Unknown database/server error.",
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
    requireDatabase,
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
                    error?.message ||
                    "Unknown database error."
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
    requireDatabase,
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

            /* -----------------------------------------
               EMAIL
            ----------------------------------------- */

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

            /* -----------------------------------------
               DESCRIPTOR
            ----------------------------------------- */

            if (!descriptor) {

                return res.status(400).json({
                    success: false,
                    authenticated: false,
                    message:
                        "Invalid face descriptor. The camera did not produce a valid 128-value face descriptor."
                });
            }

            /* -----------------------------------------
               FIND USER
            ----------------------------------------- */

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

            /* -----------------------------------------
               STORED TEMPLATE
            ----------------------------------------- */

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

            /* -----------------------------------------
               COMPARE
            ----------------------------------------- */

            const distance =
                faceDistance(
                    descriptor,
                    registeredDescriptor
                );

            /*
             * face-api.js Euclidean distance.
             *
             * Smaller = more similar.
             *
             * 0.45 = fairly strict starting point.
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
                    distance:
                        Number(
                            distance.toFixed(6)
                        )
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
                    error?.message ||
                    "Unknown server error.",
                code:
                    error?.code || null
            });
        }
    }
);

/* =========================================================
   SESSION VALIDATION
========================================================= */

app.post(
    "/api/face/session",
    requireDatabase,
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
                    error?.message ||
                    "Unknown database error."
            });
        }
    }
);

/* =========================================================
   LOGOUT
========================================================= */

app.post(
    "/api/face/logout",
    requireDatabase,
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
                    error?.message ||
                    "Unknown database error."
            });
        }
    }
);

/* =========================================================
   REMOVE FACE
========================================================= */

app.delete(
    "/api/face/remove",
    requireDatabase,
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
                    error?.message ||
                    "Unknown database error.",
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
                "Endpoint not found.",
            path:
                req.originalUrl
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
            "======================================"
        );

        console.error(
            "GLOBAL ERROR"
        );

        console.error(
            error
        );

        console.error(
            "======================================"
        );

        if (
            error?.message?.startsWith(
                "CORS blocked origin:"
            )
        ) {

            return res.status(403).json({
                success: false,
                message:
                    error.message
            });
        }

        return res.status(500).json({
            success: false,
            message:
                "Internal server error.",
            error:
                error?.message ||
                "Unknown server error."
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
                `Server listening on port ${PORT}`
            );

            console.log(
                `Frontend: ${FRONTEND_URL}`
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

            console.log(
                "======================================"
            );

            await connectDatabase();

            console.log(
                "======================================"
            );

            console.log(
                "Database status:",
                databaseReady
                    ? "CONNECTED"
                    : "DISCONNECTED"
            );

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
   GRACEFUL SHUTDOWN
========================================================= */

async function shutdown() {

    console.log(
        "Shutting down Legacy Lens AI server..."
    );

    try {

        await prisma.$disconnect();

        console.log(
            "Database disconnected."
        );

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
