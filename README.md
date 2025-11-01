# SAFEMIND
AI safety for teens
import * as functions from "firebase-functions";
import * as admin from "firebase-admin";
import * as crypto from "crypto";

admin.initializeApp();

const REQUIRED_MODULES = ["M1", "M2", "M3", "M4", "M5", "M6"];
const MIN_LESSONS_PER_MODULE = 1; // adjust to real policy
const MIN_PASSING_SCORE = 60; // adjust to real policy (per-module total or average as required)

/**
 * Placeholder for anchoring a root hash into Solana (or other chain).
 * Replace with real implementation that performs transaction/signing.
 */
async function anchorRootOnSolana(hash: string): Promise<{ txId?: string }> {
    // ... replace with real anchor logic ...
    return { txId: `ANCHOR_TX_PLACEHOLDER_for_${hash}` };
}

export const issueCredential = functions.https.onCall(
    async (data, context) => {
        if (!context.auth) {
            throw new functions.https.HttpsError(
                "unauthenticated",
                "Authentication required."
            );
        }
        const uid = context.auth.uid;
        const db = admin.firestore();

        const modulesCompleted: string[] = [];
        let aggregateScore = 0;

        try {
            for (const moduleId of REQUIRED_MODULES) {
                const lessonsSnap = await db
                    .collection("progress")
                    .doc(uid)
                    .collection(moduleId)
                    .get();

                const lessonCount = lessonsSnap.size;
                if (lessonCount < MIN_LESSONS_PER_MODULE) {
                    return { status: "MODULE_INCOMPLETE", module: moduleId };
                }

                // Sum scores for this module
                let moduleTotal = 0;
                lessonsSnap.forEach((doc) => {
                    const d = doc.data();
                    const score = typeof d.score === "number" ? d.score : 0;
                    moduleTotal += score;
                });

                if (moduleTotal < MIN_PASSING_SCORE) {
                    return { status: "MODULE_FAILED", module: moduleId };
                }

                aggregateScore += moduleTotal;
                modulesCompleted.push(moduleId);
            }

            if (modulesCompleted.length !== REQUIRED_MODULES.length) {
                throw new functions.https.HttpsError(
                    "failed-precondition",
                    "Internal audit failed. Not all modules passed."
                );
            }

            // server-side timestamp
            const verificationTs = admin.firestore.Timestamp.now();
            const issuerId =
                process.env.FUNCTION_NAME || process.env.FUNCTION_DEPLOYMENT_ID || "issueCredential";

            const hashInput = JSON.stringify({
                uid,
                modules: modulesCompleted,
                aggregateScore,
                issuerId,
                verificationTs: verificationTs.toMillis(),
            });

            const verificationHash = crypto
                .createHash("sha256")
                .update(hashInput)
                .digest("hex");

            const securePayload = {
                uid,
                issuer_id: issuerId,
                verification_ts: verificationTs,
                verification_hash: verificationHash,
                modules: modulesCompleted,
                aggregateScore,
                issued_at: admin.firestore.FieldValue.serverTimestamp(),
                non_repudiation: {
                    method: "sha256",
                    note: "Payload hashed server-side",
                },
            };

            await db.collection("certificates").doc(uid).set(securePayload);

            // Anchor the hash on Solana (or other ledger)
            const anchorResult = await anchorRootOnSolana(verificationHash);

            return {
                status: "SUCCESS",
                hash: verificationHash,
                anchor: anchorResult,
            };
        } catch (err: any) {
            throw new functions.https.HttpsError(
                "internal",
                err?.message || "Unknown error"
            );
        }
    }
);
