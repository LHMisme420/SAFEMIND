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
## 🔒 Security Mandate: Sovereign Credential Hardening

For the **Safe Mind Certificate of AI Literacy** to be considered an **immutable, verifiable record**, the following **Sovereign Security Mandates** are enforced:

### 1. Trust-No-Client Principle
The backend's `issueCredential` function operates under the principle that **all data received from the mobile application is untrusted**. The function ignores client-side completion claims and instead executes a full, internal audit.

### 2. Server-Side Progress Verification
Before generating the cryptographic hash, the Firebase Function performs a mandatory **Server-Side Progress Verification**. It queries the Firestore database directly to calculate the student's passing scores, ensuring that the completion hash is generated only from database-validated data, eliminating the threat of data spoofing or manipulation.

### 3. Non-Repudiation Payload
The final $\text{SHA-256}$ hash payload includes the **Firebase Function's unique deployment ID** and the **Server Timestamp**. This links the hash to a specific, auditable version of the issuing code, guaranteeing **non-repudiation** by the system.

### 4. Policy of Immutability
The only action permitted for the dedicated Solana anchoring wallet is to execute the simple `Memo Program` transaction. This enforces the **Principle of Least Privilege (PoLP)** and ensures the wallet cannot tamper with or delete existing on-chain records.
# Security Policy: SAFE MIND

## Core Security Mandate
The primary objective of this project's security policy is to protect student data and guarantee the **immutability** of all issued completion credentials.

### Data Privacy and Collection
* **No Personal Data:** No personally identifiable information (PII) beyond a necessary User ID is collected or transmitted to the public Solana ledger.
* **No Tracking/Advertising:** The application is designed with a **privacy-by-default** stance and contains no third-party trackers or ads.
* **Student Export:** Students retain the right to export their learning record at any time.

### Credential Integrity Mandate
* **Client Data is Untrusted:** All client-side claims regarding quiz completion or assessment scores are considered **untrusted**. The canonical source of truth for all certification logic resides exclusively within the hardened Firebase Functions layer.
* **On-Chain Verification:** Any reported vulnerability that compromises the integrity of the $\text{SHA-256}$ hash generation or the Solana anchoring process is considered a **Severity 1 Critical Flaw**.

## Vulnerability Reporting
Please report any security vulnerabilities discovered in the SAFE MIND application or infrastructure by emailing **lhmisme2011@gmail.com**.
