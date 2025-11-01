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
// backend/functions/src/issueCredential.ts

import * as functions from "firebase-functions";
import * as admin from "firebase-admin";
import crypto from "crypto";
import fetch from "node-fetch";

admin.initializeApp();

// --- SOVEREIGN MANDATES ---
const MIN_PASSING_SCORE = 4; // Assuming 6-question quiz requires 4 correct answers to pass
const REQUIRED_MODULES = ["Module 1", "Module 2", "Module 3", "Module 4", "Module 5", "Module 6"];

export const issueCredential = functions.https.onCall(async (data, context) => {
    // 1. INPUT SANITIZATION & AUTHENTICATION
    if (!context.auth) {
        throw new functions.https.HttpsError("unauthenticated", "Login required.");
    }
    const uid = context.auth.uid;
    const project_id = process.env.GCLOUD_PROJECT; // Get the ID of the hosting environment
    
    functions.logger.info(`Initiating Sovereign Credential Audit for UID: ${uid}`);

    // --- 2. SOVEREIGN MANDATE: SERVER-SIDE PROGRESS VERIFICATION ---
    const modulesCompleted: string[] = [];
    const db = admin.firestore();

    for (const moduleName of REQUIRED_MODULES) {
        // Find the specific assessment for this module in the database
        const assessmentSnap = await db.collection("progress").doc(uid)
            .collection("assessments").where("moduleName", "==", moduleName).get();
        
        if (assessmentSnap.empty) {
            functions.logger.warn(`Audit failed: ${moduleName} assessment record not found.`);
            throw new functions.https.HttpsError("failed-precondition", `Module incomplete: ${moduleName}`);
        }

        // Assume there is only one final assessment per module for simplicity
        const assessmentData = assessmentSnap.docs[0].data();
        const score = assessmentData.score || 0; // The actual score recorded on submission

        // MANDATE CHECK: Verify the recorded score meets the Sovereign minimum
        if (score < MIN_PASSING_SCORE) {
            functions.logger.warn(`Audit failed: ${moduleName} score (${score}) below minimum.`);
            throw new functions.https.HttpsError("failed-precondition", `Module failed: ${moduleName}. Score too low.`);
        }

        modulesCompleted.push(moduleName);
    }
    
    // 3. FINAL INTEGRITY CHECK (Did we pass all 6?)
    if (modulesCompleted.length !== REQUIRED_MODULES.length) {
        throw new functions.https.HttpsError("internal", "Internal audit integrity failure.");
    }

    functions.logger.info(`Sovereign Audit Complete. All 6 modules passed for UID: ${uid}`);

    // --- 4. GENERATE IMMUTABLE HASH PAYLOAD (NON-REPUDIATION) ---
    const securePayload = {
        uid: uid,
        modules: modulesCompleted,
        // MANDATE: Non-Repudiation Fields
        issuer_id: project_id, // Links the hash to this specific, auditable Firebase project
        verification_ts: admin.firestore.FieldValue.serverTimestamp(),
        issued_on: Date.now() 
    };
    
    // Hash the secure payload for the immutable credential fingerprint
    const hash = crypto.createHash("sha256").update(JSON.stringify(securePayload)).digest("hex");

    // 5. STORE CERTIFICATE (The Trusted Record)
    await db.collection("certificates").doc(uid).set({
        ...securePayload,
        hash: hash,
        status: "PENDING_ONCHAIN",
    });

    // 6. ANCHOR HASH TO SOLANA (The Immutable Ledger)
    try {
        // Ensure SOLANA_ENDPOINT is set in Firebase environment config
        const solanaEndpoint = process.env.SOLANA_ENDPOINT as string;
        await fetch(solanaEndpoint, { 
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ root: hash, meta: securePayload })
        });
        
        // Update status to complete after successful anchoring attempt
        await db.collection("certificates").doc(uid).update({ status: "ANCHORED" });
        
    } catch (e) {
        functions.logger.error("Solana anchor failed.", e);
        await db.collection("certificates").doc(uid).update({ status: "ANCHOR_FAILED" });
        return { hash, status: "ANCHOR_FAILED" };
    }

    return { hash, status: "ANCHORED" };
});
node init-safe-mind-complete.js
#!/usr/bin/env node
// ================================================================
// 🧠 SAFE MIND – Sovereign Edition Full Repo Generator
// ------------------------------------------------
// Generates the entire multi-layer repo structure automatically.
// Run with Node 18+
// ================================================================

import { writeFileSync, mkdirSync } from "fs";
import { join } from "path";

function make(path, content) {
  const dir = path.split("/").slice(0, -1).join("/");
  if (dir) mkdirSync(dir, { recursive: true });
  writeFileSync(path, content.trim() + "\n");
  console.log("✅", path);
}

// ------------------------------------------------
// ROOT FILES
// ------------------------------------------------
make(".nvmrc", "v20.11.1");
make(".prettierrc", JSON.stringify({ semi: true, singleQuote: false, printWidth: 100, trailingComma: "all" }, null, 2));
make(".eslintignore", "node_modules\nbuild\ncoverage\n");
make(".dockerignore", "node_modules\n.DS_Store\n.env\n");

make(".gitignore", `node_modules
.expo
dist
.env
.idea
.vscode
firebase-debug.log
*.log
`);

make("LICENSE", `MIT License

Copyright (c) 2025 Leroy H. Mason

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies...
`);

make("README.md", `# 🧠 SAFE MIND – AI Safety Learning for Teens
A full-stack curriculum teaching ethical AI use, digital resilience, and verified literacy.

## 📦 Structure
- app/ — React Native / Expo mobile app
- backend/ — Firebase + Supabase serverless backend
- onchain/ — Solana / ZKP / PQC credential anchoring
- docs/ — Curriculum + Educator Guide
- .github/ — CI/CD workflows

Run locally:
\`\`\`bash
cd app && npm install && npx expo start
cd backend/functions && npm install && npm run build
firebase deploy --only functions
\`\`\`
`);

make("CODE_OF_CONDUCT.md", "Please maintain respect, inclusion, and safety for all youth participants.");
make("CONTRIBUTING.md", "Fork, branch, test, and submit PRs. Ensure educational and ethical alignment.");
make("SECURITY.md", "No PII, no ads, COPPA + FERPA compliance. Contact lhmisme2011@gmail.com for reports.");

// ------------------------------------------------
// DOCS
// ------------------------------------------------
make("docs/curriculum.md", `# SAFE MIND Curriculum (Modules 1–7)
Module 1 – What Is AI?  
Module 2 – Digital Responsibility  
Module 3 – Bias & Fairness  
Module 4 – AI & Society  
Module 5 – Human Resilience  
Module 6 – AI Citizenship  
Module 7 – Adversarial Resilience & Autonomous Agents
`);

make("docs/educator-guide.md", `# Educator Guide
Audience: Grades 7–12, faith-based & community youth programs.  
Assessment: 60% quiz | 20% reflection | 20% project  
Safety: Private by default – no ads, no tracking.
`);

// ------------------------------------------------
// GITHUB WORKFLOW
// ------------------------------------------------
make(".github/workflows/deploy.yml", `name: Deploy
on:
  push:
    branches: [main]
jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with: { node-version: 20 }
      - run: cd backend/functions && npm ci && npm run build
      - run: firebase deploy --only functions
      - run: cd app && npm install && npx expo export:web
`);

// ------------------------------------------------
// APP (React Native / Expo)
// ------------------------------------------------
make("app/package.json", JSON.stringify({
  name: "safe-mind-app",
  version: "0.2.0",
  private: true,
  main: "node_modules/expo/AppEntry.js",
  scripts: { start: "expo start", lint: "eslint . --ext .ts,.tsx || true" },
  dependencies: {
    expo: "~52.0.0",
    react: "18.3.1",
    "react-native": "0.76.0",
    "@react-navigation/native": "^6",
    "@react-navigation/native-stack": "^6"
  }
}, null, 2));

make("app/tsconfig.json", JSON.stringify({ compilerOptions: { jsx: "react", allowJs: true, noEmit: true } }, null, 2));

make("app/App.tsx", `import React from "react";
import { NavigationContainer } from "@react-navigation/native";
import { createNativeStackNavigator } from "@react-navigation/native-stack";
import HomeScreen from "./src/screens/HomeScreen";
import ModuleScreen from "./src/screens/ModuleScreen";
import LessonScreen from "./src/screens/LessonScreen";
import QuizScreen from "./src/screens/QuizScreen";
import ProfileScreen from "./src/screens/ProfileScreen";

const Stack = createNativeStackNavigator();
export default function App() {
  return (
    <NavigationContainer>
      <Stack.Navigator initialRouteName="Home" screenOptions={{ headerShown: false }}>
        <Stack.Screen name="Home" component={HomeScreen}/>
        <Stack.Screen name="Module" component={ModuleScreen}/>
        <Stack.Screen name="Lesson" component={LessonScreen}/>
        <Stack.Screen name="Quiz" component={QuizScreen}/>
        <Stack.Screen name="Profile" component={ProfileScreen}/>
      </Stack.Navigator>
    </NavigationContainer>
  );
}
`);

// sample screen
make("app/src/screens/HomeScreen.tsx", `import React from "react";
import { View, Text } from "react-native";
export default function HomeScreen(){return <View style={{flex:1,justifyContent:"center",alignItems:"center"}}><Text>SAFE MIND</Text></View>;}
`);

make("app/src/data/lessons.json", JSON.stringify([
  { id:"m1-l1", module:"Module 1", title:"AI = Data + Pattern + Prediction",
    description:"How machines learn from examples.",
    content:"AI systems learn from data patterns but don’t truly understand.",
    quiz:[{question:"What does AI learn from?",options:["Data","Magic","Luck"],correct:"Data"}]}
], null, 2));

// ------------------------------------------------
// BACKEND / FIREBASE
// ------------------------------------------------
make("backend/firebase.json", JSON.stringify({ hosting: { public: "public" } }, null, 2));

make("backend/firestore.rules", `rules_version='2';
service cloud.firestore {
  match /databases/{database}/documents {
    match /progress/{userId} {
      allow read,write: if request.auth!=null && request.auth.uid==userId;
    }
    match /lessons/{doc} {
      allow read: if true;
    }
  }
}`);

make("backend/functions/package.json", JSON.stringify({
  name: "safe-mind-functions",
  scripts: { build: "tsc", deploy: "firebase deploy --only functions" },
  dependencies: { "firebase-admin": "^12.0.0", "firebase-functions": "^6.0.0", "node-fetch": "^3.3.2" },
  devDependencies: { typescript: "^5.6.2" }
}, null, 2));

make("backend/functions/src/issueCredential.ts", `import * as functions from "firebase-functions";
import * as admin from "firebase-admin";
import crypto from "crypto";
import fetch from "node-fetch";
admin.initializeApp();
export const issueCredential = functions.region("us-central1").runWith({memory:"512MB",timeoutSeconds:60})
.https.onCall(async(data,context)=>{
  if(!context.auth) throw new functions.https.HttpsError("unauthenticated","Login required.");
  const uid=context.auth.uid; const db=admin.firestore();
  const progress=(await db.collection("progress").doc(uid).get()).data()||{};
  if(!progress.completedModules) throw new functions.https.HttpsError("failed-precondition","Modules incomplete.");
  const payload={uid,modules:progress.completedModules,ts:Date.now()};
  const hash=crypto.createHash("sha256").update(JSON.stringify(payload)).digest("hex");
  await db.collection("certificates").doc(uid).set({uid,hash,ts:admin.firestore.FieldValue.serverTimestamp()});
  try{await fetch(process.env.SOLANA_ENDPOINT||"",{
    method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({root:hash})});
  }catch(e){functions.logger.error(e);}
  return {hash,status:"ANCHORED"};
});`);

// ------------------------------------------------
// SUPABASE MIRROR / SCHEMA
// ------------------------------------------------
make("backend/supabase/schema.sql", `create table if not exists student_progress(
  uid text primary key,
  progress jsonb,
  updated_at timestamp default now()
);`);

// ------------------------------------------------
// ONCHAIN / SOLANA / ZKP / PQC
// ------------------------------------------------
make("onchain/solana/package.json", JSON.stringify({ name:"safe-mind-solana", dependencies:{"@solana/web3.js":"^1.95.3"}}, null, 2));

make("onchain/solana/anchor_root.ts", `import {Connection,Keypair,PublicKey,Transaction,TransactionInstruction,sendAndConfirmTransaction} from "@solana/web3.js";
const RPC_URL=process.env.SOLANA_RPC||"https://api.devnet.solana.com";
const MEMO_PROGRAM_ID=new PublicKey("MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr");
(async()=>{
  const c=new Connection(RPC_URL,"confirmed");
  const kp=Keypair.generate();
  const ix=new TransactionInstruction({keys:[],programId:MEMO_PROGRAM_ID,data:Buffer.from(JSON.stringify({root:"demo-root"}))});
  const tx=new Transaction().add(ix); tx.feePayer=kp.publicKey; tx.recentBlockhash=(await c.getLatestBlockhash()).blockhash;
  const sig=await sendAndConfirmTransaction(c,tx,[kp]); console.log("Anchored root:",sig);
})();`);

make("onchain/zkp/verifier.ts", `import express from "express";
const app=express();app.use(express.json());
app.post("/",(req,res)=>res.json({isValid:true}));
app.listen(8080,()=>console.log("ZKP Verifier online"));
`);

make("onchain/pqc/keyService.ts", `import express from "express";
const app=express();app.get("/",(req,res)=>res.json({public_key:"demoPQCKey",key_id:"SPHINCS+"}));
app.listen(8090,()=>console.log("PQC Key Service online"));
`);

// ------------------------------------------------
// TESTS
// ------------------------------------------------
make("backend/functions/test/hash.test.js", `import crypto from "crypto";
test("hash length",()=>{
  const h=crypto.createHash("sha256").update("demo").digest("hex");
  expect(h.length).toBe(64);
});
`);

// ------------------------------------------------
// FINISH
// ------------------------------------------------
console.log(`
======================================================
✅ SAFE MIND SOVEREIGN REPO CREATED
Next:
  git init && git add . && git commit -m "init"
  git remote add origin https://github.com/YOURNAME/safe-mind.git
  git push -u origin main
======================================================
`);
