import { describe, it, expect } from 'vitest';
import { RequestCookies } from '@edge-runtime/cookies';
import { TransactionStore } from './transaction-store.js';
import { encrypt } from './cookies.js';

const getStore = () => new TransactionStore({ secret: 'a-super-secret-key-that-is-long-enough' });

describe('TransactionStore Unhandled Rejection Vulnerability', () => {
  it('should cause an unhandled rejection when an expired cookie is replayed as a transaction cookie', async () => {
    const store = getStore();
    const state = 'some-random-state-value';
    const transactionCookieName = `__txn_${state}`;

    // Craft an expired JWE cookie value (expired 1 hour ago)
    const expiredPayload = { foo: 'bar' };
    const expirationTime = Math.floor(Date.now() / 1000) - 3600;
    const expiredCookieValue = await encrypt(expiredPayload, 'a-super-secret-key-that-is-long-enough', expirationTime);

    // Simulate attack by placing expired cookie with expected transaction cookie name
    const reqCookies = new RequestCookies(new Headers());
    reqCookies.set(transactionCookieName, expiredCookieValue);

    // Expect store.get to reject with expiration error
    await expect(store.get(reqCookies, state)).rejects.toThrow('"exp" claim timestamp check failed');
  });
});
