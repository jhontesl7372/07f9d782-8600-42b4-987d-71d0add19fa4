import { encrypt, decrypt } from './src/server/cookies.js';
import { SessionData, ConnectionTokenSet } from './src/types/index.js';

async function main() {
  console.log('--- Starting Type Confusion Verification Script ---');

  const secret = 'super-secret-key-that-is-long-enough';

  const sessionData: SessionData = {
    user: { sub: 'user-123' },
    tokenSet: { accessToken: 'access-token', idToken: 'id-token', expiresAt: 0 },
    internal: { createdAt: Date.now(), sid: 'sid-abc' }
  };

  console.log('Original SessionData:', JSON.stringify(sessionData, null, 2));

  // 1. Encrypt a valid SessionData object.
  const encryptedSession = await encrypt(sessionData, secret, 0);
  console.log('\nEncrypted Paseto Token:', encryptedSession);

  // 2. Attempt to decrypt it as a ConnectionTokenSet.
  let decryptedPayload: ConnectionTokenSet | null = null;
  let error: any = null;

  try {
    console.log('\nAttempting to decrypt as ConnectionTokenSet...');
    const result = await decrypt<ConnectionTokenSet>(encryptedSession, secret);
    decryptedPayload = result?.payload ?? null;
  } catch (e) {
    error = e;
  }

  console.log('\n--- Decryption Result ---');
  console.log('Error:', error ? error.message : 'No error caught');
  console.log('Decrypted Payload:', JSON.stringify(decryptedPayload, null, 2));

  // 3. Analyze the outcome.
  if (error) {
    console.log('\n--- Analysis ---');
    console.log('Decryption failed with an error. This is not the expected outcome.');
  } else if (decryptedPayload) {
    console.log('\n--- Analysis ---');
    const hasUserProperty = 'user' in decryptedPayload;
    const hasConnectionProperty = 'connection' in decryptedPayload;
    console.log(`Payload has 'user' property (from SessionData): ${hasUserProperty}`);
    console.log(`Payload has 'connection' property (from ConnectionTokenSet): ${hasConnectionProperty}`);

    if (hasUserProperty && !hasConnectionProperty) {
      console.log('\n[VULNERABILITY CONFIRMED]: Decryption succeeded, but the payload is a SessionData object, not a ConnectionTokenSet. Type confusion is confirmed.');
    } else {
      console.log('\n[UNEXPECTED RESULT]: Decryption succeeded, but the payload structure is not what was expected. Further investigation needed.');
    }
  } else {
      console.log('\n[UNEXPECTED RESULT]: Decryption resulted in a null payload without throwing an error.');
  }
}

main().catch(err => {
  console.error('Script failed with an unhandled error:', err);
});
