<?php

declare(strict_types=1);

namespace SDPMlab\LSVID\Tests;

use PHPUnit\Framework\TestCase;
use SDPMlab\LSVID\JtiReplayCache;

final class JtiReplayCacheTest extends TestCase
{
    public function testFreshJtiReturnsFalse(): void
    {
        $cache = new JtiReplayCache();
        $this->assertFalse($cache->seenOrRecord('jti-1', time() + 300));
    }

    public function testDuplicateJtiReturnsTrue(): void
    {
        $cache = new JtiReplayCache();
        $cache->seenOrRecord('jti-1', time() + 300);
        $this->assertTrue($cache->seenOrRecord('jti-1', time() + 300));
    }

    public function testExpiredEntriesAreGarbageCollected(): void
    {
        $cache = new JtiReplayCache();
        // Record a jti that has already expired.
        $cache->seenOrRecord('old', time() - 10);
        // After GC (triggered by next call), old should be evicted.
        $this->assertFalse($cache->seenOrRecord('old', time() + 300));
    }

    public function testFifoEvictionWhenMaxReached(): void
    {
        $cache = new JtiReplayCache(maxEntries: 3);
        $futureExp = time() + 3600;
        $cache->seenOrRecord('a', $futureExp);
        $cache->seenOrRecord('b', $futureExp);
        $cache->seenOrRecord('c', $futureExp);
        $this->assertSame(3, $cache->size());

        // Adding a 4th should evict 'a' (the oldest).
        $cache->seenOrRecord('d', $futureExp);
        $this->assertSame(3, $cache->size());

        // 'a' should no longer be seen.
        $this->assertFalse($cache->seenOrRecord('a', $futureExp));
    }

    public function testSizeReflectsLiveEntries(): void
    {
        $cache = new JtiReplayCache();
        $this->assertSame(0, $cache->size());
        $cache->seenOrRecord('x', time() + 300);
        $this->assertSame(1, $cache->size());
        $cache->seenOrRecord('y', time() + 300);
        $this->assertSame(2, $cache->size());
    }
}
