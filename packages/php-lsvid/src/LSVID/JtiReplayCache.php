<?php

declare(strict_types=1);

namespace SDPMlab\LSVID;

/**
 * Lightweight, per-process JTI replay cache.
 *
 * Tracks which `jti` values have been seen during this process's lifetime.
 * Entries are passively expired based on the LSVID `exp` timestamp, and a
 * FIFO eviction fires when the cache exceeds $maxEntries. This is adequate
 * for a single PHP worker process; cross-worker / cross-instance replay
 * protection would require a shared store (Redis, etc.) and is intentionally
 * out of scope.
 */
final class JtiReplayCache
{
    /** @var array<string, int> jti → exp timestamp */
    private array $entries = [];

    public function __construct(
        private readonly int $maxEntries = 4096,
    ) {
    }

    /**
     * Check whether $jti has been seen before. If not, record it.
     *
     * @param string $jti Token identifier to check
     * @param int    $exp Expiry timestamp — used for passive garbage collection
     *
     * @return bool True if $jti was already present (replay), false if freshly recorded.
     */
    public function seenOrRecord(string $jti, int $exp): bool
    {
        $this->garbageCollect();

        if (isset($this->entries[$jti])) {
            return true;
        }

        // FIFO eviction: remove oldest entries until we are under the limit.
        while (count($this->entries) >= $this->maxEntries) {
            // array_key_first is O(1) for insertion-ordered PHP arrays.
            $oldest = array_key_first($this->entries);
            if ($oldest === null) {
                break;
            }
            unset($this->entries[$oldest]);
        }

        $this->entries[$jti] = $exp;
        return false;
    }

    public function size(): int
    {
        return count($this->entries);
    }

    /**
     * Remove entries whose exp timestamp has passed.
     */
    private function garbageCollect(): void
    {
        $now = time();
        foreach ($this->entries as $jti => $exp) {
            if ($exp < $now) {
                unset($this->entries[$jti]);
            }
        }
    }
}
