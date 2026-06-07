<?php

declare(strict_types=1);

namespace SDPMlab\LSVID;

/**
 * Per-coroutine holder for the LSVID currently being handled.
 *
 * Automatically detects the coroutine runtime (OpenSwoole / Swow) and stores
 * the token in the coroutine-local context so that concurrent requests in the
 * same worker process never overwrite each other's LSVID.
 *
 * Falls back to a plain static variable when no coroutine runtime is loaded
 * (CLI scripts, PHPUnit, traditional FPM).
 *
 * Usage:
 *   LSVIDContext::set($rawInboundToken);
 *   try {
 *       $eventBus->dispatch($event);   // Saga::publish() will read current()
 *   } finally {
 *       LSVIDContext::clear();
 *   }
 */
final class LSVIDContext
{
    private const CTX_KEY = '__lsvid_current';

    /** Fallback for non-coroutine environments. */
    private static ?string $fallback = null;

    /** @var 'swoole'|'swow'|'none'|null */
    private static ?string $runtime = null;

    public static function set(?string $rawToken): void
    {
        $value = ($rawToken !== null && $rawToken !== '') ? $rawToken : null;

        match (self::detectRuntime()) {
            'swoole' => self::swooleSet($value),
            'swow'   => self::swowSet($value),
            default  => self::$fallback = $value,
        };
    }

    public static function current(): ?string
    {
        return match (self::detectRuntime()) {
            'swoole' => self::swooleGet(),
            'swow'   => self::swowGet(),
            default  => self::$fallback,
        };
    }

    public static function clear(): void
    {
        self::set(null);
    }

    // ── OpenSwoole / Swoole ────────────────────────────────

    private static function swooleSet(?string $value): void
    {
        $cid = \Swoole\Coroutine::getCid();
        if ($cid < 1) {
            // Not inside a coroutine — fall back to static.
            self::$fallback = $value;
            return;
        }
        $ctx = \Swoole\Coroutine::getContext($cid);
        $ctx[self::CTX_KEY] = $value;
    }

    private static function swooleGet(): ?string
    {
        $cid = \Swoole\Coroutine::getCid();
        if ($cid < 1) {
            return self::$fallback;
        }
        $ctx = \Swoole\Coroutine::getContext($cid);
        return $ctx[self::CTX_KEY] ?? null;
    }

    // ── Swow ───────────────────────────────────────────────

    /** @var array<int, ?string> Coroutine-ID → token */
    private static array $swowStore = [];

    private static function swowSet(?string $value): void
    {
        $id = \Swow\Coroutine::getCurrent()->getId();
        if ($value === null) {
            unset(self::$swowStore[$id]);
        } else {
            self::$swowStore[$id] = $value;
        }
    }

    private static function swowGet(): ?string
    {
        $id = \Swow\Coroutine::getCurrent()->getId();
        return self::$swowStore[$id] ?? null;
    }

    // ── Runtime detection (cached) ─────────────────────────

    /** @return 'swoole'|'swow'|'none' */
    private static function detectRuntime(): string
    {
        if (self::$runtime !== null) {
            return self::$runtime;
        }

        if (extension_loaded('swoole') || extension_loaded('openswoole')) {
            return self::$runtime = 'swoole';
        }

        if (extension_loaded('swow')) {
            return self::$runtime = 'swow';
        }

        return self::$runtime = 'none';
    }

    /**
     * Reset the cached runtime detection.
     * Intended for testing only.
     */
    public static function resetRuntimeDetection(): void
    {
        self::$runtime = null;
        self::$fallback = null;
        self::$swowStore = [];
    }
}
