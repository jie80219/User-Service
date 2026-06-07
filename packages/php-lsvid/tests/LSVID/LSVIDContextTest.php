<?php

declare(strict_types=1);

namespace SDPMlab\LSVID\Tests;

use PHPUnit\Framework\TestCase;
use SDPMlab\LSVID\LSVIDContext;

final class LSVIDContextTest extends TestCase
{
    protected function setUp(): void
    {
        LSVIDContext::clear();
    }

    protected function tearDown(): void
    {
        LSVIDContext::clear();
    }

    public function testSetAndCurrent(): void
    {
        self::assertNull(LSVIDContext::current());

        LSVIDContext::set('token-abc');
        self::assertSame('token-abc', LSVIDContext::current());
    }

    public function testClearResetsToNull(): void
    {
        LSVIDContext::set('token-abc');
        LSVIDContext::clear();

        self::assertNull(LSVIDContext::current());
    }

    public function testEmptyStringIsNormalisedToNull(): void
    {
        LSVIDContext::set('');
        self::assertNull(LSVIDContext::current());
    }

    public function testNullIsAccepted(): void
    {
        LSVIDContext::set('token-abc');
        LSVIDContext::set(null);

        self::assertNull(LSVIDContext::current());
    }

    public function testOverwritesPreviousValue(): void
    {
        LSVIDContext::set('first');
        LSVIDContext::set('second');

        self::assertSame('second', LSVIDContext::current());
    }

    /**
     * Swow is loaded in this environment — verify that concurrent coroutines
     * each see their own LSVID, not each other's.
     */
    public function testSwowCoroutineIsolation(): void
    {
        if (!extension_loaded('swow')) {
            self::markTestSkipped('ext-swow not loaded.');
        }

        $results = [];

        // Coroutine A sets 'token-A', sleeps, then reads back.
        $coA = \Swow\Coroutine::run(function () use (&$results) {
            LSVIDContext::set('token-A');
            // Yield to let coroutine B run.
            \Swow\Coroutine::yield();
            $results['A'] = LSVIDContext::current();
        });

        // Coroutine B sets 'token-B', resumes A, then reads back.
        $coB = \Swow\Coroutine::run(function () use (&$results, $coA) {
            LSVIDContext::set('token-B');
            // Resume A — if static-only, A would now see 'token-B'.
            $coA->resume();
            $results['B'] = LSVIDContext::current();
        });

        self::assertSame('token-A', $results['A'], 'Coroutine A must see its own token.');
        self::assertSame('token-B', $results['B'], 'Coroutine B must see its own token.');
    }

    /**
     * Verify that the main coroutine context is independent from child coroutines.
     */
    public function testSwowMainCoroutineIndependence(): void
    {
        if (!extension_loaded('swow')) {
            self::markTestSkipped('ext-swow not loaded.');
        }

        LSVIDContext::set('main-token');

        \Swow\Coroutine::run(function () {
            // Child coroutine should NOT inherit the main token.
            LSVIDContext::set('child-token');
        });

        self::assertSame('main-token', LSVIDContext::current(), 'Main coroutine must be unaffected by child.');
    }
}
