<?php

declare(strict_types=1);

namespace SDPMlab\LSVID\Tests;

use PHPUnit\Framework\TestCase;
use SDPMlab\LSVID\LSVID;
use SDPMlab\LSVID\LSVIDException;
use SDPMlab\LSVID\LSVIDSigner;

final class LSVIDSignerTest extends TestCase
{
    private TestSvidReader $reader;
    private LSVIDSigner $signer;

    protected function setUp(): void
    {
        $this->reader = TestSvidReader::create('spiffe://test.local/gateway');
        $this->signer = new LSVIDSigner($this->reader, defaultTtlSeconds: 300);
    }

    // ── createBase() ─────────────────────────────────────────

    public function testCreateBaseProducesL0WithRequiredClaims(): void
    {
        $l0 = $this->signer->createBase(
            audience: 'spiffe://test.local/worker',
            extraClaims: ['traceId' => 'test-trace'],
        );

        $this->assertSame(0, $l0->level());
        $this->assertSame('spiffe://test.local/gateway', $l0->issuer());
        $this->assertSame('spiffe://test.local/gateway', $l0->subject());
        $this->assertSame('spiffe://test.local/worker', $l0->audience());
        $this->assertNotNull($l0->issuedAt());
        $this->assertNotNull($l0->expiresAt());
        $this->assertNotNull($l0->tokenId());
        $this->assertSame('test-trace', $l0->payload['traceId']);
        $this->assertNull($l0->nested);
    }

    public function testCreateBaseThrowsOnEmptyAudience(): void
    {
        $this->expectException(LSVIDException::class);
        $this->expectExceptionMessage('audience');
        $this->signer->createBase(audience: '');
    }

    public function testCreateBaseStripsReservedClaims(): void
    {
        $l0 = $this->signer->createBase(
            audience: 'spiffe://test.local/worker',
            extraClaims: [
                'iss' => 'attacker',
                'sub' => 'attacker',
                'iat' => 0,
                'exp' => PHP_INT_MAX,
                'jti' => 'fixed',
                'nested' => 'injected',
                'custom' => 'kept',
            ],
        );

        // Reserved claims must be set by signer, not caller.
        $this->assertSame('spiffe://test.local/gateway', $l0->issuer());
        $this->assertSame('spiffe://test.local/gateway', $l0->subject());
        $this->assertNotSame(0, $l0->issuedAt());
        $this->assertNotSame(PHP_INT_MAX, $l0->expiresAt());
        $this->assertNotSame('fixed', $l0->tokenId());
        $this->assertNull($l0->nested);
        // Custom claims pass through.
        $this->assertSame('kept', $l0->payload['custom']);
    }

    public function testCreateBaseWithExplicitSubject(): void
    {
        $l0 = $this->signer->createBase(
            audience: 'spiffe://test.local/worker',
            subject: 'spiffe://test.local/other-workload',
        );

        $this->assertSame('spiffe://test.local/gateway', $l0->issuer());
        $this->assertSame('spiffe://test.local/other-workload', $l0->subject());
    }

    // ── extend() ─────────────────────────────────────────────

    public function testExtendProducesL1WithNestedL0(): void
    {
        $l0 = $this->signer->createBase(audience: 'spiffe://test.local/worker');
        $l1 = $this->signer->extend(
            priorRawToken: $l0->raw,
            audience: 'spiffe://test.local/downstream',
            extraClaims: ['level' => 'L1'],
        );

        $this->assertSame(1, $l1->level());
        $this->assertNotNull($l1->nested);
        $this->assertSame(0, $l1->nested->level());
        $this->assertSame('spiffe://test.local/downstream', $l1->audience());
        $this->assertSame('L1', $l1->payload['level']);
    }

    public function testExtendThrowsOnEmptyPrior(): void
    {
        $this->expectException(LSVIDException::class);
        $this->expectExceptionMessage('prior raw token');
        $this->signer->extend(priorRawToken: '', audience: 'x');
    }

    public function testExtendThrowsOnEmptyAudience(): void
    {
        $l0 = $this->signer->createBase(audience: 'spiffe://test.local/worker');
        $this->expectException(LSVIDException::class);
        $this->expectExceptionMessage('audience');
        $this->signer->extend(priorRawToken: $l0->raw, audience: '');
    }

    // ── sign() backward compat ───────────────────────────────

    public function testSignBackwardCompatStillWorks(): void
    {
        $lsvid = $this->signer->sign(
            claims: ['custom' => 'value'],
            priorRawToken: null,
            audience: 'spiffe://test.local/worker',
        );

        $this->assertSame(0, $lsvid->level());
        $this->assertSame('spiffe://test.local/gateway', $lsvid->issuer());
        $this->assertNotNull($lsvid->tokenId());
    }

    // ── Round-trip (sign → parse) ─────────────────────────────

    public function testRoundTripParsePreservesFields(): void
    {
        $l0 = $this->signer->createBase(audience: 'spiffe://test.local/worker');
        $parsed = LSVID::parse($l0->raw);

        $this->assertSame($l0->issuer(), $parsed->issuer());
        $this->assertSame($l0->subject(), $parsed->subject());
        $this->assertSame($l0->audience(), $parsed->audience());
        $this->assertSame($l0->tokenId(), $parsed->tokenId());
        $this->assertSame($l0->issuedAt(), $parsed->issuedAt());
        $this->assertSame($l0->expiresAt(), $parsed->expiresAt());
    }

    public function testUniqueJtiPerCall(): void
    {
        $a = $this->signer->createBase(audience: 'spiffe://test.local/worker');
        $b = $this->signer->createBase(audience: 'spiffe://test.local/worker');
        $this->assertNotSame($a->tokenId(), $b->tokenId());
    }
}
