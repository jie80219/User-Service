<?php

declare(strict_types=1);

namespace SDPMlab\LSVID\Tests;

use PHPUnit\Framework\TestCase;
use SDPMlab\LSVID\JtiReplayCache;
use SDPMlab\LSVID\LSVIDException;
use SDPMlab\LSVID\LSVIDSigner;
use SDPMlab\LSVID\LSVIDValidator;

final class LSVIDValidatorTest extends TestCase
{
    private TestSvidReader $gwReader;
    private TestSvidReader $wkReader;
    private LSVIDSigner $gwSigner;
    private LSVIDSigner $wkSigner;
    private LSVIDValidator $validator;
    private JtiReplayCache $jtiCache;

    protected function setUp(): void
    {
        $this->gwReader = TestSvidReader::create('spiffe://test.local/gateway');
        $this->wkReader = $this->gwReader->deriveWorkload('spiffe://test.local/worker');
        $this->gwSigner = new LSVIDSigner($this->gwReader, defaultTtlSeconds: 300);
        $this->wkSigner = new LSVIDSigner($this->wkReader, defaultTtlSeconds: 300);
        $this->jtiCache = new JtiReplayCache();
        $this->validator = new LSVIDValidator($this->wkReader, clockSkewSeconds: 30, jtiCache: $this->jtiCache);
    }

    // ── Happy path ───────────────────────────────────────────

    public function testValidatesL0Successfully(): void
    {
        $l0 = $this->gwSigner->createBase(audience: 'spiffe://test.local/worker');
        // Validate using the worker reader (has same CA bundle).
        $validator = new LSVIDValidator($this->gwReader, clockSkewSeconds: 30, jtiCache: $this->jtiCache);
        $parsed = $validator->validate($l0->raw);
        $this->assertSame(0, $parsed->level());
    }

    public function testValidatesL0ToL1Chain(): void
    {
        $l0 = $this->gwSigner->createBase(audience: 'spiffe://test.local/worker');
        $l1 = $this->wkSigner->extend(
            priorRawToken: $l0->raw,
            audience: 'spiffe://test.local/downstream',
        );

        $parsed = $this->validator->validate($l1->raw);
        $this->assertSame(1, $parsed->level());
        $chain = $parsed->chain();
        $this->assertSame('spiffe://test.local/gateway', $chain[0]->issuer());
        $this->assertSame('spiffe://test.local/worker', $chain[1]->issuer());
    }

    public function testExpectedAudiencePassesWhenMatching(): void
    {
        $l0 = $this->gwSigner->createBase(audience: 'spiffe://test.local/worker');
        $validator = new LSVIDValidator($this->gwReader, clockSkewSeconds: 30);
        $parsed = $validator->validate($l0->raw, expectedAudience: 'spiffe://test.local/worker');
        $this->assertSame('spiffe://test.local/worker', $parsed->audience());
    }

    public function testExpectedSubjectPassesWhenMatching(): void
    {
        $l0 = $this->gwSigner->createBase(audience: 'spiffe://test.local/worker');
        $validator = new LSVIDValidator($this->gwReader, clockSkewSeconds: 30);
        $parsed = $validator->validate(
            $l0->raw,
            expectedSubject: 'spiffe://test.local/gateway',
        );
        $this->assertSame('spiffe://test.local/gateway', $parsed->subject());
    }

    // ── Failures ─────────────────────────────────────────────

    public function testFailsOnTamperedPayload(): void
    {
        $l0 = $this->gwSigner->createBase(audience: 'spiffe://test.local/worker');
        // Flip a byte in the payload segment.
        $parts = explode('.', $l0->raw);
        $parts[1] = substr($parts[1], 0, -1) . 'X';
        $tampered = implode('.', $parts);

        $validator = new LSVIDValidator($this->gwReader, clockSkewSeconds: 30);
        $this->expectException(LSVIDException::class);
        $validator->validate($tampered);
    }

    public function testFailsOnAudienceMismatch(): void
    {
        $l0 = $this->gwSigner->createBase(audience: 'spiffe://test.local/worker');
        $validator = new LSVIDValidator($this->gwReader, clockSkewSeconds: 30);
        $this->expectException(LSVIDException::class);
        $this->expectExceptionMessage('audience mismatch');
        $validator->validate($l0->raw, expectedAudience: 'spiffe://test.local/other');
    }

    public function testFailsOnSubjectMismatch(): void
    {
        $l0 = $this->gwSigner->createBase(audience: 'spiffe://test.local/worker');
        $validator = new LSVIDValidator($this->gwReader, clockSkewSeconds: 30);
        $this->expectException(LSVIDException::class);
        $this->expectExceptionMessage('L0 subject mismatch');
        $validator->validate($l0->raw, expectedSubject: 'spiffe://test.local/attacker');
    }

    public function testChainContinuityEnforced(): void
    {
        // Build L0 with aud = "wrong-target" (not the worker).
        // Then worker extends it — chain continuity should fail because
        // L0.aud !== L1.iss.
        $l0 = $this->gwSigner->createBase(audience: 'spiffe://test.local/wrong-target');
        $l1 = $this->wkSigner->extend(
            priorRawToken: $l0->raw,
            audience: 'spiffe://test.local/downstream',
        );

        $this->expectException(LSVIDException::class);
        $this->expectExceptionMessage('chain broken');
        $this->validator->validate($l1->raw);
    }

    public function testJtiReplayDetected(): void
    {
        $l0 = $this->gwSigner->createBase(audience: 'spiffe://test.local/worker');
        $validator = new LSVIDValidator($this->gwReader, clockSkewSeconds: 30, jtiCache: $this->jtiCache);
        // First validation succeeds.
        $validator->validate($l0->raw);
        // Second with same jti should fail.
        $this->expectException(LSVIDException::class);
        $this->expectExceptionMessage('replay detected');
        $validator->validate($l0->raw);
    }

    public function testEmptyTrustBundleThrows(): void
    {
        $emptyReader = new class implements \SDPMlab\LSVID\SvidReader {
            public function readX509Primary(): ?array
            {
                return ['spiffe_id' => 'x', 'trust_domain' => 'x', 'cert_pem' => '', 'key_pem' => '', 'bundle_pem' => '', 'hint' => '', 'updated_at' => 0];
            }
        };
        $validator = new LSVIDValidator($emptyReader);
        $l0 = $this->gwSigner->createBase(audience: 'x');
        $this->expectException(LSVIDException::class);
        $this->expectExceptionMessage('Trust bundle is empty');
        $validator->validate($l0->raw);
    }
}
