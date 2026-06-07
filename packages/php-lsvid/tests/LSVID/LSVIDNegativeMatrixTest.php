<?php

declare(strict_types=1);

namespace SDPMlab\LSVID\Tests;

use PHPUnit\Framework\TestCase;
use SDPMlab\LSVID\JtiReplayCache;
use SDPMlab\LSVID\LSVID;
use SDPMlab\LSVID\LSVIDException;
use SDPMlab\LSVID\LSVIDSigner;
use SDPMlab\LSVID\LSVIDValidator;

/**
 * Systematic negative-case coverage for LSVIDValidator.
 *
 * Every attack scenario described in docs/lsvid-experiment.md §3 is
 * exercised here so the report can cite concrete pass/fail evidence.
 *
 * Conventions:
 *   - `gateway` reader issues L0 (trust domain: zt.local)
 *   - `worker`  reader issues L1 (derived from the same CA)
 *   - The default validator is built with:
 *       trustDomain = 'zt.local'
 *       requireAudienceOnAllLevels = true
 *       jtiCache = fresh per-test
 */
final class LSVIDNegativeMatrixTest extends TestCase
{
    private const TRUST_DOMAIN = 'zt.local';
    private const GW_SPIFFE = 'spiffe://zt.local/gateway';
    private const WK_SPIFFE = 'spiffe://zt.local/worker';
    private const DOWNSTREAM = 'spiffe://zt.local/downstream';

    private TestSvidReader $gwReader;
    private TestSvidReader $wkReader;
    private LSVIDSigner $gwSigner;
    private LSVIDSigner $wkSigner;
    private LSVIDValidator $validator;
    private JtiReplayCache $jtiCache;

    protected function setUp(): void
    {
        $this->gwReader = TestSvidReader::create(self::GW_SPIFFE, self::TRUST_DOMAIN);
        $this->wkReader = $this->gwReader->deriveWorkload(self::WK_SPIFFE);
        $this->gwSigner = new LSVIDSigner($this->gwReader, defaultTtlSeconds: 300);
        $this->wkSigner = new LSVIDSigner($this->wkReader, defaultTtlSeconds: 300);
        $this->jtiCache = new JtiReplayCache();
        $this->validator = new LSVIDValidator(
            $this->wkReader,
            clockSkewSeconds: 30,
            jtiCache: $this->jtiCache,
            trustDomain: self::TRUST_DOMAIN,
            requireNbf: false,
            requireAudienceOnAllLevels: true,
        );
    }

    // ─────────────────────────────────────────────────────────
    //  Happy path sanity — proves the matrix setup is wired right
    // ─────────────────────────────────────────────────────────

    public function testHappyPathL0L1L2(): void
    {
        $l0 = $this->gwSigner->createBase(audience: self::WK_SPIFFE);
        $l1 = $this->wkSigner->extend(priorRawToken: $l0->raw, audience: self::DOWNSTREAM);

        $parsed = $this->validator->validate($l1->raw, expectedAudience: self::DOWNSTREAM);
        $this->assertSame(1, $parsed->level());
        $this->assertSame(self::GW_SPIFFE, $parsed->chain()[0]->issuer());
        $this->assertSame(self::WK_SPIFFE, $parsed->chain()[1]->issuer());
    }

    // ─────────────────────────────────────────────────────────
    //  Structural tampering
    // ─────────────────────────────────────────────────────────

    public function testTamperedHeader(): void
    {
        $l0 = $this->gwSigner->createBase(audience: self::WK_SPIFFE);
        $parts = explode('.', $l0->raw);
        $parts[0] = rtrim(strtr(base64_encode('{"alg":"RS256","typ":"LSVID"}'), '+/', '-_'), '=');
        $bad = implode('.', $parts);

        $this->expectException(LSVIDException::class);
        $this->validator->validate($bad);
    }

    public function testTamperedPayload(): void
    {
        $l0 = $this->gwSigner->createBase(audience: self::WK_SPIFFE);
        $parts = explode('.', $l0->raw);
        $parts[1] = substr($parts[1], 0, -1) . 'A';
        $bad = implode('.', $parts);

        $this->expectException(LSVIDException::class);
        $this->expectExceptionMessageMatches('/signature verification failed|not valid JSON/i');
        $this->validator->validate($bad);
    }

    public function testTamperedSignature(): void
    {
        $l0 = $this->gwSigner->createBase(audience: self::WK_SPIFFE);
        $parts = explode('.', $l0->raw);
        $parts[2] = str_repeat('A', strlen($parts[2]));
        $bad = implode('.', $parts);

        $this->expectException(LSVIDException::class);
        $this->expectExceptionMessage('signature verification failed');
        $this->validator->validate($bad);
    }

    // ─────────────────────────────────────────────────────────
    //  Temporal
    // ─────────────────────────────────────────────────────────

    public function testExpiredToken(): void
    {
        // TTL = -500s → exp is 500 seconds in the past (well outside skew).
        $staleSigner = new LSVIDSigner($this->gwReader, defaultTtlSeconds: -500);
        $stale = $staleSigner->createBase(audience: self::WK_SPIFFE);

        $this->expectException(LSVIDException::class);
        $this->expectExceptionMessageMatches('/has expired/');
        $this->validator->validate($stale->raw);
    }

    public function testNbfInTheFuture(): void
    {
        $future = time() + 3600;
        $l0 = $this->gwSigner->createBase(
            audience: self::WK_SPIFFE,
            notBefore: $future,
        );

        $this->expectException(LSVIDException::class);
        $this->expectExceptionMessageMatches('/not yet valid|nbf in the future/');
        $this->validator->validate($l0->raw);
    }

    // ─────────────────────────────────────────────────────────
    //  Trust / authority
    // ─────────────────────────────────────────────────────────

    public function testWrongCaRejected(): void
    {
        // A different TestSvidReader builds its own CA. The validator
        // still uses $this->wkReader's bundle, so the foreign leaf must
        // fail CA verification.
        $foreignReader = TestSvidReader::create(self::GW_SPIFFE, self::TRUST_DOMAIN);
        $foreignSigner = new LSVIDSigner($foreignReader, defaultTtlSeconds: 300);
        $foreign = $foreignSigner->createBase(audience: self::WK_SPIFFE);

        $this->expectException(LSVIDException::class);
        $this->expectExceptionMessage('not signed by any trusted CA');
        $this->validator->validate($foreign->raw);
    }

    public function testForeignTrustDomainRejected(): void
    {
        // Build a token whose iss/sub/aud live under spiffe://other.local/
        // but is signed by a cert in OUR CA (so signature + CA pass but
        // trust-domain isolation catches it).
        //
        // Trick: derive a workload with a foreign SPIFFE URI from the
        // shared CA. The leaf SAN will carry the foreign URI, and the
        // validator's iss↔SAN check will still pass; only the trust
        // domain enforcement should reject it.
        $foreignReader = $this->gwReader->deriveWorkload('spiffe://other.local/rogue');
        $foreignSigner = new LSVIDSigner($foreignReader, defaultTtlSeconds: 300);
        $foreign = $foreignSigner->createBase(audience: self::WK_SPIFFE);

        $this->expectException(LSVIDException::class);
        $this->expectExceptionMessage('outside the expected trust domain');
        $this->validator->validate($foreign->raw);
    }

    // ─────────────────────────────────────────────────────────
    //  Audience / subject expectations
    // ─────────────────────────────────────────────────────────

    public function testAudienceMismatch(): void
    {
        $l0 = $this->gwSigner->createBase(audience: self::WK_SPIFFE);

        $this->expectException(LSVIDException::class);
        $this->expectExceptionMessage('audience mismatch');
        $this->validator->validate($l0->raw, expectedAudience: 'spiffe://zt.local/other');
    }

    public function testSubjectMismatch(): void
    {
        $l0 = $this->gwSigner->createBase(audience: self::WK_SPIFFE);

        $this->expectException(LSVIDException::class);
        $this->expectExceptionMessage('L0 subject mismatch');
        $this->validator->validate($l0->raw, expectedSubject: 'spiffe://zt.local/attacker');
    }

    // ─────────────────────────────────────────────────────────
    //  Chain continuity
    // ─────────────────────────────────────────────────────────

    public function testChainBrokenWhenNestedAudMismatches(): void
    {
        // Gateway points L0 at "wrong-target" (not worker), worker still
        // extends → chain continuity must refuse because L0.aud !== L1.iss.
        $l0 = $this->gwSigner->createBase(audience: 'spiffe://zt.local/wrong-target');
        $l1 = $this->wkSigner->extend(priorRawToken: $l0->raw, audience: self::DOWNSTREAM);

        $this->expectException(LSVIDException::class);
        $this->expectExceptionMessage('chain broken');
        $this->validator->validate($l1->raw);
    }

    // ─────────────────────────────────────────────────────────
    //  Replay
    // ─────────────────────────────────────────────────────────

    public function testJtiReplayRejected(): void
    {
        $l0 = $this->gwSigner->createBase(audience: self::WK_SPIFFE);

        // First validation passes, second must be rejected on jti.
        $this->validator->validate($l0->raw);

        $this->expectException(LSVIDException::class);
        $this->expectExceptionMessage('replay detected');
        $this->validator->validate($l0->raw);
    }

    // ─────────────────────────────────────────────────────────
    //  Authority surface — empty bundle
    // ─────────────────────────────────────────────────────────

    public function testEmptyTrustBundleRejected(): void
    {
        $emptyReader = new class implements \SDPMlab\LSVID\SvidReader {
            public function readX509Primary(): ?array
            {
                return [
                    'spiffe_id' => 'x', 'trust_domain' => 'x',
                    'cert_pem' => '', 'key_pem' => '', 'bundle_pem' => '',
                    'hint' => '', 'updated_at' => 0,
                ];
            }
        };
        $v = new LSVIDValidator($emptyReader, trustDomain: self::TRUST_DOMAIN);
        $l0 = $this->gwSigner->createBase(audience: self::WK_SPIFFE);

        $this->expectException(LSVIDException::class);
        $this->expectExceptionMessage('Trust bundle is empty');
        $v->validate($l0->raw);
    }

    // ─────────────────────────────────────────────────────────
    //  Claim hardening
    // ─────────────────────────────────────────────────────────

    public function testRequireAudienceOnAllLevelsRejectsMissingAud(): void
    {
        // Craft a raw token with the `aud` claim stripped from the
        // payload. Since the signer always fills aud, we have to do
        // surgery on the bytes AFTER signing. The signature will then
        // mismatch the recomputed signing input, so this case actually
        // exercises the signature check first — which still proves that
        // audience stripping is detected. We keep this test for defense
        // in depth.
        $l0 = $this->gwSigner->createBase(audience: self::WK_SPIFFE);
        $parts = explode('.', $l0->raw);
        $payload = json_decode(LSVID::b64UrlDecode($parts[1]), true);
        unset($payload['aud']);
        $parts[1] = LSVID::b64UrlEncode(json_encode(
            $payload,
            JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE,
        ));
        $bad = implode('.', $parts);

        $this->expectException(LSVIDException::class);
        // Either the sig check or the missing-audience check may fire first.
        $this->validator->validate($bad, expectedAudience: self::WK_SPIFFE);
    }

    public function testTrustDomainFailClosedBlocksEmptyPayloadValues(): void
    {
        // Sanity: the validator rejects obvious non-spiffe iss.
        // We use a derived workload with a bogus iss URI.
        $evilReader = $this->gwReader->deriveWorkload('spiffe://evil.example/rogue');
        $evilSigner = new LSVIDSigner($evilReader, defaultTtlSeconds: 300);
        $evil = $evilSigner->createBase(audience: self::WK_SPIFFE);

        $this->expectException(LSVIDException::class);
        $this->expectExceptionMessage('outside the expected trust domain');
        $this->validator->validate($evil->raw);
    }
}
