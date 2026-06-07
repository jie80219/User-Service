<?php

declare(strict_types=1);

namespace SDPMlab\LSVID\Tests;

use PHPUnit\Framework\TestCase;
use SDPMlab\LSVID\LSVID;
use SDPMlab\LSVID\LSVIDException;

final class LSVIDParseTest extends TestCase
{
    public function testParsesValidThreeSegmentToken(): void
    {
        $header = LSVID::b64UrlEncode(json_encode(['alg' => 'ES256', 'typ' => 'LSVID']));
        $payload = LSVID::b64UrlEncode(json_encode([
            'iss' => 'spiffe://test.local/gw',
            'sub' => 'spiffe://test.local/gw',
            'iat' => time(),
            'exp' => time() + 300,
            'jti' => 'abc123',
        ]));
        $sig = LSVID::b64UrlEncode('fakesig');
        $raw = "$header.$payload.$sig";

        $lsvid = LSVID::parse($raw);
        $this->assertSame('spiffe://test.local/gw', $lsvid->issuer());
        $this->assertSame('spiffe://test.local/gw', $lsvid->subject());
        $this->assertSame('abc123', $lsvid->tokenId());
        $this->assertNull($lsvid->nested);
        $this->assertSame(0, $lsvid->level());
    }

    public function testRejectsTokenWithWrongNumberOfSegments(): void
    {
        $this->expectException(LSVIDException::class);
        $this->expectExceptionMessage('three dot-separated');
        LSVID::parse('only.two');
    }

    public function testRejectsInvalidJsonPayload(): void
    {
        $header = LSVID::b64UrlEncode(json_encode(['alg' => 'ES256', 'typ' => 'LSVID']));
        $payload = LSVID::b64UrlEncode('not json');
        $sig = LSVID::b64UrlEncode('sig');

        $this->expectException(LSVIDException::class);
        $this->expectExceptionMessage('not valid JSON');
        LSVID::parse("$header.$payload.$sig");
    }

    public function testRejectsWrongTyp(): void
    {
        $header = LSVID::b64UrlEncode(json_encode(['alg' => 'ES256', 'typ' => 'JWT']));
        $payload = LSVID::b64UrlEncode(json_encode(['iss' => 'x']));
        $sig = LSVID::b64UrlEncode('sig');

        $this->expectException(LSVIDException::class);
        $this->expectExceptionMessage('Unexpected LSVID typ');
        LSVID::parse("$header.$payload.$sig");
    }

    public function testMaxDepthPreventsDeepRecursion(): void
    {
        // Build a chain deeper than MAX_NESTED_DEPTH.
        $depth = LSVID::MAX_NESTED_DEPTH + 2;
        $token = $this->buildNested($depth);

        $this->expectException(LSVIDException::class);
        $this->expectExceptionMessage('nesting depth exceeds limit');
        LSVID::parse($token);
    }

    public function testCustomMaxDepthWorks(): void
    {
        $token = $this->buildNested(3);
        // Should throw at depth 2.
        $this->expectException(LSVIDException::class);
        LSVID::parse($token, maxDepth: 2);
    }

    public function testChainReturnsRootFirst(): void
    {
        $inner = $this->buildNested(0, iss: 'inner');
        $outer = $this->buildNested(0, iss: 'outer', nested: $inner);

        $lsvid = LSVID::parse($outer);
        $chain = $lsvid->chain();
        $this->assertCount(2, $chain);
        $this->assertSame('inner', $chain[0]->issuer());
        $this->assertSame('outer', $chain[1]->issuer());
    }

    // ── Helpers ───────────────────────────────────────────────

    private function buildNested(int $depth, string $iss = 'test', ?string $nested = null): string
    {
        $payload = ['iss' => $iss, 'sub' => $iss, 'iat' => time(), 'exp' => time() + 300, 'jti' => bin2hex(random_bytes(4))];
        if ($nested !== null) {
            $payload['nested'] = $nested;
        }

        $token = LSVID::b64UrlEncode(json_encode(['alg' => 'ES256', 'typ' => 'LSVID']))
            . '.' . LSVID::b64UrlEncode(json_encode($payload))
            . '.' . LSVID::b64UrlEncode('sig');

        if ($depth <= 0) {
            return $token;
        }

        return $this->buildNested($depth - 1, $iss, $token);
    }
}
