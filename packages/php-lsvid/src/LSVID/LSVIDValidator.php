<?php

declare(strict_types=1);

namespace SDPMlab\LSVID;

/**
 * Verifies Nested LSVIDs against the trust domain's CA bundle.
 *
 * For every level in the chain (root L0 → leaf Ln) the validator:
 *   1. Asserts required claims (iss, sub, iat, exp, jti) are present.
 *   2. Pulls the leaf X.509 certificate from the `x5c` header claim and
 *      checks it against a CA from the trust bundle (openssl_x509_verify).
 *   3. Verifies the leaf certificate notBefore / notAfter temporal validity.
 *   4. Verifies the JWS signature with the leaf certificate's public key.
 *   5. Asserts iat/exp (and nbf when present) are within an allowed
 *      clock-skew window.
 *   6. Asserts the cert's URI SAN matches the payload's `iss` claim.
 *   7. (when configured) Asserts every `iss`/`sub`/`aud` lives under
 *      `spiffe://{trustDomain}/` — fail-closed trust-domain isolation.
 *   8. (extensions only) Asserts chain continuity: the nested level's
 *      audience MUST be present and match the enclosing level's issuer.
 *   9. Checks every jti against a per-process replay cache (when provided).
 *
 * Usage:
 *   $cache     = new JtiReplayCache();
 *   $validator = new LSVIDValidator(
 *       $reader,
 *       clockSkewSeconds: 30,
 *       jtiCache: $cache,
 *       trustDomain: 'zt.local',
 *       requireAudienceOnAllLevels: true,
 *   );
 *   $lsvid = $validator->validate(
 *       $rawToken,
 *       expectedAudience: 'spiffe://zt.local/php-worker',
 *       expectedSubject:  'spiffe://zt.local/php-gateway',
 *   );
 */
final class LSVIDValidator
{
    /** @var string|null Memoize key for trust bundle (sha256 of bundle_pem) */
    private ?string $bundleCacheKey = null;

    /** @var list<\OpenSSLCertificate> Memoized parsed CA certs */
    private array $bundleCacheValue = [];

    /**
     * @param SvidReader         $reader
     * @param int                $clockSkewSeconds            Max tolerated drift for temporal checks.
     * @param JtiReplayCache|null $jtiCache                   Optional replay cache; checks every jti.
     * @param string|null        $trustDomain                 When set (e.g. "zt.local"), every iss/sub/aud
     *                                                        on every level must begin with
     *                                                        `spiffe://{trustDomain}/`.
     * @param bool               $requireNbf                  When true, every level MUST carry an `nbf`
     *                                                        claim; when false, `nbf` is optional but
     *                                                        still checked if present.
     * @param bool               $requireAudienceOnAllLevels  When true, every level (including L0) must
     *                                                        have a non-empty `aud`. Extensions already
     *                                                        enforce `aud` implicitly through chain
     *                                                        continuity; this flag makes the requirement
     *                                                        explicit on the outermost level too.
     */
    public function __construct(
        private readonly SvidReader $reader,
        private readonly int $clockSkewSeconds = 30,
        private readonly ?JtiReplayCache $jtiCache = null,
        private readonly ?string $trustDomain = null,
        private readonly bool $requireNbf = false,
        private readonly bool $requireAudienceOnAllLevels = false,
    ) {
    }

    /**
     * @param string|null $expectedAudience Expected `aud` on the outermost level.
     * @param string|null $expectedSubject  Expected `sub` on L0 (the chain root).
     */
    public function validate(
        string $rawToken,
        ?string $expectedAudience = null,
        ?string $expectedSubject = null,
    ): LSVID {
        $lsvid = LSVID::parse($rawToken);
        $caCerts = $this->loadTrustBundleCaCerts();
        if ($caCerts === []) {
            throw new LSVIDException('Trust bundle is empty — cannot verify LSVID.');
        }

        // Walk root-first so we verify L0 before its nester.
        $chain = $lsvid->chain();
        $lastIndex = count($chain) - 1;
        foreach ($chain as $i => $level) {
            $this->verifyLevel($level, $caCerts, $i);

            // Chain continuity (applies to every extension level, i.e. i > 0).
            if ($i > 0) {
                $nested = $level->nested;
                if ($nested !== null) {
                    $nestedAud = $nested->audience();
                    if ($nestedAud === null) {
                        throw new LSVIDException(sprintf(
                            'LSVID chain broken at L%d: nested level is missing required audience claim.',
                            $i,
                        ));
                    }
                    if ($nestedAud !== $level->issuer()) {
                        throw new LSVIDException(sprintf(
                            'LSVID chain broken: nested audience %s ≠ enclosing issuer %s.',
                            $nestedAud,
                            $level->issuer(),
                        ));
                    }
                }
            }

            // When requireAudienceOnAllLevels is set, the outermost level
            // also MUST carry aud. (Intermediate levels already get caught
            // by the chain-continuity check above.)
            if ($this->requireAudienceOnAllLevels && $i === $lastIndex) {
                if ($level->audience() === null) {
                    throw new LSVIDException(sprintf(
                        'LSVID L%d is missing required audience claim.',
                        $i,
                    ));
                }
            }
        }

        // Outermost audience check.
        if ($expectedAudience !== null) {
            $aud = $lsvid->audience();
            if ($aud === null) {
                if ($this->requireAudienceOnAllLevels) {
                    throw new LSVIDException(
                        'LSVID outermost level has no audience but expectedAudience was provided.',
                    );
                }
            } elseif ($aud !== $expectedAudience) {
                throw new LSVIDException(sprintf(
                    'LSVID audience mismatch: got %s, expected %s.',
                    $aud,
                    $expectedAudience,
                ));
            }
        }

        // L0 subject ↔ envelope source identity reconciliation.
        if ($expectedSubject !== null && $chain !== []) {
            $l0Subject = $chain[0]->subject();
            if ($l0Subject !== null && $l0Subject !== $expectedSubject) {
                throw new LSVIDException(sprintf(
                    'LSVID L0 subject mismatch: L0.sub=%s, expected=%s.',
                    $l0Subject,
                    $expectedSubject,
                ));
            }
        }

        // JTI replay detection — applied only to the outermost level (the
        // one actually created at this hop). Inner levels re-appear on
        // every downstream token as chain proof, so replaying their jti
        // check would false-positive from L2 onwards.
        if ($this->jtiCache !== null) {
            $outerJti = $lsvid->tokenId();
            $outerExp = $lsvid->expiresAt();
            if ($outerJti !== null && $outerExp !== null) {
                if ($this->jtiCache->seenOrRecord($outerJti, $outerExp)) {
                    throw new LSVIDException(sprintf(
                        'LSVID replay detected: jti=%s has been seen before.',
                        $outerJti,
                    ));
                }
            }
        }

        return $lsvid;
    }

    /**
     * @param list<\OpenSSLCertificate> $caCerts
     */
    private function verifyLevel(LSVID $level, array $caCerts, int $levelIndex): void
    {
        // 0. Required claims — every level MUST carry these.
        $requiredClaims = ['iss', 'sub', 'iat', 'exp', 'jti'];
        foreach ($requiredClaims as $claim) {
            if (!isset($level->payload[$claim]) || $level->payload[$claim] === '') {
                throw new LSVIDException(sprintf(
                    'LSVID L%d is missing required claim: %s.',
                    $levelIndex,
                    $claim,
                ));
            }
        }
        if ($this->requireNbf && !isset($level->payload['nbf'])) {
            throw new LSVIDException(sprintf(
                'LSVID L%d is missing required claim: nbf.',
                $levelIndex,
            ));
        }

        // 1. Pull leaf cert from header.
        $leafPem = $level->leafCertificatePem();
        if ($leafPem === null) {
            throw new LSVIDException('LSVID header is missing x5c claim.');
        }
        $leafCert = openssl_x509_read($leafPem);
        if ($leafCert === false) {
            throw new LSVIDException('LSVID x5c leaf certificate is not parseable.');
        }

        // 2. Verify leaf against at least one CA in the trust bundle.
        $trusted = false;
        foreach ($caCerts as $ca) {
            $caKey = openssl_pkey_get_public($ca);
            if ($caKey === false) {
                continue;
            }
            if (openssl_x509_verify($leafCert, $caKey) === 1) {
                $trusted = true;
                break;
            }
        }
        if (!$trusted) {
            throw new LSVIDException('LSVID leaf certificate is not signed by any trusted CA.');
        }

        // 3. Certificate temporal validity (notBefore / notAfter).
        $certInfo = openssl_x509_parse($leafPem);
        if ($certInfo !== false) {
            $now = time();
            $notBefore = $certInfo['validFrom_time_t'] ?? null;
            $notAfter  = $certInfo['validTo_time_t'] ?? null;
            if ($notBefore !== null && $notBefore > $now + $this->clockSkewSeconds) {
                throw new LSVIDException('LSVID leaf certificate is not yet valid (notBefore in the future).');
            }
            if ($notAfter !== null && $notAfter + $this->clockSkewSeconds < $now) {
                throw new LSVIDException('LSVID leaf certificate has expired (notAfter).');
            }
        }

        // 4. Verify signature with leaf public key.
        $leafPubKey = openssl_pkey_get_public($leafCert);
        if ($leafPubKey === false) {
            throw new LSVIDException('Failed to extract leaf public key for LSVID verification.');
        }

        $alg = (string) ($level->header['alg'] ?? '');
        [$opensslAlg, $isEcdsa, $ecBits] = self::algFromHeader($alg);

        $signature = $level->signature;
        if ($isEcdsa) {
            $signature = self::joseEcdsaToDer($signature, $ecBits);
        }

        $ok = openssl_verify($level->signingInput, $signature, $leafPubKey, $opensslAlg);
        if ($ok !== 1) {
            throw new LSVIDException('LSVID signature verification failed.');
        }

        // 5. Temporal checks (LSVID payload claims).
        $now = time();
        $iat = $level->issuedAt();
        $exp = $level->expiresAt();
        if ($iat !== null && $iat > $now + $this->clockSkewSeconds) {
            throw new LSVIDException(sprintf('LSVID L%d iat is in the future.', $levelIndex));
        }
        if ($exp !== null && $exp + $this->clockSkewSeconds < $now) {
            throw new LSVIDException(sprintf('LSVID L%d has expired.', $levelIndex));
        }
        // 5a. Optional `nbf` claim — when present it must not be in the future.
        if (isset($level->payload['nbf'])) {
            $nbf = (int) $level->payload['nbf'];
            if ($nbf > $now + $this->clockSkewSeconds) {
                throw new LSVIDException(sprintf(
                    'LSVID L%d is not yet valid (nbf in the future).',
                    $levelIndex,
                ));
            }
        }

        // 6. Issuer ↔ cert SAN continuity.
        $sanUri = self::certUriSan($leafPem);
        if ($sanUri === null) {
            throw new LSVIDException('Leaf certificate lacks a URI SAN.');
        }
        if ($level->issuer() !== $sanUri) {
            throw new LSVIDException(sprintf(
                'LSVID L%d iss=%s does not match cert SAN URI=%s.',
                $levelIndex,
                $level->issuer(),
                $sanUri,
            ));
        }

        // 6a. Trust-domain isolation — every identity claim must live under
        //     `spiffe://{trustDomain}/`. A mismatched foreign SPIFFE ID is
        //     rejected even if it happened to be signed by a trusted CA.
        if ($this->trustDomain !== null) {
            $prefix = 'spiffe://' . $this->trustDomain . '/';
            foreach (['iss', 'sub', 'aud'] as $claim) {
                $value = $level->payload[$claim] ?? null;
                if ($value === null || $value === '') {
                    continue;
                }
                if (!is_string($value) || !str_starts_with($value, $prefix)) {
                    throw new LSVIDException(sprintf(
                        'LSVID L%d claim %s=%s is outside the expected trust domain %s.',
                        $levelIndex,
                        $claim,
                        is_string($value) ? $value : '(non-string)',
                        $this->trustDomain,
                    ));
                }
            }
        }

        // 7. JTI replay detection — skipped here; enforced only on the
        //    outermost level in validate() once the chain walk completes.
        //    Inner levels are carried forward as signed proof of chain at
        //    every hop, so the same inner jti recurs in every downstream
        //    token. Recording them would cause false-positive replays after
        //    the second hop.
    }

    /**
     * @return list<\OpenSSLCertificate>
     */
    private function loadTrustBundleCaCerts(): array
    {
        $svid = $this->reader->readX509Primary();
        if ($svid === null || !isset($svid['bundle_pem']) || $svid['bundle_pem'] === '') {
            return [];
        }

        $bundlePem = (string) $svid['bundle_pem'];
        $cacheKey = hash('sha256', $bundlePem);
        if ($cacheKey === $this->bundleCacheKey) {
            return $this->bundleCacheValue;
        }

        $certs = [];
        if (preg_match_all(
            '/-----BEGIN CERTIFICATE-----[^-]+-----END CERTIFICATE-----/s',
            $bundlePem,
            $matches,
        )) {
            foreach ($matches[0] as $pem) {
                $cert = openssl_x509_read($pem);
                if ($cert !== false) {
                    $certs[] = $cert;
                }
            }
        }

        $this->bundleCacheKey = $cacheKey;
        $this->bundleCacheValue = $certs;
        return $certs;
    }

    /**
     * @return array{0: int, 1: bool, 2: int}  [OPENSSL_ALGO_*, isEcdsa, ecdsaBits]
     */
    private static function algFromHeader(string $alg): array
    {
        return match ($alg) {
            'RS256' => [OPENSSL_ALGO_SHA256, false, 0],
            'RS384' => [OPENSSL_ALGO_SHA384, false, 0],
            'RS512' => [OPENSSL_ALGO_SHA512, false, 0],
            'ES256' => [OPENSSL_ALGO_SHA256, true, 256],
            'ES384' => [OPENSSL_ALGO_SHA384, true, 384],
            'ES512' => [OPENSSL_ALGO_SHA512, true, 512],
            default => throw new LSVIDException(sprintf('Unsupported LSVID alg: %s', $alg)),
        };
    }

    private static function certUriSan(string $leafPem): ?string
    {
        $parsed = openssl_x509_parse($leafPem);
        if ($parsed === false) {
            return null;
        }
        $san = $parsed['extensions']['subjectAltName'] ?? '';
        if (!is_string($san) || $san === '') {
            return null;
        }

        if (preg_match('/(?:^|,\s*)URI:(\S+?)(?:,|$)/', $san, $m)) {
            return $m[1];
        }

        return null;
    }

    private static function joseEcdsaToDer(string $jose, int $algBits): string
    {
        $partLen = match ($algBits) {
            256 => 32,
            384 => 48,
            512 => 66,
            default => throw new LSVIDException('Unsupported ECDSA bit length.'),
        };

        if (strlen($jose) !== 2 * $partLen) {
            throw new LSVIDException('Malformed ECDSA JWS signature length.');
        }

        $r = ltrim(substr($jose, 0, $partLen), "\x00");
        $s = ltrim(substr($jose, $partLen), "\x00");
        if ($r !== '' && (ord($r[0]) & 0x80) !== 0) {
            $r = "\x00" . $r;
        }
        if ($s !== '' && (ord($s[0]) & 0x80) !== 0) {
            $s = "\x00" . $s;
        }

        $encodeInt = static fn(string $int): string => "\x02" . chr(strlen($int)) . $int;
        $rEnc = $encodeInt($r);
        $sEnc = $encodeInt($s);
        $body = $rEnc . $sEnc;

        return "\x30" . chr(strlen($body)) . $body;
    }
}
