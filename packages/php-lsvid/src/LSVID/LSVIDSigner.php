<?php

declare(strict_types=1);

namespace SDPMlab\LSVID;

/**
 * Signs Nested LSVIDs using the workload's current X.509-SVID private key.
 *
 * Two entry points correspond to the LSVID lifecycle:
 *
 *   Step 1 — Creation  → {@see createBase()}   (produces L0)
 *   Step 2 — Extension → {@see extend()}       (produces L1, L2, …)
 *
 * Both flow through {@see signInternal()}, which:
 *   - Always reads the current primary X.509-SVID from the shared-memory
 *     store (rotation-safe: no cached key material).
 *   - Populates the authority-controlled reserved claims
 *     (`iss`, `sub`, `iat`, `exp`, `jti`, `nested`) itself. Any caller-
 *     provided values for these keys are silently stripped so callers
 *     cannot spoof identity, lifetime, or replay identifiers.
 *   - Embeds the leaf X.509 certificate (DER) in the JOSE header `x5c`
 *     claim so verifiers are self-contained against the trust bundle.
 *
 * Backward-compat shim {@see sign()} is kept for existing call sites
 * (MessageBus) and routes to createBase/extend based on $priorRawToken.
 */
final class LSVIDSigner
{
    /**
     * 保留宣告（reserved claims）清單。
     * 這些欄位由簽章流程自動填入，呼叫端傳入的同名欄位會被靜默移除，
     * 以避免身份（iss/sub）、有效期（iat/exp/nbf）、重放識別碼（jti）或
     * 巢狀鏈（nested）被偽造。`nbf` 只能透過 createBase()/extend() 的
     * $notBefore 參數顯式設定，呼叫端不得透過 extraClaims 注入。
     *
     * @var list<string>
     */
    private const RESERVED_CLAIMS = ['iss', 'sub', 'aud', 'iat', 'exp', 'nbf', 'jti', 'nested'];

    /**
     * Per-SVID signing-prep cache.
     *
     * Keyed by sha256(key_pem) — when the watcher rotates the SVID, the key
     * PEM bytes change, the hash misses, and we re-derive. Within a single
     * SVID's lifetime (~hours) every sign reuses the parsed private key
     * resource, picked alg, and pre-base64-encoded leaf DER for the x5c
     * header.
     *
     * Without this cache, every sign re-runs:
     *   - openssl_pkey_get_private  (PEM → EVP_PKEY)        ~80 μs
     *   - openssl_pkey_get_details  (detect curve)          ~10 μs
     *   - leafDerFromPem            (PEM strip + base64dec) ~20 μs
     *   - base64_encode(DER)        (x5c header)            ~5 μs
     *
     * @var array{
     *     hash:           string,
     *     pk:             \OpenSSLAsymmetricKey,
     *     alg:            string,
     *     opensslAlg:     int,
     *     leafB64:        string,
     *     signerSpiffeId: string,
     * }|null
     */
    private ?array $prep = null;

    /**
     * Run 8: prep-cache hit/miss observability. Gated on LSVID_PREP_DEBUG=1
     * (default 0 → zero overhead, no behaviour change). When enabled it
     * confirms the steady-state assertion that this signer is a long-lived
     * singleton reused across requests — a healthy run shows misses ≈ number
     * of SVID rotations, hits ≈ number of signs. A miss count that tracks the
     * request count would mean the signer is being rebuilt per request.
     */
    private int $prepHits = 0;
    private int $prepMisses = 0;
    private readonly bool $prepDebug;

    /**
     * 建構子。
     *
     * @param SvidReader $reader                  共享記憶體 SVID 讀取器，每次簽章都會即時讀取最新憑證，
     *                                            確保 SVID 自動輪替時不會使用過期的私鑰。
     * @param int        $defaultTtlSeconds       LSVID 預設存活秒數（預設 1800 秒 = 30 分鐘）。
     * @param int        $certExpiryGraceSeconds  簽章前安全邊界：若憑證將在此秒數內過期，拒絕簽章（預設 60 秒）。
     */
    public function __construct(
        private readonly SvidReader $reader,
        private readonly int $defaultTtlSeconds = 1800,
        private readonly int $certExpiryGraceSeconds = 60,
    ) {
        $this->prepDebug = getenv('LSVID_PREP_DEBUG') === '1';
    }

    /**
     * Step 1 — Creation. Mint a fresh base-level LSVID (L0).
     *
     * @param string               $audience     Required next-hop SPIFFE ID (becomes `aud`).
     * @param string|null          $subject      Workload being attested; defaults to signer SVID.
     * @param array<string, mixed> $extraClaims  Additional non-reserved claims to merge.
     * @param int|null             $notBefore    Optional `nbf` claim (Unix ts); defaults to $iat.
     */
    public function createBase(
        string $audience,
        ?string $subject = null,
        array $extraClaims = [],
        ?int $notBefore = null,
    ): LSVID {
        if ($audience === '') {
            throw new LSVIDException('createBase(): audience (next-hop SPIFFE ID) is required for L0.');
        }

        return $this->signInternal(
            claims:        $extraClaims,
            audience:      $audience,
            priorRawToken: null,
            subject:       $subject,
            notBefore:     $notBefore,
        );
    }

    /**
     * Step 2 — Extension. Wrap a prior-level raw token as the `nested`
     * claim of a new level signed by this workload's current SVID.
     *
     * @param int|null $notBefore Optional `nbf` claim (Unix ts); defaults to $iat.
     */
    public function extend(
        string $priorRawToken,
        string $audience,
        array $extraClaims = [],
        ?int $notBefore = null,
    ): LSVID {
        if ($priorRawToken === '') {
            throw new LSVIDException('extend(): prior raw token is required.');
        }
        if ($audience === '') {
            throw new LSVIDException('extend(): audience (next-hop SPIFFE ID) is required.');
        }

        return $this->signInternal(
            claims:        $extraClaims,
            audience:      $audience,
            priorRawToken: $priorRawToken,
            subject:       null,
            notBefore:     $notBefore,
        );
    }

    /**
     * Backward-compatible entry point kept for existing MessageBus wiring.
     * New code should call {@see createBase()} / {@see extend()} directly.
     *
     * @param array<string, mixed> $claims
     */
    public function sign(array $claims, ?string $priorRawToken = null, ?string $audience = null): LSVID
    {
        return $this->signInternal(
            claims:        $claims,
            audience:      $audience,
            priorRawToken: $priorRawToken,
            subject:       null,
            notBefore:     null,
        );
    }

    /**
     * 核心簽章邏輯（內部方法）。
     *
     * @param array<string, mixed> $claims        呼叫端傳入的額外宣告（保留宣告會被移除）。
     * @param string|null          $audience       下一跳 SPIFFE ID，寫入 `aud`。
     * @param string|null          $priorRawToken  前一層 LSVID 原始 JWT 字串，寫入 `nested`。
     * @param string|null          $subject        被簽證的工作負載 SPIFFE ID；為 null 時以簽章者自身代入。
     * @param int|null             $notBefore      可選的 `nbf` Unix timestamp；null 時沿用 iat。
     */
    private function signInternal(
        array $claims,
        ?string $audience,
        ?string $priorRawToken,
        ?string $subject,
        ?int $notBefore = null,
    ): LSVID {
        $svid = $this->reader->readX509Primary();
        if ($svid === null) {
            throw new LSVIDException('No X.509-SVID available: shared-memory store is empty.');
        }

        // Signing-prep cache. Hit on the steady-state path (SVID stable for
        // hours between rotations); miss only on rotation. The hash compare
        // is the one mandatory cost — everything below is amortized.
        $keyPem = (string) $svid['key_pem'];
        $hash = hash('sha256', $keyPem, binary: true);
        $prepMiss = $this->prep === null || $this->prep['hash'] !== $hash;
        if ($this->prepDebug) {
            if ($prepMiss) {
                $this->prepMisses++;
            } else {
                $this->prepHits++;
            }
            fwrite(STDERR, sprintf(
                "[lsvid-prep] %s hits=%d misses=%d\n",
                $prepMiss ? 'MISS' : 'hit',
                $this->prepHits,
                $this->prepMisses,
            ));
        }
        if ($prepMiss) {
            $privateKey = openssl_pkey_get_private($keyPem);
            if ($privateKey === false) {
                throw new LSVIDException('Failed to load private key from SPIFFE store: ' . self::lastOpensslError());
            }
            $details = openssl_pkey_get_details($privateKey);
            if ($details === false) {
                throw new LSVIDException('Failed to inspect SVID private key.');
            }
            [$alg, $opensslAlg] = self::pickAlg($details);
            $leafDer = self::leafDerFromPem((string) $svid['cert_pem']);

            $signerSpiffeId = (string) ($svid['spiffe_id'] ?? '');
            if ($signerSpiffeId === '') {
                throw new LSVIDException('SVID record is missing spiffe_id.');
            }

            $this->prep = [
                'hash'           => $hash,
                'pk'             => $privateKey,
                'alg'            => $alg,
                'opensslAlg'     => $opensslAlg,
                'leafB64'        => base64_encode($leafDer),
                'signerSpiffeId' => $signerSpiffeId,
            ];
        }
        $prep = $this->prep;

        $this->assertCertNotExpired($svid['cert_pem']);

        $header = [
            'alg' => $prep['alg'],
            'typ' => 'LSVID',
            'x5c' => [$prep['leafB64']],
        ];

        foreach (self::RESERVED_CLAIMS as $reserved) {
            unset($claims[$reserved]);
        }

        $now = time();
        $payload = $claims;
        $payload['iss'] = $prep['signerSpiffeId'];
        $payload['sub'] = ($subject !== null && $subject !== '') ? $subject : $prep['signerSpiffeId'];
        $payload['iat'] = $now;
        $payload['nbf'] = $notBefore ?? $now;
        $payload['exp'] = $now + $this->defaultTtlSeconds;
        $payload['jti'] = bin2hex(random_bytes(16));
        if ($audience !== null && $audience !== '') {
            $payload['aud'] = $audience;
        }
        if ($priorRawToken !== null && $priorRawToken !== '') {
            $payload['nested'] = $priorRawToken;
        }

        $headerB64  = LSVID::b64UrlEncode(self::jsonEncode($header));
        $payloadB64 = LSVID::b64UrlEncode(self::jsonEncode($payload));
        $signingInput = $headerB64 . '.' . $payloadB64;

        $signature = '';
        $ok = openssl_sign($signingInput, $signature, $prep['pk'], $prep['opensslAlg']);
        if ($ok !== true) {
            throw new LSVIDException('openssl_sign failed: ' . self::lastOpensslError());
        }

        if (str_starts_with($prep['alg'], 'ES')) {
            $signature = self::derEcdsaToJose($signature, (int) substr($prep['alg'], 2));
        }

        $sigB64 = LSVID::b64UrlEncode($signature);
        $raw = $signingInput . '.' . $sigB64;

        return LSVID::fromParts(
            raw:          $raw,
            signingInput: $signingInput,
            header:       $header,
            payload:      $payload,
            signature:    $signature,
            nested:       $priorRawToken !== null ? LSVID::parse($priorRawToken) : null,
        );
    }

    /**
     * @param array<string, mixed> $details  Output of openssl_pkey_get_details
     * @return array{0: string, 1: int}      [JWS alg, OPENSSL_ALGO_* constant]
     */
    private static function pickAlg(array $details): array
    {
        $type = $details['type'] ?? null;

        if ($type === OPENSSL_KEYTYPE_RSA) {
            return ['RS256', OPENSSL_ALGO_SHA256];
        }

        if ($type === OPENSSL_KEYTYPE_EC) {
            $curve = $details['ec']['curve_name'] ?? '';
            return match ($curve) {
                'prime256v1', 'secp256r1' => ['ES256', OPENSSL_ALGO_SHA256],
                'secp384r1'               => ['ES384', OPENSSL_ALGO_SHA384],
                'secp521r1'               => ['ES512', OPENSSL_ALGO_SHA512],
                default => throw new LSVIDException(sprintf('Unsupported EC curve: %s', $curve)),
            };
        }

        throw new LSVIDException('Unsupported SVID key type for LSVID signing.');
    }

    private static function leafDerFromPem(string $pem): string
    {
        if (!preg_match(
            '/-----BEGIN CERTIFICATE-----\s*([A-Za-z0-9+\/=\s]+?)\s*-----END CERTIFICATE-----/',
            $pem,
            $m,
        )) {
            throw new LSVIDException('SVID cert_pem does not contain a valid CERTIFICATE block.');
        }

        $der = base64_decode(preg_replace('/\s+/', '', $m[1]) ?? '', true);
        if ($der === false) {
            throw new LSVIDException('SVID leaf certificate is not valid base64.');
        }

        return $der;
    }

    private static function derEcdsaToJose(string $der, int $algBits): string
    {
        $partLen = match ($algBits) {
            256 => 32,
            384 => 48,
            512 => 66,
            default => throw new LSVIDException('Unsupported ECDSA bit length.'),
        };

        $offset = 0;
        if (($der[$offset++] ?? '') !== "\x30") {
            throw new LSVIDException('Invalid ECDSA DER: missing SEQUENCE.');
        }
        $seqLen = ord($der[$offset++]);
        if ($seqLen & 0x80) {
            $n = $seqLen & 0x7f;
            $offset += $n;
        }

        $readInt = static function (string $der, int &$offset) use ($partLen): string {
            if (($der[$offset++] ?? '') !== "\x02") {
                throw new LSVIDException('Invalid ECDSA DER: missing INTEGER.');
            }
            $len = ord($der[$offset++]);
            $int = substr($der, $offset, $len);
            $offset += $len;
            $int = ltrim($int, "\x00");
            if (strlen($int) > $partLen) {
                throw new LSVIDException('ECDSA integer longer than curve size.');
            }
            return str_pad($int, $partLen, "\x00", STR_PAD_LEFT);
        };

        $r = $readInt($der, $offset);
        $s = $readInt($der, $offset);

        return $r . $s;
    }

    /**
     * @param array<string, mixed> $data
     */
    private static function jsonEncode(array $data): string
    {
        $json = json_encode($data, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
        if ($json === false) {
            throw new LSVIDException('Failed to JSON-encode LSVID component: ' . json_last_error_msg());
        }
        return $json;
    }

    /**
     * 簽章前檢查葉憑證是否已過期或即將過期。
     * 若憑證的 notAfter 落在 (now + graceSeconds) 之前，拒絕簽章。
     */
    private function assertCertNotExpired(string $certPem): void
    {
        $certInfo = openssl_x509_parse($certPem);
        if ($certInfo === false) {
            return;
        }
        $notAfter = $certInfo['validTo_time_t'] ?? null;
        if ($notAfter === null) {
            return;
        }
        $now = time();
        if ($notAfter - $this->certExpiryGraceSeconds < $now) {
            throw new LSVIDException(sprintf(
                'Refusing to sign: leaf X.509 certificate %s (notAfter=%d, now=%d, grace=%ds)',
                $notAfter < $now ? 'has expired' : 'expires within grace period',
                $notAfter,
                $now,
                $this->certExpiryGraceSeconds,
            ));
        }
    }

    private static function lastOpensslError(): string
    {
        $messages = [];
        while (($err = openssl_error_string()) !== false) {
            $messages[] = $err;
        }
        return $messages === [] ? '(no details)' : implode('; ', $messages);
    }
}
