<?php

declare(strict_types=1);

namespace SDPMlab\LSVID\Tests;

use SDPMlab\LSVID\SvidReader;

/**
 * Ephemeral in-memory SvidReader for tests.
 *
 * Generates a fresh self-signed EC P-256 CA + leaf certificate pair
 * with a SPIFFE URI SAN. The leaf is signed by the CA, so the
 * trust bundle (CA cert) can validate signatures made by the leaf.
 */
final class TestSvidReader implements SvidReader
{
    private string $spiffeId;
    private string $trustDomain;
    private string $leafCertPem;
    private string $leafKeyPem;
    private string $caCertPem;
    private string $caKeyPem;

    private function __construct() {}

    public static function create(
        string $spiffeId = 'spiffe://test.local/gateway',
        string $trustDomain = 'test.local',
    ): self {
        $self = new self();
        $self->spiffeId = $spiffeId;
        $self->trustDomain = $trustDomain;

        // 1. CA key + self-signed CA cert
        $caKey = openssl_pkey_new(['private_key_type' => OPENSSL_KEYTYPE_EC, 'curve_name' => 'prime256v1']);
        $caCsr = openssl_csr_new(['commonName' => 'Test SPIFFE CA'], $caKey, ['digest_alg' => 'sha256']);
        $caCert = openssl_csr_sign($caCsr, null, $caKey, 365, ['digest_alg' => 'sha256']);
        $caCertPem = '';
        $caKeyPem = '';
        openssl_x509_export($caCert, $caCertPem);
        openssl_pkey_export($caKey, $caKeyPem);
        $self->caCertPem = $caCertPem;
        $self->caKeyPem = $caKeyPem;

        // 2. Leaf
        [$self->leafCertPem, $self->leafKeyPem] = self::signLeaf($spiffeId, $caCert, $caKey);

        return $self;
    }

    /**
     * Build a second reader with a different identity signed by the same CA.
     * Useful for two-hop chain tests (gateway → worker).
     */
    public function deriveWorkload(string $spiffeId): self
    {
        $self = new self();
        $self->spiffeId = $spiffeId;
        $self->trustDomain = $this->trustDomain;
        $self->caCertPem = $this->caCertPem;
        $self->caKeyPem = $this->caKeyPem;

        $caCert = openssl_x509_read($this->caCertPem);
        $caKey = openssl_pkey_get_private($this->caKeyPem);
        [$self->leafCertPem, $self->leafKeyPem] = self::signLeaf($spiffeId, $caCert, $caKey);

        return $self;
    }

    public function readX509Primary(): ?array
    {
        return [
            'spiffe_id'    => $this->spiffeId,
            'trust_domain' => $this->trustDomain,
            'cert_pem'     => $this->leafCertPem,
            'key_pem'      => $this->leafKeyPem,
            'bundle_pem'   => $this->caCertPem,
            'hint'         => 'test',
            'updated_at'   => time(),
        ];
    }

    public function spiffeId(): string { return $this->spiffeId; }

    /**
     * @return array{0: string, 1: string} [leafCertPem, leafKeyPem]
     */
    private static function signLeaf(
        string $spiffeId,
        \OpenSSLCertificate $caCert,
        \OpenSSLAsymmetricKey $caKey,
    ): array {
        $leafKey = openssl_pkey_new([
            'private_key_type' => OPENSSL_KEYTYPE_EC,
            'curve_name'       => 'prime256v1',
        ]);

        $sanConfig = tempnam(sys_get_temp_dir(), 'spiffe_san_');
        file_put_contents($sanConfig, <<<CONF
        [req]
        distinguished_name = req_dn
        req_extensions = v3_req
        [req_dn]
        CN = Test SPIFFE Leaf
        [v3_req]
        subjectAltName = URI:{$spiffeId}
        CONF);

        $leafCsr = openssl_csr_new(
            ['commonName' => 'Test SPIFFE Leaf'],
            $leafKey,
            ['digest_alg' => 'sha256', 'config' => $sanConfig, 'req_extensions' => 'v3_req'],
        );
        $leafCert = openssl_csr_sign(
            $leafCsr, $caCert, $caKey, 365,
            ['digest_alg' => 'sha256', 'config' => $sanConfig, 'x509_extensions' => 'v3_req'],
        );

        openssl_x509_export($leafCert, $leafCertPem);
        openssl_pkey_export($leafKey, $leafKeyPem);
        @unlink($sanConfig);

        return [$leafCertPem, $leafKeyPem];
    }
}
