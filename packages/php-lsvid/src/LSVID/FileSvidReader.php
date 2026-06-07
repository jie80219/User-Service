<?php

declare(strict_types=1);

namespace SDPMlab\LSVID;

/**
 * File-based SvidReader that reads PEM files directly from disk.
 *
 * Designed for deployments where spiffe-helper writes SVID credentials
 * as plain PEM files (svid.pem, svid_key.pem, bundle.pem). Each call to
 * readX509Primary() re-reads the files from disk, so SVID rotation is
 * automatically picked up without restarting the process.
 *
 * Usage:
 *   $reader = new FileSvidReader(
 *       certPath:   '/tmp/spiffe-shared/svid.pem',
 *       keyPath:    '/tmp/spiffe-shared/svid_key.pem',
 *       bundlePath: '/tmp/spiffe-shared/bundle.pem',
 *   );
 */
final class FileSvidReader implements SvidReader
{
    public function __construct(
        private readonly string $certPath,
        private readonly string $keyPath,
        private readonly string $bundlePath,
    ) {
    }

    public function readX509Primary(): ?array
    {
        $cert = @file_get_contents($this->certPath);
        $key  = @file_get_contents($this->keyPath);
        $bundle = @file_get_contents($this->bundlePath);

        if ($cert === false || $key === false || $bundle === false) {
            return null;
        }

        if ($cert === '' || $key === '' || $bundle === '') {
            return null;
        }

        // Extract SPIFFE ID from the certificate's SAN URI.
        $spiffeId = '';
        $trustDomain = '';
        $parsed = openssl_x509_parse($cert);
        if ($parsed !== false) {
            $san = $parsed['extensions']['subjectAltName'] ?? '';
            if (is_string($san) && preg_match('/URI:(spiffe:\/\/[^\s,]+)/', $san, $m)) {
                $spiffeId = $m[1];
            }
        }

        // Extract trust domain from SPIFFE ID.
        if ($spiffeId !== '' && preg_match('#^spiffe://([^/]+)#', $spiffeId, $m)) {
            $trustDomain = $m[1];
        }

        return [
            'spiffe_id'    => $spiffeId,
            'trust_domain' => $trustDomain,
            'cert_pem'     => $cert,
            'key_pem'      => $key,
            'bundle_pem'   => $bundle,
            'hint'         => '',
            'updated_at'   => filemtime($this->certPath) ?: time(),
        ];
    }
}
