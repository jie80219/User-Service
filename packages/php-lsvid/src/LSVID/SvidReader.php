<?php

declare(strict_types=1);

namespace SDPMlab\LSVID;

/**
 * Minimal abstraction over the SPIFFE SVID store so that the LSVID
 * signer/validator can be unit-tested without touching the filesystem.
 *
 * The return shape matches what `SpiffeTableReader::readX509Primary()`
 * already produces; do not drift from it.
 */
interface SvidReader
{
    /**
     * @return array{
     *     spiffe_id:    string,
     *     trust_domain: string,
     *     cert_pem:     string,
     *     key_pem:      string,
     *     bundle_pem:   string,
     *     hint:         string,
     *     updated_at:   int,
     * }|null
     */
    public function readX509Primary(): ?array;
}
