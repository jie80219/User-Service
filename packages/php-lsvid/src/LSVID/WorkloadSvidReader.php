<?php

declare(strict_types=1);

namespace SDPMlab\LSVID;

use Spiffe\SpiffeWorkloadAPIClient;
use Spiffe\Workload\X509SVIDResponse;

/**
 * SvidReader that fetches SVID directly from the SPIRE Agent Workload API
 * and holds the result in memory.
 *
 * MVP approach: no SHM, no watcher, no filesystem — Gateway/Worker each
 * call fetchX509Svid() at startup and cache the result. Subsequent calls
 * to readX509Primary() return the cached data (zero I/O).
 *
 * Automatically handles both coroutine and non-coroutine contexts:
 * if called outside a coroutine (e.g. bin/worker.php main scope),
 * it wraps the gRPC call in an OpenSwoole Scheduler.
 *
 * Usage:
 *   $reader = WorkloadSvidReader::fromWorkloadAPI('unix:/run/spire/sockets/agent.sock');
 *   $signer = new LSVIDSigner($reader);
 */
final class WorkloadSvidReader implements SvidReader
{
    private function __construct(
        private readonly string $spiffeId,
        private readonly string $trustDomain,
        private readonly string $certPem,
        private readonly string $keyPem,
        private readonly string $bundlePem,
    ) {
    }

    /**
     * Connect to the SPIRE Agent Workload API and fetch the primary X.509-SVID.
     *
     * Works in both coroutine and non-coroutine contexts — when called
     * outside a coroutine, automatically wraps the call in an OpenSwoole
     * Scheduler so the gRPC transport can use coroutine sockets.
     *
     * @param string $socketPath  Agent UDS path (e.g. "unix:/run/spire/sockets/agent.sock")
     * @param float  $timeout     Connect + recv timeout in seconds
     *
     * @throws \RuntimeException if no SVID is returned
     */
    public static function fromWorkloadAPI(
        string $socketPath = 'unix:/run/spire/sockets/agent.sock',
        float $timeout = 10.0,
    ): self {
        // 如果不在 coroutine 裡（例如 worker.php 的 main scope），
        // 用 Scheduler 包一層讓 OpenSwoole socket API 可用。
        if (self::inCoroutine()) {
            return self::doFetch($socketPath, $timeout);
        }

        $result = null;
        $error = null;
        $scheduler = new \OpenSwoole\Coroutine\Scheduler();
        $scheduler->add(static function () use ($socketPath, $timeout, &$result, &$error) {
            try {
                $result = self::doFetch($socketPath, $timeout);
            } catch (\Throwable $e) {
                $error = $e;
            }
        });
        $scheduler->start();

        if ($error !== null) {
            throw $error;
        }
        if ($result === null) {
            throw new \RuntimeException('WorkloadSvidReader: Scheduler completed without result.');
        }

        return $result;
    }

    /**
     * Actual gRPC fetch — must be called within a coroutine context.
     */
    private static function doFetch(string $socketPath, float $timeout): self
    {
        $client = new SpiffeWorkloadAPIClient($socketPath, $timeout, $timeout);

        try {
            $resp = $client->fetchX509Svid();
        } finally {
            $client->close();
        }

        $svids = $resp->getSvids();
        if (count($svids) === 0) {
            throw new \RuntimeException(
                'WorkloadSvidReader: SPIRE Agent returned 0 SVIDs. '
                . 'Check workload registration and agent health.',
            );
        }

        $svid = $svids[0];
        $spiffeId = $svid->getSpiffeId();

        // Convert DER cert/key to PEM
        $certPem = self::derToPem($svid->getX509Svid(), 'CERTIFICATE');
        $keyPem = self::derToPem($svid->getX509SvidKey(), 'PRIVATE KEY');

        // Build bundle PEM from the trust bundle
        $bundlePem = '';
        $bundle = $svid->getBundle();
        if ($bundle !== '') {
            $bundlePem = self::derToPem($bundle, 'CERTIFICATE');
        }
        // Also check federated bundles in the response
        if ($bundlePem === '') {
            foreach ($resp->getFederatedBundles() as $td => $b) {
                $bundlePem .= self::derToPem($b, 'CERTIFICATE');
            }
        }

        // Extract trust domain from SPIFFE ID
        $trustDomain = '';
        if (preg_match('#^spiffe://([^/]+)#', $spiffeId, $m)) {
            $trustDomain = $m[1];
        }

        return new self($spiffeId, $trustDomain, $certPem, $keyPem, $bundlePem);
    }

    private static function inCoroutine(): bool
    {
        if (!class_exists(\OpenSwoole\Coroutine::class)) {
            return false;
        }
        return \OpenSwoole\Coroutine::getCid() > 0;
    }

    public function readX509Primary(): ?array
    {
        if ($this->certPem === '' || $this->keyPem === '') {
            return null;
        }

        return [
            'spiffe_id'    => $this->spiffeId,
            'trust_domain' => $this->trustDomain,
            'cert_pem'     => $this->certPem,
            'key_pem'      => $this->keyPem,
            'bundle_pem'   => $this->bundlePem,
            'hint'         => '',
            'updated_at'   => time(),
        ];
    }

    /**
     * Convert DER-encoded binary data to PEM format.
     */
    private static function derToPem(string $der, string $type): string
    {
        if ($der === '') {
            return '';
        }

        return "-----BEGIN {$type}-----\n"
            . chunk_split(base64_encode($der), 64, "\n")
            . "-----END {$type}-----\n";
    }
}
