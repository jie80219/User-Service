<?php

declare(strict_types=1);

namespace SDPMlab\LSVID\Middleware;

use Psr\Http\Message\ResponseFactoryInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Server\RequestHandlerInterface;
use SDPMlab\LSVID\LSVIDException;
use SDPMlab\LSVID\LSVIDValidator;

/**
 * PSR-15 middleware that validates inbound LSVID tokens.
 *
 * Reads the raw LSVID from the configured HTTP header (default: X-LSVID),
 * validates it via LSVIDValidator, and attaches the parsed result to the
 * request attributes for downstream handlers.
 *
 * Usage (Slim 4 example):
 *   $app->add(new LSVIDMiddleware(
 *       $validator,
 *       $responseFactory,
 *       required: true,
 *       expectedAudience: getenv('SPIFFE_ID'),
 *   ));
 */
final class LSVIDMiddleware implements MiddlewareInterface
{
    public function __construct(
        private readonly LSVIDValidator $validator,
        private readonly ResponseFactoryInterface $responseFactory,
        private readonly bool $required = true,
        private readonly ?string $expectedAudience = null,
        private readonly string $headerName = 'X-LSVID',
    ) {
    }

    public function process(
        ServerRequestInterface $request,
        RequestHandlerInterface $handler,
    ): ResponseInterface {
        $rawToken = $request->getHeaderLine($this->headerName);

        if ($rawToken === '') {
            if ($this->required) {
                return $this->jsonResponse(401, ['error' => 'Missing ' . $this->headerName . ' header']);
            }
            return $handler->handle($request);
        }

        try {
            $lsvid = $this->validator->validate(
                $rawToken,
                expectedAudience: $this->expectedAudience,
            );
        } catch (LSVIDException $e) {
            return $this->jsonResponse(403, [
                'error' => 'LSVID validation failed: ' . $e->getMessage(),
            ]);
        }

        // Attach validated LSVID to request attributes for downstream use.
        $chain = $lsvid->chain();
        $request = $request->withAttribute('lsvid', $lsvid);
        $request = $request->withAttribute('lsvid.issuer', $lsvid->issuer());
        $request = $request->withAttribute('lsvid.subject', $chain !== [] ? $chain[0]->subject() : null);

        return $handler->handle($request);
    }

    /**
     * @param array<string, mixed> $body
     */
    private function jsonResponse(int $status, array $body): ResponseInterface
    {
        $response = $this->responseFactory->createResponse($status);
        $response->getBody()->write(json_encode($body, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE));
        return $response->withHeader('Content-Type', 'application/json');
    }
}
