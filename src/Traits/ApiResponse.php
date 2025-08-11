<?php

namespace Whilesmart\UserAuthentication\Traits;

use Illuminate\Http\JsonResponse;
use Whilesmart\UserAuthentication\Interfaces\ResponseFormatterInterface;

trait ApiResponse
{
    /**
     * Return a success response.
     */
    protected function success(mixed $data = null, string $message = 'Operation successful', int $statusCode = 200): JsonResponse
    {
        return app(ResponseFormatterInterface::class)->success($data, $message, $statusCode);
    }

    /**
     * Return a failure response.
     */
    protected function failure(string $message = 'Operation failed', int $statusCode = 400, array $errors = []): JsonResponse
    {
        return app(ResponseFormatterInterface::class)->failure($message, $statusCode, $errors);
    }
}
