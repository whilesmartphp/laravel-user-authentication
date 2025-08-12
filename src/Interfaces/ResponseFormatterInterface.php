<?php

namespace Whilesmart\UserAuthentication\Interfaces;

use Illuminate\Http\JsonResponse;

interface ResponseFormatterInterface
{
    /**
     * Format a success response.
     */
    public function success(mixed $data = null, string $message = 'Operation successful', int $statusCode = 200): JsonResponse;

    /**
     * Format a failure response.
     */
    public function failure(string $message = 'Operation failed', int $statusCode = 400, array $errors = []): JsonResponse;
}
