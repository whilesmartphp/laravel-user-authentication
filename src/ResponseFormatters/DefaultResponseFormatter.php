<?php

namespace Whilesmart\UserAuthentication\ResponseFormatters;

use Illuminate\Http\JsonResponse;
use Whilesmart\UserAuthentication\Interfaces\ResponseFormatterInterface;

class DefaultResponseFormatter implements ResponseFormatterInterface
{
    /**
     * Format a success response.
     */
    public function success(mixed $data = null, string $message = 'Operation successful', int $statusCode = 200): JsonResponse
    {
        return response()->json([
            'success' => true,
            'message' => $message,
            'data' => $data,
        ], $statusCode);
    }

    /**
     * Format a failure response.
     */
    public function failure(string $message = 'Operation failed', int $statusCode = 400, array $errors = []): JsonResponse
    {
        return response()->json([
            'success' => false,
            'message' => $message,
            'errors' => $errors,
        ], $statusCode);
    }
}
