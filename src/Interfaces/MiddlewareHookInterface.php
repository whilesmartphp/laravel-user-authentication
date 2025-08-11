<?php

namespace Whilesmart\UserAuthentication\Interfaces;

use Illuminate\Http\Request;

interface MiddlewareHookInterface
{
    /**
     * Handle the request before processing.
     */
    public function before(Request $request, string $action): ?Request;
}
