<?php

use Illuminate\Support\Facades\Route;
use Whilesmart\UserAuthentication\Http\Controllers\Auth\AuthController;

Route::get('/oauth/whilesmart/login', [\Whilesmart\UserAuthentication\Http\Controllers\Auth\WhilesmartController::class, 'login'])->middleware('throttle:20,1');
Route::get('/oauth/whilesmart/callback', [\Whilesmart\UserAuthentication\Http\Controllers\Auth\WhilesmartController::class, 'callback'])->middleware('throttle:20,1');

Route::post('/oauth/whilesmart/link', [\Whilesmart\UserAuthentication\Http\Controllers\Auth\WhilesmartController::class, 'link'])->middleware(['auth:sanctum', 'two-factor', 'throttle:20,1']);

// OAUTH
Route::get('/oauth/{driver}/login', [AuthController::class, 'oauthLogin']);
// Some providers use POST, while others use GET for the callback
Route::match(['get', 'post'], '/oauth/{driver}/callback', [AuthController::class, 'oauthCallback']);
Route::post('/oauth/firebase/{driver}/callback', [AuthController::class, 'firebaseAuthCallback']);
