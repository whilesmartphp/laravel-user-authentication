<?php

use Illuminate\Support\Facades\Route;
use Whilesmart\UserAuthentication\Http\Controllers\Auth\AuthController;

// OAUTH
Route::get('/oauth/{driver}/login', [AuthController::class, 'oauthLogin']);
Route::get('/oauth/{driver}/callback', [AuthController::class, 'oauthCallback']);
Route::post('/oauth/firebase/{driver}/callback', [AuthController::class, 'firebaseAuthCallback']);
