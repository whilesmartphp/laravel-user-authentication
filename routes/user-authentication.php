<?php

use Illuminate\Support\Facades\Route;
use Whilesmart\UserAuthentication\Http\Controllers\Auth\AuthController;
use Whilesmart\UserAuthentication\Http\Controllers\Auth\PasswordResetController;
use Whilesmart\UserAuthentication\Http\Controllers\Auth\TwoFactorController;

/*
|--------------------------------------------------------------------------
| API Routes
|--------------------------------------------------------------------------
|
| Here is where you can register API routes for your application. These
| routes are loaded by the RouteServiceProvider and all of them will
| be assigned to the "api" middleware group. Make something great!
|
*/

// Auth routes
Route::post('/register', [AuthController::class, 'register']);
Route::post('/login', [AuthController::class, 'login']);
Route::post('/send-verification-code', [AuthController::class, 'sendVerificationCode']);
Route::post('/verify-code', [AuthController::class, 'verifyCode']);
Route::post('/password/reset-code', [PasswordResetController::class, 'sendPasswordResetCode']);
Route::post('/password/reset', [PasswordResetController::class, 'resetPasswordWithCode']);

Route::group(['middleware' => ['auth:sanctum', 'two-factor']], function () {
    Route::post('logout', [AuthController::class, 'logout']);
    Route::prefix('2fa')->group(function () {
        Route::post('/setup', [TwoFactorController::class, 'setup'])->middleware('throttle:two-factor-setup');
        Route::post('/confirm', [TwoFactorController::class, 'confirm'])->middleware('throttle:two-factor-confirm');
        Route::post('/disable', [TwoFactorController::class, 'disable'])->middleware('throttle:two-factor-disable');
    });
});

Route::post('/2fa/verify', [TwoFactorController::class, 'verify'])->middleware('throttle:two-factor-verify');
Route::post('/2fa/resend', [TwoFactorController::class, 'resend'])->middleware('throttle:two-factor-resend');
Route::post('/2fa/verify-link', [TwoFactorController::class, 'verifyLink'])->middleware('throttle:two-factor-link');
