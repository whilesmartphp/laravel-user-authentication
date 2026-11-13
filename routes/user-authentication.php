<?php

use Illuminate\Support\Facades\Route;
use Whilesmart\UserAuthentication\Http\Controllers\Auth\AuthController;
use Whilesmart\UserAuthentication\Http\Controllers\Auth\PasskeyController;
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
Route::post('/passkeys/login/options', [PasskeyController::class, 'loginOptions'])->middleware('throttle:passkey-login-options');
Route::post('/passkeys/login', [PasskeyController::class, 'login'])->middleware('throttle:passkey-login');

Route::group(['middleware' => ['auth:sanctum', 'two-factor']], function () {
    Route::post('logout', [AuthController::class, 'logout']);
    Route::prefix('2fa')->group(function () {
        Route::get('/factors', [TwoFactorController::class, 'index']);
        Route::post('/recovery-codes', [TwoFactorController::class, 'regenerateRecoveryCodes'])
            ->middleware('throttle:two-factor-confirm');
        Route::post('/setup', [TwoFactorController::class, 'setup'])->middleware('throttle:two-factor-setup');
        Route::post('/confirm', [TwoFactorController::class, 'confirm'])->middleware('throttle:two-factor-confirm');
        Route::post('/disable', [TwoFactorController::class, 'disable'])->middleware('throttle:two-factor-disable');
    });

    Route::post('/passkeys/register/options', [PasskeyController::class, 'registerOptions'])->middleware('throttle:passkey-register-options');
    Route::post('/passkeys/register', [PasskeyController::class, 'register'])->middleware('throttle:passkey-register');
    Route::delete('/passkeys/{id}', [PasskeyController::class, 'destroy']);
    Route::get('/passkeys', [PasskeyController::class, 'index']);
});

Route::post('/2fa/verify', [TwoFactorController::class, 'verify'])->middleware('throttle:two-factor-verify');
Route::post('/2fa/resend', [TwoFactorController::class, 'resend'])->middleware('throttle:two-factor-resend');
Route::post('/2fa/verify-link', [TwoFactorController::class, 'verifyLink'])->middleware('throttle:two-factor-link');
