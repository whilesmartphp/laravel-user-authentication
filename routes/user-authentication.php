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

// Resource routes
Route::group(['middleware' => ['auth:sanctum']], function () {
    Route::post('logout', [AuthController::class, 'logout']);

    // 2FA onboarding and management
    Route::prefix('2fa')->group(function () {
        Route::post('/setup', [TwoFactorController::class, 'setup']); // start 2fa
        Route::post('/confirm', [TwoFactorController::class, 'confirm']); // confirm and enable 2fa
        Route::post('/disable', [TwoFactorController::class, 'disable']); // turn off 2fa
    });
});

// 2FA Routes
Route::post('/2fa/verify', [TwoFactorController::class, 'verify'])
    ->middleware('throttle:5,1'); // Limit to 5 attempts per minute
Route::post('/2fa/resend', [TwoFactorController::class, 'resend'])
    ->middleware('throttle:3,1'); // Limit to 3 resend attempts per minute

// The Magic Link endpoint (GET request for the email button)
Route::get('/2fa/verify', [TwoFactorController::class, 'verifyLink']);
