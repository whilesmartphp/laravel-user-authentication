<?php

namespace Whilesmart\LaravelUserAuthentication\Http\Controllers\Auth;

use App\Models\User;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Routing\Controller;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Validator;
use OpenApi\Attributes as OA;
use Whilesmart\LaravelUserAuthentiation\Events\PasswordResetCodeGeneratedEvent;
use Whilesmart\LaravelUserAuthentiation\Events\PasswordResetCompleteEvent;
use Whilesmart\LaravelUserAuthentication\Models\VerificationCode;
use Whilesmart\LaravelUserAuthentication\Traits\ApiResponse;

#[OA\Tag(name: 'Authentication', description: 'Endpoints for password reset')]
class PasswordResetController extends Controller
{
    use ApiResponse;

    #[OA\Post(
        path: '/password/reset-code',
        summary: 'Send password reset code',
        security: [],
        requestBody: new OA\RequestBody(
            required: true,
            content: new OA\JsonContent(
                required: ['email'],
                properties: [
                    new OA\Property(
                        property: 'email',
                        description: 'The email address of the user',
                        type: 'string',
                        format: 'email'
                    ),
                ]
            )
        ),
        tags: ['Authentication'],
        responses: [
            new OA\Response(
                response: 200,
                description: 'Password reset code sent successfully',
                content: new OA\JsonContent(
                    properties: [
                        new OA\Property(
                            property: 'message',
                            type: 'string',
                            example: 'Password reset code sent successfully.'
                        ),
                    ]
                )
            ),
            new OA\Response(
                response: 422,
                description: 'Validation error'
            ),
        ]
    )]
    public function sendPasswordResetCode(Request $request): JsonResponse
    {
        $validator = Validator::make($request->all(), [
            'email' => 'required|email|exists:users,email',
        ]);

        if ($validator->fails()) {
            return $this->failure('Validation failed.', 422, [$validator->errors()]);
        }

        $email = $request->email;
        $verificationCode = random_int(100000, 999999);
        $expiresAt = now()->addMinutes(15);

        VerificationCode::updateOrCreate(
            ['contact' => $email, 'purpose' => 'password_reset'],
            ['code' => $verificationCode, 'expires_at' => $expiresAt]
        );

        PasswordResetCodeGeneratedEvent::dispatch($email, $verificationCode);

        return $this->success([], 'Password reset code sent successfully.');
    }

    #[OA\Post(
        path: '/password/reset',
        summary: 'Reset password using verification code',
        security: [],
        requestBody: new OA\RequestBody(
            required: true,
            content: new OA\JsonContent(
                required: ['email', 'code', 'new_password'],
                properties: [
                    new OA\Property(
                        property: 'email',
                        description: 'The email address of the user',
                        type: 'string',
                        format: 'email'
                    ),
                    new OA\Property(
                        property: 'code',
                        description: 'The verification code sent to the user',
                        type: 'integer'
                    ),
                    new OA\Property(
                        property: 'new_password',
                        description: 'The new password for the user',
                        type: 'string'
                    ),
                ]
            )
        ),
        tags: ['Authentication'],
        responses: [
            new OA\Response(
                response: 200,
                description: 'Password reset successful',
                content: new OA\JsonContent(
                    properties: [
                        new OA\Property(
                            property: 'message',
                            type: 'string',
                            example: 'Password has been reset successfully.'
                        ),
                    ]
                )
            ),
            new OA\Response(
                response: 422,
                description: 'Validation error'
            ),
            new OA\Response(
                response: 400,
                description: 'Invalid or expired code'
            ),
        ]
    )]
    public function resetPasswordWithCode(Request $request): JsonResponse
    {
        $validator = Validator::make($request->all(), [
            'email' => 'required|email|exists:users,email',
            'code' => 'required|integer',
            'new_password' => 'required|string|min:8',
        ]);

        if ($validator->fails()) {
            return $this->failure('Validation failed.', 422, [$validator->errors()]);
        }

        $codeEntry = VerificationCode::where('contact', $request->email)
            ->where('purpose', 'password_reset')
            ->first();

        if (!$codeEntry || $codeEntry->code != $request->code || $codeEntry->isExpired()) {
            return $this->failure('Invalid or expired code.', 400);
        }

        $user = User::where('email', $request->email)->first();
        $user->password = Hash::make($request->new_password);
        $user->save();

        PasswordResetCompleteEvent::dispatch($user);

        $codeEntry->delete();

        return $this->success([], 'Password has been reset successfully.');
    }
}
