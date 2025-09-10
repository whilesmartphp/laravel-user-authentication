<?php

namespace Whilesmart\UserAuthentication\Services;

use Smartpings\Messaging\SmartpingsService;

class SmartPingsVerificationService
{
    protected SmartpingsService $smartPings;

    protected bool $enabled;

    public function __construct()
    {
        $this->enabled = config('user-authentication.verification.provider') === 'smartpings' &&
                        ! config('user-authentication.verification.self_managed', true);

        if ($this->enabled) {
            $clientId = config('user-authentication.smartpings.client_id');
            $secretId = config('user-authentication.smartpings.secret_id');

            if ($clientId && $secretId) {
                $this->smartPings = SmartpingsService::create($clientId, $secretId);
            } else {
                \Log::error('SmartPings is enabled but client_id or secret_id is missing. SmartPings verification disabled.');
                $this->enabled = false;
            }
        }
    }

    public function isEnabled(): bool
    {
        return $this->enabled;
    }

    public function sendVerification(string $contact, string $type): array
    {
        if (! $this->enabled) {
            return [
                'success' => false,
                'message' => 'SmartPings verification is not enabled',
            ];
        }

        $expiryMinutes = config('user-authentication.verification.code_expiry_minutes', 5);

        try {
            $response = $this->smartPings->verifyContact(
                type: $type,
                contact: $contact,
                expirationMinutes: $expiryMinutes
            );

            $responseBody = $response->getBody()->getContents();
            $responseData = json_decode($responseBody, true);

            \Log::info('SmartPingsVerificationService: Send verification response', [
                'status' => $response->getStatusCode(),
                'response' => $responseData,
                'contact' => $contact,
                'type' => $type,
            ]);

            if (isset($responseData['success']) && $responseData['success'] === true) {
                return [
                    'success' => true,
                    'message' => $responseData['message'] ?? ucfirst($type).' verification sent successfully',
                ];
            }

            return [
                'success' => false,
                'message' => $responseData['message'] ?? 'Failed to send verification',
            ];
        } catch (\Exception $e) {
            \Log::error('SmartPingsVerificationService: Exception during send verification', [
                'message' => $e->getMessage(),
                'type' => $type,
                'contact' => $contact,
            ]);

            return [
                'success' => false,
                'message' => 'Verification service temporarily unavailable',
            ];
        }
    }

    public function verify(string $contact, string $code, string $type): bool
    {
        if (! $this->enabled) {
            return false;
        }

        try {
            $response = $this->smartPings->verifyContact(
                type: $type,
                contact: $contact,
                code: $code
            );

            $responseBody = $response->getBody()->getContents();
            $responseData = json_decode($responseBody, true);

            \Log::info('SmartPingsVerificationService: Verify response', [
                'status' => $response->getStatusCode(),
                'response' => $responseData,
                'contact' => $contact,
                'type' => $type,
            ]);

            return isset($responseData['success']) && $responseData['success'] === true;
        } catch (\Exception $e) {
            \Log::error('SmartPingsVerificationService: Exception during verification with provided code', [
                'contact' => $contact,
                'type' => $type,
                'error' => $e->getMessage(),
            ]);

            return false;
        }
    }

    public function isVerified(string $contact, string $type): bool
    {
        if (! $this->enabled) {
            return false;
        }

        try {
            $response = $this->smartPings->verifyContact(type: $type, contact: $contact);

            $responseBody = $response->getBody()->getContents();
            $responseData = json_decode($responseBody, true);

            \Log::info('SmartPingsVerificationService: Is verified response', [
                'status' => $response->getStatusCode(),
                'response' => $responseData,
                'contact' => $contact,
                'type' => $type,
            ]);

            return isset($responseData['success']) && $responseData['success'] === true;
        } catch (\Exception $e) {
            \Log::error('SmartPingsVerificationService: Exception during isVerified check', [
                'message' => $e->getMessage(),
                'type' => $type,
                'contact' => $contact,
            ]);

            return false;
        }
    }
}
