<?php

namespace Whilesmart\UserAuthentication\Models;

use Cose\Algorithm\Manager;
use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\MorphTo;
use Symfony\Component\Serializer\SerializerInterface;
use Webauthn\AttestationStatement\AttestationStatementSupportManager;
use Webauthn\AttestationStatement\FidoU2FAttestationStatementSupport;
use Webauthn\AttestationStatement\NoneAttestationStatementSupport;
use Webauthn\AttestationStatement\PackedAttestationStatementSupport;
use Webauthn\CredentialRecord;
use Webauthn\Denormalizer\WebauthnSerializerFactory;

/**
 * @property string $data
 */
class Passkey extends Model
{
    use HasFactory;

    protected $fillable = [
        'name',
        'credential_id',
        'data',
        'keyable_type',
        'keyable_id',
    ];

    public function keyable(): MorphTo
    {
        return $this->morphTo();
    }

    public function getCredential(): CredentialRecord
    {

        return $this->webAuthnSerializer()->deserialize(
            $this->data,
            CredentialRecord::class,
            'json'
        );
    }

    public static function webAuthnSerializer(): SerializerInterface
    {
        $attestationStatementSupportManager = new AttestationStatementSupportManager();
        $attestationStatementSupportManager->add(new NoneAttestationStatementSupport());
        $attestations = config('user-authentication.passkey.attestations');
        if (in_array('packed', $attestations, true)) {
            $manager = new Manager();
            $attestationStatementSupportManager->add(new PackedAttestationStatementSupport($manager));
        }
        if (in_array('fido', $attestations, true)) {
            $attestationStatementSupportManager->add(new FidoU2FAttestationStatementSupport());
        }

        return (new WebauthnSerializerFactory($attestationStatementSupportManager))->create();
    }
}
