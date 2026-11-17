<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class () extends Migration {
    public function up(): void
    {
        Schema::create('whilesmart_identities', function (Blueprint $table) {
            $table->string('identity_key', 64)->primary();
            $table->string('issuer', 512);
            $table->string('subject', 255);
            $table->string('user_type');
            $table->string('user_id', 128)->index();
            $table->text('credentials')->nullable();
            $table->timestamps();
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('whilesmart_identities');
    }
};
