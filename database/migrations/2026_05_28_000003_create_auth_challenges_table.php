<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class () extends Migration {
    public function up(): void
    {
        Schema::create('auth_challenges', function (Blueprint $table) {
            $table->string('id', 64)->primary();
            $table->string('purpose', 32);
            $table->string('method', 16);
            $table->nullableMorphs('authenticatable');
            $table->foreignId('factor_id')->nullable()->constrained('auth_factors')->cascadeOnDelete();
            $table->string('contact')->nullable();
            $table->string('binding_key', 64)->nullable()->unique();
            $table->string('token_hash', 64)->unique();
            $table->string('policy', 64)->nullable();
            $table->string('action', 32)->nullable();
            $table->string('code_hash')->nullable();
            $table->string('link_hash', 64)->nullable()->unique();
            $table->unsignedInteger('attempts')->default(0);
            $table->timestamp('code_expires_at')->nullable();
            $table->timestamp('link_expires_at')->nullable();
            $table->timestamp('expires_at')->index();
            $table->timestamp('consumed_at')->nullable();
            $table->string('ip_address', 45)->nullable();
            $table->text('user_agent')->nullable();
            $table->json('metadata')->nullable();
            $table->timestamps();
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('auth_challenges');
    }
};
