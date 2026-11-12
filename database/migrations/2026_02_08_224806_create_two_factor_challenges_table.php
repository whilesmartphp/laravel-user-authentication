<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class () extends Migration {
    public function up(): void
    {
        Schema::create('two_factor_challenges', function (Blueprint $table) {
            $table->string('id', 64)->primary();
            $table->foreignId('factor_id')->unique()->constrained('two_factor_auths')->cascadeOnDelete();
            $table->string('token_hash', 64)->unique();
            $table->string('purpose', 32);
            $table->string('method', 16);
            $table->string('contact')->nullable();
            $table->string('policy', 64);
            $table->string('action', 32);
            $table->string('code_hash')->nullable();
            $table->string('link_hash', 64)->nullable()->unique();
            $table->unsignedInteger('attempts')->default(0);
            $table->timestamp('expires_at');
            $table->timestamp('consumed_at')->nullable();
            $table->timestamps();
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('two_factor_challenges');
    }
};
