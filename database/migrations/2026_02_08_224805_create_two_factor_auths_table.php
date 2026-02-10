<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    /**
     * Run the migrations.
     */
    public function up(): void
    {
        Schema::create('two_factor_auths', function (Blueprint $table) {
            $table->id();
            // polymorphic columns: authenticatable_id, authenticatable_type
            $table->morphs('authenticatable');

            $table->text('secret')->nullable();
            $table->string('type')->default('totp')->nullable();
            $table->boolean('is_enabled')->default(false);

            $table->timestamp('confirmed_at')->nullable();
            $table->json('recovery_codes')->nullable();

            $table->timestamps();
        });
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        Schema::dropIfExists('two_factor_auths');
    }
};
