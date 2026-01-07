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
        Schema::table('users', function (Blueprint $table) {
            $table->string('last_name')->nullable();
            $table->string('username')->nullable();
            $table->string('phone')->nullable()->unique();
            if (Schema::hasColumn('users', 'name')) {
                $table->renameColumn('name', 'first_name');
            } else {
                $table->string('first_name');
            }
            $table->text('two_factor_secret')->nullable();
            $table->boolean('two_factor_enabled')->default(false);
            // 2fa type options: totp, email, phone, smartpings
            $table->string('two_factor_type')->default('totp')->comment('2fa type options: totp, email, phone, smartpings');
            $table->timestamp('two_factor_confirmed_at')->nullable();

            $table->json('two_factor_recovery_codes')->nullable();
        });
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        Schema::table('users', function (Blueprint $table) {
            $table->dropColumn('last_name');
            $table->dropColumn('username');
            $table->dropColumn('phone');
            $table->renameColumn('first_name', 'name');
            $table->dropColumn('two_factor_secret');
            $table->dropColumn('two_factor_enabled');
            $table->dropColumn('two_factor_type');
            $table->dropColumn('two_factor_confirmed_at');

            $table->dropColumn('two_factor_recovery_codes');
        });
    }
};
