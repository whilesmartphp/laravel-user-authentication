<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class () extends Migration {
    public function up(): void
    {
        Schema::create('auth_factors', function (Blueprint $table) {
            $table->id();
            $table->morphs('authenticatable');
            $table->string('type', 32);
            $table->string('label')->nullable();
            $table->text('secret')->nullable();
            $table->unsignedBigInteger('last_used_step')->nullable();
            $table->unsignedInteger('setup_attempts')->default(0);
            $table->timestamp('confirmed_at')->nullable();
            $table->timestamp('last_used_at')->nullable();
            $table->json('metadata')->nullable();
            $table->timestamps();
            $table->index(['authenticatable_type', 'authenticatable_id', 'type'], 'auth_factors_owner_type_index');
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('auth_factors');
    }
};
