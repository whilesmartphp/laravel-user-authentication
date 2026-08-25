<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class () extends Migration {
    /**
     * Run the migrations.
     */
    public function up(): void
    {
        $userModel = config('user-authentication.user_model', \Whilesmart\UserAuthentication\Models\User::class);
        $userTable = (new $userModel())->getTable();

        Schema::create('magic_links', function (Blueprint $table) use ($userTable) {
            $table->id();

            $table->foreignId('user_id')->constrained($userTable)->onDelete('cascade');
            $table->string('token')->unique();
            $table->timestamp('expires_at');
            $table->boolean('is_used')->default(false);

            $table->timestamps();
        });
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        Schema::dropIfExists('magic_links');
    }
};
