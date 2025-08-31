# Installation Guide

## 1. Require the package

```bash
composer require whilesmart/laravel-user-authentication
```

## 2. Publish the configuration and migrations

You do not need to publish the migrations and configurations except if you want to make modifications. You can choose to publish the migrations, routes, controllers separately or all at once.

### 2.1 Publishing only the routes

Run the command below to publish only the routes.

```bash
php artisan vendor:publish --tag=laravel-user-authentication-routes
php artisan migrate
```

The routes will be available at `routes/user-authentication.php`. You should `require` this file in your `api.php` file.

```php
require 'user-authentication.php';
```

### 2.2 Publishing only the migrations

If you would like to make changes to the migration files, run the command below to publish only the migrations.

```bash
php artisan vendor:publish --tag=laravel-user-authentication-migrations
php artisan migrate
```

The migrations will be available in the `database/migrations` folder.

### 2.3 Publish only the controllers

To publish the controllers, run the command below

```bash
php artisan vendor:publish --tag=laravel-user-authentication-controllers
php artisan migrate
```

The controllers will be available in the `app/Http/Controllers/Api/Auth` directory.
Finally, change the namespace in the published controllers to your namespace.

**Note: Publishing the controllers will also publish the routes. See section 2.1**

### 2.4 Publish the config

To publish the config, run the command below

```bash
php artisan vendor:publish --tag=laravel-user-authentication-config
```

The config file will be available in the `config/user-authentication.php`.

### 2.5 Publish everything

To publish the migrations, config, routes, and controllers, you can run the command below

```bash
php artisan vendor:publish --tag=laravel-user-authentication
php artisan migrate
```

## 3. OAuth Configuration

This package uses `laravel/socialite` for oauth. Please refer to the [Socialite Documentation](https://laravel.com/docs/12.x/socialite) if your application requires oauth.

## 4. Updates to the User model

Add the following to the `$fillable` variable in your User model:

```php
'first_name',
'last_name',
'username',
'phone'
```