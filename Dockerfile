FROM php:8.3-cli

# Install system dependencies
RUN apt-get update && apt-get upgrade -y && apt-get install -y \
    git \
    curl \
    libzip-dev \
    unzip \
    && docker-php-ext-install zip pdo_mysql

COPY --from=composer:latest /usr/bin/composer /usr/bin/composer

# Set working directory
WORKDIR /app

# The user will be the same as the host user to avoid permission issues
ARG UID
RUN useradd -G www-data,root -u ${UID} -d /home/user user
RUN mkdir -p /home/user/.composer && \
    chown -R user:user /home/user

USER user
