<?php

require __DIR__ . '/../vendor/autoload.php';
require __DIR__ . '/../shorty.php';

$dotenv = Dotenv\Dotenv::createImmutable(__DIR__ . '/../');
$dotenv->load();

try {
    $connection = new PDO("mysql:dbname={$_ENV['DB_NAME']};host={$_ENV['DB_HOST']}", $_ENV['DB_USER'], $_ENV['DB_PASS']);
} catch (PDOException $ex) {
    die(json_encode(array(
        'error' => true,
        'message' => 'Unable to connect to db.'
    )));
}

$shorty = new Shorty($_ENV['BASE_URL'], $connection);

if(isset($_ENV['AUTH_CREDS'])){
    $shorty->set_creds(json_decode($_ENV['AUTH_CREDS'], true));
}

$shorty->set_chars($_ENV['CHARS']);
$shorty->set_salt($_ENV['SALT']);
$shorty->set_padding($_ENV['PADDING']);

$shorty->run();
