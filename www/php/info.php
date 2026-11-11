<?php
header('Content-Type: text/html; charset=utf-8');
echo "<h1>⚡ ZMax Server + PHP-FPM FastCGI Calisiyor!</h1>";
echo "<p>PHP Surumu: " . phpversion() . "</p>";
echo "<p>Sunucu SAPI: " . php_sapi_name() . "</p>";
echo "<p>Sunucu Yazilimi: " . ($_SERVER['SERVER_SOFTWARE'] ?? 'ZMax Server') . "</p>";

