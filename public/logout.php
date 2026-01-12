<?php
require_once __DIR__ . '/../src/bootstrap.php';
session_unset();
session_destroy();
setcookie(session_name(), '', time()-3600, '/');
header('Location: login.php');
exit;
