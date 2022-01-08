<?php
session_start();
error_reporting(E_ERROR | E_PARSE);
date_default_timezone_set('Europe/Berlin');
require_once("captcha/AntiSpam.php");
$q = AntiSpam::getRandomQuestion();
header(('Content-Type: text/html; charset=utf-8'));

$script_root = substr(__FILE__, 0,
    strrpos(__FILE__,
        DIRECTORY_SEPARATOR)
        ).DIRECTORY_SEPARATOR;

$remote = getenv("REMOTE_ADDR");

function encrypt($string, $key) {
    $result = '';
    for($i=0; $i<strlen($string); $i++) {
        $char = substr($string, $i, 1);
        $keychar = substr($key, ($i % strlen($key))-1, 1);
        $char = chr(ord($char)+ord($keychar));
        $result.=$char;
    }
    return base64_encode($result);
}

@require('config.php');
require_once('captcha/Antispam.php');
include('PHPMailer/Secureimage.php');

// form-data should be deleted
if (isset($_POST['delete'])&& $_POST['delete']) {
    unset($_POST);
}

// form has been sent
if (isset($_POST["kf-km"]) && $_POST["kf-km"]) {
    
    // clean data
    $name = stripslashes($_POST["name"]);
    $telefon = $_POST["telefon"];
    $email = stripslashes($_POST["email"]);
    $betreff = stripslashes($_POST["betreff"]);
    $nachricht = stripslashes($_POST["nachricht"]);
    if($cfg['DATENSCHUTZ_ERKLÄRUNG']) { $datenschutz = stripslashes($_POST["datenschutz"]); }
    if($cfg['Sicherheitscode']){
        $sicherheits_eingabe = encrypt($_POST["sicherheitscode"], "8h384ls94");
        $sicherheits_eingabe = str_replace("=", "", $sicherheits_eingabe);
    }

    $date = date("d.m.Y | H:i");
    $ip = $_SERVER['REMOTE_ADDR'];
    $UserAgent = $_ERVER("HTTP_USER_AGENT");
    $host = gethostbyaddr($remote);

    // formcheck
}