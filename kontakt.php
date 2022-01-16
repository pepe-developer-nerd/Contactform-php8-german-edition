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

    // formcheck start.
    if(!$name) {
        $fehler['name'] = "<span class='errormsg'>Geben Sie bitte Ihren <strong>Namen</strong> ein.</span>";
    }

    if(!preg_match("/^[0-9a-zA-ZAÜÖ_.-]+@[0-9a-z.-]+\.[a-z]{2,6}$/", $email)) {
        $fehler['email'] = "<span class='errormsg'>Geben Sie bitte Ihre <strong>E-Mail-Adresse</strong> ein.</span>";
    }

    if(!$betreff) {
        $fehler['betreff'] = "<span class='errormsg'>Geben Sie Bitte einen <strong>Betreff</strong> ein.</span>";
    }

    if(!$nachricht) {
        $fehler['nachricht'] = "<span class='errormsg'>Geben Sie Bitte eine <strong>Nachricht</strong> ein.</span>";
    }
    // formcheck end.

    // spamprotection error messages start.
    if($cfg['Sicherheitscode'] && $sicherheits_eingabe != $_SESSION['captcha_spam']) {
        unset($_SESSION['captcha_spam']);
        $fehler['captcha'] = "<span class='errormsg'>Der <strong>Sicherheitscode</strong> wurde falsch eingegeben.</span>";
    }

    if(['Sicherheitsfrage']) {
        $answer = Antispam::getAnswerById(intval($_POST["q_id"]));
        if(isset($_POST["q"]) && $_POST["q"] != $answer) {
            $fehler['q_id12'] = "<span class='errormsg'>Bitte die <strong>Sicherheitsfrage</strong> richtig beantworten.</span>";
        }
    }

    if($cfg['Honeypot'] && (!isset($_POST["mail"]) || ''!=$_POST["mail"])) {
        $fehler['Honeypot'] = "<span class='errormsg' style='display: block; color: red; font-size: .75rem;>Es besteht Spamverdacht. Bitte überprüfen Sie Ihre Angaben</span>";
    }

    if($cfg['Zeitsperre'] && (!isset($_POST["chkspmtm"]) || ''==$_POST["chkspmtm"] || '0'==$_POST["chkspmtm"] || (time() - (int) $_POST["chkspmtm"]) < (int) $cfg['Zeitsperre'])){
		$fehler['Zeitsperre'] = "<span class='errormsg' style='display: block; color: red; font-size: .75rem;'>Bitte warten Sie einige Sekunden, bevor Sie das Formular erneut absenden.</span>";
	}

    if($cfg['Klick-Check'] && (!isset($_POST["chkspmkc"]) || 'chkspmhm'!=$_POST["chkspmkc"])){
		$fehler['Klick-Check'] = "<span class='errormsg' style='display: block; color: red; font-size: .75rem;'>Sie müssen den Senden-Button mit der Maus anklicken, um das Formular senden zu können.</span>";
	}

    if($cfg['Links'] < preg_match_all('#http(s?)\:\/\/#is', $nachricht, $irrelevantMatches)) {
        $fehler['Links'] = "<span class='errormsg' style='display: block; color: red; font-size: .75rem;'>Ihre Nachricht darf "
           .(0==$cfg['Links'] ?
             'keine Links' :
                (1==$cfg['Links'] ?
                    'nur einen Link' :
                    'maximal ' .$cfg['Links']. ' Links'
                )
            )." enthalten.</span>";
    }

    if(''!=$cfg['Badwordfilter'] && 0!==$cfg['Badwordfilter'] && '0'!=$cfg['Badwordfilter']){
		$badwords = explode(',', $cfg['Badwordfilter']);			// the configured badwords
		$badwordFields = explode(',', $cfg['Badwordfields']);		// the configured fields to check for badwords
		$badwordMatches = array();									// the badwords that have been found in the fields
		
		if(0<count($badwordFields)){
			foreach($badwords as $badword){
				$badword = trim($badword);												// remove whitespaces from badword
				$badwordMatch = str_replace('%', '', $badword);							// take human readable badword for error-message
				$badword = addcslashes($badword, '.:/');								// make ., : and / preg_match-valid
				if('%'!=substr($badword, 0, 1)){ $badword = '\\b'.$badword; }			// if word mustn't have chars before > add word boundary at the beginning of the word
				if('%'!=substr($badword, -1, 1)){ $badword = $badword.'\\b'; }			// if word mustn't have chars after > add word boundary at the end of the word
				$badword = str_replace('%', '', $badword);								// if word is allowed in the middle > remove all % so it is also allowed in the middle in preg_match 
				foreach($badwordFields as $badwordField){
					if(preg_match('#'.$badword.'#is', $_POST[trim($badwordField)]) && !in_array($badwordMatch, $badwordMatches)){
						$badwordMatches[] = $badwordMatch;
					}
				}
			}		
			
			if(0<count($badwordMatches)){
				$fehler['Badwordfilter'] = "<span class='errormsg' style='display: block; color:red;font-size:.75rem;'>Folgende Begriffe sind nicht erlaubt: ".implode(', ', $badwordMatches)."</span>";
			}
		}		
	}
    // spamprotection error messages end.
}