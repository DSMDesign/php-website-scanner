<?php
/*
Plugin Name: php web scanner
Description: The php web scanner checks all files for one of the most common malicious code attacks, the eval( base64_decode() ) attack...
Description: Also checks for any files that have been added, deleted or modified.
Version: 1.1
Author: Kenny Turner
Author URI: http://www.southcoastweb.co.uk
Credit: Thanks to Mike Stowe (http://www.mikestowe.com) for eval malware code scanner
License: MIT
*/

// Avoid memory errors (i.e in foreachloop)
ini_set('memory_limit', '-1');

// Setup
define('EMAIL_ALERT','');
define('DOMAIN', '');
define('FROM_EMAIL', '');

// grab the class
require('src/scanner.php');

// Run the scan
$scan = new phpWebScan();
$scan->readFile();
$scan->scan($_SERVER['DOCUMENT_ROOT']);
$scan->sendAlert();

