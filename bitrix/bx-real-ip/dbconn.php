<?php
define("BX_USE_MYSQLI", true);
$DBDebug = false;
$DBDebugToFile = false;

define("CACHED_b_file", 3600);
define("CACHED_b_file_bucket_size", 10);
define("CACHED_b_lang", 3600);
define("CACHED_b_option", 3600);
define("CACHED_b_lang_domain", 3600);
define("CACHED_b_site_template", 3600);
define("CACHED_b_event", 3600);
define("CACHED_b_agent", 3660);
define("CACHED_menu", 3600);

define("BX_FILE_PERMISSIONS", 0644);
define("BX_DIR_PERMISSIONS", 0755);
@umask(~(BX_FILE_PERMISSIONS | BX_DIR_PERMISSIONS) & 0777);

define("BX_DISABLE_INDEX_PAGE", true);

define("BX_UTF", true);
mb_internal_encoding("UTF-8");

define('BX_CRONTAB_SUPPORT', true);

// For insert in /bitrix/php_interface/dbconn.php

// Start FortiWeb Support Code
// (P) 2018 INCO Group
if(isset($_SERVER['HTTP_X_FORWARDED_FOR'])) {
    foreach(array('HTTP_X_FORWARDED_FOR') as $key => $value) {
        if(
            isset($_SERVER[$value])
            &&  strlen($_SERVER[$value]) > 0
            &&  strpos($_SERVER[$value], "127.") !== 0
        ) {
            if($p = stripos($_SERVER[$value], ","))
            {
				$_SERVER["REMOTE_ADDR"]= $REMOTE_ADDR = trim(substr($_SERVER[$value], 0, $p));
				break;
            }
			else
                $_SERVER["REMOTE_ADDR"]= $REMOTE_ADDR = $_SERVER[$value]; 

			break;
        }
    }
}
// End FortiWeb Support Code
