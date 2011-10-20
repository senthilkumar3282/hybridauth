<?php
/**
 * HybridAuth
 * 
 * An open source Web based Single-Sign-On PHP Library used to authentificates users with
 * major Web account providers and accessing social and data apis at Google, Facebook,
 * Yahoo!, MySpace, Twitter, Windows live ID, etc. 
 *
 * Copyright (c) 2009 (http://hybridauth.sourceforge.net)
 *
 * @package     Hybrid_Auth
 * @author      hybridAuth Dev Team
 * @copyright   Copyright (c) 2009, hybridAuth Dev Team.
 * @license     http://hybridauth.sourceforge.net/licenses.html under MIT and GPL
 * @link        http://hybridauth.sourceforge.net 
 */
 
/**
 * Logging wrapper for the Yahoo objects.
 *
 * Logging wrapper for the Yahoo objects.
 *
 * @package    Hybrid_Auth 
 * @author     Zachy <hybridauth@gmail.com>
 * @version    1.0
 * @since      HybridAuth 1.0.1 
 */
class Hybrid_Logger
{
	function __construct()
	{
		if ( Hybrid_Auth::$config["debug_mode"] ):
			if ( ! file_exists( Hybrid_Auth::$config["debug_file"] ) ):
				throw new Exception( "'debug_mode' is set to 'true', but the given log file path 'debug_file' do not exist.", 1 );
			endif; 

			if ( ! is_writable( Hybrid_Auth::$config["debug_file"] ) ):
				throw new Exception( "'debug_mode' is set to 'true', but the given log file path 'debug_file' is not a writable file.", 1 );
			endif; 
		endif; 
	}

    /**
     * Log a message at the debug level.
     *
     * @param $message The message to log.
     */
    public static function debug($message, $object = NULL)
	{
		if( Hybrid_Auth::$config["debug_mode"] )
		{
		    $datetime = new DateTime();
		    $datetime =  $datetime->format(DATE_ATOM);
    
			file_put_contents
			( 
				Hybrid_Auth::$config["debug_file"], 
				"DEBUG -- " . $_SERVER['REMOTE_ADDR'] . " -- " . $datetime . " -- " . $message . " -- " . print_r($object, true) . "\n", 
				FILE_APPEND
			);
        }
    }

	// --------------------------------------------------------------------

    /**
     * Log a message at the info level.
     *
     * @param $message The message to log.
     */
    public static function info( $message )
	{ 
		if( Hybrid_Auth::$config["debug_mode"] )
		{
		    $datetime = new DateTime();
		    $datetime =  $datetime->format(DATE_ATOM);
    
			file_put_contents
			( 
				Hybrid_Auth::$config["debug_file"], 
				"INFO -- " . $_SERVER['REMOTE_ADDR'] . " -- " . $datetime . " -- " . $message . "\n", 
				FILE_APPEND
			);
        }
    }

	// --------------------------------------------------------------------

    /**
     * Log a message at the error level.
     *
     * @param $message The message to log.
     */
    public static function error($message, $object = NULL)
	{ 
		if( Hybrid_Auth::$config["debug_mode"] )
		{
		    $datetime = new DateTime();
		    $datetime =  $datetime->format(DATE_ATOM);
    
			file_put_contents
			( 
				Hybrid_Auth::$config["debug_file"], 
				"ERROR -- " . $_SERVER['REMOTE_ADDR'] . " -- " . $datetime . " -- " . $message . " -- " . print_r($object, true) . "\n", 
				FILE_APPEND
			);
        }
    }
}
