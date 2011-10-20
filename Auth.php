<?php
/**
* HybridAuth
* 
* A Social-Sign-On PHP Library for authentication through identity providers like Facebook,
* Twitter, Google, Yahoo, LinkedIn, MySpace, Windows Live, Tumblr, Friendster, OpenID, PayPal,
* Vimeo, Foursquare, AOL, Gowalla, and others.
*
* Copyright (c) 2009-2011 (http://hybridauth.sourceforge.net) 
*/ 

// ------------------------------------------------------------------------
// The main file to include in Hybrid_Auth package 
// ------------------------------------------------------------------------

# some required includes  
require_once "Error.php"; 
require_once "Logger.php"; 

require_once "Storage.php";  

require_once "Provider_Model.php";
require_once "Provider_Adapter.php"; 

require_once "User.php"; 
require_once "User/Profile.php";

class Hybrid_Auth 
{
	public static $config  = ARRAY();

	public static $store   = NULL;

	public static $error   = NULL;

	public static $logger  = NULL;

	// --------------------------------------------------------------------

	/**
	* Try to start a new session of none then initialize Hybrid_Auth
	*/
	function __construct( $config )
	{
		if ( ! session_id() ):
			if( ! session_start() ):
				throw new Exception( "Hybriauth require the use of 'session_start()' at the start of your script, which appears to be disabled.", 1 );
			endif;
		endif;

		Hybrid_Auth::initialize( $config ); 
	}

	// --------------------------------------------------------------------

	/**
	* Try to initialize Hybrid_Auth
	*/
	public static function initialize( $config )
	{
		if ( ! session_id() ): 
			throw new Exception( "Hybriauth require the use of 'session_start()' at the start of your script.", 1 );
		endif;

		if( ! is_array( $config ) && ! file_exists( $config ) ){
			throw new Exception( "Hybriauth config does not exist on the given path.", 1 );
		}

		if( ! is_array( $config ) ){
			$config = include $config;
		} 

		// build some need'd paths
		$config["path_base"]        = realpath( dirname( __FILE__ ) )  . "/"; 
		$config["path_libraries"]   = $config["path_base"] . "thirdparty/";
		$config["path_resources"]   = $config["path_base"] . "resources/";
		$config["path_providers"]   = $config["path_base"] . "Providers/";

		if( ! isset( $config["debug_mode"] ) ){
			$config["debug_mode"] = false;
			$config["debug_file"] = null;
		}

		// hash given config
		Hybrid_Auth::$config = $config;

		// start session storage
		Hybrid_Auth::$store = new Hybrid_Storage();
		
		// instace of errors mng
		Hybrid_Auth::$error = new Hybrid_Error();

		// instace of log mng
		Hybrid_Auth::$logger = new Hybrid_Logger();

		// store php session.. well juste pour faire beau
		$_SESSION["HA::PHP_SESSION_ID"] = session_id(); 
		
		// almost done, check for error then move on
		Hybrid_Logger::info( "Hybrid_Auth::initialize(), stated. Hybrid_Auth has been called from: " . Hybrid_Auth::getCurrentUrl() );

		Hybrid_Logger::debug( "Hybrid_Auth initialize. dump used config: ", serialize( $config ) );

		Hybrid_Logger::info( "Hybrid_Auth initialize: check if any error is stored on the endpoint..." );

		if( Hybrid_Error::hasError() ){ 
			$m = Hybrid_Error::getErrorMessage();
			$c = Hybrid_Error::getErrorCode();
			$p = Hybrid_Error::getErrorPrevious();

			Hybrid_Logger::error( "Hybrid_Auth initialize: A stored Error found, Throw an new Exception and delete it from the store: Error#$c, '$m'" );

			Hybrid_Error::clearError(); 

			// try to provide the previous if any
			// Exception::getPrevious (PHP 5 >= 5.3.0) 
			// http://php.net/manual/en/exception.getprevious.php
			if ( version_compare( PHP_VERSION, '5.3.0', '>=' ) ) {  
				throw new Exception( $m, $c, $p );
			}
			else{
				throw new Exception( $m, $c );
			}
		}

		Hybrid_Logger::info( "Hybrid_Auth initialize: no error found. initialization succeed." );
		
		// Eo initialize 
	}

	// --------------------------------------------------------------------

	/**
	* Hybrid storage system accessor
	*
	* Users sessions are stored using HybridAuth storage system ( HybridAuth 2.0 handle PHP Session only) and can be acessed directly by
	* Hybrid_Auth::storage()->get($key) to retrieves the data for the given key, or calling
	* Hybrid_Auth::storage()->set($key, $value) to store the key => $value set.
	*/
	public static function storage()
	{
		return Hybrid_Auth::$store;
	}

	// --------------------------------------------------------------------

	/**
	* Get the session stored data. To be used on case you want to store session on a more persistent backend
	*/
	function getSessionData()
	{ 
		return Hybrid_Auth::storage()->getSessionData();
	}

	// --------------------------------------------------------------------

	/**
	* set the session data. To be used on case you want to store session on a more persistent backend
	*/
	function restoreSessionData( $sessiondata = NULL )
	{ 
		Hybrid_Auth::storage()->restoreSessionData( $sessiondata );
	}

	// --------------------------------------------------------------------

	/**
	* Try to authenticate the user with a given provider. 
	*
	* If the user is already connected we just return and instance of provider adapter,
	* ELSE, try to authenticate and authorize the user with the provider. 
	*
	* $params is generally an array with required info in order for this provider and HybridAuth to work,
	*  like :
	*          hauth_return_to: URL to call back after authentication is done
	*        openid_identifier: The OpenID identity provider identifier
	*           google_service: can be "Users" for Google user accounts service or "Apps" for Google hosted Apps
	*/
	public static function authenticate( $providerId, $params = NULL )
	{
		Hybrid_Logger::info( "Enter Hybrid_Auth::authenticate( $providerId )" );

		// if user not connected to $providerId then try setup a new adapter and start the login process for this provider
		if( ! Hybrid_Auth::storage()->get( "hauth_session.$providerId.is_logged_in" ) ){ 
			Hybrid_Logger::info( "Hybrid_Auth::authenticate( $providerId ), User not connected to the provider. Try to authenticate.." );

			$provider_adapter = Hybrid_Auth::setup( $providerId, $params );

			$provider_adapter->login();
		}

		// else, setup then return the adapter instance for the given provider
		else{
			Hybrid_Logger::info( "Hybrid_Auth::authenticate( $providerId ), User is already connected to this provider. Return the adapter instance." );

			return Hybrid_Auth::setup( $providerId );
		}
	} 

	// --------------------------------------------------------------------

   /**
	* Return the adapter instance for a given provider
	*/ 
	public static function getAdapter( $providerId = NULL )
	{
		Hybrid_Logger::info( "Enter Hybrid_Auth::getAdapter( $providerId )" );

		return Hybrid_Auth::setup( $providerId );
	}

	// --------------------------------------------------------------------

   /**
	* Check if the current user is connected to a given provider
	*/ 
	public static function isConnectedWith( $providerId = NULL )
	{
		Hybrid_Logger::info( "Enter Hybrid_Auth::isConnectedWith( $providerId )" );

		return 
			( bool) Hybrid_Auth::storage()->get( "hauth_session.{$providerId}.is_logged_in" );
	}

	// --------------------------------------------------------------------

   /**
	* Return array listing all authenticated providers
	*/ 
	public static function getConnectedProviders()
	{
		Hybrid_Logger::info( "Enter Hybrid_Auth::getAuthenticatedAdapters()" );

		$authenticatedProviders = ARRAY();
		
		foreach( Hybrid_Auth::$config["providers"] as $idpid => $params ){
			if( ( bool) Hybrid_Auth::storage()->get( "hauth_session.{$idpid}.is_logged_in" ) ){
				$authenticatedProviders[] = $idpid;
			}
		}

		return $authenticatedProviders;
	}

	// --------------------------------------------------------------------

   /**
	* Setup an adapter for a given provider
	*/ 
	public static function setup( $providerId, $params = NULL )
	{
		Hybrid_Logger::debug( "Enter Hybrid_Auth::setup( $providerId )", $params );

		if( ! $params ){ 
			$params = Hybrid_Auth::storage()->get( "hauth_session.$providerId.id_provider_params" );
			
			Hybrid_Logger::debug( "Hybrid_Auth::setup( $providerId ), no params given. Trying to get the sotred for this provider.", $params );
		}

		if( ! $params ){ 
			$params = ARRAY();
			
			Hybrid_Logger::info( "Hybrid_Auth::setup( $providerId ), no stored params found for this provider. Initialize a new one for new session" );
		}

		if( ! isset( $params["hauth_return_to"] ) ){
			$params["hauth_return_to"] = Hybrid_Auth::getCurrentUrl(); 
		}

		Hybrid_Logger::debug( "Hybrid_Auth::setup( $providerId ). HybridAuth Callback URL set to: ", $params["hauth_return_to"] );

		# instantiate a new IDProvider Adapter
		$provider   = new Hybrid_Provider_Adapter();

		$provider->factory( $providerId, $params );

		return $provider;
	} 

	// --------------------------------------------------------------------

   /**
	* Utility function, redirect to a given URL with php header or using javascript location.href
	*/
	public static function redirect( $url, $mode = "PHP", $postdata = ARRAY() )
	{ 
		Hybrid_Logger::info( "Enter Hybrid_Auth::redirect( $url, $mode )" );

		if( $mode == "PHP" )
		{
			header( "Location: $url" ) ;
		}
		elseif( $mode == "JS" )
		{
			echo '<html>';
			echo '<head>';
			echo '<script type="text/javascript">';
			echo 'function redirect(){ window.top.location.href="' . $url . '"; }';
			echo '</script>';
			echo '</head>';
			echo '<body onload="redirect()">';
			echo 'Redirecting, please wait...';
			echo '</body>';
			echo '</html>'; 
		}

		die();
	}

	// --------------------------------------------------------------------

   /**
	* Utility function, return the current url. TRUE to get $_SERVER['REQUEST_URI'], FALSE for $_SERVER['PHP_SELF']
	*/
	public static function getCurrentUrl( $request_uri = true ) 
	{ 
		$scheme = 'http';

		if ( isset( $_SERVER['HTTPS'] ) and $_SERVER['HTTPS'] == 'on' )
		{
			$scheme .= 's';
		}

		$server_port = "";
		$ps_or_ri    = $_SERVER['REQUEST_URI'];

		if( $_SERVER['SERVER_PORT'] != 80 ){
			$server_port = ":$server_port";
		}

		if( ! $request_uri ){
			$ps_or_ri = $_SERVER['PHP_SELF'];
		}

		return sprintf( "%s://%s%s%s", $scheme, $_SERVER['SERVER_NAME'], $server_port, $ps_or_ri ); 
	}
}
