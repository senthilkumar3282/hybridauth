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

// ------------------------------------------------------------------------

/**
 * The Providers_Model class is a simple abstract model for providers wrappers 
 *
 * @package    Hybrid_Auth 
 * @author     Zachy <hybridauth@gmail.com>
 * @version    1.0
 * @since      HybridAuth 1.0.1 
 * @link       http://hybridauth.sourceforge.net/userguide/Supported_identity_providers_and_setup_keys.html
 * @see        Hybrid_Provider_Adapter
 */
abstract class Hybrid_Provider_Model
{
   /**
	* the IDp api client (optional)
	*/
	var $api              = NULL; 

	/**
	* Hybrid_User obj, represents the current user
	*/
	var $user             = NULL;

   /**
	* IDp adapter config on hybridauth.php
	*/
	var $config           = NULL;

   /**
	* IDp adapter requireds params
	*/
	var $params           = NULL;

   /**
	* IDp ID (or unique name)
	*/
	var $providerId       = NULL;

   /**
	* Hybridauth Endpoint URL
	*/
	var $endpoint        = NULL; 

   /**
	* common IDp wrappers constructor
	*/
	function __construct( $providerId, $config, $params = NULL )
	{
		$this->config     = $config;
		$this->providerId = $providerId;

		# init the IDp adapter parameters, get them from the cache if possible
		if( ! $params )
		{
			$this->params = Hybrid_Auth::storage()->get( "hauth_session.$providerId.id_provider_params" );
		}
		else
		{
			$this->params = $params;
		}

		$this->user               = new Hybrid_User(); 

		$this->user->providerId   = $this->providerId; 
		
		// set HybridAuth endpoint for this provider
		$this->endpoint           = Hybrid_Auth::storage()->get( "hauth_session.$providerId.hauth_endpoint" );

		$this->initialize(); 
	}

	// --------------------------------------------------------------------

   /**
	* IDp wrappers initializer
	*
	* The main job of wrappers initializer is to performs (depend on the IDp api client it self): 
	*     - include some libs nedded by this provider,
	*     - check IDp key and secret,
	*     - set some needed parameters (stored in $this->params) by this IDp api client
	*     - create and setup an instance of the IDp api client on $this->api 
	*/
	abstract protected function initialize(); 

	// --------------------------------------------------------------------

   /**
	* begin login 
	*/
	abstract protected function loginBegin();

	// --------------------------------------------------------------------

   /**
	* finish login
	*/
	abstract protected function loginFinish();

	// --------------------------------------------------------------------

   /**
	* generic logout, just erase current provider adapter stored data to let Hybrid_Auth all forget about it
	*/
	function logout()
	{
		Hybrid_Logger::info( "Enter [{$this->providerId}]::logout()" );

		$this->clearTokens(); 

		return TRUE;
	}

	// --------------------------------------------------------------------

   /**
	* grab the user profile from the IDp api client
	*/
	abstract protected function getUserProfile();

	// --------------------------------------------------------------------

   /**
	* load the current logged in user contacts list from the IDp api client 
	*
	* HybridAuth dont provide users contats on version 1.0.x
	*/
	function getUserContacts() 
	{
		Hybrid_Logger::error( "HybridAuth do not provide users contats list for {$this->providerId} yet." ); 
		
		throw new Exception( "Provider does not support this feature.", 8 ); 
	}

	// --------------------------------------------------------------------

	public function isUserConnected()
	{
		return 
			( bool) Hybrid_Auth::storage()->get( "hauth_session.{$this->providerId}.is_logged_in" );
	}

	// --------------------------------------------------------------------

	public function setUserConnected()
	{
		Hybrid_Logger::info( "Enter [{$this->providerId}]::setUserConnected()" );
		
		Hybrid_Auth::storage()->set( "hauth_session.{$this->providerId}.is_logged_in", 1 );
	}

	// --------------------------------------------------------------------

	public function setUserUnconnected()
	{
		Hybrid_Logger::info( "Enter [{$this->providerId}]::setUserUnconnected()" );
		
		Hybrid_Auth::storage()->set( "hauth_session.{$this->providerId}.is_logged_in", 0 ); 
	}

	// --------------------------------------------------------------------

	public function token( $token, $value = NULL )
	{
		if( $value === NULL ){
			return Hybrid_Auth::storage()->get( "hauth_session.{$this->providerId}.token.$token" );
		}
		else{
			Hybrid_Auth::storage()->set( "hauth_session.{$this->providerId}.token.$token", $value );
		}
	}

	// --------------------------------------------------------------------

	public function clearTokens()
	{ 
		Hybrid_Auth::storage()->deleteMatch( "hauth_session.{$this->providerId}." );
	}
}
