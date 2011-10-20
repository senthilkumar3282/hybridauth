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

/**
 * The Hybrid_Provider_Adapter class is a kinda of factory to create providers wrapper instances,  
 */
class Hybrid_Provider_Adapter
{
   /**
	* IDp ID (or unique name)
	*/
	var $id       = NULL ;

   /**
	* IDp adapter config on hybrid.config.php
	*/
	var $config   = NULL ;

   /**
	* IDp adapter requireds params
	*/
	var $params   = NULL ; 

   /**
	* IDp adapter path
	*/
	var $wrapper  = NULL ;

   /**
	* IDp adapter instance
	*/
	var $adapter  = NULL ;

    /**
     * create a new adapter switch IDp name or ID
     *
     * @param string  $id      The id or name of the IDp
     * @param array   $params  (optional) required parameters by the adapter 
     */
	function factory( $id, $params = NULL )
	{
		Hybrid_Logger::info( "Enter Hybrid_Provider_Adapter::factory( $id )" );

		# init the adapter config and params
		$this->id     = $id;
		$this->params = $params;
		$this->id     = $this->getProviderCiId( $this->id );
		$this->config = $this->getConfigById( $this->id );

		# check the IDp id
		if( ! $this->id )
		{
			throw new Exception( "No provider ID specified.", 2 ); 
		}

		# check the IDp config
		if( ! $this->config )
		{
			throw new Exception( "Unknown Provider ID, check your configuration file.", 3 ); 
		}

		# check the IDp adapter is enabled
		if( ! $this->config["enabled"] )
		{
			throw new Exception( "The provider '{$this->id}' is not enabled.", 3 );
		}

		# include the adapter wrapper
		require_once Hybrid_Auth::$config["path_providers"] . "/" . $this->id . ".php" ;

		$this->wrapper = "Hybrid_Providers_" . $this->id;

		# create the adapter instance, and pass the current params and config
		$this->adapter = new $this->wrapper( $this->id, $this->config, $this->params );

		return $this;
	}

	// --------------------------------------------------------------------

    /**
     * This is the methode that should be specified when a user requests a sign in whith an IDp.
     * 
     * Hybrid_Provider_Adapter::login(), prepare the user session and the authentification request
	 * for hybrid.endpoint.php
     */
	function login()
	{
		Hybrid_Logger::info( "Enter Hybrid_Provider_Adapter::login( {$this->id} ) " );

		if( ! $this->adapter )
		{
			return NULL;
		}
		
		$this->adapter->clearTokens();

		$this->adapter->setUserUnconnected();

		# get hybridauth base url
		$HYBRID_AUTH_URL_BASE = Hybrid_Auth::$config["base_url"];

		# we make use of session_id() as storage hash to identify the current user
		# using session_regenerate_id() will be a problem, but ..
		$this->params["hauth_token"] = session_id();

		# set request timestamp
		$this->params["hauth_time"]  = time();

		# for default HybridAuth endpoint url hauth_login_start_url
		# 	auth.start  required  the IDp ID
		# 	auth.time   optional  login request timestamp
		$this->params["login_start"] = $HYBRID_AUTH_URL_BASE . ( strpos( $HYBRID_AUTH_URL_BASE, '?' ) ? '&' : '?' ) . "hauth.start={$this->id}&hauth.time={$this->params["hauth_time"]}";

		# for default HybridAuth endpoint url hauth_login_done_url
		# 	auth.done   required  the IDp ID
		$this->params["login_done"]  = $HYBRID_AUTH_URL_BASE . ( strpos( $HYBRID_AUTH_URL_BASE, '?' ) ? '&' : '?' ) . "hauth.done={$this->id}";

		Hybrid_Auth::storage()->set( "hauth_session.{$this->id}.hauth_return_to"	, $this->params["hauth_return_to"] );
		Hybrid_Auth::storage()->set( "hauth_session.{$this->id}.hauth_endpoint"	    , $this->params["login_done"]      ); 
		Hybrid_Auth::storage()->set( "hauth_session.{$this->id}.id_provider_params"	, $this->params );

		// store config to be used by the end point
		$_SESSION["HA::CONFIG"] = serialize( Hybrid_Auth::$config );

		// move on
		Hybrid_Logger::debug( "Hybrid_Provider_Adapter::login( {$this->id} ), Call HybridAuth Endpoint to start with Given params ", $this->params );
		
		Hybrid_Auth::redirect( $this->params["login_start"] );
	}

	// --------------------------------------------------------------------

   /**
	* let hybridauth forget all about the user
	*/
	function logout()
	{
		$this->adapter->logout();
	}

	// --------------------------------------------------------------------

	public function isUserConnected()
	{
		return $this->adapter->isUserConnected();
	}

	// --------------------------------------------------------------------

	public function getUserProfile()
	{
		Hybrid_Logger::info( "Enter Hybrid_Provider_Adapter::getUserProfile(), Provider: {$this->id}" );

		if ( ! $this->isUserConnected() )
		{
			throw new Exception( "User profile request failed! User not connected to {$this->id}.", 6 );
		} 

		return $this->adapter->getUserProfile();
	}

	// --------------------------------------------------------------------

	public function getAccessToken()
	{
		if( ! $this->adapter->isUserConnected() ){
			Hybrid_Logger::error( "User not connected to the provider." );

			throw new Exception( "User not connected to the provider.", 7 );
		}

		return
				ARRAY(
					"access_token"        => $this->adapter->token( "access_token" ),
					"access_token_secret" => $this->adapter->token( "access_token_secret" ),
				);
	}

	// --------------------------------------------------------------------

   /**
	* Naive getter of the current connected IDp API client
	*/
	function api()
	{
		if( ! $this->adapter->isUserConnected() ){
			Hybrid_Logger::error( "User not connected to the provider." );

			throw new Exception( "User not connected to the provider.", 7 );
		}

		return $this->adapter->api;
	}

	// --------------------------------------------------------------------

   /**
	* redirect the user to hauth_return_to (the callback url)
	*/
	function returnToCallbackUrl()
	{ 
		// get stored callback url
		$callback_url = Hybrid_Auth::storage()->get( "hauth_session.{$this->id}.hauth_return_to" );

		// remove some unneed'd stored data 
		Hybrid_Auth::storage()->delete( "hauth_session.{$this->id}.hauth_return_to"    );
		Hybrid_Auth::storage()->delete( "hauth_session.{$this->id}.hauth_endpoint"     );
		Hybrid_Auth::storage()->delete( "hauth_session.{$this->id}.id_provider_params" );

		// back to home
		Hybrid_Auth::redirect( $callback_url );
	}

	// --------------------------------------------------------------------

	function getProviderCiId( $id )
	{
		foreach( Hybrid_Auth::$config["providers"] as $idpid => $params ){
			if( strtolower( $idpid ) == strtolower( $id ) ){
				return $idpid;
			}
		}

		return NULL;
	}

	// --------------------------------------------------------------------

    /**
     * find the IDp config on hybrid.config.php HybridAuth configuration file
     *
     * @param string  $id      The id or name of the IDp
     *
     * @return array if the IDp config founded on $GLOBAL_HYBRID_AUTH_IDPROVIDERS
     * @return NULL if no match
     */
	function getConfigById( $id )
	{ 
		if( isset( Hybrid_Auth::$config["providers"][$id] ) ){
			return Hybrid_Auth::$config["providers"][$id];
		} 

		return NULL;
	}
}
